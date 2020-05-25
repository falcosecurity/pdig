#define __USE_GNU

#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <limits.h>
#include <syscall.h>

#include <atomic>
#include <unordered_map>


enum class process_state {
	spawning,

	attaching,
	attaching_first_syscall_enter,
	attaching_first_syscall_exit,

	waiting_for_enter,
	waiting_for_exit,
};


struct pdig_process_context {
	pdig_process_context(process_state state_, bool use_seccomp_, uint64_t parent_clone_flags_):
		state(state_),
		pid(0),
		clone_flags(0),
		parent_clone_flags(parent_clone_flags_),
		use_seccomp(use_seccomp_)
	{}

	process_state state;
	pid_t pid; // we know the tid but need to store the pid somewhere

	uint64_t clone_flags; // clone() flags this thread was created with
	uint64_t parent_clone_flags; // clone() flags when this thread is a parent

	bool use_seccomp;
};


struct pdig_context {
	pid_t mainpid;
	int exitcode;
	struct sock_fprog* seccomp_filter;
	std::unordered_map<pid_t, pdig_process_context> procs;
};

static std::atomic<bool> die(false);

extern "C" {
#include "pdig.h"
#include "udig_capture.h"
#include "ppm_events_public.h"
#include "ppm.h"
}

void ignore_sig(int _sig)
{
}

static constexpr const uintptr_t PTRACE_FLAGS =
	PTRACE_O_TRACESYSGOOD | \
	PTRACE_O_EXITKILL | \
	PTRACE_O_TRACEFORK | \
	PTRACE_O_TRACECLONE | \
	PTRACE_O_TRACEVFORK | \
	PTRACE_O_TRACEEXEC | \
	PTRACE_O_TRACEEXIT;

static constexpr const uintptr_t SECCOMP_FLAGS = PTRACE_FLAGS | PTRACE_O_TRACESECCOMP;

static constexpr void* ptrace_options(bool use_seccomp)
{
	return (void*)(use_seccomp ? SECCOMP_FLAGS : PTRACE_FLAGS);
}


pid_t get_pid(pid_t tid)
{
	struct user_regs_struct saved_regs;

	EXPECT(ptrace(PTRACE_GETREGS, tid, &saved_regs, &saved_regs));

	struct user_regs_struct regs = saved_regs;
	regs.rax = __NR_getpid;
	regs.rip = saved_regs.rip - 2;
	EXPECT(ptrace(PTRACE_SETREGS, tid, &regs, &regs));
	EXPECT(step(tid));
	EXPECT(ptrace(PTRACE_GETREGS, tid, &regs, &regs));
	EXPECT(ptrace(PTRACE_SETREGS, tid, &saved_regs, &saved_regs));
	return regs.rax;
}

static bool wait_for_next_syscall(pid_t tid, pdig_process_context& pctx)
{
	if(pctx.use_seccomp) {
		EXPECT(ptrace(PTRACE_CONT, tid, NULL, NULL));
	} else {
		EXPECT(ptrace(PTRACE_SYSCALL, tid, NULL, NULL));
	}

	pctx.state = process_state::waiting_for_enter;
	return true;
}

static bool deliver_signal(pid_t tid, pdig_process_context& pctx, int sig)
{
	if(pctx.use_seccomp) {
		EXPECT(ptrace(PTRACE_CONT, tid, sig, sig));
	} else {
		EXPECT(ptrace(PTRACE_SYSCALL, tid, sig, sig));
	}

	pctx.state = process_state::waiting_for_enter;
	return true;
}

void handle_syscall(pid_t pid, pdig_process_context& pctx, bool enter)
{
	struct user_regs_struct regs;
	uint64_t context[CTX_PID_TID + 1];

	if (ptrace(PTRACE_GETREGS, pid, &regs, &regs) < 0) {
		WARN("PTRACE_GETREGS failed for pid %d", pid);
		return;
	}
	context[CTX_REG_RDI] = regs.rdi;
	context[CTX_REG_RSI] = regs.rsi;
	context[CTX_REG_RDX] = regs.rdx;
	context[CTX_REG_R10] = regs.r10;
	context[CTX_REG_R8]  = regs.r8;
	context[CTX_REG_R9]  = regs.r9;
	context[CTX_REG_RAX_ENTER] = regs.orig_rax;
	context[CTX_REG_RAX] = regs.rax;
	context[CTX_PID_TID] = ((uint64_t)pctx.pid) << 32 | pid;

	DEBUG("pid=%d tid=%d syscall=%lld ret=%lld enter=%d rip=%016llx\n", pctx.pid, pid, regs.orig_rax, regs.rax, enter, regs.rip);

	if(regs.orig_rax == __NR_rt_sigreturn)
	{
		DEBUG("rt_sigreturn, faking exit event\n");
		on_syscall(context, false);
	}
	else if(regs.orig_rax == __NR_execve && regs.rax == 0)
	{
		DEBUG("ignoring execve return, will capture PTRACE_EVENT_EXEC\n");
	}
	else if((int64_t)regs.orig_rax >= 0)
	{
		// rt_sigreturn yields two events, the other one with orig_rax == -1, ignore it
		on_syscall(context, enter);

		if(regs.orig_rax == __NR_clone && enter)
		{
			DEBUG("SYSCALL tid %d clone(%08llx)\n", pid, regs.rdi);
			pctx.parent_clone_flags = regs.rdi;
		}
	}
}
// state transitions

static bool handle_execve_exit(pid_t tid, pdig_process_context& pctx)
{
	uint64_t context[CTX_PID_TID + 1] = {0};
	context[CTX_REG_RAX_ENTER] = __NR_execve;
	context[CTX_REG_RAX] = 0;
	context[CTX_PID_TID] = ((uint64_t)tid) << 32 | tid; // pid == tid here
	on_syscall(context, false);
	return wait_for_next_syscall(tid, pctx);
}

static bool handle_exit(pid_t tid, pdig_process_context& pctx)
{
	record_procexit_event(tid, pctx.pid);
	return wait_for_next_syscall(tid, pctx);
}

static bool handle_ptrace_clone_event(pid_t tid, pdig_process_context& pctx, pdig_context& main_ctx)
{
	uint64_t child_tid;
	if (ptrace(PTRACE_GETEVENTMSG, tid, NULL, &child_tid) < 0) {
		WARN("PTRACE_GETEVENTMSG failed for tid %d", tid);
		return wait_for_next_syscall(tid, pctx);
	}

	DEBUG("CLONE tid %d cloned to %lu with flags %08lx\n", tid, child_tid, pctx.parent_clone_flags);
	main_ctx.procs.insert({
		child_tid,
		{
			process_state::spawning,
			pctx.use_seccomp,
			pctx.parent_clone_flags
		}
	});

	return wait_for_next_syscall(tid, pctx);
}

static bool handle_spawning(pid_t tid, pdig_process_context& pctx)
{
	EXPECT(ptrace(PTRACE_SETOPTIONS, tid, 0, ptrace_options(pctx.use_seccomp)));
	pctx.pid = get_pid(tid);

	DEBUG("hello tid %d (pid %d)\n", tid, pctx.pid);
	if(pctx.clone_flags) {
		uint64_t context[CTX_PID_TID + 1] = {0};
		context[CTX_REG_RAX_ENTER] = __NR_clone;
		context[CTX_REG_RAX] = 0;
		context[CTX_REG_RDI] = pctx.clone_flags;
		context[CTX_PID_TID] = ((uint64_t)pctx.pid) << 32 | tid;
		DEBUG("clone pid_tid = %016lx flags = %08lx\n", context[CTX_PID_TID], pctx.clone_flags);
		on_syscall(context, false);
	}

	return wait_for_next_syscall(tid, pctx);
}

static bool handle_attaching(pid_t tid, pdig_process_context& pctx)
{
	EXPECT(ptrace(PTRACE_SETOPTIONS, tid, 0, ptrace_options(pctx.use_seccomp)));
	pctx.pid = get_pid(tid);
	EXPECT(ptrace(PTRACE_SYSCALL, tid, NULL, NULL));

	if(!pctx.use_seccomp) {
		pctx.state = process_state::waiting_for_enter;
	} else {
		pctx.state = process_state::attaching_first_syscall_enter;
	}

	return true;
}

static bool handle_attaching_first_syscall_enter(pid_t tid, pdig_process_context& pctx)
{
	// TODO: we could want to instrument this syscall too
	//       but we don't have the process id yet
	//       (we can't inject getpid() until this syscall finishes)
	EXPECT(ptrace(PTRACE_SYSCALL, tid, NULL, NULL));
	pctx.state = process_state::attaching_first_syscall_exit;
	return true;
}

static bool handle_attaching_first_syscall_exit(pid_t tid, pdig_process_context& pctx, pdig_context& main_ctx)
{
	struct sock_fprog* prog = main_ctx.seccomp_filter;
	struct user_regs_struct saved_regs;

	EXPECT(ptrace(PTRACE_GETREGS, tid, &saved_regs, &saved_regs));

	struct user_regs_struct regs = saved_regs;
	regs.rax = __NR_prctl;
	regs.rdi = PR_SET_NO_NEW_PRIVS;
	regs.rsi = 1;
	regs.rdx = 0;
	regs.r10 = 0;
	regs.r8 = 0;
	regs.rip = saved_regs.rip - 2;
	EXPECT(ptrace(PTRACE_SETREGS, tid, &regs, &regs));
	EXPECT(step(tid));
	EXPECT(ptrace(PTRACE_GETREGS, tid, &regs, &regs));
	if(regs.rax != 0) {
		WARN("Failed to enable PR_SET_NO_NEW_PRIVS, disabling seccomp%s", "");
		pctx.use_seccomp = false;
		EXPECT(ptrace(PTRACE_SETREGS, tid, &saved_regs, &saved_regs));
		EXPECT(ptrace(PTRACE_SYSCALL, tid, NULL, NULL));
		pctx.state = process_state::waiting_for_enter;
		return true;
	}

	// set stack pointer before we copy our data over
	EXPECT(ptrace(PTRACE_SETREGS, tid, &regs, &regs));

	// stack layout
	//
	// [prog][sock_filter[]][red zone][orig stack]
	// ^     ^                        ^
	// |     |                        saved_regs.rsp
	// |     sock_fprog->filter
	// rdx, rsp

	unsigned long payload_len = sizeof(*prog) + prog->len * sizeof(prog->filter[0]);
	unsigned long payload_addr = (saved_regs.rsp - payload_len - 128) & ~0x0f;
	regs = saved_regs;
	regs.rax = __NR_prctl;
	regs.rdi = PR_SET_SECCOMP;
	regs.rsi = SECCOMP_MODE_FILTER;
	regs.rdx = payload_addr;
	prog->filter = (struct sock_filter*)(payload_addr + sizeof(*prog));
	regs.r10 = 0;
	regs.r8 = 0;
	regs.rip = saved_regs.rip - 2;
	regs.rsp = payload_addr;

	copy_to_user(tid, prog, (void*)payload_addr, (payload_len + 0x0f) & ~0x0f);

	EXPECT(step(tid));
	EXPECT(ptrace(PTRACE_GETREGS, tid, &regs, &regs));
	if(regs.rax != 0) {
		abort();
	}

	EXPECT(ptrace(PTRACE_SETREGS, tid, &saved_regs, &saved_regs));
	EXPECT(ptrace(PTRACE_CONT, tid, NULL, NULL));
	pctx.state = process_state::waiting_for_enter;

	return true;
}

static bool handle_syscall_enter(pid_t tid, pdig_process_context& pctx)
{
	handle_syscall(tid, pctx, true);
	EXPECT(ptrace(PTRACE_SYSCALL, tid, NULL, NULL));

	pctx.state = process_state::waiting_for_exit;
	return true;
}

static bool handle_syscall_exit(pid_t tid, pdig_process_context& pctx, pdig_context& main_ctx)
{
	handle_syscall(tid, pctx, false);
	if(die && !pctx.use_seccomp) {
		DEBUG("Detaching from tid %d\n", tid);
		EXPECT(ptrace(PTRACE_DETACH, tid, 0, 0));
		main_ctx.procs.erase(tid);
		return true;
	} else {
		return wait_for_next_syscall(tid, pctx);
	}
}

// event handlers

static bool handle_signal(pid_t tid, pdig_process_context& pctx, int sig, pdig_context& main_ctx)
{
	DEBUG("Got signal %04x for tid %u in state %d\n", sig, tid, static_cast<int>(pctx.state));
	switch(sig) {
	case SIGSTOP:
		switch(pctx.state) {
		case process_state::spawning:
			return handle_spawning(tid, pctx);

		case process_state::attaching:
			return handle_attaching(tid, pctx);

		default:
			return true;
		}
	case SIGTRAP | (PTRACE_EVENT_SECCOMP << 8):
	case SIGTRAP | 0x80:
		switch(pctx.state) {
		case process_state::attaching_first_syscall_enter:
			return handle_attaching_first_syscall_enter(tid, pctx);

		case process_state::attaching_first_syscall_exit:
			return handle_attaching_first_syscall_exit(tid, pctx, main_ctx);

		case process_state::waiting_for_enter:
			return handle_syscall_enter(tid, pctx);

		case process_state::waiting_for_exit:
			return handle_syscall_exit(tid, pctx, main_ctx);

		default:
			WARN("Got signal %04x for tid %u in state %d", sig, tid, static_cast<int>(pctx.state));
			return true;
	}
	case SIGTRAP | (PTRACE_EVENT_EXEC << 8):
		return handle_execve_exit(tid, pctx);
	case SIGTRAP | (PTRACE_EVENT_EXIT << 8):
		return handle_exit(tid, pctx);
	case SIGTRAP | (PTRACE_EVENT_CLONE << 8): // is clone guaranteed to stay within the same tgid?
	case SIGTRAP | (PTRACE_EVENT_VFORK << 8):
	case SIGTRAP | (PTRACE_EVENT_FORK << 8):
		return handle_ptrace_clone_event(tid, pctx, main_ctx);
	case SIGTRAP:
		return wait_for_next_syscall(tid, pctx);
	default:
		if((sig & 0x3f) == SIGTRAP) {
			WARN("Got unhandled signal %04x for tid %u in state %d", sig, tid, static_cast<int>(pctx.state));
		}
		return deliver_signal(tid, pctx, sig);
	}
}

static bool handle_waitpid(pid_t tid, int status, pdig_context& main_ctx)
{
	set_pid(tid);

	if(WIFEXITED(status)) {
		DEBUG("tracee %d exited: %d\n", tid, WEXITSTATUS(status));
		if(tid == main_ctx.mainpid) {
			main_ctx.exitcode = WEXITSTATUS(status);
		}
		main_ctx.procs.erase(tid);
	} else if(WIFSIGNALED(status)) {
		DEBUG("tracee %d died with signal %d\n", tid, WTERMSIG(status));
		if(tid == main_ctx.mainpid) {
			main_ctx.exitcode = 128 + WTERMSIG(status);
		}
		main_ctx.procs.erase(tid);
	} else if(WIFSTOPPED(status)) {
		auto proc = main_ctx.procs.find(tid);
		if (proc == main_ctx.procs.end()) {
			WARN("Got notification from unexpected thread %d", tid);
		} else {
			return handle_signal(tid, proc->second, status >> 8, main_ctx);
		}
	} else {
		WARN("Got unexpected waitpid status %08x for tid %u", status, tid);
	}
	return true;
}



#define X32_SYSCALL_BIT 0x40000000
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

static struct sock_fprog* build_filter(bool capture_all)
{
	size_t num_syscalls = 0;

	uint32_t instrumented_syscalls[SYSCALL_TABLE_SIZE] = {0};

	for(size_t i=0; i<SYSCALL_TABLE_SIZE; ++i) {
		uint32_t flags = g_syscall_table[i].flags;
		if (!(flags & UF_USED)) {
			continue;
		}

		bool instrument = capture_all;

		if(!instrument) {
			enum ppm_event_type enter_event = g_syscall_table[i].enter_event_type;
			enum ppm_event_type exit_event = g_syscall_table[i].exit_event_type;

			uint32_t enter_event_flags = g_event_info[enter_event].flags;
			uint32_t exit_event_flags = g_event_info[exit_event].flags;

			instrument = (enter_event_flags & EF_MODIFIES_STATE) || (exit_event_flags & EF_MODIFIES_STATE);
		}

		if(instrument) {
			instrumented_syscalls[num_syscalls++] = i;
		}
	}

	struct sock_filter filter_header[] = {
		// if arch != AUDIT_ARCH_X86_64 { return ERRNO | ENOSYS }
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, arch))),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (ENOSYS & SECCOMP_RET_DATA)),

		// if nr >= X32_SYSCALL_BIT { return ERRNO | ENOSYS }
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr))),
		BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, X32_SYSCALL_BIT, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (ENOSYS & SECCOMP_RET_DATA)),
	};

	struct sock_filter filter_footer[] = {
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};

	const size_t CHUNK_SIZE = 255; // must be < 256

	size_t num_chunks = (num_syscalls + CHUNK_SIZE - 1) / CHUNK_SIZE;
	size_t last_chunk_len = num_syscalls % CHUNK_SIZE;
	size_t trace_insn = ARRAY_SIZE(filter_header) - 1;

	size_t filter_size = ARRAY_SIZE(filter_header) + num_syscalls + num_chunks + ARRAY_SIZE(filter_footer);
	DEBUG("filter has %zu insns\n", filter_size);
	size_t payload_size = sizeof(struct sock_fprog) + filter_size * sizeof(struct sock_filter);
	char* buf = (char*)calloc((payload_size + 0x0f) & ~0x0f, 1);
	if(!buf) {
		return NULL;
	}

	struct sock_filter* filter = (struct sock_filter*)(buf + sizeof(struct sock_fprog));
	struct sock_fprog* prog = (struct sock_fprog*)buf;

	memcpy(&filter[0], filter_header, sizeof(filter_header));
	int insn = ARRAY_SIZE(filter_header);

	for(size_t i = 0; i < num_syscalls; ++i) {
		size_t chunk = i / CHUNK_SIZE;
		size_t chunk_off = i % CHUNK_SIZE;
		size_t current_chunk_size;
		if (chunk == num_chunks - 1) {
			current_chunk_size = last_chunk_len;
		} else {
			current_chunk_size = CHUNK_SIZE;
		}
		int at_chunk_end = (chunk_off == current_chunk_size - 1);

		if (chunk_off == 0) {
			trace_insn += current_chunk_size + 1;
			if (chunk != 0) {
				DEBUG("[insn#%d] RET_TRACE\n", insn);
				filter[insn++] = BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE);
			}
		}

		int jt = trace_insn - insn - 1;
		int jf = at_chunk_end;

		if(jt != (uint8_t)jt) {
			abort();
		}

		if(jf != (uint8_t)jf) {
			abort();
		}

		DEBUG("[insn#%d] if nr == %d { goto +%d (%d) } else { goto +%d (%d) }\n",
			insn, instrumented_syscalls[i], jt, insn + jt + 1, jf, insn + jf + 1);
		filter[insn++] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, instrumented_syscalls[i], (uint8_t)jt, (uint8_t)jf);
	}
	DEBUG("[insn#%d] RET_TRACE\n", insn);
	filter[insn++] = BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE);

	memcpy(&filter[insn], filter_footer, sizeof(filter_footer));

	prog->len = (unsigned short)filter_size;
	prog->filter = filter;
	return prog;
}

static int spawn(int argc, char** argv, pdig_context& main_ctx)
{
	bool use_seccomp = main_ctx.seccomp_filter != nullptr;
	pid_t pid = fork();
	switch(pid) {
		case 0: /* child */
			DEBUG("child forked, pid = %d\n", getpid());
			signal(SIGCHLD, SIG_DFL);
			signal(SIGINT, SIG_DFL);
			EXPECT(ptrace(PTRACE_TRACEME, 0, NULL, NULL));
			DEBUG("PTRACE_TRACEME done\n");
			EXPECT(raise(SIGSTOP));
			if(use_seccomp) {
				EXPECT(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
				DEBUG("NO_NEW_PRIVS done\n");
				EXPECT(prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, main_ctx.seccomp_filter, 0, 0));
			}

			DEBUG("child calling execve\n");
			execvp(argv[0], argv);
			DEBUG("child execve failed\n");
			abort();
		case -1: /* error */
			abort();
	}

	main_ctx.procs.insert({
		pid,
		{
			process_state::spawning,
			use_seccomp,
			0,
		}
	});

	return 0;
}

static int attach(pid_t tid, pdig_context& main_ctx)
{
	bool use_seccomp = main_ctx.seccomp_filter != nullptr;

	EXPECT(ptrace(PTRACE_ATTACH, tid, 0, 0));

	main_ctx.procs.insert({
		tid,
		{
			process_state::attaching,
			use_seccomp,
			0,
		}
	});

	return 0;
}

static void usage()
{
	printf(
"Usage: pdig [options] comdline\n\n"
"Options:\n"
" -a, --capture-all   capture all of the system calls and not only the ones used by falco.\n"
" -p PID, --pid PID   attach to an already running process.\n"
" -S, --force_seccomp enable seccomp even for attaching to running processes.\n"
"                     Note: this will improve performance but will kill the traced process when pdig exits.\n"
" -h, --help          Print this page\n"
);
}

void sigint(int _sig)
{
	if(!die) {
		die = true;
	} else {
		exit(1);
	}
}

int main(int argc, char **argv)
{
	pid_t pid = -1;
	int exitcode = 0;
	bool capture_all = false;
	bool force_seccomp = false;
	int op;
	int long_index = 0;
	pdig_context main_ctx = {0};

	static struct option long_options[] =
	{
		{"capture-all", no_argument, 0, 'a' },
		{"pid", required_argument, 0, 'p' },
		{"force-seccomp", no_argument, 0, 'S' },
		{"help", no_argument, 0, 'h' }
	};

	while((op = getopt_long(argc, argv, "+ap:Sh", long_options, &long_index)) != -1) {
		switch(op) {
			case 'a':
				capture_all = true;
				break;
			case 'p':
				pid = atoi(optarg);
				break;
			case 'S':
				force_seccomp = true;
				break;
			case 'h':
				usage();
				return exitcode;
			default:
				break;
		}
	}

	signal(SIGCHLD, ignore_sig);
	signal(SIGINT, sigint);

	if(force_seccomp || pid == -1)
	{
		main_ctx.seccomp_filter = build_filter(capture_all);
	}

	if(pid != -1)
	{
		EXPECT(attach(pid, main_ctx));
	}
	else
	{
		EXPECT(spawn(argc - optind, argv + optind, main_ctx));
	}

	EXPECT(pdig_init_shm());
	DEBUG("parent pid = %d\n", getpid());

	do {
		int status;
		DEBUG("parent calling waitpid()\n");
		pid = waitpid(-1, &status, WUNTRACED);
		DEBUG("waitpid(-1) = %d, status = %04x, errno = %d\n", pid, status, errno);
		if(pid == -1 && errno == ECHILD)
		{
			break;
		}
		EXPECT(pid);
		handle_waitpid(pid, status, main_ctx);
	} while(!main_ctx.procs.empty());

	free(main_ctx.seccomp_filter);
	return exitcode;
}

