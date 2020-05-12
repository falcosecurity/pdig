#define __USE_GNU

#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
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


struct pdig_process_context {
	pdig_process_context() : saw_initial_sigstop(false), syscall_enter(true), clone_flags(0), parent_clone_flags(0), pid(0) {}
	pdig_process_context(const pdig_process_context&) = delete;
	pdig_process_context& operator= (const pdig_process_context&) = delete;

	bool saw_initial_sigstop;
	bool syscall_enter;
	uint64_t clone_flags; // clone() flags this thread was created with
	uint64_t parent_clone_flags; // clone() flags when this thread is a parent
	pid_t pid; // we know the tid but need to store the pid somewhere
};


extern "C" {
#include "pdig.h"
#include "udig_capture.h"
#include "ppm_events_public.h"
#include "ppm.h"
}

#define EXPECT(v) do { \
    int __ret = (v); \
	if(__ret < 0) { \
		fprintf(stderr, "%s failed at %s:%d with %d (errno %s)\n", #v, __FILE__, __LINE__, __ret, strerror(errno)); \
		abort(); \
	} \
} while(0)

#ifdef _DEBUG
#define DEBUG(...) fprintf(stderr, __VA_ARGS__)
#else
#define DEBUG(...)
#endif

#define WARN(fmt, ...) fprintf(stderr, fmt " at %s:%d (errno %s)\n", __VA_ARGS__, __FILE__, __LINE__, strerror(errno))

void ignore_sig(int _sig)
{
}

std::unordered_map<pid_t, pdig_process_context> procs;

void handle_clone_exit(pid_t pid, const pdig_process_context& pctx)
{
	if(pctx.clone_flags) {
		uint64_t context[CTX_PID_TID + 1] = {0};
		context[CTX_REG_RAX_ENTER] = __NR_clone;
		context[CTX_REG_RAX] = 0;
		context[CTX_REG_RDI] = pctx.clone_flags;
		context[CTX_PID_TID] = ((uint64_t)pctx.pid) << 32 | pid;
		DEBUG("clone pid_tid = %016lx flags = %08lx\n", context[CTX_PID_TID], pctx.clone_flags);
		on_syscall(context, false);
	}
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

void handle_ptrace_clone_event(pid_t tid)
{
	uint64_t child_tid;
	if (ptrace(PTRACE_GETEVENTMSG, tid, NULL, &child_tid) < 0) {
		WARN("PTRACE_GETEVENTMSG failed for tid %d", tid);
		return;
	}

	DEBUG("CLONE tid %d cloned to %lu with flags %08lx\n", tid, child_tid, procs[tid].parent_clone_flags);
	procs[child_tid].clone_flags = procs[tid].parent_clone_flags;
}

void handle_execve_exit(pid_t pid)
{
	uint64_t context[CTX_PID_TID + 1] = {0};
	context[CTX_REG_RAX_ENTER] = __NR_execve;
	context[CTX_REG_RAX] = 0;
	context[CTX_PID_TID] = ((uint64_t)pid) << 32 | pid; // pid == tid here
	on_syscall(context, false);
}

int get_pid(pid_t tid)
{
	int pid = -1; // tid?
	// XXX can we get this otherwise?
	char buf[256];
	snprintf(buf, sizeof(buf), "/proc/%d/status", tid);

	FILE* fp = fopen(buf, "rb");
	if(!fp) {
		return -1; // tid?
	}

	while(fgets(buf, sizeof(buf), fp) != NULL) {
		if(sscanf(buf, "Tgid:\t%d", &pid) == 1) {
			break;
		}
	}

	fclose(fp);
	return pid;
}

#define X32_SYSCALL_BIT 0x40000000
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

static struct sock_fprog* build_filter(bool capture_all)
{
	size_t num_syscalls = 0;
	uint32_t filtered_flags = EF_UNUSED;
	if(!capture_all) {
		filtered_flags |= EF_DROP_SIMPLE_CONS;
	}

	uint32_t instrumented_syscalls[SYSCALL_TABLE_SIZE] = {0};

	for(size_t i=0; i<SYSCALL_TABLE_SIZE; ++i) {
		uint32_t flags = g_syscall_table[i].flags;
		if ((flags & (UF_USED | UF_ALWAYS_DROP)) != UF_USED) {
			continue;
		}

		enum ppm_event_type enter_event = g_syscall_table[i].enter_event_type;
		uint32_t enter_event_flags = g_event_info[enter_event].flags;
		if ((enter_event_flags & filtered_flags) != 0 && (enter_event_flags & EF_MODIFIES_STATE) == 0) {
			continue;
		}

		enum ppm_event_type exit_event = g_syscall_table[i].exit_event_type;
		uint32_t exit_event_flags = g_event_info[exit_event].flags;
		if ((exit_event_flags & filtered_flags) != 0 && (exit_event_flags & EF_MODIFIES_STATE) == 0) {
			continue;
		}

		instrumented_syscalls[num_syscalls++] = i;

		DEBUG("syscall#%zu flags %08x enter flags = %08x exit flags = %08x\n", i, g_syscall_table[i].flags, enter_event_flags, exit_event_flags);
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
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE),
	};

	size_t filter_size = ARRAY_SIZE(filter_header) + num_syscalls + ARRAY_SIZE(filter_footer);
	char* buf = (char*)calloc(sizeof(struct sock_fprog) + filter_size * sizeof(struct sock_filter), 1);
	if(!buf) {
		return NULL;
	}

	struct sock_filter* filter = (struct sock_filter*)(buf + sizeof(struct sock_fprog));
	struct sock_fprog* prog = (struct sock_fprog*)buf;

	memcpy(&filter[0], filter_header, sizeof(filter_header));
	int insn = ARRAY_SIZE(filter_header);

	for(size_t i = 0; i < num_syscalls; ++i) {
		uint8_t jmp_off = num_syscalls - i;
		filter[insn++] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, instrumented_syscalls[i], jmp_off, 0);
	}

	memcpy(&filter[insn], filter_footer, sizeof(filter_footer));

	prog->len = (unsigned short)filter_size;
	prog->filter = filter;
	return prog;
}

static pid_t spawn(int argc, char** argv, bool capture_all)
{
	struct sock_fprog* prog;
	pid_t pid = fork();
	switch(pid) {
		case 0: /* child */
			DEBUG("child forked, pid = %d\n", getpid());
			EXPECT(ptrace(PTRACE_TRACEME, 0, NULL, NULL));
			DEBUG("PTRACE_TRACEME done\n");
			EXPECT(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
			DEBUG("NO_NEW_PRIVS done\n");
			EXPECT(raise(SIGSTOP));
			prog = build_filter(capture_all);
			EXPECT(prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, prog, 0, 0));
			free(prog);
			DEBUG("child calling execve\n");
			execvp(argv[0], argv);
			DEBUG("child execve failed\n");
			abort();
		case -1: /* error */
			abort();
	}

	return pid;
}

unsigned long copy_to_user(pid_t pid, void* from, void* to, unsigned long n)
{
	struct iovec local_iov[] = {{
		.iov_base = from,
		.iov_len = n,
	}};
	struct iovec remote_iov[] = {{
		.iov_base = to,
		.iov_len = n,
	}};

	if (process_vm_writev(pid, local_iov, 1, remote_iov, 1, 0) >= 0) {
		return 0;
	}

	if(n % sizeof(long) != 0) {
		abort();
	}

	unsigned long *ulfrom = (unsigned long*) from;
	unsigned long *ulto = (unsigned long*) to;
	for (unsigned long i = 0; i < n / sizeof(long); ++i) {
		EXPECT(ptrace(PTRACE_POKETEXT, pid, (void*) ulto, *ulfrom));
		ulfrom++;
		ulto++;
	}

	return 0;
}

static int step(pid_t target)
{
	int status;

	EXPECT(ptrace(PTRACE_SINGLESTEP, target, NULL, NULL));
	EXPECT(waitpid(target, &status, WSTOPPED));

	if(!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
		abort();
	}
	return 0;
}

static int attach(pid_t target, bool use_seccomp, bool capture_all)
{
	struct sock_fprog* prog = build_filter(capture_all);
	struct user_regs_struct saved_regs;

	set_pid(target);
	EXPECT(ptrace(PTRACE_ATTACH, target, NULL, NULL));
	EXPECT(waitpid(target, 0, WUNTRACED));
	if(!use_seccomp) {
		EXPECT(ptrace(PTRACE_SETOPTIONS, target, 0, (void*)(PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL | PTRACE_O_TRACEFORK | PTRACE_O_TRACECLONE | PTRACE_O_TRACEVFORK | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT)));

		EXPECT(ptrace(PTRACE_SYSCALL, target, NULL, NULL));
		return 0;
	}

	EXPECT(ptrace(PTRACE_SETOPTIONS, target, 0, (void*)(PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL | PTRACE_O_TRACEFORK | PTRACE_O_TRACECLONE | PTRACE_O_TRACEVFORK | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT | PTRACE_O_TRACESECCOMP)));

	EXPECT(ptrace(PTRACE_GETREGS, target, &saved_regs, &saved_regs));

	DEBUG("original rip = %016llx\n", saved_regs.rip);

	uint8_t patch[] = {
		0x0f, 0x05, // syscall (mmap)
		0x0f, 0x05, // syscall (no_new_privs)
		0x0f, 0x05, // syscall (seccomp)
		0x0f, 0x05, // syscall (munmap)

		0xff, 0xe0, // jmp %rax
		0x66, 0x90, // nop
		0x66, 0x90, // nop
		0x66, 0x90, // nop
	};
	uint8_t saved_text[sizeof(patch)];

	struct user_regs_struct new_regs = saved_regs;

	EXPECT(ppm_copy_from_user(saved_text, (void*)saved_regs.rip, sizeof(saved_text)));
	EXPECT(copy_to_user(target, patch, (void*)saved_regs.rip, sizeof(patch)));

	new_regs.rax = __NR_mmap;
	new_regs.rdi = 0; // addr
	new_regs.rsi = PAGE_SIZE; // size
	new_regs.rdx = PROT_READ | PROT_EXEC;
	new_regs.r10 = MAP_PRIVATE | MAP_ANONYMOUS;
	new_regs.r8 = -1; // fd
	new_regs.r9 = 0; // offset
	EXPECT(ptrace(PTRACE_SETREGS, target, &new_regs, &new_regs));
	DEBUG("setting rip = %016llx\n", new_regs.rip);

	EXPECT(step(target)); // syscall (mmap)
	EXPECT(ptrace(PTRACE_GETREGS, target, &new_regs, &new_regs));
	DEBUG("rip now = %016llx\n", new_regs.rip);
	unsigned long mmapped = new_regs.rax;

	unsigned long payload_len = sizeof(*prog) + prog->len * sizeof(prog->filter[0]);
	prog->filter = (struct sock_filter*)(mmapped + sizeof(*prog));
	DEBUG("mapped a page at %016lx, copying payload of %lu bytes\n", mmapped, payload_len);

	DEBUG("filter is at %p\n", prog->filter);
	EXPECT(copy_to_user(target, (void*)prog, (void*)mmapped, payload_len));
	free(prog);

	new_regs.rax = __NR_prctl;
	new_regs.rdi = PR_SET_NO_NEW_PRIVS;
	new_regs.rsi = 1;
	new_regs.rdx = 0;
	new_regs.r10 = 0;
	new_regs.r8 = 0;
	EXPECT(ptrace(PTRACE_SETREGS, target, &new_regs, &new_regs));
	EXPECT(step(target)); // syscall (no_new_privs)

	// EXPECT(prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0));
	new_regs.rax = __NR_prctl;
	new_regs.rdi = PR_SET_SECCOMP;
	new_regs.rsi = SECCOMP_MODE_FILTER;
	new_regs.rdx = mmapped;
	new_regs.r10 = 0;
	new_regs.r8 = 0;
	EXPECT(ptrace(PTRACE_SETREGS, target, &new_regs, &new_regs));
	EXPECT(step(target)); // syscall (seccomp)

	new_regs.rax = __NR_munmap;
	new_regs.rdi = mmapped;
	new_regs.rsi = PAGE_SIZE;
	EXPECT(ptrace(PTRACE_SETREGS, target, &new_regs, &new_regs));
	EXPECT(step(target)); // syscall (munmap)

	new_regs.rax = mmapped;
	EXPECT(ptrace(PTRACE_SETREGS, target, &new_regs, &new_regs));
	EXPECT(step(target)); // jmp %rax

	EXPECT(ptrace(PTRACE_SETREGS, target, &saved_regs, &saved_regs));
	EXPECT(copy_to_user(target, saved_text, (void*)saved_regs.rip, sizeof(saved_text)));

	EXPECT(ptrace(PTRACE_CONT, target, NULL, NULL));
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

static std::atomic<bool> die(false);

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
	__ptrace_request ptrace_default_op = PTRACE_CONT;

	static struct option long_options[] =
	{
		{"capture-all", no_argument, 0, 'a' },
		{"pid", required_argument, 0, 'p' },
		{"force-seccomp", no_argument, 0, 'S' },
		{"help", no_argument, 0, 'h' }
	};

	while((op = getopt_long(argc, argv, "ap:Sh", long_options, &long_index)) != -1) {
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

	if(pid != -1)
	{
		EXPECT(attach(pid, force_seccomp, capture_all));
		if(!force_seccomp) {
			ptrace_default_op = PTRACE_SYSCALL;
		}
	}
	else
	{
		pid = spawn(argc - optind, argv + optind, capture_all);
	}

	pid_t mainpid = pid;

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
		set_pid(pid);

		if(WIFEXITED(status)) {
			DEBUG("tracee exited: %d\n", WEXITSTATUS(status));
			if(pid == mainpid) {
				exitcode = WEXITSTATUS(status);
			}
			procs.erase(pid);
		} else if(WIFSIGNALED(status)) {
			DEBUG("tracee died with signal %d\n", WTERMSIG(status));
			if(pid == mainpid) {
				exitcode = 128 + WTERMSIG(status);
			}
			procs.erase(pid);
		} else if(WIFSTOPPED(status)) {
			__ptrace_request ptrace_op = ptrace_default_op;
			int sig = status >> 8;
			pdig_process_context& pctx = procs[pid];
			DEBUG("waitpid(-1) = %d, status = %04x, errno = %d\n", pid, status, errno);

			switch(sig) {
				case SIGSTOP:
					DEBUG("pid=%d hello, saw stop=%d\n", pid, pctx.saw_initial_sigstop);
					if(!pctx.saw_initial_sigstop) {
						pctx.saw_initial_sigstop = true;
						pctx.pid = get_pid(pid);
						DEBUG("SIGSTOP hello tid %d pid %d\n", pid, pctx.pid);
						EXPECT(ptrace(PTRACE_SETOPTIONS, pid, 0, (void*)(PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL | PTRACE_O_TRACEFORK | PTRACE_O_TRACECLONE | PTRACE_O_TRACEVFORK | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT | PTRACE_O_TRACESECCOMP)));
						handle_clone_exit(pid, pctx);
						sig = 0;
					}
					break;
				case SIGTRAP | (PTRACE_EVENT_SECCOMP << 8):
					DEBUG("seccomp, tid = %d, pid = %d\n", pid, pctx.pid);
					handle_syscall(pid, pctx, true);
					pctx.syscall_enter = false;
					ptrace_op = PTRACE_SYSCALL; // trap the exit event
					sig = 0;
					break;
				case SIGTRAP | (PTRACE_EVENT_EXEC << 8):
					DEBUG("execve exit, tid = %d, pid = %d\n", pid, pctx.pid);
					handle_execve_exit(pid);
					sig = 0;
					break;
				case SIGTRAP | (PTRACE_EVENT_EXIT << 8):
					DEBUG("exit, tid = %d, pid = %d\n", pid, pctx.pid);
					record_procexit_event(pid, pctx.pid);
					sig = 0;
					break;
				case SIGTRAP | (PTRACE_EVENT_CLONE << 8): // is clone guaranteed to stay within the same tgid?
				case SIGTRAP | (PTRACE_EVENT_VFORK << 8):
				case SIGTRAP | (PTRACE_EVENT_FORK << 8):
					DEBUG("SIGTRAP clone exit, tid = %d, pid = %d\n", pid, pctx.pid);
					handle_ptrace_clone_event(pid);
					sig = 0;
					break;
				case SIGTRAP:
					sig = 0;
					break;
				case SIGTRAP | 0x80:
					sig = 0;
					handle_syscall(pid, pctx, pctx.syscall_enter);
					pctx.syscall_enter = !pctx.syscall_enter;
					if(die && ptrace_default_op == PTRACE_SYSCALL) {
						if(pctx.syscall_enter) {
							fprintf(stderr, "detaching from pid %d\n", pid);
							EXPECT(ptrace(PTRACE_DETACH, pid, 0, 0));
							procs.erase(pid);
							continue;
						} else {
							fprintf(stderr, "pid %d in the middle of a syscall, not detaching yet\n", pid);
						}
					}
					break;
				default:
					if((sig & 0x3f) == SIGTRAP) {
						DEBUG("pid=%d unhandled SIGTRAP, status = %08x\n", pid, status);
						sig = 0;
					}
					break;
			}
			if(ptrace(ptrace_op, pid, 0, sig) < 0) {
				WARN("ptrace(%d, %d, 0, %d) failed", ptrace_op, pid, sig);
			}
		} else {
			DEBUG("pid=%d unhandled status = %08x\n", pid, status);
		}
	} while(!procs.empty());

	return exitcode;
}

