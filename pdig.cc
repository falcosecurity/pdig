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

#include "pdig_api.h"
#include "pdig_debug.h"
#include "pdig_ptrace.h"
#include "pdig_seccomp.h"


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
	uint64_t context[CTX_SIZE];

	if (ptrace(PTRACE_GETREGS, pid, &regs, &regs) < 0) {
		WARN("PTRACE_GETREGS failed for pid %d", pid);
		return;
	}
	fill_context(context, pid, pctx.pid, regs);

	DEBUG("pid=%d tid=%d syscall=%ld ret=%ld enter=%d\n",
		pctx.pid, pid, context[CTX_SYSCALL_ID], context[CTX_RETVAL], enter);

	if(context[CTX_SYSCALL_ID] == __NR_rt_sigreturn)
	{
		DEBUG("rt_sigreturn, faking exit event\n");
		on_syscall(context, false);
	}
	else if(context[CTX_SYSCALL_ID] == __NR_execve && context[CTX_RETVAL] == 0)
	{
		DEBUG("ignoring execve return, will capture PTRACE_EVENT_EXEC\n");
	}
	else if((int64_t)context[CTX_SYSCALL_ID] >= 0)
	{
		// rt_sigreturn yields two events, the other one with orig_rax == -1, ignore it
		on_syscall(context, enter);

		if(context[CTX_SYSCALL_ID] == __NR_clone && enter)
		{
			DEBUG("SYSCALL tid %d clone(%08lx)\n", pid, context[CTX_ARG0]);
			pctx.parent_clone_flags = context[CTX_ARG0];
		}
	}
}
// state transitions

static bool handle_execve_exit(pid_t tid, pdig_process_context& pctx)
{
	uint64_t context[CTX_SIZE] = {0};
	context[CTX_SYSCALL_ID] = __NR_execve;
	context[CTX_RETVAL] = 0;
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
	pctx.pid = inject_getpid(tid);

	DEBUG("hello tid %d (pid %d)\n", tid, pctx.pid);
	if(pctx.clone_flags) {
		uint64_t context[CTX_SIZE] = {0};
		context[CTX_SYSCALL_ID] = __NR_clone;
		context[CTX_RETVAL] = 0;
		context[CTX_ARG0] = pctx.clone_flags;
		context[CTX_PID_TID] = ((uint64_t)pctx.pid) << 32 | tid;
		DEBUG("clone pid_tid = %016lx flags = %08lx\n", context[CTX_PID_TID], pctx.clone_flags);
		on_syscall(context, false);
	}

	return wait_for_next_syscall(tid, pctx);
}

static bool handle_attaching(pid_t tid, pdig_process_context& pctx)
{
	EXPECT(ptrace(PTRACE_SETOPTIONS, tid, 0, ptrace_options(pctx.use_seccomp)));
	pctx.pid = inject_getpid(tid);
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
	struct user_regs_struct saved_regs;

	EXPECT(ptrace(PTRACE_GETREGS, tid, &saved_regs, &saved_regs));

	if (inject_prctl_set_no_new_privs(tid, saved_regs) != 0) {
		pctx.use_seccomp = false;
		EXPECT(ptrace(PTRACE_SETREGS, tid, &saved_regs, &saved_regs));
		EXPECT(ptrace(PTRACE_SYSCALL, tid, NULL, NULL));
		pctx.state = process_state::waiting_for_enter;
		return true;
	}

	if (inject_seccomp_filter(tid, saved_regs, main_ctx.seccomp_filter) != 0) {
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

