#define __USE_GNU

#include <errno.h>
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
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <limits.h>
#include <syscall.h>

#include <unordered_map>


struct pdig_process_context {
	pdig_process_context() : saw_initial_sigstop(false), clone_flags(0), parent_clone_flags(0), pid(0) {}
	pdig_process_context(const pdig_process_context&) = delete;
	pdig_process_context& operator= (const pdig_process_context&) = delete;

	bool saw_initial_sigstop;
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

static int install_filter()
{
	size_t num_syscalls = 0;

	uint32_t instrumented_syscalls[SYSCALL_TABLE_SIZE] = {0};

	for(size_t i=0; i<SYSCALL_TABLE_SIZE; ++i) {
		uint32_t flags = g_syscall_table[i].flags;
		if ((flags & (UF_USED | UF_ALWAYS_DROP)) != UF_USED) {
			continue;
		}

		enum ppm_event_type enter_event = g_syscall_table[i].enter_event_type;
		uint32_t enter_event_flags = g_event_info[enter_event].flags;
		if (enter_event_flags & (EF_UNUSED | EF_DROP_SIMPLE_CONS)) {
			continue;
		}

		enum ppm_event_type exit_event = g_syscall_table[i].exit_event_type;
		uint32_t exit_event_flags = g_event_info[exit_event].flags;
		if (exit_event_flags & (EF_UNUSED | EF_DROP_SIMPLE_CONS)) {
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

	struct sock_filter filter[ARRAY_SIZE(filter_header) + num_syscalls + ARRAY_SIZE(filter_footer)] = {0};

	memcpy(&filter[0], filter_header, sizeof(filter_header));
	int insn = ARRAY_SIZE(filter_header);


	for(size_t i = 0; i < num_syscalls; ++i) {
		uint8_t jmp_off = num_syscalls - i;
		filter[insn++] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, instrumented_syscalls[i], jmp_off, 0);
	}

	memcpy(&filter[insn], filter_footer, sizeof(filter_footer));

	struct sock_fprog prog = {
		.len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
		.filter = filter
	};

	EXPECT(prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0));
	return 0;
}

int main(int argc, char **argv)
{
	pid_t pid = fork();
	pid_t mainpid = pid;
	int exitcode = 0;
	switch(pid) {
		case 0: /* child */
			DEBUG("child forked, pid = %d\n", getpid());
			EXPECT(ptrace(PTRACE_TRACEME, 0, NULL, NULL));
			DEBUG("PTRACE_TRACEME done\n");
			EXPECT(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
			DEBUG("NO_NEW_PRIVS done\n");
			EXPECT(raise(SIGSTOP));
			install_filter();
			DEBUG("child calling execve\n");
			execv(argv[1], argv+1);
			DEBUG("child execve failed\n");
			abort();
		case -1: /* error */
			abort();
	}

	EXPECT(pdig_init_shm());
	DEBUG("parent pid = %d\n", getpid());
	signal(SIGCHLD, ignore_sig);

	while(1) {
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
			__ptrace_request ptrace_op = PTRACE_CONT;
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
					handle_syscall(pid, pctx, false);
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
	}

	return exitcode;
}

