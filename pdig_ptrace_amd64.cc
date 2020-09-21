#include "pdig_ptrace.h"
#include "pdig_debug.h"
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stdint.h>
#include <syscall.h>
#include <sys/prctl.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/uio.h>

static inline unsigned long align_down(unsigned long n, size_t shift)
{
	unsigned long mask = (1 << shift) - 1;
	return n & ~mask;
}

static const size_t RED_ZONE = 128;

static void assert_at_syscall_insn(pid_t tid, const struct user_regs_struct& saved_regs)
{
#ifdef _DEBUG
	const char syscall_insn[] = {0x0f, 0x05};
	const int insn_size = sizeof(syscall_insn);
	char insn[insn_size];

	EXPECT(copy_from_user(tid, insn, (void*)(saved_regs.rip - insn_size), insn_size));
	EXPECT(memcmp(insn, syscall_insn, insn_size));
#endif
}

int inject_prctl_set_no_new_privs(pid_t tid, const struct user_regs_struct& saved_regs)
{
	assert_at_syscall_insn(tid, saved_regs);

	struct user_regs_struct regs = saved_regs;
	regs.rax = __NR_prctl;
	regs.rdi = PR_SET_NO_NEW_PRIVS;
	regs.rsi = 1;
	regs.rdx = 0;
	regs.r10 = 0;
	regs.r8 = 0;
	regs.rip = saved_regs.rip - 2;
	EXPECT(ptrace(PTRACE_SETREGS, tid, &regs, &regs));
	EXPECT(singlestep(tid));
	EXPECT(ptrace(PTRACE_GETREGS, tid, &regs, &regs));
	return regs.rax;
}

int inject_seccomp_filter(pid_t tid, const struct user_regs_struct& saved_regs, struct sock_fprog* prog)
{
	assert_at_syscall_insn(tid, saved_regs);

	// stack layout
	//
	// [prog][sock_filter[]][red zone][orig stack]
	// ^     ^                        ^
	// |     |                        saved_regs.rsp
	// |     sock_fprog->filter
	// rdx, rsp

	unsigned long payload_len = sizeof(*prog) + prog->len * sizeof(prog->filter[0]);
	unsigned long payload_addr = align_down(saved_regs.rsp - payload_len - RED_ZONE, 4);
	struct user_regs_struct regs = saved_regs;

	regs.rax = __NR_prctl;
	regs.rdi = PR_SET_SECCOMP;
	regs.rsi = SECCOMP_MODE_FILTER;
	regs.rdx = payload_addr;
	prog->filter = (struct sock_filter*)(payload_addr + sizeof(*prog));
	regs.r10 = 0;
	regs.r8 = 0;
	regs.rip = saved_regs.rip - 2;
	regs.rsp = payload_addr;
	// set stack pointer before we copy our data over
	EXPECT(ptrace(PTRACE_SETREGS, tid, &regs, &regs));

	copy_to_user(tid, prog, (void*)payload_addr, payload_len);

	EXPECT(singlestep(tid));
	EXPECT(ptrace(PTRACE_GETREGS, tid, &regs, &regs));
	return regs.rax;
}

pid_t inject_getpid(pid_t tid)
{
	struct user_regs_struct saved_regs;
	EXPECT(ptrace(PTRACE_GETREGS, tid, &saved_regs, &saved_regs));
	assert_at_syscall_insn(tid, saved_regs);

	struct user_regs_struct regs = saved_regs;
	regs.rax = __NR_getpid;
	regs.rip = saved_regs.rip - 2;
	EXPECT(ptrace(PTRACE_SETREGS, tid, &regs, &regs));
	EXPECT(singlestep(tid));
	EXPECT(ptrace(PTRACE_GETREGS, tid, &regs, &regs));
	EXPECT(ptrace(PTRACE_SETREGS, tid, &saved_regs, &saved_regs));
	return regs.rax;
}

int singlestep(pid_t target)
{
	int status;

	EXPECT(ptrace(PTRACE_SINGLESTEP, target, NULL, NULL));
	EXPECT(waitpid(target, &status, WSTOPPED));

	if(!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
		abort();
	}
	return 0;
}

void fill_context(
	unsigned long* context,
	pid_t tid, pid_t tgid,
	const struct user_regs_struct& regs)
{
	context[CTX_ARG0] = regs.rdi;
	context[CTX_ARG1] = regs.rsi;
	context[CTX_ARG2] = regs.rdx;
	context[CTX_ARG3] = regs.r10;
	context[CTX_ARG4] = regs.r8;
	context[CTX_ARG5] = regs.r9;
	context[CTX_SYSCALL_ID] = regs.orig_rax;
	context[CTX_RETVAL] = regs.rax;
	context[CTX_PID_TID] = ((uint64_t)tgid) << 32 | ((uint64_t)(uint32_t)tid);
}

int inject_getXXXXname(pid_t tid, int fd, struct sockaddr *sock_address, socklen_t *alen, unsigned long syscall_no)
{
	struct user_regs_struct saved_regs;
	EXPECT(ptrace(PTRACE_GETREGS, tid, &saved_regs, &saved_regs));

	// stack layout while running our injected system call
	//
	//                      ~~~~~~~~ 128 bytes (amd64)
	//        ~~~~~~~~~~~~ *alen
	//  ~~~~  socklen_t
	// [alen][sock_address][red zone][orig stack]
	// ^     ^                       ^
	// |     |                       regs.rsp
	// |     rsi
	// rdx, new_rsp
	unsigned long new_rsp = saved_regs.rsp - RED_ZONE - *alen - sizeof(socklen_t);

	struct user_regs_struct regs = saved_regs;
	regs.rax = syscall_no;
	regs.rdi = fd;
	regs.rsi = new_rsp + sizeof(socklen_t);
	regs.rdx = new_rsp;
	regs.rip = regs.rip - 2; // syscall insn is two bytes long
	regs.rsp = new_rsp;
	EXPECT(ptrace(PTRACE_SETREGS, tid, &regs, &regs));
	EXPECT(copy_to_user(tid, alen, (void*)new_rsp, sizeof(socklen_t)));
	singlestep(tid);
	EXPECT(ptrace(PTRACE_GETREGS, tid, &regs, &regs));
	EXPECT(ptrace(PTRACE_SETREGS, tid, &saved_regs, &saved_regs));

	int ret = regs.rax;
	if(ret < 0) {
		return -1;
	}

	struct iovec local_iov[] = {
		{
			.iov_base = alen,
			.iov_len = sizeof(socklen_t),
		},
		{
			.iov_base = sock_address,
			.iov_len = *alen,
		}
	};
	struct iovec remote_iov[] = {{
		.iov_base = (void*)new_rsp,
		.iov_len = sizeof(socklen_t) + *alen,
	}};

	size_t nread = process_vm_readv(tid, local_iov, 2, remote_iov, 1, 0);
	if (nread != remote_iov[0].iov_len) { // *alen is (hopefully) overwritten by now
		return -1;
	}

	return ret;
}
