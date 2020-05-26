#ifndef PDIG_PTRACE_H
#define PDIG_PTRACE_H

#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/types.h>

#define CTX_ARG0 0
#define CTX_ARG1 1
#define CTX_ARG2 2
#define CTX_ARG3 3
#define CTX_ARG4 4
#define CTX_ARG5 5
#define CTX_SYSCALL_ID 6
#define CTX_RETVAL 7
#define CTX_PID_TID 8
#define CTX_ARGS_BASE CTX_ARG0
#define CTX_SIZE (CTX_PID_TID + 1)

#ifdef __cplusplus
// used by C++ only
int singlestep(pid_t tid);

pid_t inject_getpid(pid_t tid);

int inject_prctl_set_no_new_privs(pid_t tid, const struct user_regs_struct& saved_regs);

// the actual filter array *must* start immediately after the header struct
int inject_seccomp_filter(pid_t tid, const struct user_regs_struct& saved_regs, struct sock_fprog* prog);

void fill_context(
	unsigned long* context,
	pid_t tid, pid_t tgid,
	const struct user_regs_struct& regs);

extern "C" {
#endif

// this code is called from fillers (in C) so it needs C linkage
int inject_getXXXXname(pid_t tid, int fd, struct sockaddr *sock_address, socklen_t *alen, unsigned long syscall_no);

unsigned long copy_to_user(pid_t pid, void* from, void* to, unsigned long n);
unsigned long copy_from_user(pid_t pid, void* to, const void* from, unsigned long n);

#ifdef __cplusplus
}
#endif

#endif
