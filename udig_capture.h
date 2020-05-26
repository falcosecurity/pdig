#include <linux/quota.h>
#include <sys/resource.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "pdig_linux.h"
#include "pdig_ptrace.h"

// This is never used at user level, so it doesn't matter
typedef int __kernel_pid_t;
#define __user

#ifndef __always_inline
#define __always_inline __inline__
#endif

#define SYSCALL_TABLE_ID0 0
#define current NULL
#define UNIX_PATH_MAX 108
#define PROC_FILENAME_BUF_MAX 48

// linux/fcntl.h
#define F_LINUX_SPECIFIC_BASE 1024
#define F_CANCELLK (F_LINUX_SPECIFIC_BASE + 5)

// linux/quota.h
#define QFMT_VFS_OLD 1
#define QFMT_VFS_V0 2
#define QFMT_OCFS2 3
#define QFMT_VFS_V1 4

void ppm_syscall_get_arguments(void* task, uint64_t* regs, uint64_t* args);
void syscall_get_arguments_deprecated(void* task, uint64_t* regs, uint32_t start, uint32_t len, uint64_t* args);
uint8_t* patch_pointer(uint8_t* pointer);
typedef struct event_filler_arguments event_filler_arguments;
int udig_proc_startupdate(struct event_filler_arguments* args);
int accumulate_argv_or_env(const char __user * __user *argv, char *str_storage, int available);

static __inline__ long syscall_get_return_value(void* task, uint64_t* regs)
{
	return regs[CTX_RETVAL];
}

int udig_getsockname(int fd, struct sockaddr *sock_address, socklen_t *alen);
int udig_getpeername(int fd, struct sockaddr *sock_address, socklen_t *alen);

//
// Some definitions that are missing in userspace
//
#define min(a,b) (((a)<(b))?(a):(b))
#define max(a,b) (((a)>(b))?(a):(b))

#define EFAULT 14

#define SOL_TCP 6

unsigned long ppm_copy_from_user(void *to, const void __user *from, unsigned long n);
long ppm_strncpy_from_user(char *to, const char __user *from, unsigned long n);
