#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "pdig_ptrace.h"
#include "pdig_debug.h"

#include <stdint.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/user.h>

#ifndef MIN
#define MIN(X,Y) ((X) < (Y)? (X):(Y))
#endif

static inline void* page_align(void* ptr)
{
	uintptr_t aligned = ((uintptr_t)ptr & ~(PAGE_SIZE - 1));
	return (void*)aligned;
}

static inline const void* next_page(const void* ptr)
{
	uintptr_t aligned = ((uintptr_t)ptr & ~(PAGE_SIZE - 1)) + PAGE_SIZE;
	return (const void*)aligned;
}

unsigned long copy_from_user(pid_t pid, void* to, const void* from, unsigned long n)
{
	struct iovec local_iov[] = {{
		.iov_base = to,
		.iov_len = n,
	}};

	int first_page = ((uintptr_t)from) / PAGE_SIZE;
	int last_page = ((uintptr_t)from + n) / PAGE_SIZE;
	int npages = last_page - first_page + 1;

	struct iovec remote_iov[npages];
	const void *ptr = from;
	unsigned long to_read = n;

	for(int p = 0; p < npages; ++p)
	{
		const void* next_ptr = next_page(ptr);

		unsigned long chunk = MIN(to_read, next_ptr - ptr);
		remote_iov[p].iov_base = (void*)ptr;
		remote_iov[p].iov_len = chunk;

		to_read -= chunk;
		ptr = next_ptr;
	}
	int ret = n - process_vm_readv(pid, local_iov, 1, remote_iov, npages, 0);
	return ret;
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


