#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "ppm_events_public.h"
#include "ppm_events.h"

#include "pdig_debug.h"

#define likely(x)	__builtin_expect(!!(x), 1)
#define unlikely(x)	__builtin_expect(!!(x), 0)

struct event_data_t {
	enum ppm_capture_category category;
	bool compat;

	union {
		struct {
			uint64_t* regs;
			long id;
			const enum ppm_syscall_code *cur_g_syscall_code_routing_table;
		} syscall_data;
	} event_info;
};

size_t strlcpy(char *dst, const char *src, size_t size);
