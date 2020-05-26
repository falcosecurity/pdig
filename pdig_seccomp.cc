#define __USE_GNU

#include "pdig_seccomp.h"
#include "pdig_linux.h"

#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

extern "C" {
#include "ppm_events_public.h"
#include "ppm.h"
}

#include "pdig_debug.h"

#define X32_SYSCALL_BIT 0x40000000
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

struct sock_fprog* build_filter(bool capture_all)
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


