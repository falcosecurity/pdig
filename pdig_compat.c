#define _GNU_SOURCE

#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <stdlib.h>
#include <sys/uio.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <syscall.h>
#include <sys/signal.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <stdio.h>
#include <limits.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <sys/wait.h>

#include <arpa/inet.h> // dbg

#include "udig_capture.h"
#include "udig_inf.h"
#include "pdig.h"
#include "scap.h"
#include "ppm_ringbuffer.h"

#include "pdig_ptrace.h"

#ifndef MIN
#define MIN(X,Y) ((X) < (Y)? (X):(Y))
#endif

extern const struct ppm_event_info g_event_info[];
extern const struct syscall_evt_pair g_syscall_table[];
extern const enum ppm_syscall_code g_syscall_code_routing_table[];

static struct udig_ring_buffer_status* g_ring_status = NULL;
static struct ppm_ring_buffer_info* g_ring_info = NULL;
static uint8_t* g_ring = NULL;
int g_ring_fd = -1;
uint32_t g_ringsize = 0;
char g_console_print_buf[256];
int g_ring_descs_fd = -1;
static char g_str_storage[PAGE_SIZE];

int pdig_init_shm()
{
	int res;
	res = udig_alloc_ring(&g_ring_fd, &g_ring, &g_ringsize, g_console_print_buf);
	if(res < 0)
	{
		return res;
	}

	res = udig_alloc_ring_descriptors(&g_ring_descs_fd, &g_ring_info, 
		&g_ring_status, g_console_print_buf);
	if(res < 0)
	{
		return res;
	}

	return 0;
}

void cwrite(char* str)
{
	write(2, str, strlen(str));
}

int cprintf(const char* format, ...)
{
	va_list args;
	va_start(args, format);
	int res = vsnprintf(g_console_print_buf, 
		sizeof(g_console_print_buf) - 1, 
		format, 
		args);
	va_end(args);

	cwrite(g_console_print_buf);

	return res;
}

uint8_t* patch_pointer(uint8_t* pointer)
{
	return pointer;
}

size_t strlcpy(char *dst, const char *src, size_t size)
{
    const size_t srclen = strlen(src);
    if (srclen + 1 < size) {
        memcpy(dst, src, srclen + 1);
    } else if (size != 0) {
        memcpy(dst, src, size - 1);
        dst[size-1] = '\0';
    }
    return srclen;
}

static pid_t the_pid;

void set_pid(pid_t pid)
{
	the_pid = pid;
}

static bool is_enter;

void set_direction(bool enter)
{
	is_enter = enter;
}

static __inline__ uint64_t ctx_getpid(uint64_t* context)
{
	uint64_t res = context[CTX_PID_TID];
	return res >> 32;
}

static __inline__ uint64_t ctx_gettid(uint64_t* context)
{
	uint64_t res = context[CTX_PID_TID];
	return res & 0xffffffff;
}

static __inline__ uint64_t timespec_to_ns(const struct timespec *ts)
{
	return((uint64_t) ts->tv_sec * 1000000000) + ts->tv_nsec;
}

static __inline__ int ud_clock_gettime(clockid_t clk_id, struct timespec *tp)
{
	return syscall(__NR_clock_gettime, clk_id, tp);
}

unsigned long ppm_copy_from_user(void* to, const void* from, unsigned long n)
{
	return copy_from_user(the_pid, to, (void*)from, n);
}

long ppm_strncpy_from_user_impl(pid_t pid, char* to, char* from, unsigned long n)
{
	int ret = copy_from_user(pid, to, from, n);
	if (ret < 0) {
		return ret;
	}

	to[n-1] = 0;
	return strlen(to) + 1;
}

long ppm_strncpy_from_user(char* to, const char* from, unsigned long n)
{
	return ppm_strncpy_from_user_impl(the_pid, to, (char*)from, n);
}

void ppm_syscall_get_arguments(void* task, uint64_t* regs, uint64_t* args)
{
	memcpy(args, regs + CTX_ARGS_BASE, 6 * sizeof(uint64_t));
}

void syscall_get_arguments_deprecated(void* task, uint64_t* regs, uint32_t start, uint32_t len, uint64_t* args)
{
	memcpy(args, regs + CTX_ARGS_BASE + start, len * sizeof(uint64_t));
}

static int record_event(enum ppm_event_type event_type, enum syscall_flags drop_flags,
	struct timespec *ts, struct event_data_t *event_datap);

static inline void record_drop_e(struct udig_consumer_t *consumer, struct timespec *ts)
{
	struct event_data_t event_data = {0};

	if (record_event(PPME_DROP_E, UF_NEVER_DROP, ts, &event_data) == 0) {
		consumer->need_to_insert_drop_e = 1;
	} else {
		if (consumer->need_to_insert_drop_e == 1)
			printf("drop enter event delayed insert\n");

		consumer->need_to_insert_drop_e = 0;
	}
}

static inline void record_drop_x(struct udig_consumer_t *consumer, struct timespec *ts)
{
	struct event_data_t event_data = {0};

	if (record_event(PPME_DROP_X, UF_NEVER_DROP, ts, &event_data) == 0) {
		consumer->need_to_insert_drop_x = 1;
	} else {
		if (consumer->need_to_insert_drop_x == 1)
			printf("drop exit event delayed insert\n");

		consumer->need_to_insert_drop_x = 0;
	}
}

// Return 1 if the event should be dropped, else 0
static inline int drop_nostate_event(enum ppm_event_type event_type,
				uint64_t* regs)
{
	unsigned long args[6] = {};
	unsigned long arg = 0;
	bool drop = false;

	switch (event_type) {
	case PPME_SYSCALL_CLOSE_X:
	case PPME_SOCKET_BIND_X:
		if (syscall_get_return_value(current, regs) < 0)
			drop = true;
		break;
	case PPME_SYSCALL_FCNTL_E:
	case PPME_SYSCALL_FCNTL_X:
		// cmd arg
		ppm_syscall_get_arguments(current, regs, args);
		arg = args[1];
		if (arg != F_DUPFD && arg != F_DUPFD_CLOEXEC)
			drop = true;
		break;
	default:
		break;
	}

	if (drop)
		return 1;
	else
		return 0;
}

// Return 1 if the event should be dropped, else 0
static inline int drop_event(struct udig_consumer_t *consumer,
			     enum ppm_event_type event_type,
			     enum syscall_flags drop_flags,
			     struct timespec *ts,
			     uint64_t* regs)
{
	int maybe_ret = 0;

	if (consumer->dropping_mode) {
		maybe_ret = drop_nostate_event(event_type, regs);
		if (maybe_ret > 0)
			return maybe_ret;
	}

	if (drop_flags & UF_NEVER_DROP) {
		ASSERT((drop_flags & UF_ALWAYS_DROP) == 0);
		return 0;
	}

	if (consumer->dropping_mode) {
		if (drop_flags & UF_ALWAYS_DROP) {
			ASSERT((drop_flags & UF_NEVER_DROP) == 0);
			return 1;
		}

		if (ts->tv_nsec >= consumer->sampling_interval) {
			if (consumer->is_dropping == 0) {
				consumer->is_dropping = 1;
				record_drop_e(consumer, ts);
			}

			return 1;
		}

		if (consumer->is_dropping == 1) {
			consumer->is_dropping = 0;
			record_drop_x(consumer, ts);
		}
	}

	return 0;
}

static int record_event(enum ppm_event_type event_type,
	enum syscall_flags drop_flags,
	struct timespec *ts,
	struct event_data_t *event_datap)
{
	int res = 0;
	size_t event_size = 0;
	int next;
	uint32_t freespace;
	uint32_t usedspace;
	uint32_t delta_from_end;
	struct event_filler_arguments args;
	uint32_t ttail;
	uint32_t head;
	int drop = 1;
	int32_t cbres = PPM_SUCCESS;

	struct udig_consumer_t* consumer = &(g_ring_status->m_consumer);

	if (event_type != PPME_DROP_E && event_type != PPME_DROP_X) {
		if (consumer->need_to_insert_drop_e == 1)
			record_drop_e(consumer, ts);
		else if (consumer->need_to_insert_drop_x == 1)
			record_drop_x(consumer, ts);

		if (drop_event(consumer, event_type, drop_flags, ts,
			       event_datap->event_info.syscall_data.regs))
			return res;
	}

	uint64_t tid = ctx_gettid(event_datap->event_info.syscall_data.regs);

	g_ring_info->n_evts++;

	/*
	 * Calculate the space currently available in the buffer
	 */
	head = g_ring_info->head;
	ttail = g_ring_info->tail;

	if (ttail > head)
		freespace = ttail - head - 1;
	else
		freespace = RING_BUF_SIZE + ttail - head - 1;

	usedspace = RING_BUF_SIZE - freespace - 1;
	delta_from_end = RING_BUF_SIZE + (2 * PAGE_SIZE) - head - 1;

	ASSERT(freespace <= RING_BUF_SIZE);
	ASSERT(usedspace <= RING_BUF_SIZE);
	ASSERT(ttail <= RING_BUF_SIZE);
	ASSERT(head <= RING_BUF_SIZE);
	ASSERT(delta_from_end < RING_BUF_SIZE + (2 * PAGE_SIZE));
	ASSERT(delta_from_end > (2 * PAGE_SIZE) - 1);
	ASSERT(event_type < PPM_EVENT_MAX);

	/*
	 * Determine how many arguments this event has
	 */
	args.nargs = g_event_info[event_type].nparams;
	args.arg_data_offset = args.nargs * sizeof(u16);


	/*
	 * Make sure we have enough space for the event header.
	 * We need at least space for the header plus 16 bit per parameter for the lengths.
	 */
	if (likely(freespace >= sizeof(struct ppm_evt_hdr) + args.arg_data_offset)) {
		/*
		 * Populate the header
		 */
		struct ppm_evt_hdr *hdr = (struct ppm_evt_hdr *)(g_ring + head);

#ifdef PPM_ENABLE_SENTINEL
		hdr->sentinel_begin = ring->nevents;
#endif
		hdr->ts = timespec_to_ns(ts);
		hdr->tid = tid;
		hdr->type = event_type;
		hdr->nparams = args.nargs;

		/*
		 * Populate the parameters for the filler callback
		 */
		args.consumer = consumer;
		args.buffer = g_ring + head + sizeof(struct ppm_evt_hdr);
#ifdef PPM_ENABLE_SENTINEL
		args.sentinel = ring->nevents;
#endif
		args.buffer_size = MIN(freespace, delta_from_end) - sizeof(struct ppm_evt_hdr); /* freespace is guaranteed to be bigger than sizeof(struct ppm_evt_hdr) */
		args.event_type = event_type;

		args.regs = event_datap->event_info.syscall_data.regs;
		args.syscall_id = event_datap->event_info.syscall_data.id;
		args.cur_g_syscall_code_routing_table = event_datap->event_info.syscall_data.cur_g_syscall_code_routing_table;
		args.curarg = 0;
		args.arg_data_size = args.buffer_size - args.arg_data_offset;
		args.nevents = g_ring_info->n_evts;
		args.str_storage = g_str_storage;
		args.enforce_snaplen = false;
		args.is_socketcall = false;

		/*
		 * Fire the filler callback
		 */
		if (likely(g_ppm_events[event_type].filler_callback)) {
			/*
			 * Note how we we calculate the callback address by using the g_portal_base 
			 * and g_portal_base_ori offsets. This is because gcc fails to generate relative
			 * calls whith function pointers from the entries in g_ppm_events, and uses original
			 * absolute addresses instead.
			 */
			const struct ppm_event_entry* pe = &g_ppm_events[event_type];
			cbres = pe->filler_callback(&args);
		} else {
			cprintf("corrupted filler for event type %d: NULL callback\n", event_type);
			ASSERT(0);
		}

		if (likely(cbres == PPM_SUCCESS)) {
			/*
			 * Validate that the filler added the right number of parameters
			 */
			if (likely(args.curarg == args.nargs)) {
				/*
				 * The event was successfully inserted in the buffer
				 */
				event_size = sizeof(struct ppm_evt_hdr) + args.arg_data_offset;
				hdr->len = event_size;
				drop = 0;
			} else {
				cprintf("corrupted filler for event type %d (added %u args, should have added %u)\n",
				       event_type,
				       args.curarg,
				       args.nargs);
				ASSERT(0);
			}
		}
	}

	if (likely(!drop)) {
		res = 1;

		next = head + event_size;

		if (unlikely(next >= RING_BUF_SIZE)) {
			/*
			 * If something has been written in the cushion space at the end of
			 * the buffer, copy it to the beginning and wrap the head around.
			 * Note, we don't check that the copy fits because we assume that
			 * filler_callback failed if the space was not enough.
			 */
			if (next > RING_BUF_SIZE) {
				memcpy(g_ring,
				g_ring + RING_BUF_SIZE,
				next - RING_BUF_SIZE);
			}

			next -= RING_BUF_SIZE;
		}

		/*
		 * Make sure all the memory has been written in real memory before
		 * we update the head and the user space process (on another CPU)
		 * can access the buffer.
		 */
		__sync_synchronize();

		g_ring_info->head = next;
	} else {
		if (cbres == PPM_SUCCESS) {
			ASSERT(freespace < sizeof(struct ppm_evt_hdr) + args.arg_data_offset);
			g_ring_info->n_drops_buffer++;
		} else if (cbres == PPM_FAILURE_BUFFER_FULL) {
			g_ring_info->n_drops_buffer++;
		} else {
			ASSERT(false);
		}
	}

	return res;
}


void record_procexit_event(pid_t tid, pid_t pid)
{
	struct timespec ts;
	ud_clock_gettime(CLOCK_REALTIME, &ts);
	struct event_data_t event_data;

	uint64_t context[CTX_PID_TID + 1] = {0};
	context[CTX_PID_TID] = ((uint64_t)pid) << 32 | tid;

	event_data.category = PPMC_SYSCALL;
	event_data.event_info.syscall_data.regs = context;
	event_data.event_info.syscall_data.id = __NR_exit;
	event_data.event_info.syscall_data.cur_g_syscall_code_routing_table = g_syscall_code_routing_table;
	event_data.compat = false;

	record_event(PPME_PROCEXIT_1_E, UF_NEVER_DROP, &ts, &event_data);
}


///////////////////////////////////////////////////////////////////////////////
// INSTRUMENTATION CALLBACKS
///////////////////////////////////////////////////////////////////////////////
#ifdef FILTERING_ENABLED
uint64_t on_syscall(uint64_t* context, bool is_enter)
#else
void on_syscall(uint64_t* context, bool is_enter)
#endif
{
	//
	// Check if event capture is enabled
	//
	if(g_ring_status->m_capturing_pid == 0 || g_ring_status->m_stopped != 0)
	{
#ifdef FILTERING_ENABLED
		return 0;
#else
		return;
#endif
	}

	set_direction(is_enter);

	//
	// Get ready for record_event
	//
	long table_index = context[CTX_SYSCALL_ID];
	const struct syscall_evt_pair *cur_g_syscall_table = g_syscall_table;

	if(table_index >= 0 && table_index < SYSCALL_TABLE_SIZE)
	{
		struct event_data_t event_data;
		int used = cur_g_syscall_table[table_index].flags & UF_USED;
		enum syscall_flags drop_flags = cur_g_syscall_table[table_index].flags;
		enum ppm_event_type type;
		if(is_enter)
		{
			type = cur_g_syscall_table[table_index].enter_event_type;
		}
		else
		{
			type = cur_g_syscall_table[table_index].exit_event_type;
		}
		
		event_data.category = PPMC_SYSCALL;
		event_data.event_info.syscall_data.regs = context;
		event_data.event_info.syscall_data.id = table_index;
		event_data.event_info.syscall_data.cur_g_syscall_code_routing_table = g_syscall_code_routing_table;
		event_data.compat = false;

		struct timespec ts;
		ud_clock_gettime(CLOCK_REALTIME, &ts);
		
		//
		// Fire record_event!
		//
		if(used)
		{
			record_event(type, drop_flags, &ts, &event_data);
		}
		else
		{
			if(is_enter)
			{
				record_event(PPME_GENERIC_E, UF_ALWAYS_DROP, &ts, &event_data);
			}
			else
			{
				record_event(PPME_GENERIC_X, UF_ALWAYS_DROP, &ts, &event_data);
			}
		}

#ifdef FILTERING_ENABLED
		//
		// Perform the filtering
		//
		int64_t fres = filter_event(type, drop_flags, &ts, &event_data);
		if(fres != 0)
		{
			return fres;
		}
#endif
	}
	else
	{
		cprintf("invalid table index %lu (tid: %d)\n", table_index, ctx_gettid(context));
		ASSERT(false);
	}

#ifdef FILTERING_ENABLED
	return 0;
#endif
}

int udig_getsockname(int fd, struct sockaddr *sock_address, socklen_t *alen)
{
	// can't call a syscall in the middle of another one :(
	if(is_enter) { return -1; }

	return inject_getXXXXname(the_pid, fd, sock_address, alen, __NR_getsockname);
}

int udig_getpeername(int fd, struct sockaddr *sock_address, socklen_t *alen)
{
	// can't call a syscall in the middle of another one :(
	if(is_enter) { return -1; }

	return inject_getXXXXname(the_pid, fd, sock_address, alen, __NR_getpeername);
}
