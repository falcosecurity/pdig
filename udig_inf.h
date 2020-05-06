#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "ppm_events_public.h"
#include "ppm_events.h"

#ifndef MIN
#define MIN(X,Y) ((X) < (Y)? (X):(Y))
#endif

//#include "../settings.h"

#define MAX_HOLE_SIZE 16
#define MAX_MMAP_AREAS 32
#define N_TRAMPOLINE_MINISTACKS 64
// The following two need to be the same
#define TRAMPOLINE_MINISTACK_SIZE 16384
#define TRAMPOLINE_MINISTACK_SIZE_STR "16384"
#define CALLBACK_STACK_SIZE (1024 * 128)
#define MAX_R_REGIONS 2048
#ifdef FILTERING_ENABLED
#define TRAMPOLINE_MAX_SIZE 2048
#else
#define TRAMPOLINE_MAX_SIZE 1536
#endif
#define TARGET_GROUP_MAX_DISTANCE 0x5000000
#define MMAP_STEP_SIZE_BYTES 0x5000000
#define TRAMPOLINE_AREA_MAX_DISTANCE 0x40000000
#define SHARED_MEM_NAME "sysdig_dyn"

int cprintf(const char* format, ...);

#ifdef _DEBUG
#define ASSERT(X) if(!(X)) { \
	cprintf("%s:%d ASSERTION FAILED: "#X"\n", __FILE__, __LINE__); \
	asm("int3;"); \
}
#else
#define ASSERT(X)
#endif

#define likely(x)	__builtin_expect(!!(x), 1)
#define unlikely(x)	__builtin_expect(!!(x), 0)

typedef struct mmap_area_info
{
	uint8_t* m_base_addr;
	uint8_t* m_cur_addr;
	uint32_t m_size;
	uint32_t m_n_trampolines;
	uint8_t* m_first_target_addr;
}mmap_area_info;

typedef struct target_info
{
	uint64_t m_target_addr;
	int32_t m_hole_jmp_delta;
	uint32_t m_hole_size;
	uint8_t m_hole_data[MAX_HOLE_SIZE];
	uint8_t m_original_hole_data[MAX_HOLE_SIZE];
	uint32_t m_mmap_area_num;
	uint8_t* m_trampoline_addr;
}target_info;

typedef struct mem_region_info
{
	uint8_t* m_start_addr;
	uint32_t m_length;
}mem_region_info;

#ifdef FILTERING_ENABLED
int64_t on_syscall_enter(uint64_t* context);
int64_t on_syscall_exit(uint64_t* context);
#else
void on_syscall_enter(uint64_t* context);
void on_syscall_exit(uint64_t* context);
#endif
int main(int argc, char *argv[]);
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
typedef struct trampoline_state
{
	uint64_t m_pid;
	uint64_t m_stack;
	volatile uint64_t* m_plock;
	uint64_t m_trampoline_ministacks;
}trampoline_state;
