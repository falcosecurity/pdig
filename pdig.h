#pragma once

#include <errno.h>
#include <stdio.h>
#include <sys/types.h>

int pdig_init_shm();
void set_pid(pid_t pid);
void set_direction(bool enter);
unsigned long ppm_copy_from_user(void* to, const void* from, unsigned long n);
long ppm_strncpy_from_user(char* to, const char* from, unsigned long n);
unsigned long copy_to_user(pid_t pid, void* from, void* to, unsigned long n);
int step(pid_t pid);

#ifdef FILTERING_ENABLED
uint64_t on_syscall(uint64_t* context, bool is_enter);
#else
void on_syscall(uint64_t* context, bool is_enter);
#endif

void record_procexit_event(pid_t tid, pid_t pid);

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

