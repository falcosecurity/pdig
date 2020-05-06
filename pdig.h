#pragma once

#include <sys/types.h>

int pdig_init_shm();
void set_pid(pid_t pid);
unsigned long ppm_copy_from_user(void* to, const void* from, unsigned long n);
long ppm_strncpy_from_user(char* to, const char* from, unsigned long n);

#ifdef FILTERING_ENABLED
uint64_t on_syscall(uint64_t* context, bool is_enter);
#else
void on_syscall(uint64_t* context, bool is_enter);
#endif

void record_procexit_event(pid_t tid, pid_t pid);
