// API to interface with the libscap event layer
#ifndef PDIG_API_H
#define PDIG_API_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// init the shared memory segment
int pdig_init_shm();

// fillers rely on having a current pid without receiving
// it as an argument, so we need to set it explicitly
// (in a global variable) before every event
void set_pid(pid_t pid);

// the main entrypoint to process an event
#ifdef FILTERING_ENABLED
uint64_t on_syscall(uint64_t* context, bool is_enter);
#else
void on_syscall(uint64_t* context, bool is_enter);
#endif

// shortcut to emit procexit events without going through
// the whole machinery with a synthetic system call
void record_procexit_event(pid_t tid, pid_t pid);

#ifdef __cplusplus
}
#endif

#endif
