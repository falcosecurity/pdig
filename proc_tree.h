#pragma once

#include "pdig_proc.h"

// attach a single thread
// if tgid is unknown, it may be set to zero, but then
// somebody, somewhere must reset it to a valid value
// and insert the tgid to main_ctx.incomplete_mt_procs
bool attach_thread(pid_t tid, pid_t tgid, pdig_context& main_ctx);

// attach all threads of a process, but no child processes
void attach_all_threads(pid_t tgid, pdig_context& main_ctx);

// try to attach to remaining threads of (multithreaded) processes
// that we've partially attached to
void find_threads_to_attach(pdig_context& main_ctx);

// scan /proc, looking for processes that are not attached but should be
// (children of an attached process)
// returns the number of new processes found
size_t find_procs_to_attach(pdig_context& main_ctx);
