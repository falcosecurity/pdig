#pragma once

#include "pdig_proc.h"

// attach a single thread
// if tgid is unknown, it may be set to zero, but then
// somebody, somewhere must reset it to a valid value
// and insert the tgid to main_ctx.incomplete_mt_procs
bool attach_thread(pid_t tid, pid_t tgid, pdig_context& main_ctx);

// attach all threads of a process, but no child processes
void attach_all_threads(pid_t tgid, pdig_context& main_ctx);

// check if we need to scan /proc now
// this call blocks until the next signal arrives or the timeout expires
// returns true if the main loop can go on calling waitpid()
bool schedule_next_proc_scan_if_needed(pdig_context& main_ctx);
