#pragma once

#include <stdint.h>
#include <sys/types.h>

#include <unordered_map>

struct sock_fprog;

enum class process_state {
	waiting_for_clone_event,
	spawning,

	attaching,
	attaching_first_syscall_enter,
	attaching_first_syscall_exit,

	waiting_for_enter,
	waiting_for_exit,
};


struct pdig_process_context {
	pdig_process_context(process_state state_, bool use_seccomp_, pid_t pid_):
		state(state_),
		pid(pid_),
		clone_syscall(0),
		clone_flags(0),
		use_seccomp(use_seccomp_)
	{}

	process_state state;
	pid_t pid; // we know the tid but need to store the pid somewhere

	// after a thread calls clone()/fork()/vfork(), store the flags
	// here so that we can reconstruct the event in the child
	// after we receive the ptrace CLONE event
	// TODO: clone3() needs a struct passed as a pointer so we'll want
	//       to revisit it, either by storing this struct here,
	//       or storing the complete scap event
	unsigned long clone_syscall;
	uint64_t clone_flags;

	bool use_seccomp;
};


struct pdig_context {
	pid_t mainpid;
	int exitcode;
	struct sock_fprog* seccomp_filter;
	std::unordered_map<pid_t, pdig_process_context> procs;

	// processes that may still have unattached threads
	// the value is the number of attempts remaining
	// once it runs out, we give up with a warning
	std::unordered_map<pid_t, size_t> incomplete_mt_procs;

	size_t full_proc_scans_remaining;
};

