#include "proc_tree.h"

#include "pdig_debug.h"

#include <dirent.h>
#include <errno.h>
#include <stdlib.h>
#include <string>
#include <sys/ptrace.h>
#include <sys/signal.h>
#include <sys/time.h>
#include <unordered_map>
#include <unordered_set>

using pid2pid_map = std::unordered_map<pid_t, pid_t>;
using proc_map = std::unordered_map<pid_t, pdig_process_context>;

// works on main thread ids only
// propagate the result to all other threads in the caller
static bool need_to_attach(pid_t tgid, const pid2pid_map& tgid_to_parent, const proc_map& procs)
{
	if(procs.count(tgid) != 0) {
		// already attached
		return false;
	}
	while(tgid != 1) {
		auto parent_tgid = tgid_to_parent.find(tgid);
		if(parent_tgid == tgid_to_parent.end()) {
			DEBUG("Could not find parent tgid for tgid %d, skipping thread\n", tgid);
			return false;
		}

		if(procs.count(parent_tgid->second) != 0) {
			// a parent process is attached (or needs to be)
			// so attach us too
			return true;
		}

		tgid = parent_tgid->second;
	}

	// we've reached pid=1 without finding an attached thread
	return false;
}


static pid_t get_parent_tgid(pid_t tgid)
{
	FILE* proc_pid_status;
	const std::string proc_pid_task_path = "/proc/" + std::to_string(tgid) + "/status";
	char buf[256];

	proc_pid_status = fopen(proc_pid_task_path.c_str(), "rb");
	if(!proc_pid_status) {
		WARN("Failed to open %s", proc_pid_task_path.c_str());
		return 0;
	}

	pid_t ptid = 0;
	while(fgets(buf, sizeof(buf), proc_pid_status)) {
		if(!strncmp(buf, "PPid:\t", strlen("PPid:\t"))) {
			ptid = atol(buf + strlen("PPid:\t"));
			break;
		}
	}

	fclose(proc_pid_status);
	return ptid;
}


static pid2pid_map build_process_tree()
{
	DIR* proc;
	struct dirent* dentry;
	pid2pid_map proc_tree;

	proc = opendir("/proc");
	if(!proc) {
		WARN("Failed to open %s", "/proc");
		return proc_tree;
	}

	while(1) {
		errno = 0;
		dentry = readdir(proc);
		if(!dentry) {
			break;
		}

		pid_t tgid = atol(dentry->d_name);
		if(tgid > 0) {
			pid_t ptid = get_parent_tgid(tgid);
			if(ptid > 0) {
				proc_tree.emplace(tgid, ptid);
			} else {
				DEBUG("Failed to get parent tgid of %d\n", tgid);
			}
		}
	}

	if(errno != 0) {
		WARN("Failed to scan %s", "/proc");
	}

	closedir(proc);
	return proc_tree;
}


static std::unordered_set<pid_t> get_threads(pid_t tgid)
{
	DIR* proc_pid_task;
	struct dirent* dentry;
	std::unordered_set<pid_t> threads = { tgid }; // whatever happens, there's at least this thread
	const std::string proc_pid_task_path = "/proc/" + std::to_string(tgid) + "/task";

	proc_pid_task = opendir(proc_pid_task_path.c_str());
	if(!proc_pid_task) {
		WARN("Failed to open %s", proc_pid_task_path.c_str());
		return threads;
	}

	while(1) {
		errno = 0;
		dentry = readdir(proc_pid_task);
		if(!dentry) {
			break;
		}

		pid_t tid = atol(dentry->d_name);
		if(tid > 0) {
			threads.insert(tid);
		}
	}

	if(errno != 0) {
		WARN("Failed to list threads from %s", proc_pid_task_path.c_str());
	}

	closedir(proc_pid_task);
	return threads;
}


bool attach_thread(pid_t tid, pid_t tgid, pdig_context& main_ctx)
{
	bool use_seccomp = main_ctx.seccomp_filter != nullptr;

	auto it = main_ctx.procs.insert({
		tid,
		{
			process_state::attaching,
			use_seccomp,
			tgid
		}
	});

	if(it.second) {
		// try 10 times to find all threads
		// we expect 1 attempt for single-threaded processes
		// and 2 for multi-threaded, but if the process
		// keeps racing us in pthread_create, more attempts
		// may be needed; eventually we give up as we're
		// apparently trying to attach to a fork bomb
		if(tgid) {
			main_ctx.incomplete_mt_procs.emplace(tgid, 10);
		}

		DEBUG("PTRACE_ATTACH(tid=%d; use_seccomp=%d)\n", tid, use_seccomp);
		TRY(ptrace(PTRACE_ATTACH, tid, 0, 0));
		return true;
	}

	return false;
}


static size_t _attach_all_threads(pid_t tgid, pdig_context& main_ctx)
{
	const auto threads = get_threads(tgid);
	size_t n_attached = 0;
	for(auto tid : threads) {
		if(attach_thread(tid, tgid, main_ctx)) {
			n_attached++;
		}
	}

	return n_attached;
}

void attach_all_threads(pid_t tgid, pdig_context& main_ctx)
{
	auto it = main_ctx.incomplete_mt_procs.find(tgid);
	if(it == main_ctx.incomplete_mt_procs.end()) {
		return;
	}

	auto n_attached = _attach_all_threads(it->first, main_ctx);
	if(n_attached) {
		if(--(it->second) == 0) {
			WARN("Failed to attach to all threads of tgid %d, are you running a fork bomb?", it->first);
			main_ctx.incomplete_mt_procs.erase(it);
		}
	} else {
		// success, we found all the threads with the previous attempt
		main_ctx.incomplete_mt_procs.erase(it);
	}
}

// try to attach to remaining threads of (multithreaded) processes
// that we've partially attached to
// returns the number of new threads found
static size_t find_threads_to_attach(pdig_context& main_ctx)
{
	size_t total_attached = 0;

	for(auto it = main_ctx.incomplete_mt_procs.begin(); it != main_ctx.incomplete_mt_procs.end(); /**/) {
		auto n_attached = _attach_all_threads(it->first, main_ctx);
		total_attached += n_attached;
		if(n_attached) {
			if(--(it->second) == 0) {
				WARN("Failed to attach to all threads of tgid %d, are you running a fork bomb?", it->first);
				it = main_ctx.incomplete_mt_procs.erase(it);
				continue;
			}
		} else {
			// success, we found all the threads with the previous attempt
			DEBUG("Yay, found all threads of tgid %d\n", it->first);
			it = main_ctx.incomplete_mt_procs.erase(it);
			continue;
		}

		++it;
	}

	return total_attached;
}

// scan /proc, looking for processes that are not attached but should be
// (children of an attached process)
// returns the number of new processes found
static size_t find_procs_to_attach(pdig_context& main_ctx)
{
	size_t n_attached = 0;

	if(main_ctx.full_proc_scans_remaining == 0) {
		main_ctx.incomplete_mt_procs.clear();
		return 0;
	}

	--main_ctx.full_proc_scans_remaining;

	const auto proc_tree = build_process_tree();
	for(const auto& it : proc_tree) {
		if(need_to_attach(it.first, proc_tree, main_ctx.procs)) {
			n_attached += attach_thread(it.first, it.first, main_ctx);
		}
	}

	if(n_attached == 0) {
		DEBUG("Yay, attached to all processes\n");
		main_ctx.full_proc_scans_remaining = 0;
	}

	return n_attached;
}

static constexpr const uint64_t NSEC_PER_SEC = 1000000000;

// scan all threads and processes as needed
// returns true if we want another scan scheduled
bool scan_procs_and_threads(pdig_context& main_ctx)
{
	bool need_more_scans = false;

	if(find_threads_to_attach(main_ctx) != 0) {
		need_more_scans = true;
	}

	if(main_ctx.full_proc_scans_remaining) {
		if(find_procs_to_attach(main_ctx) != 0) {
			need_more_scans = true;
		}
	}

#ifdef _DEBUG
	uint64_t now = gettimeofday_ns();
	DEBUG("time_ms = %lu.%09ld, scanned procs, need_more_scans = %d\n", now / NSEC_PER_SEC, now % NSEC_PER_SEC, need_more_scans);
#endif

	return need_more_scans;
}

static uint64_t gettimeofday_ns()
{
	struct timeval tv;
	gettimeofday(&tv, nullptr);

	return tv.tv_sec * NSEC_PER_SEC + tv.tv_usec * 1000;
}

static uint64_t time_of_next_scan(int scans_so_far, uint64_t last_scan, uint64_t now)
{
	uint64_t delay;

	if (last_scan == 0) {
		// scan immediately on startup
		return now;
	} else if (scans_so_far < 3) {
		// then, schedule the next two scans quickly (50 ms) to handle the easy case
		delay = NSEC_PER_SEC / 20;
	} else {
		// scan every 500 ms afterwards
		delay = NSEC_PER_SEC / 2;
	}
	return last_scan + delay;
}

static struct timespec ns_to_timespec(uint64_t nsec)
{
	return {
		(time_t)(nsec / NSEC_PER_SEC),
		(long)(nsec % NSEC_PER_SEC),
	};
}

bool schedule_next_proc_scan_if_needed(pdig_context& main_ctx)
{
	if(!main_ctx.need_more_scans) {
		return true;
	}

	sigset_t sigs;
	sigemptyset(&sigs);
	sigaddset(&sigs, SIGCHLD);
	sigaddset(&sigs, SIGINT);
	sigaddset(&sigs, SIGTERM);


	uint64_t now = gettimeofday_ns();
	uint64_t next_scan_ns = time_of_next_scan(main_ctx.scans_so_far, main_ctx.last_scan_ns, now);
	int ret;

	DEBUG("last_scan_ns = %lu, next_scan_ns = %lu, now = %lu, delay_ns = %ld\n", main_ctx.last_scan_ns, next_scan_ns, now, next_scan_ns - now);
	if(next_scan_ns < now) {
		ret = -1;
	} else {
		struct timespec timeout = ns_to_timespec(next_scan_ns - now);
		ret = sigtimedwait(&sigs, nullptr, &timeout);
	}

	if (ret != SIGCHLD) {
		main_ctx.need_more_scans = scan_procs_and_threads(main_ctx);
		main_ctx.last_scan_ns = now;
		main_ctx.scans_so_far++;
		return false;
	}
	return true;
}
