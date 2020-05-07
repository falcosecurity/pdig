#define _GNU_SOURCE
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdarg.h>
#include <limits.h>
#include <unistd.h>
#include <sys/mman.h>
#include <signal.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <time.h>
#include <netinet/in.h>
#include <sys/param.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <poll.h>
#include <sys/sem.h>
#include <sys/file.h>
#include <sys/ptrace.h>

#include "udig_capture.h"
#include "ppm_ringbuffer.h"
#include "ppm_events_public.h"
#include "ppm_events.h"
#include "ppm.h"
#include "udig_inf.h"
#include "ppm_flag_helpers.h"

#include "scap.h"

char* strstartswith(char* bigstr, char* smallstr)
{
	char* oribigstr = bigstr;

	while(*smallstr != 0)
	{
		if(*bigstr == 0)
		{
			return NULL;
		}

		if(*(smallstr++) != *(bigstr++))
		{
			return NULL;
		}
	}

	return oribigstr;
}

int32_t scap_proc_fill_cwd(char* procdirname, struct scap_threadinfo* tinfo)
{
	int target_res;
	char filename[SCAP_MAX_PATH_SIZE];

	snprintf(filename, sizeof(filename), "%scwd", procdirname);

	target_res = readlink(filename, tinfo->cwd, sizeof(tinfo->cwd) - 1);
	if(target_res <= 0)
	{
		cprintf("readlink %s failed\n", filename);
		return SCAP_FAILURE;
	}

	tinfo->cwd[target_res] = '\0';
	return SCAP_SUCCESS;
}

int32_t scap_proc_fill_info_from_stats(char* procdirname, struct scap_threadinfo* tinfo)
{
	char filename[PROC_FILENAME_BUF_MAX];
	uint32_t nfound = 0;
	int64_t tmp;
	uint32_t uid;
	uint64_t tgid;
	uint64_t ppid;
	uint64_t vpid;
	uint64_t vtid;
	int64_t sid;
	int64_t pgid;
	int64_t vpgid;
	uint32_t vmsize_kb;
	uint32_t vmrss_kb;
	uint32_t vmswap_kb;
	uint64_t pfmajor;
	uint64_t pfminor;
	int32_t tty;
	char line[512];
	char tmpc;
	char* s;

	tinfo->uid = (uint32_t)-1;
	tinfo->ptid = (uint32_t)-1LL;
	tinfo->sid = 0;
	tinfo->vpgid = 0;
	tinfo->vmsize_kb = 0;
	tinfo->vmrss_kb = 0;
	tinfo->vmswap_kb = 0;
	tinfo->pfmajor = 0;
	tinfo->pfminor = 0;
	tinfo->filtered_out = 0;
	tinfo->tty = 0;

	snprintf(filename, sizeof(filename), "%sstatus", procdirname);

	FILE* f = fopen(filename, "r");
	if(f == NULL)
	{
		cprintf("open status file %s failed", filename);
		return PPM_FAILURE_BUG;
	}

	while(fgets(line, sizeof(line), f) != NULL)
	{
		if(strstartswith(line, "Tgid") == line)
		{
			nfound++;

			if(sscanf(line, "Tgid: %" PRIu64, &tgid) == 1)
			{
				tinfo->pid = tgid;
			}
			else
			{
				tinfo->pid = 0;
			}
		}
		if(strstartswith(line, "Uid") == line)
		{
			nfound++;

			if(sscanf(line, "Uid: %" PRIu64 " %" PRIu32, &tmp, &uid) == 2)
			{
				tinfo->uid = uid;
			}
			else
			{
				tinfo->uid = 0;
			}
		}
		else if(strstartswith(line, "Gid") == line)
		{
			nfound++;

			if(sscanf(line, "Gid: %" PRIu64 " %" PRIu32, &tmp, &uid) == 2)
			{
				tinfo->gid = uid;
			}
			else
			{
				tinfo->gid = 0;
			}
		}
		else if(strstartswith(line, "PPid") == line)
		{
			nfound++;

			if(sscanf(line, "PPid: %" PRIu64, &ppid) == 1)
			{
				tinfo->ptid = ppid;
			}
			else
			{
				tinfo->ptid = 0;
			}
		}
		else if(strstartswith(line, "VmSize:") == line)
		{
			nfound++;

			if(sscanf(line, "VmSize: %" PRIu32, &vmsize_kb) == 1)
			{
				tinfo->vmsize_kb = vmsize_kb;
			}
			else
			{
				tinfo->vmsize_kb = 0;
			}
		}
		else if(strstartswith(line, "VmRSS:") == line)
		{
			nfound++;

			if(sscanf(line, "VmRSS: %" PRIu32, &vmrss_kb) == 1)
			{
				tinfo->vmrss_kb = vmrss_kb;
			}
			else
			{
				tinfo->vmrss_kb = 0;
			}
		}
		else if(strstartswith(line, "VmSwap:") == line)
		{
			nfound++;

			if(sscanf(line, "VmSwap: %" PRIu32, &vmswap_kb) == 1)
			{
				tinfo->vmswap_kb = vmswap_kb;
			}
			else
			{
				tinfo->vmswap_kb = 0;
			}
		}
		else if(strstartswith(line, "NSpid:") == line)
		{
			nfound++;
			if(sscanf(line, "NSpid: %*u %" PRIu64, &vtid) == 1)
			{
				tinfo->vtid = vtid;
			}
			else
			{
				tinfo->vtid = tinfo->tid;
			}
		}
		else if(strstartswith(line, "NSpgid:") == line)
		{
			nfound++;
			if(sscanf(line, "NSpgid: %*u %" PRIu64, &vpgid) == 1)
			{
				tinfo->vpgid = vpgid;
			}
		}
		else if(strstartswith(line, "NStgid:") == line)
		{
			nfound++;
			if(sscanf(line, "NStgid: %*u %" PRIu64, &vpid) == 1)
			{
				tinfo->vpid = vpid;
			}
			else
			{
				tinfo->vpid = tinfo->pid;
			}
		}

		if(nfound == 10)
		{
			break;
		}
	}

	fclose(f);

	snprintf(filename, sizeof(filename), "%sstat", procdirname);

	f = fopen(filename, "r");
	if(f == NULL)
	{
		cprintf("read stat file %s failed (%s)", filename);
		return PPM_FAILURE_BUG;
	}

	if(fgets(line, sizeof(line), f) == NULL)
	{
		fclose(f);
		cprintf("Could not read from stat file %s (%s)", filename);
		return PPM_FAILURE_BUG;
	}

	s = strrchr(line, ')');
	if(s == NULL)
	{
		fclose(f);
		cprintf("Could not find closng parens in stat file %s", filename);
		return PPM_FAILURE_BUG;
	}

	//
	// Extract the line content
	//
	if(sscanf(s + 2, "%c %" PRId64 " %" PRId64 " %" PRId64 " %" PRId32 " %" PRId64 " %" PRId64 " %" PRId64 " %" PRId64 " %" PRId64,
		&tmpc,
		&tmp,
		&pgid,
		&sid,
		&tty,
		&tmp,
		&tmp,
		&pfminor,
		&tmp,
		&pfmajor) != 10)
	{
		fclose(f);
		cprintf("Could not read expected fields from stat file %s", filename);
		return PPM_FAILURE_BUG;
	}

	tinfo->pfmajor = pfmajor;
	tinfo->pfminor = pfminor;
	tinfo->sid = (uint64_t)sid;

	// If we did not find vpgid above, set it to pgid from the
	// global namespace.
	if(tinfo->vpgid == 0)
	{
		tinfo->vpgid = pgid;
	}

	tinfo->tty = tty;

	fclose(f);
	return PPM_SUCCESS;
}

//
// use prlimit to extract the RLIMIT_NOFILE for the tid. On systems where prlimit
// is not supported, just return -1
//
static __inline__ int32_t scap_proc_fill_flimit(uint64_t tid, struct scap_threadinfo* tinfo)
{
	struct rlimit rl;

	if(syscall(SYS_prlimit64, tid, RLIMIT_NOFILE, NULL, &rl) == 0)
	{
		tinfo->fdlimit = rl.rlim_cur;
		return SCAP_SUCCESS;
	}

	tinfo->fdlimit = -1;
	return SCAP_SUCCESS;
}

int32_t scap_proc_fill_cgroups(struct scap_threadinfo* tinfo, const char* procdirname)
{
	//
	// NOTE: THIS IS CURRENTLY NOT IMPLEMENTED
	//
	//return SCAP_SUCCESS;

	char filename[SCAP_MAX_PATH_SIZE];
	char line[SCAP_MAX_CGROUPS_SIZE];

	tinfo->cgroups_len = 0;

	snprintf(filename, sizeof(filename), "%scgroup", procdirname);

	if(access(filename, R_OK) == -1)
	{
		return SCAP_SUCCESS;
	}

	FILE* f = fopen(filename, "r");
	if(f == NULL)
	{
		ASSERT(false);
		cprintf("open cgroup file %s failed\n", filename);
		return SCAP_FAILURE;
	}

	while(fgets(line, sizeof(line), f) != NULL)
	{
		char* token;
		char* subsys_list;
		char* cgroup;
		char* scratch;

		// id
		token = strtok_r(line, ":", &scratch);
		if(token == NULL)
		{
			ASSERT(false);
			fclose(f);
			cprintf("Did not find id in cgroup file %s\n", filename);
			return SCAP_FAILURE;
		}

		// subsys
		subsys_list = strtok_r(NULL, ":", &scratch);
		if(subsys_list == NULL)
		{
			ASSERT(false);
			fclose(f);
			cprintf("Did not find subsys in cgroup file %s\n", filename);
			return SCAP_FAILURE;
		}

		// Hack to detect empty fields, because strtok does not support it
		// strsep() should be used to fix this but it's not available
		// on CentOS 6 (has been added from Glibc 2.19)
		if(subsys_list-token-strlen(token) > 1)
		{
			// skip cgroups like this:
			// 0::/init.scope
			continue;
		}

		// cgroup
		cgroup = strtok_r(NULL, ":", &scratch);
		if(cgroup == NULL)
		{
			ASSERT(false);
			fclose(f);
			cprintf("Did not find cgroup in cgroup file %s\n", filename);
			return SCAP_FAILURE;
		}

		// remove the \n
		cgroup[strlen(cgroup) - 1] = 0;

		while((token = strtok_r(subsys_list, ",", &scratch)) != NULL)
		{
			subsys_list = NULL;
			if(strlen(cgroup) + 1 + strlen(token) + 1 > SCAP_MAX_CGROUPS_SIZE - tinfo->cgroups_len)
			{
				ASSERT(false);
				fclose(f);
				return SCAP_SUCCESS;
			}

			snprintf(tinfo->cgroups + tinfo->cgroups_len, SCAP_MAX_CGROUPS_SIZE - tinfo->cgroups_len, "%s=%s", token, cgroup);
			tinfo->cgroups_len += strlen(cgroup) + 1 + strlen(token) + 1;
		}
	}

	fclose(f);
	return SCAP_SUCCESS;
}

int32_t scap_proc_fill_root(struct scap_threadinfo* tinfo, const char* procdirname)
{
	char root_path[SCAP_MAX_PATH_SIZE];
	snprintf(root_path, sizeof(root_path), "%sroot", procdirname);
	if(readlink(root_path, tinfo->root, sizeof(tinfo->root)) > 0)
	{
		return SCAP_SUCCESS;
	}
	else
	{
		cprintf("readlink %s failed\n", root_path);
		return SCAP_FAILURE;
	}
}

int32_t scap_proc_fill_loginuid(struct scap_threadinfo* tinfo, const char* procdirname)
{
	uint32_t loginuid;
	char loginuid_path[SCAP_MAX_PATH_SIZE];
	char line[512];
	snprintf(loginuid_path, sizeof(loginuid_path), "%sloginuid", procdirname);
	FILE* f = fopen(loginuid_path, "r");
	if(f == NULL)
	{
		ASSERT(false);
		cprintf("Open loginuid file %s failed\n", loginuid_path);
		return SCAP_FAILURE;
	}
	if (fgets(line, sizeof(line), f) == NULL)
	{
		ASSERT(false);
		cprintf("Could not read loginuid from %s\n", loginuid_path);
		fclose(f);
		return SCAP_FAILURE;
	}

	fclose(f);

	if(sscanf(line, "%" PRId32, &loginuid) == 1)
	{
		tinfo->loginuid = loginuid;
		return SCAP_SUCCESS;
	}
	else
	{
		ASSERT(false);
		cprintf("Could not read loginuid from %s\n", loginuid_path);
		return SCAP_FAILURE;
	}
}

//
// Add a process to the list by parsing its entry under /proc
//
static __inline__ int32_t udig_proc_add_from_proc(uint32_t tid, char* procdirname, struct scap_threadinfo* tinfo)
{
	char dir_name[256];
	char target_name[SCAP_MAX_PATH_SIZE];
	int target_res;
	char filename[252];
	char line[SCAP_MAX_ENV_SIZE];
	FILE* f;
	size_t filesize;
	size_t exe_len;
	int32_t res = SCAP_SUCCESS;

	snprintf(dir_name, sizeof(dir_name), "%s/%u/", procdirname, tid);
	snprintf(filename, sizeof(filename), "%sexe", dir_name);

	//
	// Gather the executable full name
	//
	target_res = readlink(filename, target_name, sizeof(target_name) - 1);			// Getting the target of the exe, i.e. to which binary it points to

	if(target_res <= 0)
	{
		//
		// No exe. This in theory should never happen for the class of processes we support
		//
		ASSERT(false);
		target_name[0] = 0;
	}
	else
	{
		// null-terminate target_name (readlink() does not append a null byte)
		target_name[target_res] = 0;
	}

	tinfo->tid = tid;

	tinfo->fdlist = NULL;

	//
	// Gathers the exepath
	//
	snprintf(tinfo->exepath, sizeof(tinfo->exepath), "%s", target_name);

	//
	// Gather the command name
	//
	snprintf(filename, sizeof(filename), "%sstatus", dir_name);

	f = fopen(filename, "r");
	if(f == NULL)
	{
		cprintf("can't open %s\n", filename);
		return SCAP_FAILURE;
	}
	else
	{
		ASSERT(sizeof(line) >= SCAP_MAX_PATH_SIZE);

		if(fgets(line, SCAP_MAX_PATH_SIZE, f) == NULL)
		{
			cprintf("can't read from %s\n", filename);
			fclose(f);
			return SCAP_FAILURE;
		}

		line[SCAP_MAX_PATH_SIZE - 1] = 0;
		sscanf(line, "Name:%s", tinfo->comm);
		fclose(f);
	}

	//
	// Gather the command line
	//
	snprintf(filename, sizeof(filename), "%scmdline", dir_name);

	f = fopen(filename, "r");
	if(f == NULL)
	{
		cprintf("can't open cmdline file %s\n", filename);
		return SCAP_FAILURE;
	}
	else
	{
		ASSERT(sizeof(line) >= SCAP_MAX_ARGS_SIZE);

		filesize = fread(line, 1, SCAP_MAX_ARGS_SIZE - 1, f);
		if(filesize > 0)
		{
			line[filesize] = 0;

			exe_len = strlen(line);
			if(exe_len < filesize)
			{
				++exe_len;
			}

			snprintf(tinfo->exe, SCAP_MAX_PATH_SIZE, "%s", line);

			tinfo->args_len = filesize - exe_len;

			memcpy(tinfo->args, line + exe_len, tinfo->args_len);
			tinfo->args[SCAP_MAX_ARGS_SIZE - 1] = 0;
			if(filesize == SCAP_MAX_ARGS_SIZE - 1)
			{
				tinfo->args[tinfo->args_len] = '.';
				tinfo->args_len++;
			}
		}
		else
		{
			tinfo->args[0] = 0;
			tinfo->exe[0] = 0;
		}

		fclose(f);
	}

	//
	// Gather the environment
	//
	snprintf(filename, sizeof(filename), "%senviron", dir_name);

	f = fopen(filename, "r");
	if(f == NULL)
	{
		cprintf("can't open environ file %s\n", filename);
		return SCAP_FAILURE;
	}
	else
	{
		ASSERT(sizeof(line) >= SCAP_MAX_ENV_SIZE);

		filesize = fread(line, 1, SCAP_MAX_ENV_SIZE, f);

		if(filesize > 0)
		{
			line[filesize - 1] = 0;

			tinfo->env_len = filesize;

			memcpy(tinfo->env, line, tinfo->env_len);
			tinfo->env[SCAP_MAX_ENV_SIZE - 1] = 0;
		}
		else
		{
			tinfo->env[0] = 0;
		}

		fclose(f);
	}

	//
	// set the current working directory of the process
	//
	if(SCAP_FAILURE == scap_proc_fill_cwd(dir_name, tinfo))
	{
		cprintf("can't fill cwd for %s\n", dir_name);
		return SCAP_FAILURE;
	}

	//
	// extract the user id and ppid from /proc/pid/status
	//
	if(SCAP_FAILURE == scap_proc_fill_info_from_stats(dir_name, tinfo))
	{
		cprintf("can't fill cwd for %s\n", dir_name);
		return SCAP_FAILURE;
	}

	//
	// Set the file limit
	//
	if(SCAP_FAILURE == scap_proc_fill_flimit(tinfo->tid, tinfo))
	{
		cprintf("can't fill flimit for %s\n", dir_name);
		return SCAP_FAILURE;
	}

	if(scap_proc_fill_cgroups(tinfo, dir_name) == SCAP_FAILURE)
	{
	 	cprintf("can't fill cgroups for %s\n", dir_name);
		tinfo->cgroups_len = 0;
	 	// return SCAP_FAILURE;
	}

	// These values should be read already from /status file for kernels > 4.1.
	// On older kernels, we are out of luck.
	if(tinfo->vtid == 0)
	{
		tinfo->vtid = tinfo->tid;
	}

	if(tinfo->vpid == 0)
	{
		tinfo->vpid = tinfo->pid;
	}

	//
	// set the current root of the process
	//
	if(SCAP_FAILURE == scap_proc_fill_root(tinfo, dir_name))
	{
		cprintf("can't fill root for %s\n", dir_name);
		return SCAP_FAILURE;
	}

	//
	// set the loginuid
	//
	if(SCAP_FAILURE == scap_proc_fill_loginuid(tinfo, dir_name))
	{
		cprintf("can't fill loginuid for %s\n", dir_name);
		return SCAP_FAILURE;
	}

	// This is not needed in udig
	tinfo->flags = 0;

	//
	// Done
	//
	return res;
}

//
// Read a single thread info from /proc
//
static __inline__  int32_t udig_proc_read_thread(char* procdirname, uint64_t tid, struct scap_threadinfo* tinfo)
{
	return udig_proc_add_from_proc(tid, procdirname, tinfo);
}

static __inline__  int32_t udig_proc_get(int64_t tid, struct scap_threadinfo* tinfo)
{
	return udig_proc_read_thread("/proc", tid, tinfo);
}

static __inline__ uint64_t ud_gettid()
{
	return syscall(__NR_gettid);
}

int udig_finish_clone_fill(struct event_filler_arguments *args, scap_threadinfo* ti)
{
	unsigned long val;
	int res = 0;

	//
	// flags
	//
	syscall_get_arguments_deprecated(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, (uint64_t)clone_flags_to_scap(val), 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	//
	// uid
	//
	res = val_to_ring(args, ti->uid, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	//
	// gid
	//
	res = val_to_ring(args, ti->gid, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	//
	// vtid
	//
	res = val_to_ring(args, ti->vtid, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	//
	// vpid
	//
	res = val_to_ring(args, ti->vpid, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return PPM_SUCCESS;
}

int udig_finish_execve_fill(struct event_filler_arguments *args, scap_threadinfo* ti, int64_t retval)
{
	unsigned long val;
	int res = 0;

	//
	// env
	//
	if(args->event_type == PPME_SYSCALL_EXECVE_19_X && retval < 0)
	{
		/*
			* The call failed, so get the env from the arguments
			*/
		syscall_get_arguments_deprecated(current, args->regs, 2, 1, &val);
		int env_len = accumulate_argv_or_env((const char __user * __user *)val,
			args->str_storage, STR_STORAGE_SIZE);

		if (unlikely(env_len < 0))
		{
			env_len = 0;
		}

		if (env_len == 0)
		{
			*args->str_storage = 0;
		}

		res = val_to_ring(args, (int64_t)(long)args->str_storage, env_len, false, 0);
		if (unlikely(res != PPM_SUCCESS))
		{
			return res;
		}
	}
	else
	{
		//
		// The call was successful, get env from ti
		//
		res = val_to_ring(args, (uint64_t)ti->env, ti->env_len, false, 0);
	}

	if (unlikely(res != PPM_SUCCESS))
		return res;

	//
	// tty
	//
	res = val_to_ring(args, ti->tty, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	//
	// pgid
	//
	res = val_to_ring(args, ti->vpgid, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	//
	// loginuid
	//
	res = val_to_ring(args, ti->loginuid, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return PPM_SUCCESS;
}

static __inline__ uint64_t ctx_gettid(uint64_t* context)
{
	uint64_t res = context[CTX_PID_TID];
	return res & 0xffffffff;
}

int udig_proc_startupdate(struct event_filler_arguments *args)
{
	unsigned long val;
	int res = 0;
	int64_t retval;

	//
	// res
	//
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if(res != PPM_SUCCESS)
	{
		return res;
	}

	struct scap_threadinfo ti;
	if(udig_proc_get(ctx_gettid(args->regs), &ti) != SCAP_SUCCESS)
	{
		return PPM_FAILURE_BUG;
		//return PPM_FAILURE_BUFFER_FULL;
	}

	///////////////////////////////////////////////////////////////////////
	// COMMON ARGS
	///////////////////////////////////////////////////////////////////////

	//
	// Note: unless udig_proc_get failed, we always fill of the event args,
	//       even if the syscall failed.
	//

	//
	// exe, args
	//
	if(args->event_type == PPME_SYSCALL_EXECVE_19_X && retval < 0)
	{
		//
		// The execve call failed. we get exe, args from the
		// input args; put one \0-separated exe-args string into
		// str_storage
		//
		args->str_storage[0] = 0;

		syscall_get_arguments_deprecated(current, args->regs, 1, 1, &val);
		int args_len = accumulate_argv_or_env((const char __user * __user *)val,
						args->str_storage, STR_STORAGE_SIZE);

		if(args_len < 0)
		{
			args_len = 0;
		}

		if(args_len == 0)
		{
			*args->str_storage = 0;
		}

		uint32_t exe_len = strnlen(args->str_storage, args_len);
		if (exe_len < args_len)
		{
			++exe_len;
		}

		//
		// exe
		//
		res = val_to_ring(args, (uint64_t)(long)args->str_storage, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
		{
			return res;
		}

		//
		// args
		//
		res = val_to_ring(args, (int64_t)(long)args->str_storage + exe_len, args_len - exe_len, false, 0);
		if (unlikely(res != PPM_SUCCESS))
		{
			return res;
		}
	}
	else
	{
		//
		// Clone or successful exeve. Just get exe and args from ti
		//

		//
		// exe
		//
		res = val_to_ring(args, (uint64_t)ti.exe, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
		{
			return res;
		}

		//
		// args
		//
		res = val_to_ring(args, (int64_t)ti.args, ti.args_len, false, 0);
		if (unlikely(res != PPM_SUCCESS))
		{
			return res;
		}
	}

	//
	// tid
	//
	res = val_to_ring(args, ti.tid, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
	{
		return res;
	}
	
	//
	// pid
	//
	res = val_to_ring(args, ti.pid, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
	{
		return res;
	}
	
	//
	// ptid
	//
	res = val_to_ring(args, ti.ptid, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
	{
		return res;
	}
	
	//
	// cwd
	//
	res = val_to_ring(args, (uint64_t)ti.cwd, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	//
	// fdlimit
	//
	res = val_to_ring(args, ti.fdlimit, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
	{
		return res;
	}
	
	//
	// pgft_maj
	//
	res = val_to_ring(args, ti.pfmajor, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
	{
		return res;
	}
	
	//
	// pgft_min
	//
	res = val_to_ring(args, ti.pfminor, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
	{
		return res;
	}
	
	//
	// vm_size
	//
	res = val_to_ring(args, ti.vmsize_kb, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
	{
		return res;
	}
	
	//
	// vm_rss
	//
	res = val_to_ring(args, ti.vmrss_kb, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
	{
		return res;
	}
	
	//
	// vm_swap
	//
	res = val_to_ring(args, ti.vmswap_kb, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
	{
		return res;
	}
	
	//
	// comm
	//
	res = val_to_ring(args, (uint64_t)ti.comm, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	//
	// cgroups
	//
	res = val_to_ring(args, (uint64_t)ti.cgroups, ti.cgroups_len, false, 0);
	if (unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	if(args->event_type == PPME_SYSCALL_EXECVE_19_X)
	{
		res = udig_finish_execve_fill(args, &ti, retval);
	}
	else
	{
		res = udig_finish_clone_fill(args, &ti);
	}

	if (unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	return add_sentinel(args);
}
