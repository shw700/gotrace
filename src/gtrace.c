#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stddef.h>
#include <sys/ptrace.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>
#include <asm/prctl.h>
#include <sys/prctl.h>

// TODO: waitpid(..., WUNTRACED), _WALL

#include "config.h"
#include "elfh.h"
#include "args.h"

#include <zydis/include/Zydis/Zydis.h>


#define DEBUG_LEVEL	0

#define DEBUG_PRINT(lvl,...)	do {	\
					if (lvl <= DEBUG_LEVEL)	\
						fprintf(stderr, __VA_ARGS__);	\
				} while (0)


typedef enum {
	gint = 0,
	gstring
} golang_data_type;


typedef struct saved_prolog {
	void *addr;
	long saved_prolog;
	char *fname;
} saved_prolog_t;

typedef struct remote_intercept {
	void *addr;
	char *fname;
	int is_entry;
} remote_intercept_t;

size_t saved_prolog_nentries = 1024;
size_t saved_prolog_entries = 0;
saved_prolog_t *saved_prologs = NULL;

size_t saved_ret_prolog_nentries = 64;
size_t saved_ret_prolog_entries = 0;
saved_prolog_t *saved_ret_prologs = NULL;

size_t remote_intercept_nentries = 64;
size_t remote_intercept_entries = 0;
remote_intercept_t *remote_intercepts = NULL;

long trace_flags = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACECLONE | PTRACE_O_TRACEVFORK |
	PTRACE_O_TRACEFORK | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT; /* PTRACE_O_TRACEVFORKDONE */

struct lt_config_audit cfg;

char gotrace_socket_path[128];

char *excluded_intercepts[] = {
//	"runtime.(*mcache).refill",
//	"main.GetConnection",
//	"main.TouchConnection"
/*	"runtime.atomicstorep",
	"runtime.cgocall",
	"runtime.endcgo",
	"runtime.exitsyscall",
	"runtime.exitsyscallfast",
	"runtime.lock",
	"runtime.futexwakeup"*/
/*	"threadentry",
	"setg_gcc",
	"runtime.mstart",
	"runtime.mstart1",
	"runtime.gosave",
	"runtime.asminit",
	"runtime.minit",
	"runtime.sigaltstack",
	"runtime.signalstack",
	"runtime.gettid",
	"runtime.rtsigprocmask"*/
};

char *read_bytes_remote(pid_t pid, char *addr, size_t slen);
int write_bytes_remote(pid_t pid, void *addr, void *buf, size_t blen);
void print_instruction(pid_t pid, void *addr, size_t len);

void *call_remote_func(pid_t pid, unsigned char reqtype, void *data, size_t dsize, size_t *psize);
int call_remote_intercept(pid_t pid, char **funcnames, unsigned long *addresses, size_t naddr, int is_entry);

void start_listener(void);
void *gotrace_socket_loop(void *param);

int set_all_intercepts(pid_t pid);
int set_intercept(pid_t pid, void *addr);
int set_ret_intercept(pid_t pid, const char *fname, void *addr, size_t *pidx);
int is_intercept_excluded(const char *fname);

int save_remote_intercept(pid_t pid, const char *fname, void *addr, int is_entry);

void cleanup(void);
void handle_int(int signo);


void
cleanup(void) {
	if (gotrace_socket_path[0])
		unlink(gotrace_socket_path);

	return;
}

void
handle_int(int signo) {
	if (signo == SIGINT) {
		fprintf(stderr, "Caught SIGINT... shutting down gracefully.\n");
		exit(EXIT_SUCCESS);
	}

	return;
}


static int test_fd = -1;
static pid_t test_pid = -1;

void *
call_remote_func(pid_t pid, unsigned char reqtype, void *data, size_t dsize, size_t *psize)
{
	void *result;
	int oreqtype;
	int first = 0;
	pid_t cpid;

	int fd = test_fd;

	if (send_gt_msg(pid, fd, reqtype, data, dsize, 0) < 0) {
		PRINT_ERROR("%s", "Error encountered in calling gomod function.\n");
		return NULL;
	}

	fprintf(stderr, "Sent and waiting to receive (%d)\n", fd);

	result = recv_gt_msg(pid, fd, reqtype, psize, &oreqtype, first, &cpid);

	if (result && (reqtype != oreqtype)) {
		PRINT_ERROR("Error receiving gotrace socket data of unexpected response type (%d)\n", oreqtype);
		free(result);
		return NULL;
	}

	if (first)
		fprintf(stderr, "XXX: first client pid = %d\n", cpid);

	return result;
}

char *
call_remote_serializer(pid_t pid, const char *name, void *addr) {
	void *result;
	unsigned long *upval;
	char reqbuf[128];
	size_t reqsize, outsize;

	memset(reqbuf, 0, sizeof(reqbuf));
	strncpy(reqbuf, name, sizeof(reqbuf)-(1+sizeof(void *)));
	upval = (unsigned long *)(reqbuf + strlen(reqbuf) + 1);
	*upval = (unsigned long)addr;
	reqsize = ((char *)upval) + sizeof(void *) - ((char *)reqbuf);
	result = call_remote_func(pid, GOMOD_RT_SERIALIZE_DATA, reqbuf, reqsize, &outsize);

	return result;
}

int
call_remote_intercept(pid_t pid, char **funcnames, unsigned long *addresses, size_t naddr, int is_entry) {
	void *result;
	unsigned long *taddr;
	size_t outsize;

	result = call_remote_func(pid, GOMOD_RT_SET_INTERCEPT, addresses, naddr*sizeof(unsigned long), &outsize);
	taddr = (unsigned long *)result;

	if (!result) {
		PRINT_ERROR("%s", "XXX: call remote intercept returned NULL\n");
		return -1;
	} else if (!*taddr) {
		PRINT_ERROR("%s", "Error: remote intercept attempt on function failed!\n");
		return -1;
	} else {
		fprintf(stderr, "XXX: call remote intercept: result = %p / %zu: %p\n", result, outsize, (void *)*taddr);

		if (save_remote_intercept(pid, *funcnames, (void *)*taddr, is_entry) < 0) {
			PRINT_ERROR("%s", "Unknown error occurred setting remote function intercept\n");
			return -1;
		}
	}

	return 0;
}

void *
gotrace_socket_loop(void *param) {
	int lfd;

	fprintf(stderr, "Listening for child connections!\n");
	lfd = (int)((uintptr_t)param);

	while (1) {
		struct sockaddr_un s_un;
		socklen_t slen;
		int cfd;

		fprintf(stderr, "Listening...\n");

		if ((cfd = accept(lfd, (struct sockaddr *)&s_un, &slen)) == -1) {
			perror_pid("accept", lfd);
			exit(EXIT_FAILURE);
		}

		fprintf(stderr, "XXX: ACCEPTED (%d)!\n", cfd);
		test_fd = cfd;

/*		if (set_all_intercepts(test_pid) < 0) {
			PRINT_ERROR("%s", "Error encountered while setting intercepts.\n");
			exit(EXIT_FAILURE);
		}*/

/*		char *fname = "main.GetConnection";
		unsigned long readdr = 0x0000000000402d60;
		int res = call_remote_intercept(-1, &fname, &readdr, 1, 1);
		fprintf(stderr, "XXX: int res = %d\n", res);

		fname = "main.TouchConnection";
		readdr = 0x0000000000402c60;
		res = call_remote_intercept(-1, &fname, &readdr, 1, 1);
		fprintf(stderr, "XXX: int res = %d\n", res);*/




		fprintf(stderr, "XXX: Sleeping...\n");
		sleep(2);
		fprintf(stderr, "XXX: End sleep.\n");
		break;
	}

	return NULL;
}

void
start_listener(void) {
	static struct sockaddr_un s_un;
	socklen_t ssize;
	pthread_t ptid;
	int fd;

	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		perror_pid("socket", 0);
		exit(EXIT_FAILURE);
	}

	memset(&s_un, 0, sizeof(s_un));
	s_un.sun_family = AF_UNIX;
	strncpy(s_un.sun_path, gotrace_socket_path, sizeof (s_un.sun_path));
	ssize = offsetof(struct sockaddr_un, sun_path) + strlen(s_un.sun_path);

	if (bind(fd, (struct sockaddr *)&s_un, ssize) == -1) {
		perror_pid("bind", fd);
		exit(EXIT_FAILURE);
	}

	if (listen(fd, 10) == -1) {
		perror_pid("listen", fd);
		exit(EXIT_FAILURE);
	}

	if (pthread_create(&ptid, NULL, gotrace_socket_loop, (void *)((uintptr_t)fd)) != 0) {
		perror_pid("pthread_create", 0);
		exit(EXIT_FAILURE);
	}

	return;
}

int
is_intercept_excluded(const char *fname) {
	size_t i;

	for (i = 0; i < sizeof(excluded_intercepts)/sizeof(excluded_intercepts[0]); i++) {
		if (!strcmp(fname, excluded_intercepts[i]))
			return 1;
	}

	return 0;
}

// XXX: this obviously doesn't really work.
int
is_pid_new(pid_t pid) {
	return 1;
}

int
check_remote_intercept(pid_t pid, void *pc, struct user_regs_struct *regs) {
	struct lt_symbol *lts;
	char *symname;
	size_t i;

	for (i = 0; i < remote_intercept_entries; i++) {
		if (remote_intercepts[i].addr == pc) {
			int ret;

			symname = remote_intercepts[i].fname;
			fprintf(stderr, "XXX: OOOOOOOOOOOOH YEAH: %s / %d\n", symname, remote_intercepts[i].is_entry);

			if (remote_intercepts[i].is_entry) {
				unsigned long retaddr;

				errno = 0;
				retaddr = ptrace(PTRACE_PEEKTEXT, pid, regs->rsp+sizeof(void *), 0);
				if (errno != 0) {
					perror_pid("ptrace(PTRACE_PEEKTEXT)", pid);
					return -1;
				}

				fprintf(stderr, "XXX: YUPP %p\n", (void *)retaddr);
				int res = call_remote_intercept(pid, &symname, &retaddr, 1, 0);
				fprintf(stderr, "XXX: res = %d\n", res);

				// Now we we must compensate for the size of the extra return address on the stack.
				regs->rsp += sizeof(void *);
			}

			lts = lt_symbol_bind(cfg.sh, pc, symname);
			lt_tsd_t *tsdx = thread_get_tsd(pid, 1);

			if (remote_intercepts[i].is_entry)
				ret = sym_entry(symname, lts, "from", "to", pid, regs, tsdx);
			else
				ret = sym_exit(symname, lts, "from", "to", pid, regs, regs, tsdx);

			return 0;
		}
	}

	return -1;
}

int
handle_trace_trap(pid_t pid, int status, int dont_reset) {
	struct lt_symbol *lts;
	void *hot_pc, *hot_sp;
	struct user_regs_struct regs;
	const char *symname;
	long retrace, ret_addr;
	size_t i, ra;
	int ret, is_return = 0;

//	if ((status >> 8) == (SIGTRAP | (PTRACE_EVENT_CLONE << 8))) { }

	if (!WIFSTOPPED(status) || (WSTOPSIG(status) != SIGTRAP)) {
		dump_wait_state(pid, status, 1);

		if (WIFSTOPPED(status) && (WSTOPSIG(status) == SIGSTOP)) {
			if (is_pid_new(pid)) {

				if (ptrace(PTRACE_SETOPTIONS, pid, NULL, trace_flags) < 0) {
					perror_pid("ptrace(PTRACE_SETOPTIONS)", pid);
					exit(EXIT_FAILURE);
				}

/*				if (set_all_intercepts(pid) < 0) {
					fprintf(stderr, "Error encountered while setting intercepts in new process.\n");
					exit(EXIT_FAILURE);
				}
				fprintf(stderr, "XXX: skipping set intercepts on pid %d\n", pid);*/

				// We will return into a loop that will perform this action for us.
/*				if (ptrace(PTRACE_CONT, pid, NULL, 0) < 0) {
					perror_pid("ptrace(PTRACE_CONT) [4]", pid);
					exit(EXIT_FAILURE);
				} */

				fprintf(stderr, "KEK2: %d\n", WSTOPSIG(status));
				return 1;
			}
		}

		return 0;
	}

	DEBUG_PRINT(2, "Handling trace trap!\n");

	if (ptrace(PTRACE_GETREGS, pid, 0, &regs) < 0) {
		perror_pid("ptrace(PTRACE_GETREGS)", pid);
		return -1;
	}

	// Hmm
	hot_pc = (void *)(regs.rip - 1);
	hot_sp = (void *)(regs.rsp + sizeof(void *));

	// Check for remote intercept first.
	if (!check_remote_intercept(pid, hot_pc, &regs)) {
		return 1;
	}

	for (i = 0; i < saved_prolog_entries; i++) {
		if (saved_prologs[i].addr == hot_pc)
			break;
	}

	if (i == saved_prolog_entries) {

		for (ra = 0; ra < saved_ret_prolog_entries; ra++) {
			if (saved_ret_prologs[ra].addr == hot_pc)
				break;
		}

		if (ra == saved_ret_prolog_entries) {
			PRINT_ERROR("Unexpected error: trace trap not at known intercept point (%p).\n", hot_pc);
			print_instruction(pid, (void *)hot_pc, 16);
			return -1;
		}

		is_return = 1;
	}

	if (dont_reset)
		return 0;

//	printf("is return = %d\n", is_return);

	if (!is_return) {
		size_t ridx;

		errno = 0;
		ret_addr = ptrace(PTRACE_PEEKTEXT, pid, regs.rsp, 0);
		if (errno != 0) {
			perror_pid("ptrace(PTRACE_PEEKTEXT)", pid);
			return -1;
		}

//		printf("RET ADDR would have been %lx\n", ret_addr);
		symname = lookup_addr(hot_pc);
		if (set_ret_intercept(pid, symname, (void *)ret_addr, &ridx) < 0) {
			PRINT_ERROR("%s", "Error: could not set intercept on return address\n");
	//		return -1;
		}

	}

	if (is_return) {
		DEBUG_PRINT(2, "Return address trace generated at PC %p SP %p\n", hot_pc, hot_sp);
		symname = saved_ret_prologs[ra].fname;
	} else {
		DEBUG_PRINT(2, "Trace generated at PC %p SP %p\n", hot_pc, hot_sp);
//		printf("sym = [%s]\n", symname);
	}

	// Don't replace 
	if (is_return)
		retrace = ptrace(PTRACE_POKETEXT, pid, saved_ret_prologs[ra].addr, saved_ret_prologs[ra].saved_prolog);
	else
		retrace = ptrace(PTRACE_POKETEXT, pid, saved_prologs[i].addr, saved_prologs[i].saved_prolog);

	if (retrace < 0) {
		perror_pid("ptrace(PTRACE_POKETEXT)", pid);
		return -1;
	}

	regs.rip = (long)hot_pc;

	if (ptrace(PTRACE_SETREGS, pid, 0, &regs) < 0) {
		perror_pid("ptrace(PTRACE_SETREGS)", pid);
		return -1;
	}

	lts = lt_symbol_bind(cfg.sh, hot_pc, symname);
	lt_tsd_t *tsdx = thread_get_tsd(pid, 1);

	if (is_return) {
		ret = sym_exit(symname, lts, "from", "to", pid, &regs, &regs, tsdx);
//		return 1;
	} else {
//	fprintf(stderr, "HEH: %d / %s / %p\n", pid, symname, tsdx);
		ret = sym_entry(symname, lts, "from", "to", pid, &regs, tsdx);
	}

	if (ret < 0) {
		PRINT_ERROR("Encountered unexpected error handling function %s\n",
			(is_return ? "exit" : "entry"));
	}

	if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) < 0) {
		perror_pid("ptrace(PTRACE_SINGLESTEP)", pid);
		return -1;
	}

	int wait_status = 0;

	if (waitpid(pid, &wait_status, 0) < 0) {
		perror_pid("waitpid", pid);
		return -1;
	}

	if (!WIFSTOPPED(wait_status) || (WSTOPSIG(wait_status) != SIGTRAP)) {
		PRINT_ERROR("%s", "Error: single step process returned in unexpected fashion.\n");
		return -1;
	}

	if (is_return) {
		retrace = saved_ret_prologs[ra].saved_prolog;
		ret_addr = (long)saved_ret_prologs[ra].addr;
	} else {
		retrace = saved_prologs[i].saved_prolog;
		ret_addr = (long)saved_prologs[i].addr;
	}

	*((unsigned char *)&retrace) = 0xcc;

	if (ptrace(PTRACE_POKETEXT, pid, ret_addr, retrace) < 0) {
		perror_pid("ptrace(PTRACE_POKETEXT)", pid);
		return -1;
	}

	return 1;
}

int
analyze_clone_call(pid_t pid, pid_t cpid) {
	pid_t newpid;
	int cflags, ws;
	struct user_regs_struct regs;

	if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) < 0) {
		perror_pid("ptrace(PTRACE_SYSCALL)", pid);
		return -1;
	}

	if (waitpid(pid, &ws, 0) < 0) {
		perror_pid("waitpid", pid);
		return -1;
	}

	if (ptrace(PTRACE_GETREGS, pid, 0, &regs) < 0) {
		perror_pid("ptrace(PTRACE_GETREGS)", pid);
		return -1;
	}

	newpid = (pid_t)regs.rax;
	cflags = (int)regs.rdi;
	fprintf(stderr, "XXX: New pid: %d, flags = %x\n", newpid, cflags);

	if (newpid != cpid) {
		PRINT_ERROR("%s", "Unexpected error: pid returned by clone() did not match ptrace() query.\n");
		return -1;
	}

	if (cflags & CLONE_VM)
		return 1;

	return 0;
}

void
dump_wait_state(pid_t pid, int status, int force) {
	int dbg_level = 1;
	int needs_pid = 0, did_clone = 0;

	if (force)
		dbg_level = 0;

	DEBUG_PRINT(dbg_level, "Wait status (%d): ", pid);

	if (WIFEXITED(status))
		DEBUG_PRINT(dbg_level, "exited=true/status=%d ", WEXITSTATUS(status));

	if (WIFSIGNALED(status)) {
		DEBUG_PRINT(dbg_level, "signaled=true/termsig=%d ", WTERMSIG(status));
		#ifdef WCOREDUMP
		if (WCOREDUMP(status))
			DEBUG_PRINT(dbg_level, "coredump=true ");
		#endif
	}

	if (WIFSTOPPED(status))
		DEBUG_PRINT(dbg_level, "stopped=true/stopsig=%d ", WSTOPSIG(status));

	if (WIFCONTINUED(status))
		DEBUG_PRINT(dbg_level, "continued=true");

	DEBUG_PRINT(dbg_level, "\n");

	if (WIFSIGNALED(status)) {
		siginfo_t si;

		// PTRACE_PEEKSIGINFO
		if (ptrace(pid, PTRACE_GETSIGINFO, NULL, &si) < 0) {
			perror_pid("ptrace(PTRACE_GETSIGINFO)", pid);
		} else {
			DEBUG_PRINT(dbg_level, "si_code=%d, si_pid=%d, si_uid=%d, si_status=%d, si_addr=%p, "
				"si_call_addr=%p, si_syscall=%d\n",
				si.si_code, si.si_pid, si.si_uid, si.si_status, si.si_addr,
				si.si_call_addr, si.si_syscall);
		}
	}

	if ((status >> 8) == (SIGTRAP | (PTRACE_EVENT_CLONE << 8))) {
		PRINT_ERROR("%s", "Detected clone() event\n");
		needs_pid = 1;
		did_clone = 1;
	}
	else if ((status >> 8) == (SIGTRAP | (PTRACE_EVENT_EXEC << 8)))
		PRINT_ERROR("%s", "Detected exec() event\n");
	else if ((status >> 8) == (SIGTRAP | (PTRACE_EVENT_EXIT << 8))) {
		lt_tsd_t *tsdx = thread_get_tsd(pid, 1);

		PRINT_ERROR("%s", "Detected exit() event\n");
		sym_exit("___________exit", NULL, "from", "to", pid, NULL, NULL, tsdx);
	}
	else if ((status >> 8) == (SIGTRAP | (PTRACE_EVENT_FORK << 8))) {
		PRINT_ERROR("%s", "Detected fork() event\n");
		needs_pid = 1;
	}
	else if ((status >> 8) == (SIGTRAP | (PTRACE_EVENT_VFORK << 8))) {
		PRINT_ERROR("%s", "Detected vfork() event\n");
		needs_pid = 1;
	} else if ((status >> 8) == (SIGTRAP | (PTRACE_EVENT_VFORK_DONE << 8)))
		PRINT_ERROR("%s", "Detected vfork() event\n");

	if (needs_pid) {
		unsigned long msg;
		pid_t npid;

		if (ptrace(PTRACE_GETEVENTMSG, pid, NULL, &msg) < 0) {
			perror_pid("ptrace(PTRACE_GETEVENTMSG)", pid);
			exit(EXIT_FAILURE);
		}

		npid = (pid_t)msg;

		PRINT_ERROR("Event generated by pid = %d\n", npid);

		if (did_clone) {
			int cret;

			cret = analyze_clone_call(pid, npid);
			if (cret < 0)
				PRINT_ERROR("%s", "Unexpected error inspecting result of call to clone()\n");
			else if (cret > 0) {
				fprintf(stderr, "XXX: exempting new process from intercepts: %d\n", npid);
			} else {
				int w;
				if (waitpid(npid, &w, 0) < 0) {
					perror_pid("waitpid", npid);
					exit(EXIT_FAILURE);
				}

				if (WIFSTOPPED(w) && (WSTOPSIG(w) == SIGSTOP)) {
					if (set_all_intercepts(npid) < 0) {
						PRINT_ERROR("Error encountered while setting intercepts in new process %d\n", npid);
						exit(EXIT_FAILURE);
					}
				} else
					PRINT_ERROR("Warning: traced pid %d was stopped for unexpected reason.\n", npid);

				if (ptrace(PTRACE_CONT, npid, NULL, 0) < 0) {
					perror_pid("ptrace(PTRACE_CONT) [6]", npid);
					exit(EXIT_FAILURE);
				}

			}

		}

	}

	// PTRACE_O_TRACESYSGOOD?
	if (WSTOPSIG(status) & 0x80) {
		PRINT_ERROR("%s", "Warning: unchecked delivery of SIGTRAP|0x80\n");
//		exit(EXIT_FAILURE);
	}

	return;
}

void
dump_intercepts(void) {
	size_t i;

	if (DEBUG_LEVEL < 1)
		return;

	fprintf(stderr, "Intercepts set: %zu of max %zu\n", saved_prolog_entries, saved_prolog_nentries);

	if (DEBUG_LEVEL < 2)
		return;

	for (i = 0; i < saved_prolog_entries; i++)
		fprintf(stderr, "%.3zu: %p\n", i+1, saved_prologs[i].addr);

	return;
}

int
set_intercept(pid_t pid, void *addr) {
	long saved_prolog = 0, mod_prolog;
	unsigned char *tptr;

	if (saved_prolog_entries == saved_prolog_nentries) {
		saved_prolog_t *new_prologs;

		if (!(new_prologs = realloc(saved_prologs, (saved_prolog_nentries * 2 * sizeof(saved_prolog_t))))) {
			perror_pid("realloc", pid);
			return -1;
		}

		saved_prolog_nentries *= 2;
		saved_prologs = new_prologs;
	}

	errno = 0;
	saved_prolog = ptrace(PTRACE_PEEKTEXT, pid, addr, 0);
	if (errno != 0) {
		perror_pid("ptrace(PTRACE_PEEKTEXT)", pid);
		return -1;
	}

	mod_prolog = saved_prolog;
	tptr = (unsigned char *)&mod_prolog;
	*tptr = 0xcc;

	if (ptrace(PTRACE_POKETEXT, pid, addr, mod_prolog) < 0) {
		perror_pid("ptrace(PTRACE_POKETEXT)", pid);
		return -1;
	}

	saved_prologs[saved_prolog_entries].addr = addr;
	saved_prologs[saved_prolog_entries].saved_prolog = saved_prolog;
	saved_prolog_entries++;
	return 0;
}

int
save_remote_intercept(pid_t pid, const char *fname, void *addr, int is_entry) {
	size_t i;

	if (remote_intercept_entries == remote_intercept_nentries) {
		remote_intercept_t *new_intercepts;

		if (!(new_intercepts = realloc(remote_intercepts, (remote_intercept_nentries * 2 * sizeof(*remote_intercepts))))) {
			perror_pid("realloc", pid);
			return -1;
		}

		remote_intercept_nentries *= 2;
		remote_intercepts = new_intercepts;
	}

	for (i = 0; i < remote_intercept_entries; i++) {
		if (remote_intercepts[i].addr == addr) {
			return 0;
		}
	}

	remote_intercepts[remote_intercept_entries].addr = addr;
	remote_intercepts[remote_intercept_entries].fname = strdup(fname);
	remote_intercepts[remote_intercept_entries].is_entry = is_entry;
	remote_intercept_entries++;

	return 0;
}

int
set_ret_intercept(pid_t pid, const char *fname, void *addr, size_t *pidx) {
	long saved_ret_prolog = 0, mod_prolog;
	unsigned char *tptr;
	size_t i;

//printf("set_ret_intercept: %s\n", fname);

	if (saved_ret_prolog_entries == saved_ret_prolog_nentries) {
		saved_prolog_t *new_prologs;

		if (!(new_prologs = realloc(saved_ret_prologs, (saved_ret_prolog_nentries * 2 * sizeof(saved_prolog_t))))) {
			perror_pid("realloc", pid);
			return -1;
		}

		saved_ret_prolog_nentries *= 2;
		saved_ret_prologs = new_prologs;
	}

	for (i = 0; i < saved_ret_prolog_entries; i++) {
		if (saved_ret_prologs[i].addr == addr) {
			if (pidx)
				*pidx = saved_ret_prolog_entries;

			return 0;
		}
	}

	errno = 0;
	saved_ret_prolog = ptrace(PTRACE_PEEKTEXT, pid, addr, 0);
	if (errno != 0) {
		perror_pid("ptrace(PTRACE_PEEKTEXT)", pid);
		return -1;
	}

	mod_prolog = saved_ret_prolog;
	tptr = (unsigned char *)&mod_prolog;
	*tptr = 0xcc;

	if (ptrace(PTRACE_POKETEXT, pid, addr, mod_prolog) < 0) {
		perror_pid("ptrace(PTRACE_POKETEXT)", pid);
		return -1;
	}

	saved_ret_prologs[saved_ret_prolog_entries].addr = addr;
	saved_ret_prologs[saved_ret_prolog_entries].fname = strdup(fname);
	saved_ret_prologs[saved_ret_prolog_entries].saved_prolog = saved_ret_prolog;

	if (pidx)
		*pidx = saved_ret_prolog_entries;

	saved_ret_prolog_entries++;
	return 0;
}

int
trace_init(void) {
	if (!(saved_prologs = malloc(saved_prolog_nentries * sizeof(*saved_prologs)))) {
		perror_pid("malloc", 0);
		return -1;
	}

	memset(saved_prologs, 0, saved_prolog_nentries * sizeof(*saved_prologs));

	if (!(saved_ret_prologs = malloc(saved_ret_prolog_nentries * sizeof(*saved_prologs)))) {
		perror_pid("malloc", 0);
		return -1;
	}

	memset(saved_ret_prologs, 0, saved_ret_prolog_nentries * sizeof(*saved_prologs));

	if (!(remote_intercepts = malloc(remote_intercept_nentries * sizeof(*remote_intercepts)))) {
		perror_pid("malloc", 0);
		return -1;
	}

	memset(remote_intercepts, 0, remote_intercept_nentries * sizeof(*remote_intercepts));

	return 0;
}

int
child_trace_program(const char *progname, char * const *args) {

	if (prctl(PR_SET_PTRACER, getppid()) < 0) {
		perror_pid("prctl(PR_SET_PTRACER)", 0);
//		exit(EXIT_FAILURE);
	}

	if (ptrace(PTRACE_TRACEME, NULL, 0, 0) < 0) {
		perror_pid("ptrace(PTRACE_TRACEME)", 0);
		exit(EXIT_FAILURE);
	}

	printf("In child.\n");
	raise(SIGSTOP);
	printf("After raising.\n");
//	fprintf(stderr, "socket path: [%s]\n", gotrace_socket_path);
	setenv(GOTRACE_SOCKET_ENV, gotrace_socket_path, 1);
	execv(progname, args);
	perror_pid("execv", 0);
	exit(EXIT_FAILURE);
}

int
set_all_intercepts(pid_t pid) {
	size_t i;

	for (i = 0; i < sizeof(symbol_store)/sizeof(symbol_store[0]); i++) {
		if (!symbol_store[i].l)
			continue;

		for (size_t j = 0; j < symbol_store[i].msize; j++) {
//			fprintf(stderr, "CANDIDATE: %s - %lx\n", symbol_store[i].map[j].name, symbol_store[i].map[j].addr);

			if (is_intercept_excluded(symbol_store[i].map[j].name)) {
				PRINT_ERROR("Skipping over excluded intercept: %s\n", symbol_store[i].map[j].name);
				continue;
			}

			if (set_intercept(pid, (void *)symbol_store[i].map[j].addr) < 0) {
				PRINT_ERROR("Error: could not set intercept on symbol: %s\n", symbol_store[i].map[j].name);
				return -1;
			}
		}

	}

	fprintf(stderr, "XXX: Set intercepts on %d\n", pid);
	return 0;
}

char *
read_bytes_remote(pid_t pid, char *addr, size_t slen) {
	char *result, *raddr = addr;
	size_t nread = 0;

	if (slen) {
		if (!(result = malloc(slen+1))) {
			perror_pid("malloc", pid);
			return NULL;
		}

		memset(result, 0, slen+1);
	}

	while (nread < slen) {
		size_t maxwrite;
		long val;

		errno = 0;

		val = ptrace(PTRACE_PEEKDATA, pid, raddr, 0);
		if (errno != 0) {
			perror_pid("ptrace(PTRACE_PEEKDATA)", pid);
			return NULL;
		}

		maxwrite = slen - nread;
		if (maxwrite > sizeof(long))
			maxwrite = sizeof(long);

		memcpy(&result[nread], &val, maxwrite);
		nread += maxwrite;
		raddr += maxwrite;
	}

	return result;
}

int write_bytes_remote(pid_t pid, void *addr, void *buf, size_t blen) {
	unsigned char *wptr = (unsigned char *)addr;
	unsigned char *rptr = (unsigned char *)buf;
	size_t nwritten = 0;

	while (nwritten < blen) {
		unsigned long wword;

		// If less than a word remaining, we have to rewrite part of the current contents
		if ((blen - nwritten) < sizeof(void *)) {
			unsigned long oval;

//			fprintf(stderr, "XXX: %zu bytes left in write\n", blen-nwritten);

			errno = 0;
			oval = ptrace(PTRACE_PEEKDATA, pid, wptr, 0);
			if (errno != 0) {
				perror_pid("ptrace(PTRACE_PEEKDATA)", pid);
				return -1;
			}

			memcpy(&wword, &oval, sizeof(oval));
			memcpy(&wword, rptr, (blen - nwritten));
		} else {
			memcpy(&wword, rptr, sizeof(wword));
		}

		if (ptrace(PTRACE_POKEDATA, pid, wptr, wword) == -1) {
			perror_pid("ptrace(PTRACE_POKEDATA)", pid);
			return -1;
		}

		nwritten += sizeof(void *);
		wptr += sizeof(void *);
		rptr += sizeof(void *);
	}

	return 0;
}

void
print_instruction(pid_t pid, void *addr, size_t len) {
	ZydisFormatter formatter;
	ZydisDecoder decoder;
	ZydisDecodedInstruction instruction;
	void *rdata;
	uint64_t rip = (uint64_t)addr;
	uint8_t *idata;

	if (!(rdata = read_bytes_remote(pid, addr, len))) {
		PRINT_ERROR("Error: could not print instruction at %p\n", addr);
		return;
	}

	idata = (uint8_t *)rdata;

	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
	ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

	while (ZYDIS_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, idata, len, rip, &instruction)))
	{
		char buffer[256];

		ZydisFormatterFormatInstruction(&formatter, &instruction, buffer, sizeof(buffer));
		fprintf(stderr, "Instruction: %p [%s]\n", (void *)rip, buffer);
		idata += instruction.length;
		len -= instruction.length;
		rip += instruction.length;
		break;
	}

	free(rdata);
	return;
}

int
check_child_execute(pid_t pid) {
	struct user_regs_struct regs;
	int wait_status;

	if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1)
	{
		perror_pid("ptrace(PTRACE_SYSCALL)", pid);
		return -1;
	}

	if (waitpid(pid, &wait_status, 0) == -1)
	{
		perror_pid("waitpid", pid);
		return -1;
	}

	if (!WIFSTOPPED(wait_status) || ((WSTOPSIG(wait_status) & ~0x80) != SIGTRAP)) {
		PRINT_ERROR("Unexpected error: process %d did not return with trace trap\n", pid);
		return -1;
	}

	if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {
		perror_pid("ptrace(PTRACE_GETREGS)", pid);
		return -1;
	}

	if (regs.orig_rax != SYS_execve)
		return 0;

	return 1;
}

void
dump_instruction_state(pid_t pid) {
	struct user_regs_struct regs;
	siginfo_t si;
	Dl_info ainfo, iinfo;
	int r_addr = 0, r_pc = 0;

	if (ptrace(PTRACE_GETSIGINFO, pid, 0, &si) < 0)
		perror_pid("ptrace(PTRACE_GETSIGINFO)", pid);
	else if (ptrace(PTRACE_GETREGS, pid, 0, &regs) < 0) {
		perror_pid("ptrace(PTRACE_GETREGS)", pid);
		PRINT_ERROR("%s occurred in PID %d at address: %p\n",
			strsignal(si.si_signo), pid, si.si_addr);
		r_addr = dladdr((void *)si.si_addr, &ainfo) != 0;
	} else {
		PRINT_ERROR("%s occurred in PID %d at address %p / PC %p\n",
			strsignal(si.si_signo), pid, si.si_addr, (void *)regs.rip);
		print_instruction(pid, (void *)regs.rip, 16);
		r_addr = dladdr((void *)si.si_addr, &ainfo) != 0;
		r_pc = dladdr((void *)regs.rip, &iinfo) != 0;
	}

	if (r_addr || r_pc) {
		if (r_addr)
			PRINT_ERROR("Possible address match: %s (%s)    ",
				ainfo.dli_sname, ainfo.dli_fname);
		if (r_pc)
			PRINT_ERROR("Possible PC match: %s (%s)",
				iinfo.dli_sname, iinfo.dli_fname);

		PRINT_ERROR("%s", "\n");
	}

	return;
}

void
dump_fs_addr(pid_t pid) {
	struct user_regs_struct regs;

	if (ptrace(PTRACE_GETREGS, pid, 0, &regs) < 0) {
		perror_pid("ptrace(PTRACE_GETREGS)", pid);
		return;
	}

	PRINT_ERROR("fs_base = %p\n", (void *)regs.fs_base);
	return;
}

int
set_fs_base_remote(pid_t pid, unsigned long base) {
	struct user_regs_struct regs;

	if (ptrace(PTRACE_GETREGS, pid, 0, &regs) < 0) {
		perror_pid("ptrace(PTRACE_GETREGS)", pid);
		return -1;
	}

	regs.fs_base = base;

	if (ptrace(PTRACE_SETREGS, pid, 0, &regs) < 0) {
		perror_pid("ptrace(PTRACE_SETREGS)", pid);
		return -1;
	}

	return 0;
}

int
trace_program(const char *progname, char * const *args) {
	pid_t pid;
	int wait_status;

	printf("Attempting to trace...: %s\n", progname);

	switch(pid = fork()) {
		case 0:
			child_trace_program(progname, args);
			exit(EXIT_FAILURE);
			break;
		case -1:
			perror_pid("fork", 0);
			exit(EXIT_FAILURE);
			break;
		default:
			break;
	}

	printf("In parent: sleeping\n");

/*	if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
		perror_pid("ptrace(PTRACE_ATTACH)", pid);
		exit(EXIT_FAILURE);
	} */

	if (waitpid(pid, &wait_status, 0) < 0) {
		perror_pid("waitpid", pid);
		exit(EXIT_FAILURE);
	}

	if (ptrace(PTRACE_SETOPTIONS, pid, NULL, trace_flags) < 0) {
		perror_pid("ptrace(PTRACE_SETOPTIONS)", pid);
		exit(EXIT_FAILURE);
	}
	dump_wait_state(pid, wait_status, 0);

	printf("Parent attached\n");

	if (ptrace(PTRACE_CONT, pid, NULL, 0) < 0) {
		perror_pid("ptrace(PTRACE_CONT) [3]", pid);
		exit(EXIT_FAILURE);
	}

	if (waitpid(pid, &wait_status, 0) < 0) {
		perror_pid("waitpid", pid);
		exit(EXIT_FAILURE);
	}
	dump_wait_state(pid, wait_status, 0);
	handle_trace_trap(pid, wait_status, 1);

	fprintf(stderr, "Parent detected possible exec\n");

	switch(check_child_execute(pid)) {
		case -1:
			PRINT_ERROR("%s", "Error occurred checking child execution state\n");
			break;
		case 0:
			PRINT_ERROR("%s", "Warning: child notified parent but was not in execution state\n");
			break;
		default: {
			struct user_regs_struct regs;
//			char **needed;
			void *dlhandle, *initfunc = NULL; //, *reloc_base = NULL;
			const char *libname = GOMOD_LIB_NAME;
			signed long our_fs, old_fs;
			int pres;

			if ((dlhandle = dlopen(libname, RTLD_NOW|RTLD_DEEPBIND)) == NULL) {
				PRINT_ERROR("dlopen(): %s", dlerror());
				exit(EXIT_FAILURE);
			}

//			res = call_remote_syscall(pid, SYS_arch_prctl, ARCH_SET_FS, fs_addr+32767, 0, 0, 0, 0);
#define arch_prctl(code,addr)	syscall(SYS_arch_prctl, code, addr)
			if (arch_prctl(ARCH_GET_FS, &our_fs) == -1) {
				perror("arch_prctl(ARCH_GET_FS)");
				exit(EXIT_FAILURE);
			}

			if (ptrace(PTRACE_GETREGS, pid, 0, &regs) < 0) {
				perror_pid("ptrace(PTRACE_GETREGS)", pid);
				exit(EXIT_FAILURE);
			}

			old_fs = regs.fs_base;

			if (set_fs_base_remote(pid, (unsigned long)our_fs) < 0) {
				PRINT_ERROR("%s", "Error encountered setting up thread block in remote process\n");
				exit(EXIT_FAILURE);
			}

			if (replicate_process_remotely(pid) < 0) {
				PRINT_ERROR("%s", "Error encountered replicating process address space remotely\n");
				exit(EXIT_FAILURE);
			}

/*			if (!(needed = get_all_so_needed(libname, NULL))) {
				PRINT_ERROR("Error looking up dependencies for DSO: %s\n", libname);
				exit(EXIT_FAILURE);
			}

			while (*needed) {
				void *ep;

				PRINT_ERROR("FINAL NEEDED: [%s]\n", *needed);

				if ((res = open_dso_and_get_segments(*needed, pid, NULL, &reloc_base, 0)) < 0) {
					PRINT_ERROR("Error copying out remote dependency: %s\n", *needed);
					exit(EXIT_FAILURE);
				}

				ep = get_entry_point(*needed);

				if (ep && reloc_base) {
					void *init_reloc = reloc_base + (unsigned long)ep;

					if (strstr(*needed, "libc")) {
						PRINT_ERROR("HAHA AWESOME: %s -> %p (%p) <- %p\n", *needed, init_reloc, ep, reloc_base);
						initfunc = init_reloc;
					}

				} else {
					PRINT_ERROR("Warning: DSO %s had no mappable entry point\n", *needed);
				}

				needed++;
			}

			// We mapped in all our dependencies; now do ourselves
			if ((res = open_dso_and_get_segments(libname, pid, &initfunc, &reloc_base, 1)) < 0) {
//			if ((res = open_dso_and_get_segments(libname, pid, NULL, NULL)) < 0) {
				PRINT_ERROR("Error copying out remote library: %s\n", libname);
				exit(EXIT_FAILURE);
			}*/

			start_listener();

			if (!(initfunc = dlsym(dlhandle, GOMOD_INIT_FUNC))) {
				PRINT_ERROR("dlsym(): %s\n", dlerror());
				exit(EXIT_FAILURE);
			}

			if ((pres = call_remote_lib_func(pid, initfunc, 0, 0, 0, 0, 0, 0, PTRACE_EVENT_CLONE)) < 0) {
				PRINT_ERROR("%s", "Error in initialization of remote injection module\n");
				exit(EXIT_FAILURE);
			}

			// The pid returned is our module's socket loop (native code)
			if (ptrace(PTRACE_SETOPTIONS, pres, NULL, 0) < 0) {
				perror_pid("ptrace(~PTRACE_SETOPTIONS)", pres);
				exit(EXIT_FAILURE);
			}

			if (set_fs_base_remote(pid, old_fs) < 0) {
				PRINT_ERROR("%s", "Error restoring original thread block in remote process\n");
				exit(EXIT_FAILURE);
			}/* else if (set_fs_base_remote(pres, old_fs) < 0) {
				PRINT_ERROR("%s", "Error restoring original thread block in remote process\n");
				exit(EXIT_FAILURE);
			}*/

			test_pid = pid;

			if (set_all_intercepts(pid) < 0) {
				PRINT_ERROR("%s", "Error encountered while setting intercepts.\n");
				exit(EXIT_FAILURE);
			}

//			dump_intercepts();

			// Probably unnecessary.
/*			if (ptrace(PTRACE_SETREGS, pid, 0, &regs) < 0) {
				perror_pid("ptrace(PTRACE_SETREGS)", pid);
				exit(EXIT_FAILURE);
			} */

			break;
		}
	}

	printf("Running loop...\n");

	if (ptrace(PTRACE_CONT, pid, NULL, 0) < 0) {
		perror_pid("ptrace(PTRACE_CONT) [1]", pid);
		exit(EXIT_FAILURE);
	}

	while (1) {
		pid_t cpid;

		if ((cpid = waitpid(-1, &wait_status, 0)) < 0) {
			perror_pid("waitpid", -1);
			exit(EXIT_FAILURE);
		}

		if (WIFSTOPPED(wait_status) && (WSTOPSIG(wait_status) == SIGUSR2)) {
			PRINT_ERROR("Traced PID/TID (%d) is our own code; detaching.\n", cpid);

			test_pid = cpid;
			if (set_all_intercepts(test_pid) < 0) {
				PRINT_ERROR("%s", "Error encountered while setting intercepts.\n");
				exit(EXIT_FAILURE);
			}

			if (ptrace(PTRACE_SETOPTIONS, cpid, NULL, 0) < 0) {
				perror_pid("ptrace(~PTRACE_SETOPTIONS)", cpid);
				exit(EXIT_FAILURE);
			}

			if (ptrace(PTRACE_CONT, cpid, NULL, 0) < 0) {
				perror_pid("ptrace(PTRACE_CONT) [5]", cpid);
				exit(EXIT_FAILURE);
			}

			continue;
		}

		dump_wait_state(cpid, wait_status, 0);

		if (handle_trace_trap(cpid, wait_status, 0) < 1) {
			PRINT_ERROR("%s", "Error: something bad happened while handling trace trap\n");

			if (WIFSTOPPED(wait_status) && (WSTOPSIG(wait_status) == SIGSEGV)) {
				static int scnt = 0;

				dump_instruction_state(cpid);

				if (ptrace(PTRACE_DETACH, cpid, NULL, NULL) == -1) {
					perror_pid("ptrace(PTRACE_DETACH)", cpid);
				}

				if (kill(cpid, SIGSEGV) == -1)
					perror_pid("kill(SIGSEGV)", cpid);

				if (scnt++ > 50) {
					PRINT_ERROR("%s", "Received too many SIGSEGvs... exiting.\n");
					exit(EXIT_FAILURE);
				}

			}
		}

//		if (WIFEXITED(wait_status) || (WIFSTOPPED(wait_status) && (WSTOPSIG(wait_status) != SIGTRAP))) {
		if (WIFEXITED(wait_status)) {
			fprintf(stderr, "Aborting loop.\n");
			break;
		}

		if (ptrace(PTRACE_CONT, cpid, NULL, 0) < 0) {
			perror_pid("ptrace(PTRACE_CONT) [2]", cpid);
			exit(EXIT_FAILURE);
		}

	}

	fprintf(stderr, "Waiting 3 seconds...\n");
	sleep(3);

	return 0;
}


int
main(int argc, char *argv[]) {
	static struct lt_config_shared cfg_sh;
	char *progname = argv[1];
	int syms_ok;

	if (argc < 2) {
		fprintf(stderr, "Error: must specify a program name (and optional arguments)!\n");
		exit(EXIT_FAILURE);
	}

	printf("Starting up...\n");

	trace_init();

        cfg.sh = &cfg_sh;
        cfg_sh.timestamp = 0;
        cfg_sh.hide_tid = 0;
        cfg_sh.indent_sym = 1;
        cfg_sh.indent_size = 1;
        cfg_sh.fmt_colors = 1;
        cfg_sh.braces = 1;
        cfg_sh.resolve_syms = 1;

	if (audit_init(&cfg, argc, argv, environ) < 0) {
		fprintf(stderr, "Error encountered in initialization! Aborting.\n");
		exit(EXIT_FAILURE);
	}

	if ((syms_ok = get_all_funcs_in_object(progname)) != 1) {
		fprintf(stderr, "Error: could not read symbols from debug object\n");
		exit(EXIT_FAILURE);
	}

	snprintf(gotrace_socket_path, sizeof(gotrace_socket_path), "/tmp/gotrace.sock.%d", getpid());
	atexit(cleanup);

	if (signal(SIGINT, handle_int) == SIG_ERR)
		perror_pid("signal(SIGINT,...)", 0);

	trace_program(progname, &argv[2]);
	exit(-1);
}
