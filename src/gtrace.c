#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stddef.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>

// TODO: waitpid(..., WUNTRACED)

#include "config.h"
#include "elfh.h"
#include "args.h"


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
	int refcnt;
} saved_prolog_t;

size_t saved_prolog_nentries = 1024;
size_t saved_prolog_entries = 0;
saved_prolog_t *saved_prologs = NULL;

size_t saved_ret_prolog_nentries = 64;
size_t saved_ret_prolog_entries = 0;
saved_prolog_t *saved_ret_prologs = NULL;

long trace_flags = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACECLONE | PTRACE_O_TRACEVFORK |
	PTRACE_O_TRACEFORK | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT; /* PTRACE_O_TRACEVFORKDONE */

struct lt_config_audit cfg;

char gotrace_socket_path[128];

char *excluded_intercepts[] = {
//	"runtime.atomicstorep",
//	"runtime.(*waitq).dequeue",
//	"runtime.mallocgc",
//	"runtime.newobject",
//	"runtime.heapBitsSetType",
//	"runtime.heapBitsForSpan",
//	"runtime.(*mcache).refill",

//	"runtime.chanrecv",
//	"runtime.chanrecv1",

//	"runtime.(*mcentral).cacheSpan",

//	"runtime.bgsweep",
//	"runtime.chansend",
//	"runtime.chansend1",
//	"runtime.forcegchelper",
//	"runtime.futexwakeup",
//	"runtime.gopark",
//	"runtime.goready",
//	"runtime.lock",
//	"runtime.makechan",
//	"runtime.mcommoninit",
//	"runtime.netpollinited",
//	"runtime.notesleep",
//	"runtime.notewakeup",
//	"runtime.ready",
//	"runtime.runfinq",
//	"runtime.send",
//	"runtime.stopTheWorld",
//	"runtime.unlock"
};

extern char *read_string_remote(pid_t pid, char *addr, size_t slen);

void *call_remote_func(pid_t pid, unsigned char reqtype, void *data, size_t dsize, size_t *psize);

void start_listener(void);
void *gotrace_socket_loop(void *param);

void dump_wait_state(pid_t pid, int status, int force);
int set_all_intercepts(pid_t pid);
int set_intercept(pid_t pid, void *addr);
int set_ret_intercept(pid_t pid, const char *fname, void *addr, size_t *pidx);
int is_intercept_excluded(const char *fname);



static int test_fd = -1;

void *
call_remote_func(pid_t pid, unsigned char reqtype, void *data, size_t dsize, size_t *psize)
{
	gomod_data_hdr_t hdr;
	int res;

	if (dsize > 0xffff) {
		PRINT_ERROR("Error calling gomod function with oversized data buffer (%zu bytes)\n", dsize);
		return NULL;
	}

	memset(&hdr, 0, sizeof(hdr));
	hdr.magic = GOMOD_DATA_MAGIC;
	hdr.size = dsize;
	hdr.reqtype = reqtype;

	int fd = test_fd;

	if ((res = send(fd, &hdr, sizeof(hdr), 0)) != sizeof(hdr)) {
		if (res == -1)
			perror("send");

		PRINT_ERROR("%s", "Error encountered in calling gomod function.\n");
		return NULL;
	}

	if ((res = send(fd, data, dsize, 0)) != dsize) {
		if (res == -1)
			perror("send");

		PRINT_ERROR("%s", "Error encountered in calling gomod function.\n");
		return NULL;
	}

	fprintf(stderr, "Sent and waiting to receive\n");

	if ((res = recv(fd, &hdr, sizeof(hdr), MSG_WAITALL)) != sizeof(hdr)) {
		if (res == -1)
			perror("recv");

		PRINT_ERROR("%s", "Error encountered in retrieving remote result of gomod function.\n");
		return NULL;
	}

	if (hdr.magic != GOMOD_DATA_MAGIC) {
		PRINT_ERROR("%s", "Error retrieving gomod function result with unexpected data formatting.\n");
		return NULL;
	} else if (hdr.reqtype != reqtype) {
		PRINT_ERROR("%s", "Error retrieving gomod function result with mismatched request type.\n");
		return NULL;
	}

	PRINT_ERROR("GO MOD RETURN SIZE = %u bytes\n", hdr.size);

	return NULL;
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
			perror("accept");
			exit(EXIT_FAILURE);
		}

		fprintf(stderr, "ACCEPTED!\n");
		test_fd = cfd;

	void *heh;
	#define XDATA "123456781234567812345678\x00"
	heh = call_remote_func(-1, GOMOD_RT_SET_INTERCEPT, XDATA, strlen(XDATA), NULL);
	fprintf(stderr, "call result = %p\n", heh);

		fprintf(stderr, "Sleeping...\n");
		sleep(2);
		fprintf(stderr, "End sleep.\n");
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
		perror("socket");
		exit(EXIT_FAILURE);
	}

	memset(&s_un, 0, sizeof(s_un));
	s_un.sun_family = AF_UNIX;
	strncpy(s_un.sun_path, gotrace_socket_path, sizeof (s_un.sun_path));
	ssize = offsetof(struct sockaddr_un, sun_path) + strlen(s_un.sun_path);

	if (bind(fd, (struct sockaddr *)&s_un, ssize) == -1) {
		perror("bind");
		exit(EXIT_FAILURE);
	}

	if (listen(fd, 10) == -1) {
		perror("listen");
		exit(EXIT_FAILURE);
	}

	if (pthread_create(&ptid, NULL, gotrace_socket_loop, (void *)((uintptr_t)fd)) != 0) {
		perror("pthread_create");
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

void *
decode_param(pid_t pid, void *sp, golang_data_type dtype, void *pval) {
	long val;

	errno = 0;
	val = ptrace(PTRACE_PEEKDATA, pid, sp, 0);
	if (errno != 0) {
		perror("ptrace(PTRACE_PEEKDATA)");
		return NULL;
	}

	if (dtype == gint) {
		*((int *)pval) = (int)val;
		return sp + sizeof(void *);
	} else if (dtype == gstring) {
		char *str;
		long slen;

		errno = 0;
		slen = ptrace(PTRACE_PEEKDATA, pid, sp+sizeof(void *), 0);
		if (errno != 0) {
			perror("ptrace(PTRACE_PEEKDATA)");
			return NULL;
		}

//		*((char **)pval) = (char *)val;
		if (!(str = read_string_remote(pid, (void *)val, slen)))
			return NULL;
		*((char **)pval) = str;

		return sp + ((sizeof(void *)) * 2);
	}

	return NULL;
}

int
is_pid_new(pid_t pid) {
	return 1;
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
//	int last_ref = 0;

	if (!WIFSTOPPED(status) || (WSTOPSIG(status) != SIGTRAP)) {
		dump_wait_state(pid, status, 1);

		if (WIFSTOPPED(status) && (WSTOPSIG(status) == SIGSTOP)) {
			if (is_pid_new(pid)) {

				if (ptrace(PTRACE_SETOPTIONS, pid, NULL, trace_flags) < 0) {
					perror("ptrace(PTRACE_SETOPTIONS)111");
					exit(EXIT_FAILURE);
				}

				if (set_all_intercepts(pid) < 0) {
					fprintf(stderr, "Error encountered while setting intercepts in new process.\n");
					exit(EXIT_FAILURE);
				}

				// We will return into a loop that will perform this action for us.
/*				if (ptrace(PTRACE_CONT, pid, NULL, 0) < 0) {
					perror("ptrace(PTRACE_CONT) [4]");
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
		perror("ptrace(PTRACE_GETREGS)");
		return -1;
	}

	// Hmm
	hot_pc = (void *)(regs.rip - 1);
	hot_sp = (void *)(regs.rsp + sizeof(void *));

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
			fprintf(stderr, "Unexpected error: trace trap not at known intercept point (%p).\n", hot_pc);
			return -1;
		}

		is_return = 1;

//		if (__sync_sub_and_fetch(&(saved_ret_prologs[ra].refcnt), 1) == 0)
//			last_ref = 1;

//		printf("HEH: return refcnt[%zu] for %s (%p) is %d; last ref = %d\n", ra, saved_ret_prologs[ra].fname, saved_ret_prologs[ra].addr, saved_ret_prologs[ra].refcnt, last_ref);
	}

	if (dont_reset)
		return 0;

//	printf("is return = %d\n", is_return);

	if (!is_return) {
		size_t ridx;

		errno = 0;
		ret_addr = ptrace(PTRACE_PEEKTEXT, pid, regs.rsp, 0);
		if (errno != 0) {
			perror("ptrace(PTRACE_PEEKTEXT)");
			return -1;
		}

//		printf("RET ADDR would have been %lx\n", ret_addr);
		symname = lookup_addr(hot_pc);
		if (set_ret_intercept(pid, symname, (void *)ret_addr, &ridx) < 0) {
			fprintf(stderr, "Error: could not set intercept on return address\n");
	//		return -1;
		} else {
			__sync_add_and_fetch(&(saved_ret_prologs[ridx].refcnt), 1);
//			printf("HEH2: return[%zu] refcnt for %s (%p) is %d\n", ridx, saved_ret_prologs[ridx].fname, saved_ret_prologs[ridx].addr, saved_ret_prologs[ridx].refcnt);
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
		perror("ptrace(PTRACE_POKETEXT)");
		return -1;
	}

	regs.rip = (long)hot_pc;

	if (ptrace(PTRACE_SETREGS, pid, 0, &regs) < 0) {
		perror("ptrace(PTRACE_SETREGS)");
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
		perror("ptrace(PTRACE_SINGLESTEP)");
		return -1;
	}

	int wait_status = 0;

	if (waitpid(pid, &wait_status, 0) < 0) {
		perror("waitpid");
		return -1;
	}

	if (!WIFSTOPPED(wait_status) || (WSTOPSIG(wait_status) != SIGTRAP)) {
		fprintf(stderr, "Error: single step process returned in unexpected fashion.\n");
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
		perror("ptrace(PTRACE_POKETEXT)");
		return -1;
	}

	return 1;
}

void
dump_wait_state(pid_t pid, int status, int force) {
	int dbg_level = 1;
	int needs_pid = 0;

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
			perror("ptrace(PTACE_GETSIGINFO)");
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

		if (ptrace(PTRACE_GETEVENTMSG, pid, NULL, &msg) < 0) {
			perror("ptrace(PTACE_GETEVENTMSG)");
			exit(EXIT_FAILURE);
		}

		PRINT_ERROR("Event generated by pid = %d\n", (int)msg);
	}

	// PTRACE_O_TRACESYSGOOD?
	if (WSTOPSIG(status) & 0x80) {
		PRINT_ERROR("%s", "Unchecked delivery of SIGTRAP|0x80. Aborting.\n");
		exit(EXIT_FAILURE);
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

int set_intercept_redirect(pid_t pid, void *addr) {
	return 0;
}

int
set_intercept(pid_t pid, void *addr) {
	long saved_prolog = 0, mod_prolog;
	unsigned char *tptr;

	if (saved_prolog_entries == saved_prolog_nentries) {
		saved_prolog_t *new_prologs;

		if (!(new_prologs = realloc(saved_prologs, (saved_prolog_nentries * 2 * sizeof(saved_prolog_t))))) {
			perror("realloc");
			return -1;
		}

		saved_prolog_nentries *= 2;
		saved_prologs = new_prologs;
	}

	errno = 0;
	saved_prolog = ptrace(PTRACE_PEEKTEXT, pid, addr, 0);
	if (errno != 0) {
		perror("ptrace(PTRACE_PEEKTEXT)");
		return -1;
	}

	mod_prolog = saved_prolog;
	tptr = (unsigned char *)&mod_prolog;
	*tptr = 0xcc;

	if (ptrace(PTRACE_POKETEXT, pid, addr, mod_prolog) < 0) {
		perror("ptrace(PTRACE_POKETEXT)");
		return -1;
	}

	saved_prologs[saved_prolog_entries].addr = addr;
	saved_prologs[saved_prolog_entries].saved_prolog = saved_prolog;
	saved_prolog_entries++;
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
			perror("realloc");
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
		perror("ptrace(PTRACE_PEEKTEXT)");
		return -1;
	}

	mod_prolog = saved_ret_prolog;
	tptr = (unsigned char *)&mod_prolog;
	*tptr = 0xcc;

	if (ptrace(PTRACE_POKETEXT, pid, addr, mod_prolog) < 0) {
		perror("ptrace(PTRACE_POKETEXT)");
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
		perror("malloc");
		return -1;
	}

	memset(saved_prologs, 0, saved_prolog_nentries * sizeof(*saved_prologs));

	if (!(saved_ret_prologs = malloc(saved_ret_prolog_nentries * sizeof(*saved_prologs)))) {
		perror("malloc");
		return -1;
	}

	memset(saved_ret_prologs, 0, saved_ret_prolog_nentries * sizeof(*saved_prologs));
	return 0;
}

int
child_trace_program(const char *progname, char * const *args) {

	if (prctl(PR_SET_PTRACER, getppid()) < 0) {
		perror("prctl(PR_SET_PTRACER)");
//		exit(EXIT_FAILURE);
	}

	if (ptrace(PTRACE_TRACEME, NULL, 0, 0) < 0) {
		perror("ptrace(PTRACE_TRACEME)");
		exit(EXIT_FAILURE);
	}

	printf("In child.\n");
	raise(SIGSTOP);
	printf("After raising.\n");
//	setenv(GOTRACE_SOCKET_ENV, "/home/shw/gotrace/libgomod.so.0.1.1", 1);
//	fprintf(stderr, "socket path: [%s]\n", gotrace_socket_path);
	setenv(GOTRACE_SOCKET_ENV, gotrace_socket_path, 1);
	execv(progname, args);
	perror("execv");
	exit(EXIT_FAILURE);
}

int
set_all_intercepts(pid_t pid) {
	size_t i;

	for (i = 0; i < sizeof(symbol_store)/sizeof(symbol_store[0]); i++) {
		if (symbol_store[i].l) {

		#define MAXJ	2000	
//		printf("HEH: MAXJ = %s\n", symbol_store[i].map[MAXJ].name);
			for (size_t j = 0; j < symbol_store[i].msize; j++) {
//				printf("CANDIDATE: %s - %lx\n", symbol_store[i].map[j].name, symbol_store[i].map[j].addr);

				if (is_intercept_excluded(symbol_store[i].map[j].name)) {
					fprintf(stderr, "Skipping over excluded intercept: %s\n", symbol_store[i].map[j].name);
					continue;
				}

				if (j > MAXJ)
					continue;

				if (set_intercept(pid, (void *)symbol_store[i].map[j].addr) < 0) {
					fprintf(stderr, "Error: could not set intercept on symbol: %s\n", symbol_store[i].map[j].name);
					return -1;
				}
			}

		}

	}

	fprintf(stderr, "Set intercepts.\n");
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
			perror("fork");
			exit(EXIT_FAILURE);
			break;
		default:
			break;
	}

	printf("In parent: sleeping\n");

/*	if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
		perror("ptrace(PTRACE_ATTACH)");
		exit(EXIT_FAILURE);
	} */

	if (waitpid(pid, &wait_status, 0) < 0) {
		perror("waitpid");
		exit(EXIT_FAILURE);
	}

	if (ptrace(PTRACE_SETOPTIONS, pid, NULL, trace_flags) < 0) {
		perror("ptrace(PTRACE_SETOPTIONS)111");
		exit(EXIT_FAILURE);
	}
	dump_wait_state(pid, wait_status, 0);

	printf("Parent attached\n");

	if (ptrace(PTRACE_CONT, pid, NULL, 0) < 0) {
		perror("ptrace(PTRACE_CONT) [3]");
		exit(EXIT_FAILURE);
	}

	if (waitpid(pid, &wait_status, 0) < 0) {
		perror("waitpid");
		exit(EXIT_FAILURE);
	}
	dump_wait_state(pid, wait_status, 0);
	handle_trace_trap(pid, wait_status, 1);

	printf("Parent detected possible exec\n");

	if (set_all_intercepts(pid) < 0) {
		fprintf(stderr, "Error encountered while setting intercepts.\n");
		exit(EXIT_FAILURE);
	}

	dump_intercepts();

	start_listener();

	printf("Running loop...\n");

	if (ptrace(PTRACE_CONT, pid, NULL, 0) < 0) {
		perror("ptrace(PTRACE_CONT) [1]");
		exit(EXIT_FAILURE);
	}

	while (1) {
		pid_t cpid;

		if ((cpid = waitpid(-1, &wait_status, 0)) < 0) {
			perror("waitpid");
			exit(EXIT_FAILURE);
		}

		if (WIFSTOPPED(wait_status) && (WSTOPSIG(wait_status) == SIGUSR2)) {
			PRINT_ERROR("Traced PID/TID (%d) is our own code; detaching.\n", cpid);

			if (ptrace(PTRACE_SETOPTIONS, cpid, NULL, 0) < 0) {
				perror("ptrace(~PTRACE_SETOPTIONS)");
				exit(EXIT_FAILURE);
			}

			if (ptrace(PTRACE_CONT, cpid, NULL, 0) < 0) {
				perror("ptrace(PTRACE_CONT) [5]");
				exit(EXIT_FAILURE);
			}

			continue;
		}


		dump_wait_state(cpid, wait_status, 0);

		if (handle_trace_trap(cpid, wait_status, 0) < 1) {
			fprintf(stderr, "Error: something bad happened while handling trace trap\n");
		}

//		if (WIFEXITED(wait_status) || (WIFSTOPPED(wait_status) && (WSTOPSIG(wait_status) != SIGTRAP))) {
		if (WIFEXITED(wait_status)) {
			fprintf(stderr, "Aborting loop.\n");
			break;
		}

		if (ptrace(PTRACE_CONT, cpid, NULL, 0) < 0) {
			perror("ptrace(PTRACE_CONT) [2]");
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

	trace_program(progname, &argv[2]);
	exit(-1);
}
