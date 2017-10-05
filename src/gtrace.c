#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <errno.h>

#include "config.h"
#include "elfh.h"
#include "args.h"


#define ADDR_SOMEFUNC	((void *)0x401000)
#define ADDR_SOMEFUNC2	((void *)0x401190)
#define ADDR_SOMEFUNC3	((void *)0x401330)
#define ADDR_SOMEFUNC4	((void *)0x4014d0)
#define ADDR_SOMEFUNC5	((void *)0x4017e0)


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

size_t saved_prolog_nentries = 1024;
size_t saved_prolog_entries = 0;
saved_prolog_t *saved_prologs = NULL;

size_t saved_ret_prolog_nentries = 64;
size_t saved_ret_prolog_entries = 0;
saved_prolog_t *saved_ret_prologs = NULL;

struct lt_config_audit cfg;

char *excluded_intercepts[] = {
	// hmm:
	"runtime.atomicstorep",
	"runtime.(*waitq).dequeue",
	"runtime.mallocgc",
	"runtime.newobject",
	"runtime.heapBitsSetType",
	"runtime.heapBitsForSpan",

	"runtime.chanrecv",
	"runtime.chanrecv1",

	"runtime.bgsweep",
	"runtime.chansend",
	"runtime.chansend1",
	"runtime.forcegchelper",
	"runtime.futexwakeup",
	"runtime.gopark",
	"runtime.goready",
	"runtime.lock",
//	"runtime.makechan",
	"runtime.mcommoninit",
	"runtime.netpollinited",
	"runtime.notesleep",
	"runtime.notewakeup",
	"runtime.ready",
	"runtime.runfinq",
	"runtime.send",
	"runtime.stopTheWorld",
	"runtime.unlock"
};

extern char *read_string_remote(pid_t pid, char *addr, size_t slen);

int set_intercept(pid_t pid, void *addr);
int set_ret_intercept(pid_t pid, const char *fname, void *addr);


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

lt_tsd_t tsd;

int
handle_trace_trap(pid_t pid, int status) {
	struct lt_symbol *lts;
	void *hot_pc, *hot_sp;
	struct user_regs_struct regs;
	const char *symname;
	long retrace, ret_addr;
	size_t i, ra;
	int is_return = 0;

	if (!WIFSTOPPED(status) || (WSTOPSIG(status) != SIGTRAP))
		return 0;

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
	}

//	printf("is return = %d\n", is_return);

	if (!is_return) {
		errno = 0;
		ret_addr = ptrace(PTRACE_PEEKTEXT, pid, regs.rsp, 0);
		if (errno != 0) {
			perror("ptrace(PTRACE_PEEKTEXT)");
			return -1;
		}

//		printf("RET ADDR would have been %lx\n", ret_addr);
		symname = lookup_addr(hot_pc);
		if (set_ret_intercept(pid, symname, (void *)ret_addr) < 0) {
			fprintf(stderr, "Error: could not set intercept on return address\n");
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

	if (is_return) {
//		printf("RETURN BYPASS\n");

	/*int ret = */sym_exit(symname, lts, "from", "to", pid, &regs, &regs, &tsd);
		return 1;
	}

//	memset(&tsd, 0, sizeof(tsd));
//	printf("lts = %p\n", lts);

	/*int ret = */sym_entry(symname, lts, "from", "to", pid, &regs, &tsd);

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

	retrace = saved_prologs[i].saved_prolog;
	*((unsigned char *)&retrace) = 0xcc;

	if (ptrace(PTRACE_POKETEXT, pid, saved_prologs[i].addr, retrace) < 0) {
		perror("ptrace(PTRACE_POKETEXT)");
		return -1;
	}

	return 1;
}

void
dump_wait_state(int status) {
	int dbg_level = 1;

	DEBUG_PRINT(dbg_level, "Wait status: ");

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
set_ret_intercept(pid_t pid, const char *fname, void *addr) {
	long saved_ret_prolog = 0, mod_prolog;
	unsigned char *tptr;

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
		exit(EXIT_FAILURE);
	}

	if (ptrace(PTRACE_TRACEME, NULL, 0, 0) < 0) {
		perror("ptrace(PTRACE_TRACEME)");
		exit(EXIT_FAILURE);
	}

	printf("In child.\n");
	raise(SIGSTOP);
	printf("After raising.\n");
	execv(progname, args);
	perror("execv");
	exit(EXIT_FAILURE);
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
	dump_wait_state(wait_status);

	printf("Parrent attached\n");

	if (ptrace(PTRACE_CONT, pid, NULL, 0) < 0) {
		perror("ptrace(PTRACE_CONT)");
		exit(EXIT_FAILURE);
	}

	if (waitpid(pid, &wait_status, 0) < 0) {
		perror("waitpid");
		exit(EXIT_FAILURE);
	}
	dump_wait_state(wait_status);
	handle_trace_trap(pid, wait_status);

	printf("Parent detected possible exec\n");

	for (size_t i = 0; i < sizeof(symbol_store)/sizeof(symbol_store[0]); i++) {
		if (symbol_store[i].l) {

//		#define MAXJ 	453
		#define MAXJ 	189
		printf("HEH: MAXJ = %s\n", symbol_store[i].map[MAXJ].name);
			for (size_t j = 0; j < symbol_store[i].msize; j++) {
//				printf("CANDIDATE: %s - %lx\n", symbol_store[i].map[j].name, symbol_store[i].map[j].addr);

				if (is_intercept_excluded(symbol_store[i].map[j].name)) {
					fprintf(stderr, "Skipping over excluded intercept: %s\n", symbol_store[i].map[j].name);
					continue;
				}

				if (j > MAXJ) {

				switch(symbol_store[i].map[j].addr) {
				case (long)ADDR_SOMEFUNC:
				case (long)ADDR_SOMEFUNC2:
				case (long)ADDR_SOMEFUNC3:
				case (long)ADDR_SOMEFUNC4:
				case (long)ADDR_SOMEFUNC5:
					break;
				default:
					continue;
				}
	}

				if (set_intercept(pid, (void *)symbol_store[i].map[j].addr) < 0) {
					fprintf(stderr, "Error: could not set intercept on symbol: %s\n", symbol_store[i].map[j].name);
					exit(EXIT_FAILURE);
				}
			}

		}

	}

	printf("Set intercept.\n");
	dump_intercepts();

	printf("Running loop...\n");

	while (1) {

		if (ptrace(PTRACE_CONT, pid, NULL, 0) < 0) {
			perror("ptrace(PTRACE_CONT)");
			exit(EXIT_FAILURE);
		}

		if (waitpid(pid, &wait_status, 0) < 0) {
			perror("waitpid");
			exit(EXIT_FAILURE);
		}
		dump_wait_state(wait_status);
		handle_trace_trap(pid, wait_status);

		if (WIFEXITED(wait_status) || (WIFSTOPPED(wait_status) && (WSTOPSIG(wait_status) != SIGTRAP))) {
			fprintf(stderr, "Aborting loop.\n");
			return 0;
		}

	}

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
        cfg_sh.indent_size = 2;
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

	trace_program(progname, &argv[2]);
	exit(-1);
}
