#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stddef.h>
#include <fcntl.h>
#include <linux/wait.h>
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
#include <sys/sem.h>
#include <regex.h>

// TODO: waitpid(..., WUNTRACED)

#include "config.h"
#include "args.h"
#include "gomod_print/gomod_print.h"

#include <zydis/include/Zydis/Zydis.h>


#define DEBUG_LEVEL	0

#define DEBUG_PRINT(lvl,...)	do {	\
					if (lvl <= DEBUG_LEVEL)	\
						fprintf(stderr, __VA_ARGS__);	\
				} while (0)


unsigned long MAGIC_FUNCTION = 0;


typedef enum {
	gint = 0,
	gstring
} golang_data_type;

typedef struct golang_interface {
	void *addr;
	void *bind_addr;
	void *typ;
	void *elem;
	char *name;
} golang_interface_t;

golang_interface_t *all_ginterfaces = NULL;
size_t ngolang_ifaces = 0;
size_t n_unresolved_interfaces = 0;


typedef struct remote_intercept {
	void *addr;
	char *fname;
	int is_entry;
	void *jmpbuf;
	unsigned short jblen;
	void *retaddr;
	unsigned char saved_prolog[16];
	unsigned short saved_prolog_len;
} remote_intercept_t;

size_t remote_intercept_nentries = 512;
size_t remote_intercept_entries = 0;
remote_intercept_t *remote_intercepts = NULL;

long trace_flags = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACECLONE | PTRACE_O_TRACEVFORK |
	PTRACE_O_TRACEFORK | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT; /* PTRACE_O_TRACEVFORKDONE */

struct lt_config_audit cfg;

char gotrace_socket_path[128];

char *excluded_intercepts[] = {
	"main.main",
	"runtime.init.2",
	"runtime.main",
	"runtime.init",
	"runtime.morestack",
	"fmt.Fprintln",
	"fmt.Println",
//	"fmt.(*pp).printArg",
	"fmt.\\(\\*pp\\).printArg",
//	"fmt.(*pp).printValue",
	"fmt.\\(\\*pp\\).printValue",
	"fmt.\\(\\*pp\\).*",

	"_rt0_amd64_linux",
	"main",
	"runtime.rt0_go",
	"runtime.checkASM",
	"runtime.morestack_noctxt",
};

pid_t master_pid = -1, socket_pid = -1;


typedef struct process_state {
	pid_t pid;
	int flags;
} process_state_t;

process_state_t observed_pids[1024];

int *all_shmids = NULL;


char *read_bytes_remote(pid_t pid, char *addr, size_t slen);
int write_bytes_remote(pid_t pid, void *addr, void *buf, size_t blen);
void print_instruction(pid_t pid, void *addr, size_t len);

void *call_remote_func(pid_t pid, unsigned char reqtype, void *data, size_t dsize, size_t *psize);
void * get_first_instruction_remote(pid_t pid, void *addr, size_t *psize);
int create_jmp(pid_t pid, void *ataddr, void *raddr, void *ibuf, void *outbuf, size_t *outlen);

void start_listener(void);
void *gotrace_socket_loop(void *param);

int set_all_intercepts(pid_t pid);
int is_intercept_excluded(const char *fname);
int set_pid_flags(pid_t pid, int flags, int do_mask);

void *save_remote_intercept(pid_t pid, const char *fname, void *addr, void *raddr, int is_entry);
int initialize_remote_library(pid_t pid, const char *libpath, int cont_on_err);

int is_thread_in_syscall(pid_t pid);
void monitor_pid(pid_t pid, int do_remove);
int is_pid_monitored(pid_t pid, int *pflags);

void cleanup(void);
void handle_int(int signo);


void *
xmalloc(size_t size)
{
	void *result;

	if (!(result = malloc(size))) {
		PRINT_ERROR("malloc(%zu): %s\n", size, strerror(errno));
//		exit(EXIT_FAILURE);
	}

	return result;
}

void
monitor_pid(pid_t pid, int do_remove) {
	size_t i;
	ssize_t first_empty = -1;

	for (i = 0; i < sizeof(observed_pids)/sizeof(observed_pids[0]); i++) {

		if (!observed_pids[i].pid)
			first_empty = i;
		else if (observed_pids[i].pid == pid) {

			if (do_remove)
				observed_pids[i].pid = 0;

			return;
		}

	}

	if (first_empty >= 0)
		observed_pids[first_empty].pid = pid;

	return;
}

int
is_pid_monitored(pid_t pid, int *pflags) {
	size_t i;

	for (i = 0; i < sizeof(observed_pids)/sizeof(observed_pids[0]); i++) {

		if (observed_pids[i].pid == pid) {

			if (pflags)
				*pflags = observed_pids[i].flags;

			return 1;
		}

	}

	if (pflags)
		*pflags = 0;

	return 0;
}

// Dead code for now.
int
set_pid_flags(pid_t pid, int flags, int do_mask) {
	size_t i;

	for (i = 0; i < sizeof(observed_pids)/sizeof(observed_pids[0]); i++) {

		if (observed_pids[i].pid == pid) {

			if (do_mask)
				observed_pids[i].flags |= flags;
			else
				observed_pids[i].flags = flags;

			return 1;
		}

	}

	return 0;
}

void
cleanup(void) {
	size_t ndestroyed = 0;

	if (gotrace_socket_path[0])
		unlink(gotrace_socket_path);

	fprintf(stderr, "Destroying shared memory segments...\n");

	while (all_shmids && *all_shmids) {

		if (shmctl(*all_shmids, IPC_RMID, NULL) == -1)
			PERROR("shmctl");
		else
			ndestroyed++;

		all_shmids++;
	}

	fprintf(stderr, "%zu destroyed.\n", ndestroyed);

	if (master_pid > 0)
		kill(master_pid, SIGKILL);

	return;
}

int
detach_pids(void) {
	fprintf(stderr, "Master PID (%d):\n", master_pid);
	dump_instruction_state(master_pid);
	fprintf(stderr, "\nSocket PID (%d):\n", socket_pid);
	dump_instruction_state(socket_pid);
	PTRACE(PTRACE_SETOPTIONS, master_pid, NULL, 0, 0, PT_DONTFAIL);
	PTRACE(PTRACE_SETOPTIONS, socket_pid, NULL, 0, 0, PT_DONTFAIL);
	PTRACE(PTRACE_CONT, master_pid, NULL, NULL, 0, PT_DONTFAIL);
	PTRACE(PTRACE_CONT, socket_pid, NULL, NULL, 0, PT_DONTFAIL);
	PTRACE(PTRACE_DETACH, master_pid, NULL, NULL, 0, PT_DONTFAIL);
	PTRACE(PTRACE_DETACH, socket_pid, NULL, NULL, 0, PT_DONTFAIL);
	return 0;
}

void
handle_int(int signo) {
	static size_t nint = 0;

	if (signo == SIGINT) {
		nint++;

		if (nint < 2) {
			fprintf(stderr, "Caught SIGINT... send once more to terminate program.\n");
			fprintf(stderr, "Detaching from child.\n");
			detach_pids();

			fprintf(stderr, "Waiting around...\n");
			while (1) {
				sleep(1);
				fprintf(stderr, ".");
				fflush(stderr);
			}

			return;
		}

		fprintf(stderr, "Caught SIGINT... shutting down gracefully.\n");

		if (master_pid > 0)
			kill(master_pid, SIGINT);

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
		}
*/





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

		if (strstr(excluded_intercepts[i], "*") || strstr(excluded_intercepts[i], "?")) {
			regex_t regex;
			int iret;

			if (regcomp(&regex, excluded_intercepts[i], REG_EXTENDED)) {
				PRINT_ERROR("Error compiling exclusion regex: %s\n", excluded_intercepts[i]);
				exit(EXIT_FAILURE);
				continue;
			}

			if (!(iret = regexec(&regex, fname, 0, NULL, 0))) {
//				fprintf(stderr, "XXX regex exclusion match: %s | %s\n", excluded_intercepts[i], fname);
				return 1;
			}

			regfree(&regex);
		}

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

int verify_bp(pid_t pid, void *addr) {
	unsigned long i;
	unsigned char *fi = (unsigned char *)&i;

	PTRACE_PEEK(i, PTRACE_PEEKTEXT, pid, addr, 0, PT_RETERROR);

	return (*fi == 0xcc);
}

int
check_remote_intercept(pid_t pid, void *pc, struct user_regs_struct *regs) {
	struct lt_symbol *lts;
	unsigned long new_pc;
	char *symname;
	size_t i;

	for (i = 0; i < remote_intercept_entries; i++) {
		int match = ((remote_intercepts[i].is_entry && (remote_intercepts[i].addr == pc)) ||
			(!remote_intercepts[i].is_entry && (pc >= remote_intercepts[i].jmpbuf) &&
			(pc <= remote_intercepts[i].jmpbuf+remote_intercepts[i].jblen)));

		if (match) {
			struct user_regs_struct nregs;
			int ret;

			symname = remote_intercepts[i].fname;
////			fprintf(stderr, "XXX: OOOOOOOOOOOOH YEAH: %s / %d:   %p\n", symname, remote_intercepts[i].is_entry, (void *)regs->rip);

			if (remote_intercepts[i].is_entry) {
				unsigned long retaddr;
				void *res;

				PTRACE_PEEK(retaddr, PTRACE_PEEKTEXT, pid, regs->rsp, -1, PT_RETERROR);

				if (!(res = save_remote_intercept(pid, symname, remote_intercepts[i].addr, (void *)retaddr, 0))) {
					PRINT_ERROR("Error setting function return intercept for: %s; resetting trap.\n", remote_intercepts[i].fname);
					exit(EXIT_FAILURE);
				} else {
					new_pc = (unsigned long)res;
////fprintf(stderr, "ENTRY(%s <- %p) -> %p-~%p\n", symname, (void *)retaddr, res, res+0x2e);
				}

			} else {
//				unsigned long retaddr;
//				PTRACE_PEEK(retaddr, PTRACE_PEEKTEXT, pid, regs->rsp, -1, PT_RETERROR);
////fprintf(stderr, "EXIT(%s) : %p    returning to %p\n", symname, (void *)regs->rip, (void *)retaddr);
				new_pc = regs->rip;
				// XXX: hmm... we need to adjust jmpbuf asm so trap is before stack push.
				regs->rsp += 8;
			}

			lts = lt_symbol_bind(cfg.sh, pc, symname);
			lt_tsd_t *tsdx = thread_get_tsd(pid, 1);

			if (remote_intercepts[i].is_entry)
				ret = sym_entry(symname, lts, "from", "", pid, regs, tsdx);
			else
				ret = sym_exit(symname, lts, "from", "", pid, regs, regs, tsdx);

			if (ret < 0) {
			}

			PTRACE(PTRACE_GETREGS, pid, 0, &nregs, EXIT_FAILURE, PT_FATAL);
			nregs.rip = new_pc;
			PTRACE(PTRACE_SETREGS, pid, 0, &nregs, EXIT_FAILURE, PT_FATAL);
			return 0;
		}
	}

	return -1;
}

const char *
get_ptrace_event_name(int status) {
	if ((status >> 8) == (SIGTRAP | (PTRACE_EVENT_CLONE << 8)))
		return "clone";
	else if ((status >> 8) == (SIGTRAP | (PTRACE_EVENT_EXEC << 8)))
		return "exec";
	else if ((status >> 8) == (SIGTRAP | (PTRACE_EVENT_EXIT << 8)))
		return "exit";
	else if ((status >> 8) == (SIGTRAP | (PTRACE_EVENT_FORK << 8)))
		return "fork";
	else if ((status >> 8) == (SIGTRAP | (PTRACE_EVENT_VFORK << 8)))
		return "vfork";
	else if ((status >> 8) == (SIGTRAP | (PTRACE_EVENT_VFORK_DONE << 8)))
		return "vfork_done";

	return "none";
}

int
handle_trace_trap(pid_t pid, int status, int dont_reset) {
	void *hot_pc;
	struct user_regs_struct regs;

/*	if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGUSR1) {
		fprintf(stderr, "SIGUSR1 OK\n");
		return 1;
	}*/

//	if ((status >> 8) == (SIGTRAP | (PTRACE_EVENT_CLONE << 8))) { }

	if (!WIFSTOPPED(status) || (WSTOPSIG(status) != SIGTRAP)) {

		if (WIFSTOPPED(status) && (WSTOPSIG(status) == SIGSTOP)) {
			if ((socket_pid > 0) && (pid == socket_pid)) {
				PRINT_ERROR("Skipping over execution notification for module socket: %d\n", pid);
			} else if (is_pid_new(pid)) {
				PTRACE(PTRACE_SETOPTIONS, pid, NULL, trace_flags, EXIT_FAILURE, PT_FATAL);
				is_thread_in_syscall(pid);

				monitor_pid(pid, 0);

/*				if (set_all_intercepts(pid) < 0) {
					fprintf(stderr, "Error encountered while setting intercepts in new process.\n");
					exit(EXIT_FAILURE);
				}
				fprintf(stderr, "XXX: skipping set intercepts on pid %d\n", pid);*/

				// We will return into a loop that will perform this action for us.
//				PTRACE(PTRACE_CONT, pid, NULL, 0, EXIT_FAILURE, PT_FATAL);

				return 1;
			}
		}

		dump_wait_state(pid, status, 1);
		return 0;
	}

	DEBUG_PRINT(2, "Handling trace trap!\n");

	PTRACE(PTRACE_GETREGS, pid, 0, &regs, -1, PT_RETERROR);

	// We're pointing to the instruction past our breakpoint (0xcc)
	hot_pc = (void *)(regs.rip - 1);

	// (Removed one time intercept check)

	// Check for remote intercept first.
	if (!check_remote_intercept(pid, hot_pc, &regs))
		return 1;

	return -1;
}

int
analyze_clone_call(pid_t pid, pid_t cpid) {
	pid_t newpid;
	int cflags, ws;
	struct user_regs_struct regs;

	PTRACE(PTRACE_SYSCALL, pid, NULL, NULL, -1, PT_RETERROR);

	if (waitpid(pid, &ws, __WALL) < 0) {
		perror_pid("waitpid", pid);
		return -1;
	}

	PTRACE(PTRACE_GETREGS, pid, 0, &regs, -1, PT_RETERROR);

	newpid = (pid_t)regs.rax;
	cflags = (int)regs.rdi;
	fprintf(stderr, "XXX: clone() returned new pid: %d, flags = %x\n", newpid, cflags);

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
		if (ptrace(PTRACE_GETSIGINFO, pid, NULL, &si) < 0) {
			perror_pid("ptrace(PTRACE_GETSIGINFO)", pid);
		} else {
			DEBUG_PRINT(dbg_level, "si_code=%d, si_pid=%d, si_uid=%d, si_status=%d, si_addr=%p, "
				"si_call_addr=%p, si_syscall=%d\n",
				si.si_code, si.si_pid, si.si_uid, si.si_status, si.si_addr,
				si.si_call_addr, si.si_syscall);
		}
	}

	// PTRACE_O_TRACESYSGOOD?
	if (WSTOPSIG(status) & 0x80) {
		PRINT_ERROR("%s", "Warning: unchecked delivery of SIGTRAP|0x80\n");
//		exit(EXIT_FAILURE);
	}

	return;
}

int
check_wait_event(pid_t pid, int status) {
	unsigned long msg;
	int needs_pid = 0, did_clone = 0, cret;
	pid_t npid;

	if ((status >> 8) == (SIGTRAP | (PTRACE_EVENT_CLONE << 8))) {
		PRINT_ERROR("PID %d detected clone() event", pid);
		needs_pid = 1;
		did_clone = 1;
	}
	else if ((status >> 8) == (SIGTRAP | (PTRACE_EVENT_EXEC << 8)))
		PRINT_ERROR("PID %d detected exec() event\n", pid);
	else if ((status >> 8) == (SIGTRAP | (PTRACE_EVENT_EXIT << 8))) {
		lt_tsd_t *tsdx = thread_get_tsd(pid, 1);

		monitor_pid(pid, 1);
		PRINT_ERROR("PID %d detected exit() event\n", pid);
		sym_exit("___________exit", NULL, "from", "to", pid, NULL, NULL, tsdx);
	}
	else if ((status >> 8) == (SIGTRAP | (PTRACE_EVENT_FORK << 8))) {
		PRINT_ERROR("PID %d detected fork() event", pid);
		needs_pid = 1;
	}
	else if ((status >> 8) == (SIGTRAP | (PTRACE_EVENT_VFORK << 8))) {
		PRINT_ERROR("PID %d detected vfork() event", pid);
		needs_pid = 1;
	} else if ((status >> 8) == (SIGTRAP | (PTRACE_EVENT_VFORK_DONE << 8)))
		PRINT_ERROR("PID %d detected vfork() event", pid);

	if (!needs_pid)
		return 0;

	PTRACE(PTRACE_GETEVENTMSG, pid, NULL, &msg, -1, PT_RETERROR);

	npid = (pid_t)msg;

	PRINT_ERROR("; event generated by pid = %d\n", npid);

	if (!did_clone)
		return 0;

	if ((cret = analyze_clone_call(pid, npid)) < 0)
		PRINT_ERROR("%s", "Unexpected error inspecting result of call to clone()\n");
	else if (cret > 0) {
		fprintf(stderr, "XXX: exempting new process from intercepts: %d\n", npid);
	} else {
		int w;
		if (waitpid(npid, &w, __WALL) < 0) {
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

		PTRACE(PTRACE_CONT, npid, NULL, 0, EXIT_FAILURE, PT_FATAL);
	}

	return 0;
}

int
trace_forever(pid_t pid, int verbose) {
	struct user_regs_struct regs;
	const char *fname = NULL;
	char lastsym[128], tmpbuf[128], *symp;
	size_t fend;
	int wait_status = 0;

	memset(lastsym, 0, sizeof(lastsym));

	while (1) {
		PTRACE(PTRACE_GETREGS, pid, NULL, &regs, -1, PT_RETERROR);
		resolve_sym((void *)regs.rip, 0, tmpbuf, sizeof(tmpbuf), &fname);

		if ((symp = strchr(tmpbuf, '+')))
			fend = symp - tmpbuf;
		else
			fend = strlen(tmpbuf);

		if (strncmp(lastsym, tmpbuf, fend)) {
			fprintf(stderr, " - %s (%p)\n", tmpbuf, (void *)regs.rip);
			fprintf(stderr, "      rdi = %llx, rsi = %llx, rdx = %llx, rcx = %llx             rax = %llx <- %s\n", regs.rdi, regs.rsi, regs.rdx, regs.rcx, regs.rax, lastsym);
		} else if (verbose) {
			unsigned long this_i;
			unsigned char *ic = (unsigned char *)&this_i;

			PTRACE_PEEK(this_i, PTRACE_PEEKTEXT, pid, regs.rip, 0, PT_DONTFAIL);
			fprintf(stderr, ". %p  | %x\n", (void *)regs.rip, *ic);
		}

		memset(lastsym, 0, sizeof(lastsym));
		strncpy(lastsym, tmpbuf, fend);

		PTRACE(PTRACE_SINGLESTEP, pid, 0, 0, -1, PT_RETERROR);

		if (waitpid(pid, &wait_status, __WALL) < 0) {
			perror_pid("waitpid", pid);
			return -1;
		}

		if (WIFSIGNALED(wait_status))
			fprintf(stderr, "SIGNALED\n");
		else if (WIFEXITED(wait_status))
			fprintf(stderr, "EXITED\n");
		else if (WIFSTOPPED(wait_status) && WSTOPSIG(wait_status) != SIGTRAP) {
			fprintf(stderr, "STOPPED: %u\n", WSTOPSIG(wait_status));
			dump_instruction_state(pid);
			exit(EXIT_SUCCESS);
		}

	}

	return 0;
}

void
dump_intercepts(void) {
	size_t i;

	if (DEBUG_LEVEL < 1)
		return;

	fprintf(stderr, "Intercepts set: %zu of max %zu\n", remote_intercept_entries, remote_intercept_nentries);

	if (DEBUG_LEVEL < 2)
		return;

	for (i = 0; i < remote_intercept_entries; i++)
		fprintf(stderr, "%.3zu: %p (%s)\n", i+1, remote_intercepts[i].addr,
			remote_intercepts[i].fname);

	return;
}

/*
 * Allocate space in the remote process and copy isize's worth of bytes from icode into it.
 * We can use a very simple memory management scheme since we have a relative idea of both
 * the size of the memory that needs to be allocated, the number of total entries needed,
 * and the fact that the memory will never be freed or reclaimed.
 *
 * So let's just uhh say... 4MB.
 */
void *
get_remote_jmpbuf_space(pid_t pid, void *icode, size_t isize) {
	static void *alloc_space = NULL;
	static size_t alloc_used = 0, alloc_total = (4 * 1024 * 1024);
	void *result;

	if (!alloc_space) {
		if ((alloc_space = (void *)call_remote_mmap(pid, NULL, alloc_total, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANONYMOUS|MAP_PRIVATE, 0, 0)) == MAP_FAILED) {
			perror_pid("mmap", pid);
			alloc_space = NULL;
			return NULL;
		}
	}

	if (isize + alloc_used > alloc_total) {
		PRINT_ERROR("Error: remote process is out of jump space. Try increasing cap above %zu bytes?\n", alloc_total);
		return NULL;
	}

	result = alloc_space + alloc_used;

	if (write_bytes_remote(pid, result, icode, isize) < 0) {
		PRINT_ERROR("Error writing jump buffer code to remote process at address %p\n", result);
		return NULL;
	}

	alloc_used += isize;
	return result;
}

void *
save_remote_intercept(pid_t pid, const char *fname, void *addr, void *raddr, int is_entry) {
	unsigned char jbuf[128];
	unsigned long old_prolog;
	unsigned char *tptr;
	unsigned char *saved_ibuf = NULL;
	size_t i, jblen;

	if (remote_intercept_entries == remote_intercept_nentries) {
		remote_intercept_t *new_intercepts;

		if (!(new_intercepts = realloc(remote_intercepts, (remote_intercept_nentries * 2 * sizeof(*remote_intercepts))))) {
			perror_pid("realloc", pid);
			return NULL;
		}

		remote_intercept_nentries *= 2;
		remote_intercepts = new_intercepts;
	}

	for (i = 0; i < remote_intercept_entries; i++) {

		if ((remote_intercepts[i].addr == addr) && (remote_intercepts[i].retaddr == raddr)) {

			if (is_entry)
				return ((void *)-1);
			else
				return remote_intercepts[i].jmpbuf;

		} else if ((remote_intercepts[i].addr == addr) && !is_entry && remote_intercepts[i].is_entry) {
			saved_ibuf = remote_intercepts[i].saved_prolog;
		}

	}

	PTRACE_PEEK(old_prolog, PTRACE_PEEKTEXT, pid, addr, NULL, PT_RETERROR);
	tptr = (unsigned char *)&old_prolog;

	if ((*tptr == 0xe8) || (*tptr == 0xff) || (*tptr == 0x9a)) {
		PRINT_ERROR("Warning: cannot intercept function %s at %p because it leads with a call instruction\n", fname, addr);
		return is_entry ? ((void *)-1) : NULL;
	} else if ((*tptr == 0xe9) || (*tptr == 0xeb) || (*tptr == 0xea)) {
		PRINT_ERROR("Warning: cannot intercept function %s at %p because it leads with a jump instruction\n", fname, addr);
		return is_entry ? ((void *)-1) : NULL;
	} else if (*tptr == 0xc3) {
		PRINT_ERROR("Warning: cannot intercept function %s at %p because it leads with a return\n", fname, addr);
		return is_entry ? ((void *)-1) : NULL;
	} else if ((tptr[0] == 0x48) && (tptr[1] == 0x83) && (tptr[2] == 0xec)) {
		PRINT_ERROR("Warning: cannot intercept function %s at %p because it leads with a stack change operation\n", fname, addr);
		return is_entry ? ((void *)-1) : NULL;
	}

	if (is_entry) {
		void *first_i;
		size_t to_copy;

//		fprintf(stderr, "XXX: skipping jump buf redirect for function entry point: %s\n", fname);

		if (!(first_i = get_first_instruction_remote(pid, addr, &to_copy))) {
			PRINT_ERROR("%s", "Error: could not set up jump buffer for remote function intercept\n");
			return NULL;
		} else if (to_copy > sizeof(remote_intercepts[remote_intercept_entries].saved_prolog)) {
			PRINT_ERROR("Error: read instruction was bigger than max size at %zu bytes\n", to_copy);
			free(first_i);
			return NULL;
		}

		// It's easier if we copy the entire 16 bytes, though, since we cannot write back any
		// less than that with ptrace() with minimal overhead.
//		memcpy(remote_intercepts[remote_intercept_entries].saved_prolog, first_i, to_copy);
		memcpy(remote_intercepts[remote_intercept_entries].saved_prolog, first_i,
			sizeof(remote_intercepts[remote_intercept_entries].saved_prolog));
		free(first_i);
		remote_intercepts[remote_intercept_entries].saved_prolog_len = to_copy;
		remote_intercepts[remote_intercept_entries].jmpbuf = NULL;
		remote_intercepts[remote_intercept_entries].jblen = 0;
	} else {

		if (!saved_ibuf) {
			PRINT_ERROR("Error creating return jump buffer for function %s: could not find entry point\n", fname);
			return NULL;
		}

		if (create_jmp(pid, addr, raddr, saved_ibuf, jbuf, &jblen) < 0) {
			PRINT_ERROR("%s", "Unknown error creating jump buffer\n");
			return NULL;
		}

		remote_intercepts[remote_intercept_entries].jmpbuf = get_remote_jmpbuf_space(pid, jbuf, jblen);
		remote_intercepts[remote_intercept_entries].jblen = jblen;

		if (!remote_intercepts[remote_intercept_entries].jmpbuf) {
			PRINT_ERROR("Error: could not create remote jump buffer of size %zu bytes\n", jblen);
			return NULL;
		}

/*		fprintf(stderr, "jblen = %zu\n", jblen);
		fprintf(stderr, "jbuf = %p\n", jbuf);
		fprintf(stderr, ".global main\n");
		fprintf(stderr, "main:\n");
		for (size_t xxx = 0; xxx < jblen; xxx++) {
			fprintf(stderr, ".byte 0x%.2x\n", jbuf[xxx]);
		}*/
	}

	// Overwrite after copy
	*tptr = 0xcc;
	PTRACE(PTRACE_POKETEXT, pid, addr, old_prolog, NULL, PT_RETERROR);

	remote_intercepts[remote_intercept_entries].addr = addr;
	remote_intercepts[remote_intercept_entries].fname = strdup(fname);
	remote_intercepts[remote_intercept_entries].is_entry = is_entry;
	remote_intercepts[i].retaddr = is_entry ? NULL : raddr;

	remote_intercept_entries++;

	if (is_entry)
		return ((void *)-1);

	return remote_intercepts[remote_intercept_entries-1].jmpbuf;
}

size_t
instruction_bytes_needed(void *addr, size_t maxlen) {
	ZydisDecoder decoder;
	ZydisDecodedInstruction instruction;
	uint64_t rip = (uint64_t)addr;
	uint8_t *idata = (uint8_t *)addr;
	size_t total = 0, minsize = 1;

	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);

	while (total < minsize) {

		if (!ZYDIS_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, idata, maxlen, rip, &instruction))) {
			fprintf(stderr, "Error decoding instruction at %p\n", (void *)rip);
			return 0;
		}

		idata += instruction.length;
		maxlen -= instruction.length;
		rip += instruction.length;
		total += instruction.length;
        }

	return total;
}

void *
get_first_instruction_remote(pid_t pid, void *addr, size_t *psize) {
	void *remote_i;
	// This is the largest possible instruction;
	// it's also unlikely to overflow past the end of the text segment.
	size_t copy_size = 15, res;

	if (!(remote_i = read_bytes_remote(pid, addr, copy_size))) {
		PRINT_ERROR("Error reading remote instructions at %p\n", addr);
		return NULL;
	}

	res = instruction_bytes_needed(remote_i, copy_size);
	*psize = res;

	return remote_i;
}

int
create_jmp(pid_t pid, void *ataddr, void *raddr, void *ibuf, void *outbuf, size_t *outlen) {
	void *first_i;
	unsigned char *outptr = (unsigned char *)outbuf;
	unsigned long retaddr, cont_addr;
	uint32_t ret_hi, ret_lo, cont_hi, cont_lo;
	size_t to_copy;

	if (!ibuf) {
		if (!(first_i = get_first_instruction_remote(pid, ibuf, &to_copy))) {
			PRINT_ERROR("%s", "Error: could not set up jump buffer for remote function intercept\n");
			return -1;
		}
	}
	else {
		if (!(to_copy = instruction_bytes_needed(ibuf, 15))) {
			PRINT_ERROR("%s", "Error: could not read saved instructions to create intercept\n");
			return -1;
		}
	}

	if (!ibuf) {
		memcpy(outptr, first_i, to_copy);
		free(first_i);
	} else {
		memcpy(outptr, ibuf, to_copy);
	}

	*outlen = to_copy;
	outptr += to_copy;

	cont_addr = (unsigned long)ataddr + to_copy;
	cont_hi = (((unsigned long)cont_addr) & 0xffffffff00000000) >> 32;
	cont_lo = (((unsigned long)cont_addr) & 0x00000000ffffffff);

	retaddr = (unsigned long)raddr;
	ret_hi = (((unsigned long)retaddr) & 0xffffffff00000000) >> 32;
	ret_lo = (((unsigned long)retaddr) & 0x00000000ffffffff);

#define OFFSET_WORD_CONT_HI	8
#define OFFSET_WORD_CONT_LO	16
#define OFFSET_WORD_RET_HI	29
#define OFFSET_WORD_RET_LO	36
	unsigned char return_bytes[] = {
		0x48, 0x83, 0xc4, 0x08,
		0xc7, 0x44, 0x24, 0xfc, 0x11, 0x22, 0x33, 0x44,
		0xc7, 0x44, 0x24, 0xf8, 0x55, 0x66, 0x77, 0x88,	0xff, 0x54, 0x24, 0xf8, /*0xcc,*/ 0x50,
		0xc7, 0x44, 0x24, 0x04, 0x44, 0x33, 0x22, 0x11,
		0xc7, 0x04, 0x24, 0x88, 0x77, 0x66, 0x55, 0xcc, 0xc3 };
/*
	add    $0x8,     %rsp
	movl   $0x11223344, -0x4(%rsp)
	movl   $0x55667788, -0x8(%rsp)
	callq  *-0x8(%rsp)
	push   %rax
	movl   $0x11223344, 0x4(%rsp)
	movl   $0x55667788, (%rsp)
	int3
	retq
*/

	memcpy(&return_bytes[OFFSET_WORD_CONT_HI], &cont_hi, sizeof(cont_hi));
	memcpy(&return_bytes[OFFSET_WORD_CONT_LO], &cont_lo, sizeof(cont_lo));
	memcpy(&return_bytes[OFFSET_WORD_RET_HI], &ret_hi, sizeof(ret_hi));
	memcpy(&return_bytes[OFFSET_WORD_RET_LO], &ret_lo, sizeof(ret_lo));

	memcpy(outptr, return_bytes, sizeof(return_bytes));
	*outlen += sizeof(return_bytes);

	return 0;
}

int
trace_init(void) {

	if (!(remote_intercepts = malloc(remote_intercept_nentries * sizeof(*remote_intercepts)))) {
		PERROR("pid");
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

	PTRACE(PTRACE_TRACEME, 0, 0, 0, EXIT_FAILURE, PT_FATAL);

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

			if (!symbol_store[i].map[j].is_func)
				continue;

//			fprintf(stderr, "CANDIDATE: %s - %lx\n", symbol_store[i].map[j].name, symbol_store[i].map[j].addr);

			if (is_intercept_excluded(symbol_store[i].map[j].name)) {
				PRINT_ERROR("Skipping over excluded intercept: %s\n", symbol_store[i].map[j].name);
				continue;
			}

			if (!save_remote_intercept(pid, symbol_store[i].map[j].name, (void *)symbol_store[i].map[j].addr, NULL, 1)) {
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
		if (!(result = xmalloc(slen+1))) {
			perror_pid("xmalloc", pid);
			return NULL;
		}

		memset(result, 0, slen+1);
	}

	while (nread < slen) {
		size_t maxwrite;
		long val;

		PTRACE_PEEK(val, PTRACE_PEEKDATA, pid, raddr, NULL, PT_RETERROR);

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

			PTRACE_PEEK(oval, PTRACE_PEEKDATA, pid, wptr, -1, PT_RETERROR);

			memcpy(&wword, &oval, sizeof(oval));
			memcpy(&wword, rptr, (blen - nwritten));
		} else {
			memcpy(&wword, rptr, sizeof(wword));
		}

		PTRACE(PTRACE_POKEDATA, pid, wptr, wword, -1, PT_RETERROR);

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

	xfree(rdata);
	return;
}

int
check_child_execute(pid_t pid) {
	struct user_regs_struct regs;
	int wait_status;

	PTRACE(PTRACE_SYSCALL, pid, NULL, NULL, -1, PT_RETERROR);

	if (waitpid(pid, &wait_status, __WALL) == -1)
	{
		perror_pid("waitpid", pid);
		return -1;
	}

	if (!WIFSTOPPED(wait_status) || ((WSTOPSIG(wait_status) & ~0x80) != SIGTRAP)) {
		PRINT_ERROR("Unexpected error: process %d did not return with trace trap\n", pid);
		return -1;
	}

	PTRACE(PTRACE_GETREGS, pid, 0, &regs, -1, PT_RETERROR);

	if (regs.orig_rax != SYS_execve)
		return 0;

	return 1;
}

int
is_thread_in_syscall(pid_t pid) {
	struct user_regs_struct regs;
	unsigned long word;
	unsigned char *iptr = (unsigned char *)&word;

	PTRACE(PTRACE_GETREGS, pid, 0, &regs, -1, PT_RETERROR);

	PTRACE_PEEK(word, PTRACE_PEEKTEXT, pid, regs.rip-2, -1, PT_RETERROR);

	// 0x0f05 = syscall instruction
	if ((iptr[0] == 0x0f) && (iptr[1] == 0x05)) {
		siginfo_t si;

		if (ptrace(PTRACE_GETSIGINFO, pid, NULL, &si) < 0) {
			perror_pid("ptrace(PTRACE_GETSIGINFO)", pid);
		} else {
//			fprintf(stderr, "XXX: errno = %d, code = %x, si_addr = %p\n", si.si_errno, si.si_code, si.si_addr);
//			fprintf(stderr, "XXX: call addr = %p, syscall = %d\n", si.si_call_addr, si.si_syscall);

			// (removed one time intercept code)
//			if (si.si_code == SI_TKILL) {
		}

	}

	return 0;
}

int
dump_remote_backtrace(pid_t pid) {
	struct user_regs_struct regs;
	unsigned long pc, fp;
	size_t level;
	int ret = 0;

	PTRACE(PTRACE_GETREGS, pid, 0, &regs, -1, PT_RETERROR);
	pc = regs.rip;
	fp = regs.rbp;

	while (pc && fp) {
		char tmpbuf[128];
		const char *fname = NULL;
		size_t fp_diff;
		unsigned long fp0, fp1;

		resolve_sym((void *)pc, 0, tmpbuf, sizeof(tmpbuf), &fname);
		PRINT_ERROR_SAFE("BACKTRACE / %zu %p <%s> (%s)\n", level++, (void *)pc, tmpbuf, fname);
		PTRACE_PEEK(fp0, PTRACE_PEEKDATA, pid, fp, -1, PT_RETERROR);
		PTRACE_PEEK(fp1, PTRACE_PEEKDATA, pid, fp+8, -1, PT_RETERROR);

		pc = fp1;
		fp_diff = ((unsigned long)fp > fp1) ? (unsigned long)fp - fp0: fp0 - (unsigned long)fp;
		fp = fp0;

		if (fp_diff > 0x100000) {
			PRINT_ERROR_SAFE("BACKTRACE warning: next frame pointer (%p) is far off last one (%zu bytes); aborting trace.\n",
			(void *)fp, fp_diff);
			ret = -1;
			break;
		}

		if (!pc || !fp) {
			resolve_sym((void *)pc, 0, tmpbuf, sizeof(tmpbuf), &fname);
			PRINT_ERROR_SAFE("BACKTRACE FINAL (possibly spurious?)/ %zu %p <%s> (%s)\n", level++, (void *)pc, tmpbuf, fname);
			ret = -1;
		}

	}

	return ret;
}

int
dump_instruction_state(pid_t pid) {
	struct user_regs_struct regs;
	siginfo_t si;
	Dl_info ainfo, iinfo;
	int r_addr = 0, r_pc = 0, ret = 0;

	if (ptrace(PTRACE_GETSIGINFO, pid, 0, &si) < 0) {
		perror_pid("ptrace(PTRACE_GETSIGINFO)", pid);
		ret = -1;
	} else if (ptrace(PTRACE_GETREGS, pid, 0, &regs) < 0) {
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

		if (si.si_signo == SIGSEGV) {
			dump_remote_backtrace(pid);

//			ptrace(PTRACE_SETOPTIONS, pid, NULL, 0);
			PRINT_ERROR("   rdi = %llx, rsi = %llx, rax = %llx, rbx = %llx, rcx = %llx, rdx = %llx, rsp = %llx, rbp = %llx\n",
				regs.rdi, regs.rsi, regs.rax, regs.rbx, regs.rcx, regs.rdx, regs.rsp, regs.rbp);

			if (kill(pid, si.si_signo) == -1)
				perror_pid("kill", pid);

			PTRACE(PTRACE_CONT, pid, 0, 0, 0, PT_DONTFAIL);
			PTRACE(PTRACE_DETACH, pid, NULL, NULL, 0, PT_DONTFAIL);
		}

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

	return ret;
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

	PTRACE(PTRACE_GETREGS, pid, 0, &regs, -1, PT_RETERROR);
	regs.fs_base = base;
	PTRACE(PTRACE_SETREGS, pid, 0, &regs, -1, PT_RETERROR);

	return 0;
}

/*
 * Call any initialization routines that can be found for a given library
 * in a remote process.
 * If cont_on_err is set, an init return of -1 will not cause an early return.
 */
int
initialize_remote_library(pid_t pid, const char *libpath, int cont_on_err) {
	struct link_map *lm;
	void *hnd, *entry, **ia, **iaptr;
	size_t ino = 0, ncalled = 0;
	int rres;

	entry = get_entry_point(libpath, &ia);
	fprintf(stderr, "Entry point for %s: %p\n", libpath, entry);

	if ((hnd = dlopen(libpath, RTLD_NOW|RTLD_NOLOAD|RTLD_NODELETE)) == NULL) {
		PRINT_ERROR("dlopen(%s): %s\n", libpath, dlerror());
		return -1;
	}

	if (dlinfo(hnd, RTLD_DI_LINKMAP, &lm) == -1) {
		PRINT_ERROR("dlinfo(%s): %s\n", libpath, dlerror());
		return -1;
	}

	if (dlclose(hnd) != 0)
		PRINT_ERROR("dlclose(%s): %s\n", libpath, dlerror());

	if (entry) {
		entry += lm->l_addr;

		PRINT_ERROR("About to call entry point for %s: %p\n", libpath, entry);
		ncalled++;

		if ((rres = call_remote_lib_func(pid, entry, 0, 0, 0, 0, 0, 0, PTRACE_EVENT_CLONE)) == -1) {
			PRINT_ERROR("Error in remote library initialization of %s: %x\n", libpath, rres);

			if (!cont_on_err)
				return -1;
		}

	}

	iaptr = ia;

	while (iaptr && *iaptr) {
		ino++;
		*iaptr += lm->l_addr;
		PRINT_ERROR("About to call init array func #%zu for %s: %p\n", ino, libpath, *iaptr);
		ncalled++;

		if ((rres = call_remote_lib_func(pid, *iaptr, 0, 0, 0, 0, 0, 0, PTRACE_EVENT_CLONE)) == -1) {
			PRINT_ERROR("Error in remote library initialization of %s: %x\n", libpath, rres);

			if (!cont_on_err)
				return -1;
		}

		iaptr++;
	}

	if (!ncalled) {
		PRINT_ERROR("Warning: did not find any entry points for DSO %s to call...\n", libpath);
		return -1;
	}

	return rres;
}


#define MAX_RETRIES	3

int
trace_program(const char *progname, char * const *args) {
	pid_t pid;
	int wait_status;
	static size_t nretries = 0;

	printf("Attempting to trace: %s ...\n", progname);

	switch(master_pid = pid = fork()) {
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

//	PTRACE(PTRACE_ATTACH, pid, NULL, NULL, EXIT_FAILURE, PT_FATAL);

	if (waitpid(pid, &wait_status, __WALL) < 0) {
		perror_pid("waitpid", pid);
		exit(EXIT_FAILURE);
	}

	PTRACE(PTRACE_SETOPTIONS, pid, NULL, trace_flags, EXIT_FAILURE, PT_FATAL);

	monitor_pid(pid, 0);
	dump_wait_state(pid, wait_status, 0);

	printf("Parent attached\n");

	PTRACE(PTRACE_CONT, pid, NULL, 0, EXIT_FAILURE, PT_FATAL);

	if (waitpid(pid, &wait_status, __WALL) < 0) {
		perror_pid("waitpid", pid);
		exit(EXIT_FAILURE);
	}
	dump_wait_state(pid, wait_status, 0);
//	handle_trace_trap(pid, wait_status, 1);

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
			void *dlhandle, *initfunc = NULL, *ginit_copy;
			char libpath[512] = { 0 };
			signed long our_fs;
			int pres;
			size_t i = 0, ginit_size = 0;

			// This is dead code as of now.
/*			if (!alloc_memory_before_vma(pid, 32*3000)) {
				PRINT_ERROR("%s", "Error: could not allocate jump buffer in traced process's address space");
				exit(EXIT_FAILURE);
			}
*/

			// Not statically linked in.
			if (!(dlhandle = dlopen(GOMOD_PRINTLIB_NAME, RTLD_NOW|RTLD_DEEPBIND))) {
				PRINT_ERROR("dlopen(%s): %s\n", GOMOD_PRINTLIB_NAME, dlerror());
				exit(EXIT_FAILURE);
			}

			fprintf(stderr, "XXX initializer table = %p\n", &golang_function_table);
			while (golang_function_table[i].func_name[0]) {

				if (!(golang_function_table[i].address = dlsym(dlhandle, golang_function_table[i].func_name))) {
					PRINT_ERROR("dlsym(%s): %s\n", golang_function_table[i].func_name, dlerror());
					exit(EXIT_FAILURE);
				}

//				fprintf(stderr, "XXX +++: %s -> %p\n", golang_function_table[i].func_name, golang_function_table[i].address);
				i++;
			}

			i++;

			ginit_size = (unsigned long)(&golang_function_table[i]) - (unsigned long)(&golang_function_table[0]);
//			fprintf(stderr, "XXX: ginit table size = %zu\n", ginit_size);

			if (!(ginit_copy = malloc(ginit_size))) {
				PERROR("malloc");
				exit(EXIT_FAILURE);
			}

			memcpy(ginit_copy, &golang_function_table[0], ginit_size);

			if (check_vma_collision(getpid(), pid, 1, 1)) {
				PRINT_ERROR("%s", "Error: possible VMA collision. Killing traced process...\n");
				kill(pid, SIGKILL);
				monitor_pid(pid, 1);

				if (nretries < MAX_RETRIES) {
					nretries++;
					PRINT_ERROR("Retrying execution... attempt %zu of %u\n",
						nretries, MAX_RETRIES);
					return (trace_program(progname, args));
				}

				PRINT_ERROR("%s", "Reached maximum # retries. Aborting.\n");
				exit(EXIT_FAILURE);
			}

			if (readlink("/proc/self/exe", libpath, sizeof(libpath)) == -1) {
				PERROR("readlink");
				strncpy(libpath, GOMOD_LIB_NAME, sizeof(libpath));
			} else {
				char *last = strrchr(libpath, '/');

				if (!last)
					strncpy(libpath, GOMOD_LIB_NAME, sizeof(libpath));
				else {
					last++;
					strncpy(last, GOMOD_LIB_NAME, sizeof(libpath)-strlen(libpath));
				}

			}

			if ((dlhandle = dlopen(libpath, RTLD_NOW|RTLD_DEEPBIND)) == NULL) {
				PRINT_ERROR("dlopen(): %s\n", dlerror());
				exit(EXIT_FAILURE);
			}






//			res = call_remote_syscall(pid, SYS_arch_prctl, ARCH_SET_FS, fs_addr+32767, 0, 0, 0, 0);
#define arch_prctl(code,addr)	syscall(SYS_arch_prctl, code, addr)
			if (arch_prctl(ARCH_GET_FS, &our_fs) == -1) {
				perror("arch_prctl(ARCH_GET_FS)");
				exit(EXIT_FAILURE);
			}

			PTRACE(PTRACE_GETREGS, pid, 0, &regs, EXIT_FAILURE, PT_FATAL);

			if (set_fs_base_remote(pid, (unsigned long)our_fs) < 0) {
				PRINT_ERROR("%s", "Error encountered setting up thread block in remote process\n");
				exit(EXIT_FAILURE);
			}

			if (replicate_process_remotely(pid, &all_shmids) < 0) {
				PRINT_ERROR("%s", "Error encountered replicating process address space remotely\n");
				exit(EXIT_FAILURE);
			}

/*			if (flash_remote_library_memory(pid, "/lib64/ld-linux-x86-64.so.2") < 0) {
				PRINT_ERROR("%s", "Fatal error: failed to flash DSO: ld.so\n");
				exit(EXIT_FAILURE);
			}*/

#define LIBC_PATH	"/lib/x86_64-linux-gnu/libc.so.6"
			if (flash_remote_library_memory(pid, LIBC_PATH) < 0) {
				PRINT_ERROR("Fatal error: failed to flash DSO: %s\n", LIBC_PATH);
				exit(EXIT_FAILURE);
			}

			fprintf(stderr, "Calling remote libc initialization...\n");
			fprintf(stderr, "result = %d\n", initialize_remote_library(pid, LIBC_PATH, 1));
			fprintf(stderr, "Remote libc initialization returned.\n");

#define LIBPTHREAD_PATH	"/lib/x86_64-linux-gnu/libpthread.so.0"
			if (flash_remote_library_memory(pid, LIBPTHREAD_PATH) < 0) {
				PRINT_ERROR("Fatal error: failed to flash DSO: %s\n", LIBPTHREAD_PATH);
				exit(EXIT_FAILURE);
			}

			fprintf(stderr, "Calling remote libpthread initialization...\n");
			fprintf(stderr, "result = %d\n", initialize_remote_library(pid, LIBPTHREAD_PATH, 1));
			fprintf(stderr, "Remote libpthread initialization returned.\n");

/*			if (flash_remote_library_memory(pid, "libgomod.so.0.1.1") < 0) {
				PRINT_ERROR("%s", "Fatal error: failed to flash DSO: libgomod\n");
				exit(EXIT_FAILURE);
			}

			fprintf(stderr, "Calling remote libgomod initialization...\n");
			fprintf(stderr, "result = %d\n", initialize_remote_library(pid, "libgomod.so.0.1.1", 1));
			fprintf(stderr, "Remote libgomod initialization returned.\n");
*/
			if (flash_remote_library_memory(pid, GOMOD_PRINTLIB_NAME) < 0) {
				PRINT_ERROR("%s", "Fatal error: failed to flash DSO: gomod_printlib\n");
				exit(EXIT_FAILURE);
			}




			// Update libc's pointer to the start of the environment variable array
			PTRACE(PTRACE_POKEDATA, pid, &__environ, regs.rsp+16, 0, PT_RETERROR);



			start_listener();

			if (!(initfunc = dlsym(dlhandle, GOMOD_INIT_FUNC))) {
				PRINT_ERROR("dlsym(): %s\n", dlerror());
				exit(EXIT_FAILURE);
			}

			if ((pres = call_remote_lib_func(pid, initfunc, (unsigned long)ginit_copy, 0, 0, 0, 0, 0, PTRACE_EVENT_CLONE)) < 0) {
				PRINT_ERROR("%s", "Error in initialization of remote injection module\n");
				exit(EXIT_FAILURE);
			}

			socket_pid = pres;


			// The pid returned is our module's socket loop (native code)
/*			if (ptrace(PTRACE_SETOPTIONS, pres, NULL, 0) < 0) {
				int wstatus;

				perror_pid("ptrace(~PTRACE_SETOPTIONS)", pres);

				// Let's at least try to figure out what went wrong.
				if (waitpid(pres, &wstatus, 0) == -1)
					perror_pid("waitpid", pres);
				else
					dump_wait_state(pres, wstatus, 1);

				PRINT_ERROR("Retrying PTRACE_SETOPTIONS on pid %d.\n", pres);

				PTRACE(PTRACE_SETOPTIONS, pres, NULL, 0, EXIT_FAILURE, PT_FATAL);
				PRINT_ERROR("%s", "DID NOT fail again\n");
			}*/




/*			if (set_fs_base_remote(pid, old_fs) < 0) {
				PRINT_ERROR("%s", "Error restoring original thread block in remote process\n");
				exit(EXIT_FAILURE);
			} else if (set_fs_base_remote(pres, old_fs) < 0) {
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
//			PTRACE(PTRACE_SETREGS, pid, 0, &regs, EXIT_FAILURE, PT_FATAL);

			break;
		}
	}

	printf("Running loop...\n");

	PTRACE(PTRACE_CONT, pid, NULL, 0, EXIT_FAILURE, PT_FATAL);

	while (1) {
		pid_t cpid;

		if ((cpid = waitpid(-1, &wait_status, __WALL)) < 0) {
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

			PTRACE(PTRACE_SETOPTIONS, cpid, NULL, 0, EXIT_FAILURE, PT_FATAL);
			monitor_pid(cpid, 1);
			PTRACE(PTRACE_CONT, cpid, NULL, 0, EXIT_FAILURE, PT_FATAL);

			continue;
		}

		dump_wait_state(cpid, wait_status, 0);
		check_wait_event(cpid, wait_status);

		if (handle_trace_trap(cpid, wait_status, 0) < 1) {
			PRINT_ERROR("%s", "Error: something bad happened while handling trace trap\n");

			if (WIFSTOPPED(wait_status) && (WSTOPSIG(wait_status) == SIGSEGV)) {
				static int scnt = 0;

				dump_instruction_state(cpid);

				PTRACE(PTRACE_DETACH, cpid, NULL, NULL, 0, PT_DONTFAIL);

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

		PTRACE(PTRACE_CONT, cpid, NULL, 0, 0, PT_DONTFAIL);
//			exit(EXIT_FAILURE);
	}

	fprintf(stderr, "Waiting a second...\n");
	sleep(1);

	return 0;
}

#define ITAB_PREFIX	"go.itab."
void
scan_interfaces(void) {
	size_t i, ninterfaces = 0, ctr = 0;

	for (i = 0; i < sizeof(symbol_store)/sizeof(symbol_store[0]); i++) {
		size_t j;

		if (!symbol_store[i].l)
			continue;

		for (j = 0; j < symbol_store[i].msize; j++) {

			if (strncmp(symbol_store[i].map[j].name, ITAB_PREFIX, strlen(ITAB_PREFIX)))
				continue;
			else if (symbol_store[i].map[j].is_func)
				continue;

			ninterfaces++;
		}

	}

	if (!(all_ginterfaces = malloc(sizeof(*all_ginterfaces) * ninterfaces))) {
		PERROR("malloc");
		return;
	}

	memset(all_ginterfaces, 0, sizeof(*all_ginterfaces) * ninterfaces);

	for (i = 0; i < sizeof(symbol_store)/sizeof(symbol_store[0]); i++) {
		size_t j;

		if (!symbol_store[i].l)
			continue;

		for (j = 0; j < symbol_store[i].msize; j++) {
			char *nptr;

			if (strncmp(symbol_store[i].map[j].name, ITAB_PREFIX, strlen(ITAB_PREFIX)))
				continue;
			else if (symbol_store[i].map[j].is_func)
				continue;

			nptr = symbol_store[i].map[j].name + strlen(ITAB_PREFIX);
			all_ginterfaces[ctr].addr = (void *)symbol_store[i].map[j].addr;
			all_ginterfaces[ctr].name = nptr;

//			fprintf(stderr, "IFACE: %s -> %p / %d\n", all_ginterfaces[ctr].name,
//				(void *)symbol_store[i].map[j].addr, symbol_store[i].map[j].is_func);
			ctr++;
		}

	}

	ngolang_ifaces = ninterfaces;
	n_unresolved_interfaces = ninterfaces;
	return;
}

void
resolve_all_interfaces(pid_t pid) {
	size_t i;

	for (i = 0; i < ngolang_ifaces; i++) {
		unsigned long addr;
		int err = 0;

		if (all_ginterfaces[i].typ && all_ginterfaces[i].elem)
			continue;

		if (!all_ginterfaces[i].bind_addr) {
			errno = 0;
			addr = ptrace(PTRACE_PEEKDATA, pid, all_ginterfaces[i].addr+sizeof(void *), 0);

			if (errno) {
//				perror_pid("PTRACE(PEEKDATA):int[1]", pid);
				continue;
			} else if (!addr)
				continue;

			all_ginterfaces[i].bind_addr = (void *)addr;
		}

		if (!all_ginterfaces[i].elem) {
			errno = 0;
			addr = ptrace(PTRACE_PEEKDATA, pid, all_ginterfaces[i].bind_addr, 0);

			if (errno) {
//				perror_pid("PTRACE(PEEKDATA):int[2]", pid);
				err = 1;
			} else if (!addr)
				err = 1;
			else
				all_ginterfaces[i].elem = (void *)addr;

		}

		if (!all_ginterfaces[i].typ) {
			errno = 0;
			addr = ptrace(PTRACE_PEEKDATA, pid, all_ginterfaces[i].bind_addr+sizeof(void *), 0);

			if (errno) {
//				perror_pid("PTRACE(PEEKDATA):int[3]", pid);
				err = 1;
			} else if (!addr)
				err = 1;
			else
				all_ginterfaces[i].typ = (void *)addr;

		}

		if (!err) {
			n_unresolved_interfaces--;
//			fprintf(stderr, "XXX: added interface %s - %p, %p\n",
//				all_ginterfaces[i].name, all_ginterfaces[i].elem, all_ginterfaces[i].typ);

		}

	}

	return;
}

const char *
lookup_interface(pid_t pid, void *value, int is_typ) {
	size_t i;

	if (n_unresolved_interfaces) {
//		fprintf(stderr, "XXX: %zu unresolved interfaces\n", n_unresolved_interfaces);
		resolve_all_interfaces(pid);
//		fprintf(stderr, "XXX: now: %zu unresolved interfaces\n", n_unresolved_interfaces);
	}

	for (i = 0; i < ngolang_ifaces; i++) {

		if (is_typ && all_ginterfaces[i].typ == value)
			return all_ginterfaces[i].name;
		else if (!is_typ && all_ginterfaces[i].elem == value)
			return all_ginterfaces[i].name;

	}

	return NULL;
}


#define PG	4096
void
balloon(void) {
	size_t all_sizes[] = { PG*1024, PG*1024, PG*1024*4, PG*1024*8, PG*1024*16, PG*1024*32, PG*1024*64, PG*1024*128, PG*1024*128 };
	size_t i, fd;

	if ((fd = open("/dev/zero", O_RDWR)) == -1) {
		PERROR("open(/dev/zero)");
		return;
	}

	for (i = 0; i < sizeof(all_sizes)/sizeof(all_sizes[0]); i++) {
		void *buf;

		if (!(buf = mmap(NULL, all_sizes[i], PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0))) {
			PERROR("mmap");
			return;
		}

	}

	return;
}

int
main(int argc, char *argv[]) {
	static struct lt_config_shared cfg_sh;
	void *firstmodulep;
	char *progname = argv[1];
	int syms_ok;

	if (argc < 2) {
		fprintf(stderr, "Error: must specify a program name (and optional arguments)!\n");
		exit(EXIT_FAILURE);
	}

	fprintf(stderr, "Starting up...\n");

	trace_init();

        cfg.sh = &cfg_sh;
        cfg_sh.timestamp = 0;
        cfg_sh.hide_tid = 0;
        cfg_sh.indent_sym = 1;
        cfg_sh.indent_size = 1;
        cfg_sh.fmt_colors = 1;
        cfg_sh.braces = 1;
        cfg_sh.resolve_syms = 1;
	cfg_sh.show_modules = getenv("GOTRACE_SHOW_MODULES") != NULL;

	balloon();

	if (audit_init(&cfg, argc, argv, environ) < 0) {
		fprintf(stderr, "Error encountered in initialization! Aborting.\n");
		exit(EXIT_FAILURE);
	}

	if ((syms_ok = get_all_funcs_in_object(progname)) != 1) {
		fprintf(stderr, "Error: could not read symbols from debug object\n");
		exit(EXIT_FAILURE);
	}

	if (!(firstmodulep = lookup_symbol("runtime.firstmoduledata"))) {
		PRINT_ERROR("%s", "Error: could not resolve firstmoduledata in target program\n");
		exit(EXIT_FAILURE);
	}

	if (get_pcdata(argv[1], firstmodulep, symbol_store[0].map, symbol_store[0].msize) < 0)
		PRINT_ERROR("%s", "Warning: could not read PCDATA from target program\n");

	scan_interfaces();

	snprintf(gotrace_socket_path, sizeof(gotrace_socket_path), "/tmp/gotrace.sock.%d", getpid());
	atexit(cleanup);

	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = handle_int;
	sa.sa_flags |= SA_NODEFER;
//               sigset_t   sa_mask;

//	if (signal(SIGINT, handle_int) == SIG_ERR)
	if (sigaction(SIGINT, &sa, NULL) == -1)
		perror_pid("sigaction(SIGINT,...)", 0);

	trace_program(progname, &argv[2]);
	exit(-1);
}
