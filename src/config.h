/*
  Copyright (C) 2008, 2009, 2010 Jiri Olsa <olsajiri@gmail.com>

  This file is part of the latrace.

  The latrace is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  The latrace is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with the latrace (file COPYING).  If not, see 
  <http://www.gnu.org/licenses/>.
*/


#ifndef CONFIG_H
#define CONFIG_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <search.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <sys/user.h>

#include "list.h"


typedef struct function_call {
	char *fn_name;
	struct user_regs_struct *registers;
	void **args;
	size_t argcnt;
} fn_call_t;

#define SUPPRESS_FN_LEN		128
typedef struct lt_tsd {
	char suppress_while[SUPPRESS_FN_LEN];
	int suppress_collapsed;
	int suppress_nested;
	size_t nsuppressed;

	int last_operation;
	char *fault_reason;

	int ass_integer;
	int ass_memory;

	fn_call_t *xfm_call_stack;
	size_t xfm_call_stack_max;
	size_t xfm_call_stack_sz;

	int indent_depth;
	int flow_below_stack;

	char *excised;

} lt_tsd_t;

extern lt_tsd_t *thread_get_tsd(pid_t tid, int create);


#include "args.h"


#define LT_NAMES_MAX  50
#define LT_NAMES_SEP  ','

#define LT_SYM_HMAX    1000

#define LT_ARGS_DEF_STRUCT_NUM  1000
#define LT_ARGS_DEF_TYPEDEF_NUM 1000
#define LT_ARGS_DEF_ENUM_NUM    1000
#define LT_ARGS_STRUCT_XFM_NUM  1000


struct lt_config_opt {
	int idx;
	char *sval;
	unsigned long nval;
	struct lt_list_head list;
};

struct lt_config_shared {
#define GT_CONFIG_VERSION	1

#define LT_SYMBOLS_MAXSIZE  4096
	char symbols[LT_SYMBOLS_MAXSIZE];
	char symbols_omit[LT_SYMBOLS_MAXSIZE];
	char symbols_noexit[LT_SYMBOLS_MAXSIZE];

	char flow_below[LT_SYMBOLS_MAXSIZE];

#define LT_MAXFILE 4096
	char output[LT_MAXFILE];
	FILE *fout;

	char args_def[LT_MAXFILE];
	char args_enabled;
	char args_detailed;
	char args_string_pointer_length;
#define LR_ARGS_MAXLEN 1000
	int  args_maxlen;
#define LR_ARGS_DETAIL_MAXLEN 1000
	int  args_detail_maxlen;
#define LT_ARGS_TAB 10000
	struct hsearch_data args_tab;

	int disabled;
	int verbose;
	int timestamp;
	int debug;
	int indent_sym;
	int indent_size;
	int braces;
	int fmt_colors;
	int resolve_syms;
	int counts;
	int hide_tid;
	int not_follow_exec;
	int not_follow_fork;

	/* for 'not_follow_fork' */
	pid_t pid;

	/* XXX feel like an idiot.. find another way!!! */
	struct lt_config_shared *sh;
};

struct lt_config_app {
	/*
	 * This is to copy the lt_config_audit, so we can use
	 * one PRINT_VERBOSE only.
	 */
	struct lt_config_shared *sh;

	char *prog;
#define LT_NUM_ARG 500
	char *arg[LT_NUM_ARG];
	int arg_num;

	int csort;

	struct lt_thread *threads;
	struct lt_thread *iter;
};


struct lt_config_audit {
	struct lt_config_shared *sh;

	char *symbols[LT_NAMES_MAX];
	int symbols_cnt;

	char *symbols_omit[LT_NAMES_MAX];
	int symbols_omit_cnt;

	char *symbols_noexit[LT_NAMES_MAX];
	int symbols_noexit_cnt;

	char *flow_below[LT_NAMES_MAX];
	int flow_below_cnt;

	char *dir;
	int init_ok;
};


#define lt_sh(cfg, field) ((cfg)->sh->field)


#define COLLAPSED_NONE        0
#define COLLAPSED_BASIC	      1
#define COLLAPSED_TERSE       2
#define COLLAPSED_BARE        3
#define COLLAPSED_NESTED      16


struct lt_thread {
	/* global */
        pid_t tid;

	int indent_depth;
	size_t nsuppressed;

	/* start/stop time */
	struct timeval tv_start;
	struct timeval tv_stop;

	/* symbol statistics */
        struct lt_stats_sym **sym_array;
        struct hsearch_data sym_htab;
        unsigned int sym_cnt;
        unsigned int sym_max;

	struct lt_thread *next;
};

struct lt_symbol {
	struct lt_args_sym *args;

	/* symbol name */
	const char *name;
	/* symbol address */
	void *ptr;
	int collapsed;
};


/*
 * These stubs are here in case the need for debugging arises.
 * In this case, under the circumstances, we have almost no recourse
 * except to use a home-brewed version of electric fence, since neither
 * the original works, nor will valgrind in a debugging state.
 */

void *xmalloc(size_t size);
//extern void *xmalloc(size_t size);
//extern void xfree(void *ptr);
//extern void *xrealloc(void *ptr, size_t size);

//#define xmalloc		malloc
#define xfree		free
#define xrealloc	realloc
#define xstrdup		strdup


/* audit */
int audit_init(struct lt_config_audit *cfg, int argc, char **argv, char **env);
int sym_entry(const char *symname, void *ptr, char *lib_from, char *lib_to,
		pid_t target, struct user_regs_struct *regs, lt_tsd_t *tsd);
int sym_exit(const char *symname, void *ptr, char *lib_from, char *lib_to, pid_t target,
		struct user_regs_struct *inregs, struct user_regs_struct *outregs, lt_tsd_t *tsd);


/* elf */
int get_all_funcs_in_object(const char *filename);

/* thread */
struct lt_thread *lt_thread_add(struct lt_config_app *cfg, int fd, pid_t pid);
struct lt_thread *lt_thread_first(struct lt_config_app *cfg);
struct lt_thread *lt_thread_next(struct lt_config_app *cfg);

/* output */
int lt_out_entry(struct lt_config_shared *cfg, struct timeval *tv,
		pid_t tid, int indent_depth, int collapsed,
		const char *symname, char *lib_to, char *lib_from,
		char *argbuf, char *argdbuf, size_t *nsuppressed);
int lt_out_exit(struct lt_config_shared *cfg, struct timeval *tv,
		pid_t tid, int indent_depth, int collapsed,
		const char *symname, char *lib_to, char *lib_from,
		char *argbuf, char *argdbuf, size_t *nsuppressed);

/* symbol */
struct lt_symbol* lt_symbol_bind(struct lt_config_shared *cfg,
				void *ptr, const char *name);
struct lt_symbol* lt_symbol_get(struct lt_config_shared *cfg,
				void *ptr, const char *name);

/* tracer */
char *call_remote_serializer(pid_t pid, const char *name, void *addr);
const char *lookup_interface(pid_t pid, void *value, int is_typ);


/* network */
ssize_t xsend(pid_t pid, int sockfd, const void *buf, size_t len, int do_ctl);
ssize_t xrecv(pid_t pid, int sockfd, void *buf, size_t len, int do_ctl, pid_t *pout);
int send_gt_msg(pid_t pid, int fd, int reqtype, void *data, size_t dlen, int do_ctl);
void *recv_gt_msg(pid_t pid, int fd, int reqtype, size_t *plen, int *preqtype, int do_ctl, pid_t *pout);

/* misc */
void perror_pid(const char *msg, pid_t pid);
pid_t gettid(void);
void *map_closest_area(void *refaddr, size_t msize);
size_t make_jmp_buf(unsigned long from, unsigned long to, void *buf, size_t buflen);

/* arch specific */
char *read_string_remote(pid_t pid, char *addr, size_t slen);

/* remote dynamic linker */
char **get_all_so_needed(const char *dsopath, char **curdeps);
int open_dso_and_get_segments(const char *soname, pid_t pid, void **pinit_func, void **reloc_base, int open_all);
void *get_entry_point(const char *dsopath);
unsigned long call_remote_syscall(pid_t pid, int syscall_no, unsigned long r1,
	unsigned long r2, unsigned long r3, unsigned long r4, unsigned long r5, unsigned long r6);
unsigned long call_remote_mmap(pid_t pid, void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int call_remote_mprotect(pid_t pid, void *addr, size_t len, int prot);
unsigned long call_remote_shmat(pid_t pid, int shmid, const void *shmaddr, int shmflg);
uintptr_t call_remote_lib_func(pid_t pid, void *faddr, uintptr_t r1, uintptr_t r2, uintptr_t r3,
	uintptr_t r4, uintptr_t r5, uintptr_t r6, int allow_event);
unsigned long get_fs_base_remote(pid_t pid);
int replicate_process_remotely(pid_t pid, int **shmids);


void dump_wait_state(pid_t pid, int status, int force);
void dump_instruction_state(pid_t pid);
char *read_bytes_remote(pid_t pid, char *addr, size_t slen);
int write_bytes_remote(pid_t pid, void *addr, void *buf, size_t blen);
int check_vma_collision(pid_t pid1, pid_t pid2, int exclude_vsyscall, int exclude_self);



#define PRINT(fmt, args...) \
do { \
	char lpbuf[1024]; \
	sprintf(lpbuf, "[%d %s:%05d] %s", \
		(pid_t) syscall(SYS_gettid), \
		__FUNCTION__, \
		__LINE__, \
		fmt); \
	printf(lpbuf, ## args); \
	fflush(NULL); \
} while(0)

#define PRINT_VERBOSE(cfg, cond, fmt, args...) \
do { \
	if (cond > (cfg)->sh->verbose) \
		break; \
	PRINT(fmt, ## args); \
} while(0)

#define RESET       "\033[0m"
#define BOLD	    "\033[1m"
#define BOLDOFF     "\033[22m"
#define ULINE       "\033[4m"
#define ULINEOFF    "\033[24m"
#define INVERT      "\033[7m"
#define INVOFF      "\033[27m"
#define BLACK       "\033[30m"           /* Black */
#define RED         "\033[31m"           /* Red */
#define GREEN       "\033[32m"           /* Green */
#define YELLOW      "\033[33m"           /* Yellow */
#define BLUE        "\033[34m"           /* Blue */
#define MAGENTA     "\033[35m"           /* Magenta */
#define CYAN        "\033[36m"           /* Cyan */
#define WHITE       "\033[37m"           /* White */
#define BOLDBLACK   "\033[1m\033[30m"    /* Bold Black */
#define BOLDRED     "\033[1m\033[31m"    /* Bold Red */
#define BOLDGREEN   "\033[1m\033[32m"    /* Bold Green */
#define BOLDYELLOW  "\033[1m\033[33m"    /* Bold Yellow */
#define BOLDBLUE    "\033[1m\033[34m"    /* Bold Blue */
#define BOLDMAGENTA "\033[1m\033[35m"    /* Bold Magenta */
#define BOLDCYAN    "\033[1m\033[36m"    /* Bold Cyan */
#define BOLDWHITE   "\033[1m\033[37m"    /* Bold White */

#define PRINT_COLOR(color, fmt, ...)	fprintf(stderr, color fmt RESET, __VA_ARGS__)
//#define PRINT_ERROR(fmt, ...)		PRINT_COLOR(BOLDRED, fmt, __VA_ARGS__)
#define PRINT_ERROR	PRINT_ERROR_SAFE
#define PRINT_ERROR_SAFE(fmt, ...)	do { char ___buf[1024]; memset(___buf, 0, sizeof(___buf));	\
					snprintf(___buf, sizeof(___buf), BOLDRED fmt RESET, __VA_ARGS__);	\
					if (write(STDERR_FILENO, ___buf, strlen(___buf))) { }  \
					fsync(STDERR_FILENO); } while (0)
#define PERROR(func)	do {	\
				char ___errbuf[256], *___e;	\
				memset(___errbuf, 0, sizeof(___errbuf));	\
				if ((___e = strerror_r(errno, ___errbuf, sizeof(___errbuf)))) { }	\
				PRINT_ERROR("%s: %s\n", func, ___e);	\
			} while (0)
#define PERROR_PRINTF(fmt,...)	do {	\
						char ___msgbuf[256];	\
						ssize_t ___max = sizeof(___msgbuf);	\
						memset(___msgbuf, 0, sizeof(___msgbuf));	\
						___max -= snprintf(___msgbuf, sizeof(___msgbuf), fmt, __VA_ARGS__);	\
						if (___max > 3) {	\
							char ___errbuf[256];	\
							memset(___errbuf, 0, sizeof(___errbuf));	\
							if (strerror_r(errno, ___errbuf, sizeof(___errbuf))) { }	\
							snprintf(&___msgbuf[strlen(___msgbuf)], ___max, ": %s\n", ___errbuf);	\
							if (write(STDERR_FILENO, ___msgbuf, strlen(___msgbuf))) { }	\
							fsync(STDERR_FILENO);	\
						}	\
					} while (0)


#define ANON_PREFIX_INTERNAL	"_anon_"
#define ANON_PREFIX		"$r"


#if __WORDSIZE == 64
#define ELF_DYN		Elf64_Dyn
#define ELF_SYM		Elf64_Sym
#define ELF_ST_TYPE	ELF64_ST_TYPE
#else
#define ELF_DYN		Elf32_Dyn
#define ELF_SYM		Elf32_Sym
#define ELF_ST_TYPE	ELF32_ST_TYPE
#endif



#if defined(__x86_64)
#include "sysdeps/x86_64/args.h"
#endif

#define IGN_RET(x)	{ if (x) {} }

#define GOTRACE_SOCKET_ENV	"GOTRACE_SOCKET_PATH"

#define GOMOD_DATA_MAGIC	0x93
#define GOMOD_RT_SET_INTERCEPT	1
#define GOMOD_RT_CALL_FUNC	2
#define GOMOD_RT_SERIALIZE_DATA	3
typedef struct __attribute__((packed)) gomod_data_hdr {
	uint8_t magic;
	uint16_t size;
	uint8_t reqtype;
} gomod_data_hdr_t;


#define GOMOD_LIB_NAME		"libgomod.so."CONFIG_VERSION
#define GOMOD_INIT_FUNC		"_gomod_init"

#define MAX_STRING_ALLOC_SIZE	8192


#endif // !CONFIG_H
