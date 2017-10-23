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


#include <link.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <bits/wordsize.h>
#include <gnu/lib-names.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/user.h>

#include "config.h"
#include "elfh.h"


extern struct lt_config_audit cfg;

unsigned int thread_warning = 0;

#define MAXPTIDS	256
#define MAXIDX		3

#define PKEY_VAL_INITIALIZED	(void *)0xc0ffee
#define PKEY_VAL_TLS_BAD	(void *)0xdeadbeef

#define PKEY_ID_THREAD_STATE	0
#define PKEY_ID_TSD		1
#define PKEY_ID_EXCISED		2
#define PKEY_ID_MARK_TLS	3

int lt_thread_pkey_init = 0;


static int check_names(char *name, char **ptr)
{
	char *n;
	int matched = 0;

	for(n = *ptr; n; n = *(++ptr)) {
		size_t nlen;
		unsigned char last_char;

		if (!strcmp(name, n)) {
			matched = 1;
			break;
		}

		nlen = strlen(n);
		last_char = n[nlen-1];

		if (n[0] == '*' && last_char != '*' &&
		    strcmp(&(n[1]), name) == 0) {
			matched = 1;
		}
		else if (last_char == '*') {
			if ((n[0] != '*') && (strncmp(name, n, nlen-1) == 0))
				matched = 1;
			else if ((n[0] == '*') && (memmem(name, strlen(name), &(n[1]), nlen-2)))
				matched = 1;
			
		}

		if (matched)
			break;
	}

	if (matched) {
		PRINT_VERBOSE(&cfg, 2,
			"return %d for name %s\n", 1, name);
		return 1;
	}

	PRINT_VERBOSE(&cfg, 2, "return %d for name %s\n",
			0, name);
	return 0;
}

static int check_flow_below(const char *symname, int in, lt_tsd_t *tsd)
{
	int ret = tsd->flow_below_stack;

	if (check_names((char*) symname, cfg.flow_below))
		in ? ret = ++tsd->flow_below_stack : tsd->flow_below_stack--;

	return ret;
}

static void free_argbuf(int argret, char *argbuf, char *argdbuf)
{
	xfree(argbuf);

	if (argret)
		return;

	if (lt_sh(&cfg, args_detailed) && (*argdbuf))
		free(argdbuf);
}

int sym_entry(const char *symname, void *ptr, char *lib_from, char *lib_to,
	pid_t target, struct user_regs_struct *regs, lt_tsd_t *tsd)
{
	int argret = -1;
	char *argbuf, *argdbuf = "";
	struct timeval tv;
	struct lt_symbol *sym = NULL;
	int collapsed = 0, set_suppress_collapsed = 0, is_silent = 0;

//	fprintf(stderr, "XXX: SYM_ENTRY: %d / %s\n", target, symname);

	if (!(argbuf = xmalloc(LR_ARGS_MAXLEN)))
		return -1;

	memset(argbuf, 0, LR_ARGS_MAXLEN);

	PRINT_VERBOSE(&cfg, 2, "%s@%s\n", symname, lib_to);

	// Make sure we keep track of recursive/repeated calls to ourselves.
/*	if (tsd->suppress_while[0] && (tsd->suppress_collapsed != COLLAPSED_TERSE)) {
		if (!strcmp(tsd->suppress_while, symname))
			tsd->suppress_nested++;

		is_silent = 1;
	}*/

	/* XXX: This might have gotten completely screwed up */
	if (tsd->suppress_while[0] && (!strcmp(tsd->suppress_while, symname)))
		tsd->suppress_nested++;
	if (tsd->suppress_while[0])
		is_silent = 1;

	if (is_silent) {
		sym = lt_symbol_get(cfg.sh, ptr, symname);

		if (sym && sym->args->args[LT_ARGS_RET]->latrace_custom_func_intercept) {
			argret = lt_args_sym_entry(cfg.sh, sym, target, regs, argbuf, LR_ARGS_MAXLEN, &argdbuf, is_silent, NULL);
		}

		if ((tsd->suppress_collapsed != COLLAPSED_NESTED) && (tsd->suppress_collapsed != COLLAPSED_TERSE))
			symname = "";

		collapsed = COLLAPSED_NESTED;
	}

	if (!is_silent && (tsd->suppress_collapsed == COLLAPSED_TERSE)) {
		collapsed = COLLAPSED_NESTED;
	}
	else if (!is_silent) {
//	else if (collapsed != COLLAPSED_NESTED) {

		if (cfg.flow_below_cnt && !check_flow_below(symname, 1, tsd))
			return -1;

		if (lt_sh(&cfg, timestamp) || lt_sh(&cfg, counts))
			gettimeofday(&tv, NULL);

		sym = lt_symbol_get(cfg.sh, ptr, symname);

		if (sym && sym->collapsed) {
			strncpy(tsd->suppress_while, sym->name, sizeof(tsd->suppress_while)-1);
			tsd->suppress_while[sizeof(tsd->suppress_while)-1] = 0;
			tsd->suppress_nested++;
			collapsed = sym->collapsed;
			set_suppress_collapsed = 1;
		}

		argret = lt_args_sym_entry(cfg.sh, sym, target, regs, argbuf, LR_ARGS_MAXLEN, &argdbuf, is_silent, tsd);
	}

	tsd->indent_depth++;

	if (!is_silent && set_suppress_collapsed)
		tsd->suppress_collapsed = collapsed;

	/* If symname is empty then all we care about is preserving the call stack depth */
	if (*symname) {
		lt_out_entry(cfg.sh, &tv, target, tsd->indent_depth, collapsed,
			symname, lib_to, lib_from, argbuf, argdbuf, &tsd->nsuppressed);
	}

	free_argbuf(argret, argbuf, argdbuf);
	return 0;
}

int sym_exit(const char *symname, void *ptr, char *lib_from, char *lib_to, pid_t target,
			 struct user_regs_struct *inregs, struct user_regs_struct *outregs, lt_tsd_t *tsd)
{
	int argret = -1;
	char *argbuf = NULL, *argdbuf = "";
	struct timeval tv;
	struct lt_symbol *sym = NULL;
	int collapsed = 0, is_silent = 0;

	if (!ptr) {
		argbuf = " ";
		lt_out_exit(cfg.sh, &tv, target,
			tsd->indent_depth, collapsed,
			symname, lib_to, lib_from,
			argbuf, argdbuf, &tsd->nsuppressed);

		if (tsd->indent_depth)
			tsd->indent_depth--;

		return 0;
	}

	if (!(argbuf = malloc(LR_ARGS_MAXLEN)))
		return -1;

	memset(argbuf, 0, LR_ARGS_MAXLEN);

	PRINT_VERBOSE(&cfg, 2, "%s@%s\n", symname, lib_to);

	if (tsd->suppress_while[0]) {
		if (!strcmp(tsd->suppress_while, symname)) {
			tsd->suppress_nested--;

			if (!tsd->suppress_nested) {
				memset(tsd->suppress_while, 0, sizeof(tsd->suppress_while));
				tsd->suppress_collapsed = 0;
			} else
				is_silent = 1;

		}
		else if (tsd->suppress_nested > 0)
			is_silent = 1;
	}

	if (is_silent) {
		sym = lt_symbol_get(cfg.sh, ptr, symname);

		if (sym && sym->args->args[LT_ARGS_RET]->latrace_custom_func_intercept) {
			argret = lt_args_sym_exit(cfg.sh, sym, target, inregs, outregs, argbuf, LR_ARGS_MAXLEN, &argdbuf, is_silent, tsd);
		}

		collapsed = COLLAPSED_NESTED;
	} else {

		if (cfg.flow_below_cnt && !check_flow_below(symname, 0, tsd))
			return 0;

		if (lt_sh(&cfg, timestamp) || lt_sh(&cfg, counts))
			gettimeofday(&tv, NULL);

		sym = lt_symbol_get(cfg.sh, ptr, symname);

		if (sym && sym->collapsed)
			collapsed = sym->collapsed;

		argret = lt_args_sym_exit(cfg.sh, sym, target, inregs, outregs, argbuf, LR_ARGS_MAXLEN, &argdbuf, is_silent, tsd);
	}

	lt_out_exit(cfg.sh, &tv, target,
			tsd->indent_depth, collapsed,
			symname, lib_to, lib_from,
			argbuf, argdbuf, &tsd->nsuppressed);

	if (tsd->indent_depth)
		tsd->indent_depth--;

	free_argbuf(argret, argbuf, argdbuf);
	return 0;
}

#define CHECK_PID(ret) \
do { \
	if (cfg.sh->not_follow_fork && \
	    check_pid()) \
		return ret; \
} while(0)

#define CHECK_DISABLED(ret) \
do { \
	if (lt_sh(&cfg, disabled)) \
		return ret; \
} while(0)


/*
 * Tried consoldating this into one single array where:
 * thread_data[MAXPTIDS] and void *data[MAXIDX]
 * but this didn't work for some unknown reason. Should revisit.
 */
typedef struct lt_thread_pkey {
	pid_t tid;
	void *data;
} lt_thread_pkey_t;

static lt_thread_pkey_t thread_data[MAXIDX][MAXPTIDS];

static int
SETSPECIFIC(pid_t tid, size_t idx, void *data, int *found) {
	size_t t;

	if (idx >= MAXIDX)
		return -1;

	for (t = 0; t < MAXPTIDS; t++) {

		if ((thread_data[idx][t].tid == 0) || (thread_data[idx][t].tid == tid)) {
			thread_data[idx][t].tid = tid;
			thread_data[idx][t].data = data;
			return 0;
		}

	}

	return -1;
}

static void *
GETSPECIFIC(pid_t tid, size_t idx, int *found) {
	void *result = NULL;
	size_t t;

	if (found)
		*found = 0;

	if (idx >= MAXIDX)
		return NULL;

	for (t = 0; t < MAXPTIDS; t++) {

		if (thread_data[idx][t].tid == tid) {
			result = thread_data[idx][t].data;

			if (found)
				*found = 1;

			break;
		}

	}

	return result;
}

void
setup_tsd_pkeys(void)
{

	if (lt_thread_pkey_init != 0)
		return;

//	thread_get_tsd(2);
	lt_thread_pkey_init = 1;

	return;
}

lt_tsd_t *
thread_get_tsd(pid_t tid, int create)
{
	void *pkd;

	if (create == 1 && !lt_thread_pkey_init)
		setup_tsd_pkeys();

	if (lt_thread_pkey_init <= 0)
		return NULL;

	pkd = GETSPECIFIC(tid, PKEY_ID_TSD, NULL);

	if (!pkd && create) {
		lt_tsd_t *tsd;

		if (!(tsd = malloc(sizeof(lt_tsd_t)))) {
			PERROR("Error creating TSD");
			return NULL;
		}

		memset(tsd, 0, sizeof(*tsd));
		tsd->last_operation = -1;
		pkd = tsd;
		SETSPECIFIC(tid, PKEY_ID_TSD, tsd, NULL);
	}

	return pkd;
}
