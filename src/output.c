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

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <stdarg.h>
#include <pthread.h>

#include "config.h"


static char spaces[] = "                                                                                                                                                                           ";


typedef struct thread_buffer {
	pid_t tid;
	char *buf;
	struct thread_buffer *next;
	int last_nested;
} thread_buffer_t;

thread_buffer_t *thread_buffers = NULL;

#define PRINT_DETAILS(tobuf,buf) \
do { \
	if (tobuf) \
		outbuf = sprintf_cat(outbuf, 8192, "%s\n", buf); \
	else \
		print_details(cfg, buf); \
} while(0)

static int print_details(struct lt_config_shared *cfg, char *argdbuf)
{
	fprintf(cfg->fout, "%s\n", argdbuf);
	return 0;
}

#define PRINT_DATA(tobuf,fmt,...) \
do { \
	if (!tobuf) { \
		fprintf(cfg->fout, fmt, __VA_ARGS__); \
		fflush(NULL); \
	} \
	else { \
		outbuf = sprintf_cat(outbuf, 8192, fmt, __VA_ARGS__); \
	} \
} while(0)

#define FPRINT_TID(tid) \
do { \
	fprintf(cfg->fout, "%5d   ", tid); \
} while(0)
#define SPRINT_TID(tid) \
do { \
	outbuf = sprintf_cat(outbuf, 8192, "%5d   ", tid); \
} while(0)

#define FPRINT_TIME(tv) \
do { \
	struct tm t; \
\
	gettimeofday(tv, NULL); \
	localtime_r(&tv->tv_sec, &t); \
	fprintf(cfg->fout, "[%02d/%02d/%4d %02d:%02d:%02d.%06u]   ", \
		t.tm_mon, \
		t.tm_mday, \
		t.tm_year + 1900, \
		t.tm_hour, \
		t.tm_min, \
		t.tm_sec, \
		(unsigned int) tv->tv_usec); \
} while(0)
#define SPRINT_TIME(tv) \
do { \
	struct tm t; \
\
	gettimeofday(tv, NULL); \
	localtime_r(&tv->tv_sec, &t); \
	outbuf = sprintf_cat(outbuf, 8192, "[%02d/%02d/%4d %02d:%02d:%02d.%06u]   ", \
		t.tm_mon, \
		t.tm_mday, \
		t.tm_year + 1900, \
		t.tm_hour, \
		t.tm_min, \
		t.tm_sec, \
		(unsigned int) tv->tv_usec); \
} while(0)

char *color_table[6] = { RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN };


static char *
sprintf_cat(char *buf, size_t bufsize, char *fmt, ...)
{
	va_list ap;
	char tmpbuf[1024], *result;
	int csize, nsize = 0;

	va_start(ap, fmt);
	memset(tmpbuf, 0, sizeof(tmpbuf));
	csize = vsnprintf(tmpbuf, sizeof(tmpbuf), fmt, ap);
	va_end(ap);

	if (csize < 0)
		return NULL;

	if (!buf) {
		// XXX: can change back to strdup() in near future
		if (!(result = xmalloc(strlen(tmpbuf)+1))) {
			PERROR("xmalloc");
			exit(EXIT_FAILURE);
		}
		strcpy(result, tmpbuf);
	} else {
		nsize = strlen(buf) + csize + 1;
		result = xrealloc(buf, nsize);
		strncat(result, tmpbuf, csize);
	}

	return result;
}

static void
buffer_output_data(pid_t tid, const char *output, int nest_level, int do_prefix)
{
	thread_buffer_t *tb;
	char *outbuf;
	size_t nlen = 0;
	int was_empty = 0;
	int nested = 1;

	if (!output || !*output)
		return;

	tb = thread_buffers;

	while (tb && (tb->tid != tid))
		tb = tb->next;

	if (tb && tb->buf)
		nlen += strlen(tb->buf);
	else
		was_empty = 1;

	if (do_prefix)
		nlen += 8;

	nlen += strlen(output) + 1;

	if (was_empty)
		outbuf = xmalloc(nlen);
	else
		outbuf = xrealloc(tb->buf, nlen);

	if (!outbuf) {
		PRINT_ERROR("%s", "Error: unable to allocate memory for output buffer\n");
		return;
	}

	if (was_empty)
		strcpy(outbuf, output);
	else if (nest_level > tb->last_nested)
		nested = 1;
	else if (tb->last_nested > nest_level)
		nested = -1;
	else
		nested = 0;

	if (do_prefix) {
		if (nested > 0)
			strcat(outbuf, " -> ");
		else if (nested < 0)
			strcat(outbuf, " | ");
		else if (!was_empty)
			strcat(outbuf, ", ");
	}

	if (!was_empty)
		strcat(outbuf, output);

	if (!tb) {

		if (!(tb = malloc(sizeof(*tb)))) {
			PRINT_ERROR("%s", "Error: unable to allocate memory for output buffer");
			return;
		}

		memset(tb, 0, sizeof(thread_buffer_t));
		tb->tid = tid;
		tb->next = thread_buffers;
		thread_buffers = tb;
	}

	tb->buf = outbuf;
	tb->last_nested = nest_level;
	return;
}

char *
pop_output_data(pid_t tid)
{
	thread_buffer_t *tb;
	char *result;

	tb = thread_buffers;

	while (tb && (tb->tid != tid))
		tb = tb->next;

	if (!tb)
		result = NULL;
	else {
		result = tb->buf;
		tb->buf = NULL;
		tb->last_nested = 0;

/*		if (tb != thread_buffers) {
			tb->next = thread_buffers;
			thread_buffers = tb;
		} */

	}

	return result;
}

int lt_out_entry(struct lt_config_shared *cfg,
			struct timeval *tv, pid_t tid,
			int indent_depth, int collapsed,
			const char *symname, char *lib_to,
			char *lib_from, char *argbuf,
			char *argdbuf, size_t *nsuppressed)
{
	const char *cur_color = NULL;
	const char *end_line = "{\n";
	char to_buf[128], *outbuf = NULL;
	int buffered, has_args = 1;

//	fprintf(stderr, "lt_out_entry: %s / %d\n", symname, tid);

	memset(to_buf, 0, sizeof(to_buf));

	if (cfg->show_modules && lib_to && *lib_to)
		snprintf(to_buf, sizeof(to_buf), "%s:", lib_to);

	buffered = (collapsed > 0);

	/* Would probably be helpful to pre-allocate buffer for data and not constantly resize it */
/*	if (buffered) {
		outbuf = malloc(8192);
		memset(outbuf, 0, sizeof(outbuf));
	} */

	if (!symname && argbuf && *argbuf) {
		char *fmt_on = "", *fmt_off = "";

		if (cfg->timestamp && tv)
			FPRINT_TIME(tv);

		if (!cfg->hide_tid)
			FPRINT_TID(tid);
//		fprintf(cfg->fout, "%d ", indent_depth);
	indent_depth = 0;

		if (indent_depth && cfg->indent_sym)
			fprintf(cfg->fout, "%.*s", indent_depth * cfg->indent_size, spaces);

		if (cfg->fmt_colors) {
			fmt_on = BOLDRED;
			fmt_off = RESET;
		}

		fprintf(cfg->fout, "[%s%s%s]\n", fmt_on, argbuf, fmt_off);
		fflush(NULL);
		return 0;
	}

	if (collapsed && !symname) {
		(*nsuppressed)++;
		return 0;
	}

	if (collapsed == COLLAPSED_NESTED) {
		PRINT_DATA(buffered, "%s()", symname);

		if (outbuf) {
			buffer_output_data(tid, outbuf, indent_depth, 1);
			xfree(outbuf);
		}

		return 0;
	}

	if (cfg->timestamp && tv) {
		if (buffered)
			SPRINT_TIME(tv);
		else
			FPRINT_TIME(tv);
	}

	/* Print thread ID */
	if (!cfg->hide_tid) {
		if (buffered)
			SPRINT_TID(tid);
		else
			FPRINT_TID(tid);
	}
//		fprintf(cfg->fout, "%d ", indent_depth);

	/* Print indentation. */
	if (indent_depth && cfg->indent_sym) {

		if (cfg->fmt_colors)
			cur_color = color_table[indent_depth % (sizeof(color_table)/sizeof(color_table[0]))];

	indent_depth %= 40;
		PRINT_DATA(buffered, "%.*s", indent_depth * cfg->indent_size, spaces);
	}

	if (collapsed == COLLAPSED_BARE)
		end_line = "";
	else if (collapsed == COLLAPSED_TERSE)
		end_line = "";

	if (!strcmp(argbuf, " "))
		argbuf[0] = 0;
	else if (!*argbuf)
		has_args = 0;

	/* Print the symbol and arguments. */
	if (cur_color) {
		if (has_args)
			PRINT_DATA(buffered, "%s%s%s%s%s%s(%s%s%s) %s",
					RESET, to_buf, BOLD, cur_color, symname, RESET,
					cur_color, argbuf, RESET, end_line);
		else
			PRINT_DATA(buffered, "%s%s%s%s%s %c\n",
					RESET, to_buf, cur_color, symname, RESET, cfg->braces ? '{' : ' ');
	} else {
		if (has_args)
			PRINT_DATA(buffered, "%s(%s) %s", symname, argbuf, end_line);
		else
			PRINT_DATA(buffered, "%s %c\n",
					symname, cfg->braces ? '{' : ' ');
	}

	/* Print arguments' details. */
	if (cfg->args_detailed && *argdbuf)
		PRINT_DETAILS(buffered, argdbuf);

	fflush(NULL);

	if (outbuf) {
		buffer_output_data(tid, outbuf, indent_depth, 0);
		xfree(outbuf);
	}

	return 0;
}

int lt_out_exit(struct lt_config_shared *cfg,
			struct timeval *tv, pid_t tid,
			int indent_depth, int collapsed,
			const char *symname, char *lib_to,
			char *lib_from, char *argbuf,
			char *argdbuf, size_t *nsuppressed)
{
	const char *cur_color = NULL;
	char msgbuf[128];
	char *prefix;
	int exited = 0;

	if (!argbuf) {
		argbuf = "";
	}

	if (!strcmp(symname, "___________exit")) {
		snprintf(msgbuf, sizeof(msgbuf), "Thread exited: %d", tid);
		exited = 1;
	}

	if ((prefix = pop_output_data(tid))) {

		if (*nsuppressed) {
			char *label, *eol = "", *style_on = "", *style_off = "";

			if (prefix[strlen(prefix)-1] == '\n') {
				prefix[strlen(prefix)-1] = 0;
				eol = "\n";
			}

			label = *nsuppressed == 1 ? "suppression" : "suppressions";

			if (cfg->fmt_colors) {
				style_on = INVERT;
				style_off = INVOFF;
			}

			fprintf(cfg->fout, "%s %s{%zu %s}%s%s", prefix, style_on, *nsuppressed, label, style_off, eol);
		} else
			fprintf(cfg->fout, "%s", prefix);

		xfree(prefix);
		*nsuppressed = 0;
	}

	if (!*argbuf && (!cfg->braces))
		return 0;

	if (cfg->timestamp && tv)
		FPRINT_TIME(tv);

	/* Print thread ID */
	if ((!cfg->hide_tid) && (collapsed <= COLLAPSED_BASIC))
		FPRINT_TID(tid);

//	fprintf(cfg->fout, "%d ", indent_depth);

	/* Print indentation. */
	if (indent_depth && cfg->indent_sym) {

		if (cfg->fmt_colors)
			cur_color = color_table[indent_depth % (sizeof(color_table)/sizeof(color_table[0]))];

	indent_depth %= 40;
		if ((collapsed <= COLLAPSED_BASIC) && !exited)
			fprintf(cfg->fout, "%.*s", indent_depth * cfg->indent_size, spaces);
	}

	/* We got here, because we have '-B' option enabled. */
	if (!*argbuf && (cfg->braces)) {
		fprintf(cfg->fout, "}\n");
		return 0;
	}

#define EQ_NO_COLOR	" = "
#define EQ_ANSI		(" = "ULINEOFF)
	if (!strcmp(argbuf, EQ_NO_COLOR) || !strcmp(argbuf, EQ_ANSI))
		strcpy(argbuf, ";");

	if (exited) {
		if (cur_color)
			fprintf(cfg->fout, "%s%s%s%s\n", BOLD, RED, msgbuf, RESET);
		else
			fprintf(cfg->fout, "%s\n", msgbuf);
	}
	/* Print the symbol and arguments. */
	else if (collapsed <= COLLAPSED_BASIC) {
		if (cur_color)
			fprintf(cfg->fout, "} %s%s%s%s%s\n", BOLD, cur_color, symname, RESET, argbuf);
		else
			fprintf(cfg->fout, "} %s%s\n", symname, argbuf);
	} else if (collapsed >= COLLAPSED_TERSE) {
		if (cur_color)
			fprintf(cfg->fout, "%s%s%s%s\n", BOLD, cur_color, argbuf, RESET);
		else
			fprintf(cfg->fout, "%s\n", argbuf);
	}

	/* Print arguments' details. */
	if (cfg->args_detailed && *argdbuf)
		print_details(cfg, argdbuf);

	fflush(NULL);
	return 0;
}
