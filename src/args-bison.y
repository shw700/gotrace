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

%name-prefix "lt_args_"

%{

#define YYERROR_VERBOSE 1
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "lib-include.h"

int lt_args_lex(void);
void lt_args_error(const char *m);
void lt_null_parser(int do_ignore);

extern struct lt_enum *getenum(struct lt_config_shared *cfg, char *name);
extern struct lt_bm_enum *getenum_bm(struct lt_config_shared *cfg, char *name);
extern struct lt_arg* find_arg(struct lt_config_shared *cfg, const char *type,
				struct lt_arg argsdef[], int size, int create);

extern struct lt_arg args_def_pod[LT_ARGS_DEF_POD_NUM];


static struct lt_config_shared *scfg;
static int struct_alive = 0;
static int struct_empty = 1;
struct lt_include *lt_args_sinc;


#define ERROR(fmt, args...) \
do { \
	char ebuf[1024]; \
	sprintf(ebuf, fmt, ## args); \
	lt_args_error(ebuf); \
	YYERROR; \
} while(0)

#define GET_LIST_HEAD(head) \
do { \
 	if (NULL == (head = (struct lt_list_head*) malloc(sizeof(*head)))) \
		ERROR("failed to allocate list head"); \
	lt_init_list_head(head); \
} while(0)

%}


%token NEWLINE NAME TYPE_PREFIX FILENAME FUNC STRUCT CONST IMPORT DEFINITION CONDITIONAL COND_VAR COND_EXPR COND_VAL END POINTER SLICE IGNORE NOFUNC

%union
{
	char *s;
	int i;
	struct lt_arg *arg;
	struct lt_enum_elem *enum_elem;
	struct lt_bm_enum_elem *bm_enum_elem;
	struct lt_list_head *head;
}

%type <s>         NAME
%type <s>         NOFUNC
%type <s>         TYPE_PREFIX
%type <s>         FUNC
%type <s>         POINTER
%type <s>         FILENAME
%type <s>         NEWLINE
%type <s>         COND_VAR
%type <i>         COND_EXPR
%type <s>         COND_VAL
%type <head>      STRUCT_DEF
%type <head>      CONST_DEF
%type <s>         ENUM_REF
%type <enum_elem> CONST_ELEM
%type <head>      ARGS
%type <head>      XARGS
%type <arg>       DEF
%type <arg>       XDEF

%%
entry: 
entry blank_space
|
entry struct_def
|
entry pp_def
|
entry cond_clause
|
entry const_def
|
entry func_def
|
entry nofunc_def
|
entry import_def
|
entry END
{
	if (lt_inc_close(scfg, lt_args_sinc))
		return 0;
}
|
/* left blank intentionally */

blank_space:
NEWLINE
{
}

/* struct definitions */
struct_def:
STRUCT NAME '{' STRUCT_DEF '}' ';'
{
	int ret;

	if (struct_empty)
		ret = lt_args_add_struct(scfg, $2, NULL);
	else
		ret = lt_args_add_struct(scfg, $2, $4);

	struct_empty = 1;

	switch(ret) {
	case -1:
		ERROR("failed to add struct %s\n", $2);
	case 1:
		ERROR("struct limit reached(%d) - %s\n", LT_ARGS_DEF_STRUCT_NUM, $2);
	};

	/* force creation of the new list head */
	struct_alive = 0;
}

STRUCT_DEF:
STRUCT_DEF DEF ';'
{
	struct lt_arg *def     = $2;
	struct lt_list_head *h = $1;

	if (!struct_alive++)
		GET_LIST_HEAD(h);

	lt_list_add_tail(&def->args_list, h);
	$$ = h;
	struct_empty = 0;
}
| /* left blank intentionally,
     XXX this could be done like the args_def, but user needs to be 
     able to create an empty structure, so thats why we play 
     with the global struct_alive thingie... 
     there could be better way probably */
{
}

/* "preprocessor" definitions */
pp_def:
DEFINITION COND_VAR COND_VAL
{
	unsigned int vernum;

	if (strcmp($2, "GOVERSION"))
		ERROR("Unsupported conditional variable %s; only GOVERSION is currently supported\n", $2);

	free($2);

	if (!parse_golang_vernum($3, &vernum))
		ERROR("Invalid conditional value \"%s\"; must be a version number\n", $3);

	golang_bin_version = vernum;
	free($3);
}

/* conditional section */
cond_clause:
CONDITIONAL COND_VAR COND_EXPR COND_VAL
{
	unsigned int vernum = 0;
	int matches = 0;

	if (strcmp($2, "GOVERSION"))
		ERROR("Unsupported conditional variable %s; only GOVERSION is currently supported\n", $2);

	free($2);

	if (!parse_golang_vernum($4, &vernum))
		ERROR("Invalid conditional value \"%s\"; must be a version number\n", $4);

	free($4);

	switch($3) {
		case YY_PP_EQ:
			matches = golang_bin_version == vernum;
			break;
		case YY_PP_NE:
			matches = golang_bin_version != vernum;
			break;
		case YY_PP_LT:
			matches = golang_bin_version < vernum;
			break;
		case YY_PP_LTE:
			matches = golang_bin_version <= vernum;
			break;
		case YY_PP_GT:
			matches = golang_bin_version > vernum;
			break;
		case YY_PP_GTE:
			matches = golang_bin_version >= vernum;
			break;
		default:
			ERROR("Unsupported conditional expression type in comparison\n");
			break;
	}

	lt_null_parser(!matches);
}

/* enum definitions */
const_def:
CONST NAME '(' CONST_DEF ')'
{
	switch(lt_args_add_enum(scfg, $2, 0, $4)) {
	case -1:
		ERROR("failed to add const[1] %s\n", $2);
	case 1:
		ERROR("const limit reached(%d) - %s\n", LT_ARGS_DEF_STRUCT_NUM, $2);
	};
}

CONST_DEF:
CONST_DEF CONST_ELEM NEWLINE
{
	struct lt_enum_elem *enum_elem = $2;
	struct lt_list_head *h = $1;

	if (!h) {
		GET_LIST_HEAD(h);
	}
	if (enum_elem)
		lt_list_add_tail(&enum_elem->list, h);
	$$ = h;
}
| CONST_ELEM
{
	struct lt_list_head *h;
	struct lt_enum_elem *enum_elem = $1;

	if (enum_elem) {
		GET_LIST_HEAD(h);
		lt_list_add_tail(&enum_elem->list, h);
		$$ = h;
	} else {
		$$ = NULL;
	}
}

CONST_ELEM:
NAME '=' NAME
{
	char *startval = $3;

	if (!strcmp(startval, "iota"))
		startval = "0";

	if (NULL == ($$ = lt_args_get_enum(scfg, $1, startval)))
		ERROR("failed to add const[2] '%s = %s'\n", $1, startval);
}
|
NAME
{
	if (NULL == ($$ = lt_args_get_enum(scfg, $1, NULL)))
		ERROR("failed to add enum[3] '%s = undef'\n", $1);
}
|
EMPTY_COMMA
{
	$$ = NULL;
}


EMPTY_COMMA:
 /* empty */


/* function definitions */
nofunc_def:
NOFUNC
{
	char *openp, *ptr = $1;

	while (isspace(*ptr))
		ptr++;

	if ((openp = strchr(ptr, '('))) {
		char *close = strchr(openp, ')');

		if (close && !close[1])
			*openp = 0;
	}

	add_custom_exclusion(ptr);
}

func_def:
XDEF '(' ARGS ')' XARGS
{
	struct lt_arg *arg = $1;

	if (lt_args_add_sym2(scfg, arg, $3, $5, arg->collapsed, NULL))
		ERROR("failed to add symbol with multi-value return: %s\n", arg->name);

	// force creation of new list heads
	$3 = NULL;
	$5 = NULL;
}
|
XDEF '(' ARGS ')'
{
	struct lt_arg *arg = $1;

	if (lt_args_add_sym(scfg, arg, $3, arg->collapsed, NULL))
		ERROR("failed to add symbol %s\n", arg->name);

	/* force creation of the new list head */
	$3 = NULL;
}

XARGS:
'(' ARGS ')'
{
	$$ = $2;
}
|
ARGS
{
	$$ = $1;
}

ARGS:
ARGS ',' DEF
{
	struct lt_arg *def     = $3;
	struct lt_list_head *h = $1;

	if (def->multi_arg_next) {
		struct lt_arg *first = def, *second = def->multi_arg_next, *last = def;

		while (last->multi_arg_next)
			last = last->multi_arg_next;

		last->multi_arg_next = first;
		first->multi_arg_next = NULL;
		def = second;
	}

	lt_list_add_tail(&def->args_list, h);

	if (def->multi_arg_next) {
		struct lt_arg *argptr = def->multi_arg_next;

		while (argptr) {
			lt_list_add_tail(&argptr->args_list, h);
			argptr = argptr->multi_arg_next;
		}

	}
	$$ = h;
}
| DEF
{
	struct lt_list_head *h;
	struct lt_arg *def = $1;

	// Swap if necessary.
	if (def->multi_arg_next) {
		struct lt_arg *first = def, *second = def->multi_arg_next, *last = def;

		while (last->multi_arg_next)
			last = last->multi_arg_next;

		last->multi_arg_next = first;
		first->multi_arg_next = NULL;
		def = second;
	}

	GET_LIST_HEAD(h);
	lt_list_add_tail(&def->args_list, h);

	if (def->multi_arg_next) {
		struct lt_arg *argptr = def->multi_arg_next;

		while (argptr) {
			lt_list_add_tail(&argptr->args_list, h);
			argptr = argptr->multi_arg_next;
		}

	}

	$$ = h;
}
| NAME
{
	struct lt_list_head *h;
	struct lt_arg *arg = NULL;

	if (!getenum(scfg, $1)) {

		if (find_arg(scfg, $1, args_def_pod, LT_ARGS_DEF_POD_NUM, 0) == NULL) {

			if (NULL == (arg = lt_args_getarg(scfg, $1, ANON_PREFIX_INTERNAL, 0, 1, NULL))) {
				if (NULL == (arg = lt_args_getarg(scfg, "void", ANON_PREFIX_INTERNAL, 1, 1, NULL)))
					ERROR("unnamed variable of unknown type: %s\n", $1);
			}

			arg->real_type_name = strdup($1);

			GET_LIST_HEAD(h);
			lt_list_add_tail(&arg->args_list, h);
			$$ = h;
		} else {

			if (NULL == (arg = lt_args_getarg(scfg, $1, ANON_PREFIX_INTERNAL, 0, 1, NULL)))
				ERROR("unknown error parsing anonymous instance of type: %s\n", $1);

			arg->real_type_name = strdup($1);

			GET_LIST_HEAD($$);
			lt_list_add_tail(&arg->args_list, $$);
//			$$ = h;
		}

	} else {

		if (NULL == (arg = lt_args_getarg(scfg, "int", ANON_PREFIX_INTERNAL, 0, 1, $1)))
			ERROR("unknown error parsing anonymous enum instance of type: %s\n", $1);

		GET_LIST_HEAD(h);
		lt_list_add_tail(&arg->args_list, h);
		$$ = h;
	}

}
| /* left intentionally blank */
{
	GET_LIST_HEAD($$);
}

DEF:
NAME ',' DEF {
	struct lt_arg *dup_arg, *arg = $3;

	dup_arg = argdup(NULL, arg, $1);
	arg->multi_arg_next = dup_arg;

	$$ = arg;
}
|
NAME NAME ENUM_REF
{
	struct lt_arg *arg;

	if (NULL == (arg = lt_args_getarg(scfg, $2, $1, 0, 1, $3))) {
		if (getenum(scfg, $2) == NULL) {
			if (getenum_bm(scfg, $2) == NULL) {
				if (NULL == (arg = lt_args_getarg(scfg, "void", $1, 1 /*ptrno*/, 1, $3)))
					ERROR("unknown argument type[2A] - %s; possibly due to enum specification of \"%s\"\n", $2, $3);
				arg->real_type_name = strdup($2);
			}
		}

		if (!arg && (NULL == (arg = lt_args_getarg(scfg, "int", $1, 0, 1, $2))))
			ERROR("unknown argument type[2b] - %s; possibly due to enum specification of \"%s\"\n", $2, $3);
	}

	$$ = arg;
}
|
NAME POINTER NAME ENUM_REF
{
	struct lt_arg *arg;
	int ptrno = strlen($2);

	free($2);

	if (NULL == (arg = lt_args_getarg(scfg, $3, $1, ptrno, 1, $4))) {
		if (NULL == (arg = lt_args_getarg(scfg, "void", $1, ptrno, 1, $4)))
			ERROR("unknown argument type[3a] - %s\n", $3);
	}

	arg->real_type_name = strdup($3);
	$$ = arg;
}
|
NAME SLICE NAME
{
	struct lt_arg *arg;

	if (NULL == (arg = lt_args_getarg(scfg, $3, $1, -1 /* slice */, 1, NULL)))
		ERROR("unknown argument type[3b] - %s\n", $3);

	$$ = arg;
}
|
SLICE NAME
{
	struct lt_arg *arg;

	if (NULL == (arg = lt_args_getarg(scfg, $2, ANON_PREFIX_INTERNAL, -1 /* slice */, 1, NULL)))
		ERROR("unknown argument type[3c] - %s\n", $2);

	$$ = arg;
}
|
NAME
{
	struct lt_arg *arg;

	if (NULL == (arg = lt_args_getarg(scfg, $1, ANON_PREFIX_INTERNAL, 0, 1, NULL))) {
		if (NULL == (arg = lt_args_getarg(scfg, "void", ANON_PREFIX_INTERNAL, 1 /*ptrno*/, 1, NULL)))
			ERROR("unknown argument type[2AA] - %s\n", $1);
	}

	$$ = arg;
}
|
POINTER NAME
{
	struct lt_arg *arg;
	int ptrno = strlen($1);

	free($1);

	if (NULL == (arg = lt_args_getarg(scfg, $2, ANON_PREFIX_INTERNAL, ptrno, 1, NULL))) {
		if (NULL == (arg = lt_args_getarg(scfg, "void", ANON_PREFIX_INTERNAL, ptrno, 1, NULL)))
			ERROR("unknown argument type[7] - %s\n", $2);
	}

	arg->real_type_name = strdup($2);
	$$ = arg;
}
|
NAME '=' NAME NAME
{
	struct lt_arg *arg;

	if (NULL == (arg = lt_args_getarg(scfg, $1, $4, 0, 1, $3)))
		ERROR("unknown argument type[9] - %s; possibly due to enum specification of \"%s\"\n", $1, $3);

	$$ = arg;
}

ENUM_REF:
'=' NAME
{
	$$ = $2;
}
| 
{
	$$ = NULL;
}

/* import definitions */
import_def: IMPORT '"' FILENAME '"'
{
	if (lt_inc_open(scfg, lt_args_sinc, $3))
		ERROR("failed to process import: \"%s\"", $3);
}

XDEF:
FUNC NAME
{
	struct lt_arg *arg;

	if (NULL == (arg = lt_args_getarg(scfg, "void", $2, 0, 1, NULL)))
		ERROR("unknown argument type[2b] - %s\n", $2);

	$$ = arg;
}
|
FUNC TYPE_PREFIX NAME POINTER NAME ')' NAME
{
	struct lt_arg *arg;
	char fnamebuf[256], *fname;

	if (*($7) == '.')
		($7)++;

	snprintf(fnamebuf, sizeof(fnamebuf), "%s*%s).%s", $2, $5, $7);
	fname = strdup(fnamebuf);

	if (NULL == (arg = lt_args_getarg(scfg, "void", fname, 0, 1, NULL)))
		ERROR("unknown argument type[2b] - %s\n", fname);

	free($2);
	$$ = arg;
}
|
FUNC TYPE_PREFIX POINTER NAME ')' NAME
{
	struct lt_arg *arg;
	char fnamebuf[256], *fname;

	if (*($6) == '.')
		($6)++;

	snprintf(fnamebuf, sizeof(fnamebuf), "%s*%s).%s", $2, $4, $6);
	fname = strdup(fnamebuf);

	if (NULL == (arg = lt_args_getarg(scfg, "void", fname, 0, 1, NULL)))
		ERROR("unknown argument type[2b] - %s\n", fname);

	free($2);
	$$ = arg;
}


%%

int lt_args_parse_init(struct lt_config_shared *cfg, struct lt_include *inc)
{
	scfg = cfg;
	lt_args_sinc = inc;
	return 0;
}
