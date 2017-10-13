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

extern struct lt_enum *getenum(struct lt_config_shared *cfg, char *name);
extern struct lt_bm_enum *getenum_bm(struct lt_config_shared *cfg, char *name);
extern struct lt_arg* find_arg(struct lt_config_shared *cfg, const char *type,
				struct lt_arg argsdef[], int size, int create);

extern struct lt_arg args_def_pod[LT_ARGS_DEF_POD_NUM];


static struct lt_config_shared *scfg;
static int struct_alive = 0;
static int struct_empty = 1;
struct lt_include *lt_args_sinc;

const char *typedef_mapping_table[12][2] =
{
	{ "byte", "uint8" },
	{ "rune", "int32" },
};

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


%token NEWLINE NAME FILENAME FUNC STRUCT CONST IMPORT END POINTER ATTRIBUTE

%union
{
	char *s;
	struct lt_arg *arg;
	struct lt_enum_elem *enum_elem;
	struct lt_bm_enum_elem *bm_enum_elem;
	struct lt_list_head *head;
}

%type <s>         NAME
%type <s>         VAR_NAME
%type <s>         POINTER
%type <s>         FILENAME
%type <s>         NEWLINE
%type <head>      STRUCT_DEF
%type <head>      CONST_DEF
%type <s>         ENUM_REF
%type <enum_elem> CONST_ELEM
%type <head>      ARGS
%type <arg>       DEF
%type <arg>       XDEF

%%
entry: 
entry blank_space
|
entry struct_def
|
entry enum_def
|
entry func_def
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

/* enum definitions */
enum_def:
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
func_def:
XDEF '(' ARGS ')' '(' VAR_NAME ',' VAR_NAME ')'
{
	struct lt_arg **mret;
	struct lt_arg *farg = $1, *arg, *arg2;

	// Now handle the return type
	if (!(arg = find_arg(scfg, $6, args_def_pod, LT_ARGS_DEF_POD_NUM, 0))) {

		if (!(arg = lt_args_getarg(scfg, "void", ANON_PREFIX, 1, 1, NULL))) {
			ERROR("unknown error[1] parsing return variable of type: %s\n", $6);
		}
	} else {
		arg = lt_args_getarg(scfg, $6, "ret", 0, 1, NULL);
	}

	if (!arg) {
			ERROR("unknown error[2] parsing return variable of type: %s\n", $6);
	}

	// Do the same for the next argument.
	// XXX: This code needs to be made n-ary capable.

	if (!(arg2 = find_arg(scfg, $8, args_def_pod, LT_ARGS_DEF_POD_NUM, 0))) {

		if (!(arg2 = lt_args_getarg(scfg, "void", ANON_PREFIX, 1, 1, NULL))) {
			ERROR("unknown error[1] parsing return variable of type: %s\n", $8);
		}
	} else {
		arg2 = lt_args_getarg(scfg, $8, "ret2", 0, 1, NULL);
	}

	if (!arg2) {
			ERROR("unknown error[2.2] parsing return variable of type: %s\n", $8);
	}

	mret = (struct lt_arg **)malloc(sizeof(*mret) * 2);
	memset(mret, 0, sizeof(*mret)*2);
	mret[0] = arg2;


	// Swap the first argument with the last
	// But we do need to preserve some information first
	arg->name ? free(arg->name) : arg->name;
	arg->fmt ? free(arg->fmt) : arg->fmt;
	arg->bitmask_class ? free(arg->bitmask_class) : arg->bitmask_class;

	arg->name = farg->name;
	arg->fmt = farg->fmt;
	arg->bitmask_class = farg->bitmask_class;
	arg->collapsed = farg->collapsed;
	arg->latrace_custom_struct_transformer = farg->latrace_custom_struct_transformer;
	arg->latrace_custom_func_transformer = farg->latrace_custom_func_transformer;
	arg->latrace_custom_func_intercept = farg->latrace_custom_func_intercept;

	free(farg);
	farg = arg;

	if (lt_args_add_sym_mret(scfg, arg, mret, $3, arg->collapsed))
		ERROR("failed to add symbol %s\n", arg->name);

	// force creation of the new list head
	$3 = NULL;
}
|
XDEF '(' ARGS ')' VAR_NAME
{
	struct lt_arg *farg = $1, *arg;

	// Now handle the return type
	if (!(arg = find_arg(scfg, $5, args_def_pod, LT_ARGS_DEF_POD_NUM, 0))) {

		if (!(arg = lt_args_getarg(scfg, "void", ANON_PREFIX, 1, 1, NULL))) {
			ERROR("unknown error[1] parsing return variable of type: %s\n", $5);
		}
	} else {
		arg = lt_args_getarg(scfg, $5, "ret", 0, 1, NULL);
	}

	if (!arg) {
			ERROR("unknown error[2] parsing return variable of type: %s\n", $5);
	}


	// Swap the first argument with the last
	// But we do need to preserve some information first
	arg->name ? free(arg->name) : arg->name;
	arg->fmt ? free(arg->fmt) : arg->fmt;
	arg->bitmask_class ? free(arg->bitmask_class) : arg->bitmask_class;

	arg->name = farg->name;
	arg->fmt = farg->fmt;
	arg->bitmask_class = farg->bitmask_class;
	arg->collapsed = farg->collapsed;
	arg->latrace_custom_struct_transformer = farg->latrace_custom_struct_transformer;
	arg->latrace_custom_func_transformer = farg->latrace_custom_func_transformer;
	arg->latrace_custom_func_intercept = farg->latrace_custom_func_intercept;

	arg->real_type_name = strdup($5);

	free(farg);
	farg = arg;

	if (lt_args_add_sym(scfg, arg, $3, arg->collapsed, NULL))
		ERROR("failed to add symbol %s\n", arg->name);

	// force creation of the new list head
	$3 = NULL;
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

ARGS:
ARGS ',' DEF
{
	struct lt_arg *def     = $3;
	struct lt_list_head *h = $1;

	lt_list_add_tail(&def->args_list, h);
	$$ = h;
}
| DEF
{
	struct lt_list_head *h;
	struct lt_arg *def = $1;

	GET_LIST_HEAD(h);
	lt_list_add_tail(&def->args_list, h);
	$$ = h;
}
| NAME
{
	struct lt_list_head *h;
	struct lt_arg *arg = NULL;

	if (!getenum(scfg, $1)) {

		if (find_arg(scfg, $1, args_def_pod, LT_ARGS_DEF_POD_NUM, 0) == NULL) {

			if (NULL == (arg = lt_args_getarg(scfg, $1, ANON_PREFIX, 0, 1, NULL)))
				ERROR("unnamed variable of unknown type: %s\n", $1);

			GET_LIST_HEAD(h);
			lt_list_add_tail(&arg->args_list, h);
			$$ = h;
		} else {
			GET_LIST_HEAD($$);
		}

	} else {

		if (NULL == (arg = lt_args_getarg(scfg, "int", ANON_PREFIX, 0, 1, $1)))
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
NAME NAME ENUM_REF
{
	struct lt_arg *arg;

	if (NULL == (arg = lt_args_getarg(scfg, $2, $1, 0, 1, $3))) {
		if (getenum(scfg, $2) == NULL) {
			if (getenum_bm(scfg, $2) == NULL) {
				if (NULL == (arg = lt_args_getarg(scfg, "void", $1, 1 /*ptrno*/, 1, $3))) {
					ERROR("unknown argument type[2A] - %s; possibly due to enum specification of \"%s\"\n", $2, $3);
				}
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
			ERROR("unknown argument type[3] - %s\n", $3);
	}

	arg->real_type_name = strdup($3);
	$$ = arg;
}
|
NAME
{
	struct lt_arg *arg;

	if (NULL == (arg = lt_args_getarg(scfg, $1, ANON_PREFIX, 0, 1, NULL))) {

		if (getenum(scfg, $1) == NULL)
			ERROR("unknown argument type[6a] - %s\n", $1);

		if (NULL == (arg = lt_args_getarg(scfg, "int", ANON_PREFIX, 0, 1, $1)))
			ERROR("unknown argument type[6b] - %s\n", $1);

	}

	$$ = arg;
}
|
NAME POINTER
{
	struct lt_arg *arg;
	int ptrno = strlen($2);

	free ($2);

	if (NULL == (arg = lt_args_getarg(scfg, $1, ANON_PREFIX, ptrno, 1, NULL))) {
		if (NULL == (arg = lt_args_getarg(scfg, "void", ANON_PREFIX, ptrno, 1, NULL)))
			ERROR("unknown argument type[7] - %s\n", $1);
	}

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
NAME NAME ENUM_REF
{

	if (!strcmp($1, "func"))
		$1 = "void";

	struct lt_arg *arg;

	if (NULL == (arg = lt_args_getarg(scfg, $1, $2, 0, 1, $3))) {
		if (getenum(scfg, $1) == NULL) {
			if (getenum_bm(scfg, $1) == NULL)
				ERROR("unknown argument type[2a] - %s; possibly due to enum specification of \"%s\"\n", $1, $3);
		}

		if (NULL == (arg = lt_args_getarg(scfg, "int", $2, 0, 1, $1)))
			ERROR("unknown argument type[2b] - %s; possibly due to enum specification of \"%s\"\n", $1, $3);
	}

	$$ = arg;
}
|
NAME POINTER NAME ENUM_REF
{
	struct lt_arg *arg;
	int ptrno = strlen($2);

	free($2);

	if (NULL == (arg = lt_args_getarg(scfg, $1, $3, ptrno, 1, $4))) {
		if (NULL == (arg = lt_args_getarg(scfg, "void", $3, ptrno, 1, $4)))
			ERROR("unknown argument type[3] - %s\n", $1);
	}

	$$ = arg;
}
|
NAME
{
	struct lt_arg *arg;

	if (NULL == (arg = lt_args_getarg(scfg, $1, ANON_PREFIX, 0, 1, NULL))) {

		if (getenum(scfg, $1) == NULL)
			ERROR("unknown argument type[6a] - %s\n", $1);

		if (NULL == (arg = lt_args_getarg(scfg, "int", ANON_PREFIX, 0, 1, $1)))
			ERROR("unknown argument type[6b] - %s\n", $1);

	}

	$$ = arg;
}
|
NAME POINTER
{
	struct lt_arg *arg;
	int ptrno = strlen($2);

	free ($2);

	if (NULL == (arg = lt_args_getarg(scfg, $1, ANON_PREFIX, ptrno, 1, NULL))) {
		if (NULL == (arg = lt_args_getarg(scfg, "void", ANON_PREFIX, ptrno, 1, NULL)))
			ERROR("unknown argument type[7] - %s\n", $1);
	}

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

VAR_NAME:
NAME
{
	$$ = $1;
}
|
POINTER NAME
{
	$$ = $2;
}

%%

int lt_args_parse_init(struct lt_config_shared *cfg, struct lt_include *inc)
{
	scfg = cfg;
	lt_args_sinc = inc;
	return 0;
}
