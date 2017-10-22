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


#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <search.h>
#include <setjmp.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>

#include "config.h"
#include "lib-include.h"
#include "elfh.h"

#include "gomod_print/gomod_print.h"

#define LT_EQUAL           " = "

extern int errno;
extern FILE *lt_args_in;
extern struct hsearch_data args_struct_xfm_tab, args_func_xfm_tab, args_func_intercept_tab;
int  lt_args_parse();
void lt_args__switch_to_buffer (YY_BUFFER_STATE new_buffer  );
void lt_args__delete_buffer (YY_BUFFER_STATE b  );
YY_BUFFER_STATE lt_args__create_buffer (FILE *file,int size  );

static struct lt_include inc = {
	.create_buffer    = lt_args__create_buffer,
	.switch_to_buffer = lt_args__switch_to_buffer,
	.delete_buffer    = lt_args__delete_buffer,
	.in               = &lt_args_in,
};

int lt_args_parse_init(struct lt_config_shared *cfg, struct lt_include *inc);

static int enum_init = 0;
static int enum_bm_init = 0;

static struct lt_config_shared *bm_config = NULL;


/* hardcoded POD types */
struct lt_arg args_def_pod[LT_ARGS_DEF_POD_NUM] = {
	{
		.dtype     = LT_ARGS_DTYPE_POD, 
		.type_id   = LT_ARGS_TYPEID_VOID,
		.type_len  = sizeof(void),
		.type_name = "void",
		.pointer   = 0,
		.name      = "",
		.mmbcnt    = 0,
                .arch      = NULL,
		.en        = NULL,
		.args_head = NULL,
		.args_list = { NULL, NULL }
	},
	{
		.dtype     = LT_ARGS_DTYPE_POD, 
		.type_id   = LT_ARGS_TYPEID_INT16,
		.type_len  = sizeof(int16_t),
		.type_name = "int16",
		.pointer   = 0,
		.name      = "",
		.mmbcnt    = 0,
                .arch      = NULL,
		.en        = NULL,
		.args_head = NULL,
		.args_list = { NULL, NULL }
	},
	{
		.dtype     = LT_ARGS_DTYPE_POD, 
		.type_id   = LT_ARGS_TYPEID_UINT16,
		.type_len  = sizeof(uint16_t),
		.type_name = "uint16",
		.pointer   = 0,
		.name      = "", 
		.mmbcnt    = 0,
                .arch      = NULL,
		.en        = NULL,
		.args_head = NULL,
		.args_list = { NULL, NULL }
	},
	{
		.dtype     = LT_ARGS_DTYPE_POD, 
		.type_id   = LT_ARGS_TYPEID_INT,
		.type_len  = sizeof(int64_t),
		.type_name = "int",
		.pointer   = 0,
		.name      = "",
		.mmbcnt    = 0,
                .arch      = NULL,
		.en        = NULL,
		.args_head = NULL,
		.args_list = { NULL, NULL }
	},
	{
		.dtype     = LT_ARGS_DTYPE_POD, 
		.type_id   = LT_ARGS_TYPEID_INT32,
		.type_len  = sizeof(int32_t),
		.type_name = "int32",
		.pointer   = 0,
		.name      = "",
		.mmbcnt    = 0,
                .arch      = NULL,
		.en        = NULL,
		.args_head = NULL,
		.args_list = { NULL, NULL }
	},
	{
		.dtype     = LT_ARGS_DTYPE_POD, 
		.type_id   = LT_ARGS_TYPEID_UINT,
		.type_len  = sizeof(uint64_t),
		.type_name = "uint",
		.pointer   = 0,
		.name      = "",
		.mmbcnt    = 0,
                .arch      = NULL,
		.en        = NULL,
		.args_head = NULL,
		.args_list = { NULL, NULL }
	},
	{
		.dtype     = LT_ARGS_DTYPE_POD, 
		.type_id   = LT_ARGS_TYPEID_UINT32,
		.type_len  = sizeof(uint32_t),
		.type_name = "uint32",
		.pointer   = 0,
		.name      = "",
		.mmbcnt    = 0,
                .arch      = NULL,
		.en        = NULL,
		.args_head = NULL,
		.args_list = { NULL, NULL }
	},
	{
		.dtype     = LT_ARGS_DTYPE_POD, 
		.type_id   = LT_ARGS_TYPEID_INT64,
		.type_len  = sizeof(int64_t),
		.type_name = "int64",
		.pointer   = 0,
		.name      = "",
		.mmbcnt    = 0,
                .arch      = NULL,
		.en        = NULL,
		.args_head = NULL,
		.args_list = { NULL, NULL }
	},
	{
		.dtype     = LT_ARGS_DTYPE_POD, 
		.type_id   = LT_ARGS_TYPEID_UINT64,
		.type_len  = sizeof(uint64_t),
		.type_name = "uint64",
		.pointer   = 0,
		.name      = "",
		.mmbcnt    = 0,
                .arch      = NULL,
		.en        = NULL,
		.args_head = NULL,
		.args_list = { NULL, NULL }
	},
	{
		.dtype     = LT_ARGS_DTYPE_POD, 
		.type_id   = LT_ARGS_TYPEID_CHAR,
		.type_len  = sizeof(char),
		.type_name = "char",
		.pointer   = 0,
		.name      = "",
		.mmbcnt    = 0,
                .arch      = NULL,
		.en        = NULL,
		.args_head = NULL,
		.args_list = { NULL, NULL }
	},
	{
		.dtype     = LT_ARGS_DTYPE_POD,
		.type_id   = LT_ARGS_TYPEID_INT8,
		.type_len  = sizeof(int8_t),
		.type_name = "int8",
		.pointer   = 0,
		.name      = "",
		.mmbcnt    = 0,
                .arch      = NULL,
		.en        = NULL,
		.args_head = NULL,
		.args_list = { NULL, NULL }
	},
	{
		.dtype     = LT_ARGS_DTYPE_POD, 
		.type_id   = LT_ARGS_TYPEID_UINT8,
		.type_len  = sizeof(uint8_t),
		.type_name = "uint8",
		.pointer   = 0,
		.name      = "",
		.mmbcnt    = 0,
                .arch      = NULL,
		.en        = NULL,
		.args_head = NULL,
		.args_list = { NULL, NULL }
	},
	{
		.dtype     = LT_ARGS_DTYPE_POD, 
		.type_id   = LT_ARGS_TYPEID_STRING,
		.type_len  = sizeof(char),
		.type_name = "string",
		.pointer   = 1,
		.name      = "",
		.mmbcnt    = 0,
                .arch      = NULL,
		.en        = NULL,
		.args_head = NULL,
		.args_list = { NULL, NULL }
	},
	{
		.dtype     = LT_ARGS_DTYPE_POD, 
		.type_id   = LT_ARGS_TYPEID_BOOL,
		.type_len  = sizeof(unsigned char),
		.type_name = "bool",
		.pointer   = 0,
		.name      = "",
		.mmbcnt    = 0,
                .arch      = NULL,
		.en        = NULL,
		.args_head = NULL,
		.args_list = { NULL, NULL }
	},
	{
		.dtype     = LT_ARGS_DTYPE_POD, 
		.type_id   = LT_ARGS_TYPEID_LLONG,
		.type_len  = sizeof(long long),
		.type_name = "llong",
		.pointer   = 0,
		.name      = "",
		.mmbcnt    = 0,
                .arch      = NULL,
		.en        = NULL,
		.args_head = NULL,
		.args_list = { NULL, NULL }
	},
	{
		.dtype     = LT_ARGS_DTYPE_POD, 
		.type_id   = LT_ARGS_TYPEID_ULLONG,
		.type_len  = sizeof(unsigned long long),
		.type_name = "u_llong",
		.pointer   = 0,
		.name      = "",
		.mmbcnt    = 0,
                .arch      = NULL,
		.en        = NULL,
		.args_head = NULL,
		.args_list = { NULL, NULL }
	},
	{
		.dtype     = LT_ARGS_DTYPE_POD, 
		.type_id   = LT_ARGS_TYPEID_DOUBLE,
		.type_len  = sizeof(double),
		.type_name = "double",
		.pointer   = 0,
		.name      = "",
		.mmbcnt    = 0,
                .arch      = NULL,
		.en        = NULL,
		.args_head = NULL,
		.args_list = { NULL, NULL }
	},
	{
		.dtype     = LT_ARGS_DTYPE_POD, 
		.type_id   = LT_ARGS_TYPEID_FLOAT,
		.type_len  = sizeof(float),
		.type_name = "float",
		.pointer   = 0,
		.name      = "",
		.mmbcnt    = 0,
                .arch      = NULL,
		.en        = NULL,
		.args_head = NULL,
		.args_list = { NULL, NULL }
	},
	{
		.dtype     = LT_ARGS_DTYPE_POD, 
		.type_id   = LT_ARGS_TYPEID_UINTPTR,
		.type_len  = sizeof(uintptr_t),
		.type_name = "uintptr",
		.pointer   = 0,
		.name      = "",
		.mmbcnt    = 0,
                .arch      = NULL,
		.en        = NULL,
		.args_head = NULL,
		.args_list = { NULL, NULL }
	},
	{
		.dtype     = LT_ARGS_DTYPE_POD,
		.type_id   = LT_ARGS_TYPEID_FNPTR,
		.type_len  = sizeof(void *),
		.type_name = "pfn",
		.pointer   = 1,
		.name      = "",
		.mmbcnt    = 0,
                .arch      = NULL,
		.en        = NULL,
		.args_head = NULL,
		.args_list = { NULL, NULL }
	},
	{
		.dtype     = LT_ARGS_DTYPE_POD,
		.type_id   = LT_ARGS_TYPEID_USER_DEF,
		.type_len  = sizeof(void *),
		.type_name = "custom_user_struct_transformer",
		.pointer   = 0,
		.name      = "",
		.mmbcnt    = 0,
                .arch      = NULL,
		.en        = NULL,
		.args_head = NULL,
		.args_list = { NULL, NULL }
	}
};


/* struct, typedef, enum */
static struct lt_arg args_def_struct[LT_ARGS_DEF_STRUCT_NUM];
static struct lt_arg args_def_typedef[LT_ARGS_DEF_TYPEDEF_NUM];
static int args_def_struct_cnt  = 0;
static int args_def_typedef_cnt = 0;
static struct hsearch_data args_enum_tab;
static struct hsearch_data args_enum_bm_tab;


struct lt_enum* getenum(struct lt_config_shared *cfg, char *name)
{
	struct lt_enum *en;
	ENTRY e, *ep;

	if (!enum_init) {
		if (cfg)
			PRINT_VERBOSE(cfg, 1, "request for <%s> but no enum added so far\n", name);

		return NULL;
	}

	PRINT_VERBOSE(cfg, 1, "request for <%s>\n", name);

	e.key = name;
	hsearch_r(e, FIND, &ep, &args_enum_tab);

	if (!ep) {
		PRINT_VERBOSE(cfg, 1, "failed to find enum <%s>\n", name);
		return NULL;
	}

	en = (struct lt_enum*) ep->data;

	PRINT_VERBOSE(cfg, 1, "found %p <%s>\n", en, en->name);
	return en;
}

struct lt_enum_bm *getenum_bm(struct lt_config_shared *cfg, char *name)
{
	struct lt_enum_bm *en;
	ENTRY e, *ep;

	if (!enum_bm_init) {
		if (cfg)
			PRINT_VERBOSE(cfg, 1, "request for <%s> but no enum_bm added so far\n", name);

		return NULL;
	}

	PRINT_VERBOSE(cfg, 1, "request for <%s>\n", name);

	e.key = name;
	hsearch_r(e, FIND, &ep, &args_enum_bm_tab);

	if (!ep) {
		PRINT_VERBOSE(cfg, 1, "failed to find enum_bm <%s>\n", name);
		return NULL;
	}

	en = (struct lt_enum_bm *)ep->data;

	PRINT_VERBOSE(cfg, 1, "found %p <%s>\n", en, en->name);
	return en;
}

char *lookup_bitmask_by_class(struct lt_config_shared *cfg, const char *class, unsigned long val, const char *fmt, char *outbuf, size_t bufsize) {
	unsigned long left = val;
	struct lt_enum_bm *enum_bm;
	struct lt_enum* _enum = NULL;

	if (!class)
		goto left;

	if (!cfg)
		cfg = bm_config;

	memset(outbuf, 0, bufsize);

	enum_bm = getenum_bm(cfg, (char *)class);

	if (!enum_bm)
		_enum = getenum(cfg, (char *)class);

	if (enum_bm) {
		size_t i;

		for(i = 0; i < enum_bm->cnt; i++) {
			struct lt_enum_bm_elem *elem = &enum_bm->elems[i];

			if (elem->val == val) {
				strncpy(outbuf, elem->name, bufsize);
				left = 0;
				break;
			}

			if (elem->val && (left >= elem->val) && ((left & elem->val) == elem->val)) {
				size_t cleft = bufsize - (strlen(outbuf) + 1);

				if (outbuf[0]) {
					strncat(outbuf, "|", cleft);
					cleft--;
				}

				strncat(outbuf, elem->name, cleft);
				left &= ~(elem->val);
			} else if ((val == 0) && (elem->val == 0)) {
				strncpy(outbuf, elem->name, bufsize);
				break;
			}

		}

	} else if (_enum) {
		size_t i;

		for(i = 0; i < _enum->cnt; i++) {
			struct lt_enum_elem *elem = &_enum->elems[i];

			if (elem->val && (left >= elem->val) && ((left & elem->val) == elem->val)) {
				size_t cleft = bufsize - (strlen(outbuf) + 1);

				if (outbuf[0]) {
					strncat(outbuf, "|", cleft);
					cleft--;
				}

				strncat(outbuf, elem->name, cleft);
				left &= ~(elem->val);
			} else if ((val == 0) && (elem->val == 0)) {
				strncpy(outbuf, elem->name, bufsize);
				break;
			}

		}

	}


left:
	if (left) {
		size_t cleft = bufsize - (strlen(outbuf) + 1);
		char tmpbuf[32];

		if (outbuf[0]) {
			strncat(outbuf, "|", cleft);
			cleft--;
		}

		if (fmt && !strcmp(fmt, "o"))
			sprintf(tmpbuf, "0%o", (unsigned int)left);
		else if (fmt && !strcmp(fmt, "d"))
			sprintf(tmpbuf, "%d", (int)left);
		else if (fmt && !strcmp(fmt, "u"))
			sprintf(tmpbuf, "%u", (unsigned int)left);
		else
			sprintf(tmpbuf, "0x%x", (unsigned int) left);

		if (!outbuf[0])
			strncpy(outbuf, tmpbuf, bufsize);
		else
			strncat(outbuf, tmpbuf, cleft);
		
	}

	/* Make sure we report a plain old zero */
	if (!val && !outbuf[0])
		outbuf[0] = '0';

	return outbuf;
} 

static int enum_comp(const void *ep1, const void *ep2)
{
	struct lt_enum_elem *e1 = (struct lt_enum_elem*) ep1;
	struct lt_enum_elem *e2 = (struct lt_enum_elem*) ep2;

	return e1->val - e2->val;
}

static int enum_bm_comp(const void *ep1, const void *ep2)
{
	struct lt_enum_bm_elem *e1 = (struct lt_enum_bm_elem*) ep1;
	struct lt_enum_bm_elem *e2 = (struct lt_enum_bm_elem*) ep2;

	return e1->val - e2->val;
}

static struct lt_enum_elem* get_enumelem(struct lt_config_shared *cfg,
	long val, struct lt_enum *en)
{
	struct lt_enum_elem key;
	key.val = val;

	PRINT_VERBOSE(cfg, 1, "looking for %p <%s> value %ld\n",
			en, en->name, val);

	return bsearch(&key, en->elems, en->cnt, 
		sizeof(struct lt_enum_elem), enum_comp);
}

static struct lt_enum_elem* find_enumelem(struct lt_config_shared *cfg,
	char *name, struct lt_enum *en)
{
	struct lt_enum_elem *elem;
	int i;

	for(i = 0; i < en->cnt; i++) {
		elem = &en->elems[i];

		if (!strcmp(elem->name, name))
			return elem;
	}

	return NULL;
}

int lt_args_add_enum(struct lt_config_shared *cfg, char *name,
			int bitmask, struct lt_list_head *h)
{
	ENTRY e, *ep;
	struct lt_enum_elem *elem, *last = NULL;
	struct lt_enum *en;
	int i = 0, reverted = 0;

	XMALLOC_ASSIGN(en, sizeof(*en));
	if (!en)
		return -1;

	memset(en, 0x0, sizeof(*en));
	en->name = name;
	en->bitmask = bitmask;

	/* Initialize the hash table holding enum names */
	if (!enum_init) {
	        if (!hcreate_r(LT_ARGS_DEF_ENUM_NUM, &args_enum_tab)) {
	                PERROR("failed to create hash table:");
			XFREE(en);
	                return -1;
	        }
		enum_init = 1;
		bm_config = cfg;
	}

	e.key = en->name;
	e.data = en;

	if (!hsearch_r(e, ENTER, &ep, &args_enum_tab)) {
		PERROR("hsearch_r failed");
		XFREE(en);
		return 1;
	}

	/* We've got enum inside the hash, let's prepare the enum itself.
	   The 'elems' field is going to be the qsorted list of 
	   'struct enum_elem's */
	lt_list_for_each_entry(elem, h, list)
		en->cnt++;

	XMALLOC_ASSIGN(en->elems, sizeof(struct lt_enum_elem) * en->cnt);
	if (!en->elems)
		return -1;

	PRINT_VERBOSE(cfg, 3, "enum %s (%d elems) not fixed\n",
			en->name, en->cnt);

	/*
	 * The enum element can be:
	 *
	 * 1) defined
	 * 2) undefined
	 * 3) defined via string reference
	 *
	 * ad 1) no work
	 * ad 2) value of previous element is used
	 * ad 3) we look for the string reference in defined elements' names
	 *
	 * This being said, following actions will happen now:
	 *
	 * - copy all the values to the prepared array
	 * - fix the values based on the above
	 * - sort the array
	 */

	lt_list_for_each_entry(elem, h, list) {

		PRINT_VERBOSE(cfg, 3, "\t %s = %d/%s\n",
			elem->name, elem->val, elem->strval);

		en->elems[i++] = *elem;
	}

	PRINT_VERBOSE(cfg, 3, "enum %s (%d elems) fixed\n",
			en->name, en->cnt);

	/* fixup values */
	for(i = 0; i < en->cnt; i++) {
		char *this_fmt = NULL;
		elem = &en->elems[i];

		if (elem->base == 16)
			this_fmt = "x";
		else if (elem->base == 8)
			this_fmt = "o";
		else if (elem->base == -10)
			this_fmt = "d";

		if (!en->fmt && elem->base != 10) {
			en->fmt = this_fmt;
		} else if (!reverted && en->fmt && en->fmt != this_fmt) {
			if (strcmp(en->fmt, "d") && this_fmt != NULL) {
				PRINT_ERROR("Warning: enum type %s had values with multiple bases; reverting to hexadecimal.\n", name);
				this_fmt = "x";
				reverted = 1;
			}
		}

		if (!elem->undef) {
			last = elem;
			continue;
		}

		if (elem->strval) {
			/* undefined text value, try to find it in
			 * previous enum definitions */

			struct lt_enum_elem *e;

			e = find_enumelem(cfg, elem->strval, en);
			if (!e) {
				PRINT_ERROR("failed to find '%s=%s' enum definition\n",
				       elem->name, elem->strval);
				return -1;
			}

			elem->val = e->val;

		} else {
			/* undefined value -> take last defined + 1 */
			if (!last)
				elem->val = 0;
			else
				elem->val = last->val + 1;
		}

		PRINT_VERBOSE(cfg, 3, "\t %s = %d\n",
			elem->name, elem->val);

		last = elem;
	}

	/* finally sort the array */
	qsort(en->elems, en->cnt, sizeof(struct lt_enum_elem), enum_comp);
	return 0;
}

int lt_args_add_enum_bm(struct lt_config_shared *cfg, char *name, 
			struct lt_list_head *h)
{
	ENTRY e, *ep;
	struct lt_enum_bm_elem *elem;
	struct lt_enum_bm *en;
	int i = 0;

	XMALLOC_ASSIGN(en, sizeof(*en));
	if (!en)
		return -1;

	memset(en, 0x0, sizeof(*en));
	en->name = name;

	/* Initialize the hash table holding enum names */
	if (!enum_bm_init) {
	        if (!hcreate_r(LT_ARGS_DEF_ENUM_NUM, &args_enum_bm_tab)) {
	                PERROR("failed to create hash table:");
			XFREE(en);
	                return -1;
	        }
		enum_bm_init = 1;
		bm_config = cfg;
	}

	e.key = en->name;
	e.data = en;

	if (!hsearch_r(e, ENTER, &ep, &args_enum_bm_tab)) {
		PERROR("hsearch_r failed");
		XFREE(en);
		return 1;
	}

	/* We've got enum inside the hash, let's prepare the enum itself.
	   The 'elems' field is going to be the qsorted list of 
	   'struct enum_elem's */
	lt_list_for_each_entry(elem, h, list)
		en->cnt++;

	XMALLOC_ASSIGN(en->elems, sizeof(struct lt_enum_bm_elem) * en->cnt);
	if (!en->elems)
		return -1;

	PRINT_VERBOSE(cfg, 3, "enum_bm %s (%d elems) not fixed\n",
			en->name, en->cnt);

	lt_list_for_each_entry(elem, h, list) {

		PRINT_VERBOSE(cfg, 3, "\t %s = %d\n", elem->name, elem->val);

		en->elems[i++] = *elem;
	}

	PRINT_VERBOSE(cfg, 3, "enum_bm %s (%d elems) fixed\n",
			en->name, en->cnt);

	/* fixup values */
	for(i = 0; i < en->cnt; i++)
		elem = &en->elems[i];

	/* finally sort the array */
	qsort(en->elems, en->cnt, sizeof(struct lt_enum_bm_elem), enum_bm_comp);
	return 0;
}

struct lt_enum_elem* lt_args_get_enum(struct lt_config_shared *cfg, 
	char *name, char *val)
{
	struct lt_enum_elem* elem;
	int base = 10;

	XMALLOC_ASSIGN(elem, sizeof(*elem));
	if (!elem)
		return NULL;

	memset(elem, 0x0, sizeof(*elem));
	elem->undef = 1;

	if (val) {
		long num;
		char *endptr;

		errno = 0;
		num = strtol(val, &endptr, 0);

		/* parse errors */
		if ((errno == ERANGE && (num == LONG_MAX || num == LONG_MIN)) || 
		    (errno != 0 && num == 0)) {
			XFREE(elem);
			return NULL;
		}

		if (endptr != val) {
			elem->val   = num;
			elem->undef = 0;

			if (num) {
				if (!strncmp(val, "0x", 2))
					base = 16;
				else if (*val == '0')
					base = 8;
				else if (*val == '-')
					base = -10;
			}

		} else {
			/* if no digits were found, we assume the
			 * value is set by string reference */
			XSTRDUP_ASSIGN(elem->strval, val);
			if (!elem->strval)
				return NULL;
		}

	}

	elem->base = base;

	XSTRDUP_ASSIGN(elem->name, name);
	if (!elem->name)
		return NULL;

	PRINT_VERBOSE(cfg, 3, "enum elem %s = %d, strval %s, undef = %d\n",
			elem->name, elem->val, elem->strval, elem->undef);
	return elem;
}

struct lt_enum_bm_elem *lt_args_get_enum_bm(struct lt_config_shared *cfg, 
	const char *name, const char *val)
{
	struct lt_enum_bm_elem* elem;

	XMALLOC_ASSIGN(elem, sizeof(*elem));
	if (!elem)
		return NULL;

	memset(elem, 0x0, sizeof(*elem));

	if (val) {
		long num;
		char *endptr;

		errno = 0;
		num = strtol(val, &endptr, 0);

		/* parse errors */
		if ((errno == ERANGE && (num == LONG_MAX || num == LONG_MIN)) || 
		    (errno != 0 && num == 0)) {
			XFREE(elem);
			return NULL;
		}

		if (endptr != val) {
			elem->val   = num;
		}

	}

	XSTRDUP_ASSIGN(elem->name, name);
	if (!elem->name)
		return NULL;

	PRINT_VERBOSE(cfg, 3, "enum_bm elem %s = %d\n", elem->name, elem->val);
	return elem;
}

int lt_args_add_struct(struct lt_config_shared *cfg, char *type_name, 
			struct lt_list_head *h)
{
	struct lt_arg *arg, sarg;

	if ((args_def_struct_cnt + 1) == LT_ARGS_DEF_STRUCT_NUM)
		return 1;

	/* check if the struct name is already 
	   defined as a type */
	if (lt_args_getarg(cfg, type_name, NULL, 0, 1, NULL))
		return -1;

	memset(&sarg, 0, sizeof(sarg));
	sarg.dtype     = LT_ARGS_DTYPE_STRUCT;
	sarg.type_id   = LT_ARGS_TYPEID_CUSTOM + args_def_struct_cnt;
	sarg.type_name = type_name;
	sarg.args_head = h;

	PRINT_VERBOSE(cfg, 3, "struct [%s] type %d\n",
			sarg.type_name, sarg.type_id);

	/* empty struct pass-through */
	if (!h) {
		XMALLOC_ASSIGN(h, sizeof(*h));
		if (!h) {
			PERROR("xmalloc failed");
			return -1;
		}

		lt_init_list_head(h);
		sarg.args_head = h;
	}

	lt_list_for_each_entry(arg, sarg.args_head, args_list) {

		PRINT_VERBOSE(cfg, 3, "\t %s %s %u\n",
				arg->type_name, arg->name, arg->type_len);

		/* This is not what sizeof would return on the structure.
		   The sizeof is arch dependent, this is pure sum. */
		sarg.type_len += arg->type_len;
		sarg.mmbcnt++;
	}

	args_def_struct[args_def_struct_cnt++] = sarg;

	PRINT_VERBOSE(cfg, 3, "%d.struct - final len = %u\n",
			args_def_struct_cnt, sarg.type_len);
	return 0;
}

int lt_args_add_sym2(struct lt_config_shared *cfg, struct lt_arg *ret, struct lt_list_head *h,
			struct lt_list_head *rh, int collapsed, struct lt_args_sym **psym)
{
	ENTRY e, *ep;
	struct lt_args_sym *sym;
	struct lt_arg *arg;
	int i = 0;
	size_t argno = 0, rargno = 0;

//	fprintf(stderr, "++++++++++ lt_args_add_sym2(): %s\n", ret->name);

	PRINT_VERBOSE(cfg, 3, "got symbol '%s %s'\n",
			ret->type_name, ret->name);

	XMALLOC_ASSIGN(sym, sizeof(*sym));
	if (!sym)
		return -1;

	memset(sym, 0, sizeof(*sym));
	sym->name = ret->name;

	sym->argcnt = 1;
	sym->rargcnt = 0;
	sym->collapsed = collapsed;
	lt_list_for_each_entry(arg, h, args_list)
		sym->argcnt++;

	lt_list_for_each_entry(arg, rh, args_list)
		sym->rargcnt++;

	XMALLOC_ASSIGN(sym->args, (sym->argcnt * sizeof(struct lt_arg**)));
	XMALLOC_ASSIGN(sym->ret_args, (sym->rargcnt * sizeof(struct lt_arg**)));
	if (!sym->args || !sym->ret_args) {
		perror("malloc");
		return -1;
	}

	PRINT_VERBOSE(cfg, 3, "got return %s, ptr %d\n",
			ret->type_name, ret->pointer);

	sym->args[i++] = ret;
//	fprintf(stderr, "--- TOTAL args: %d\n", sym->argcnt);
	lt_list_for_each_entry(arg, h, args_list) {
//		fprintf(stderr,"\t - '%s %s / %s'\n", arg->type_name, arg->name, arg->real_type_name);
		PRINT_VERBOSE(cfg, 3, "\t '%s %s'\n",
				arg->type_name, arg->name);
		sym->args[i++] = arg;
		argno++;

		if (!strcmp(arg->name, ANON_PREFIX_INTERNAL)) {
			char nbuf[32];

			snprintf(nbuf, sizeof(nbuf), "%s%zu", ANON_PREFIX, argno);
			XFREE(arg->name);

			XSTRDUP_ASSIGN(arg->name, nbuf);
			if (!arg->name)
				return -1;
		}

	}

//	fprintf(stderr, "TOTAL return args: %d\n", sym->rargcnt);
	lt_list_for_each_entry(arg, rh, args_list) {
//		fprintf(stderr,"\t '%s %s / %s'\n", arg->type_name, arg->name, arg->real_type_name);
		sym->ret_args[rargno++] = arg;

		if (!strcmp(arg->name, ANON_PREFIX_INTERNAL)) {
			char nbuf[32];

			snprintf(nbuf, sizeof(nbuf), "%s%zu", ANON_PREFIX, rargno);
			XFREE(arg->name);

			XSTRDUP_ASSIGN(arg->name, nbuf);
			if (!arg->name)
				return -1;
		}

	}

	e.key = sym->name;
	e.data = sym;

	if (!hsearch_r(e, ENTER, &ep, &cfg->args_tab)) {
		PERROR("hsearch_r failed");
		XFREE(sym);
		/* we dont want to exit just because
		   we ran out of our symbol limit */
		PRINT_VERBOSE(cfg, 3, "reach the symbol number limit %u\n",
				LT_ARGS_TAB);
	} else
		PRINT_VERBOSE(cfg, 3, "got symbol %s (%d args)\n",
				sym->name, sym->argcnt);

	if (psym)
		*psym = sym;

	return 0;
}

int lt_args_add_sym(struct lt_config_shared *cfg, struct lt_arg *ret,
			struct lt_list_head *h, int collapsed, struct lt_args_sym **psym)
{
	ENTRY e, *ep;
	struct lt_args_sym *sym;
	struct lt_arg *arg;
	int i = 0;
	size_t argno = 0;

//	printf("++++++++++ lt_args_add_sym(): %s\n", ret->name);

	PRINT_VERBOSE(cfg, 3, "got symbol '%s %s'\n",
			ret->type_name, ret->name);

	XMALLOC_ASSIGN(sym, sizeof(*sym));
	if (!sym)
		return -1;

	memset(sym, 0, sizeof(*sym));
	sym->name = ret->name;

	sym->argcnt = 1;
	sym->collapsed = collapsed;
	lt_list_for_each_entry(arg, h, args_list)
		sym->argcnt++;

	XMALLOC_ASSIGN(sym->args, (sym->argcnt * sizeof(struct lt_arg**)));
	if (!sym->args)
		/* no need to fre sym, since we are going
		   to exit the program anyway */
		return -1;

	PRINT_VERBOSE(cfg, 3, "got return %s, ptr %d\n",
			ret->type_name, ret->pointer);

	sym->args[i++] = ret;
	lt_list_for_each_entry(arg, h, args_list) {
		PRINT_VERBOSE(cfg, 3, "\t '%s %s'\n",
				arg->type_name, arg->name);
		sym->args[i++] = arg;
		argno++;

		if (!strcmp(arg->name, ANON_PREFIX_INTERNAL)) {
			char nbuf[32];

			snprintf(nbuf, sizeof(nbuf), "%s%zu", ANON_PREFIX, argno);
			XFREE(arg->name);

			XSTRDUP_ASSIGN(arg->name, nbuf);
			if (!arg->name)
				return -1;
		}

	}

	e.key = sym->name;
	e.data = sym;

	if (!hsearch_r(e, ENTER, &ep, &cfg->args_tab)) {
		PERROR("hsearch_r failed");
		XFREE(sym);
		/* we dont want to exit just because 
		   we ran out of our symbol limit */
		PRINT_VERBOSE(cfg, 3, "reach the symbol number limit %u\n",
				LT_ARGS_TAB);
	} else
		PRINT_VERBOSE(cfg, 3, "got symbol %s (%d args)\n",
				sym->name, sym->argcnt);

	if (psym)
		*psym = sym;

	return 0;
}

struct lt_arg* argdup(struct lt_config_shared *cfg, struct lt_arg *asrc, const char *name)
{
	struct lt_arg *arg, *a;
        struct lt_list_head *h;

	if (cfg) {
		PRINT_VERBOSE(cfg, 2, "got arg '%s %s', dtype %d\n",
				asrc->type_name, asrc->name, asrc->dtype);
	}

	XMALLOC_ASSIGN(arg, sizeof(*arg));
	if (!arg) {
		PERROR("xmalloc failed");
		return NULL;
	}

	*arg = *asrc;

	if (name) {
		XSTRDUP_ASSIGN(arg->name, name);
		if (!arg->name)
			return NULL;
	}

	if (arg->dtype != LT_ARGS_DTYPE_STRUCT)
		return arg;

	/* For structures we need also to copy all its arguments. */
	XMALLOC_ASSIGN(h, sizeof(*h));
	if (!h) {
		PERROR("xmalloc failed");
		XFREE(arg);
		return NULL;
	}
                
        lt_init_list_head(h);

	lt_list_for_each_entry(a, asrc->args_head, args_list) {
		struct lt_arg *aa;

		/* XXX Not sure how safe is this one... 
		   might need some attention in future :) */
		if (NULL == (aa = argdup(cfg, a, NULL))) {
			XFREE(h);
			XFREE(arg);
			return NULL;
		}

		lt_list_add_tail(&aa->args_list, h);
	}

	arg->args_head = h;
	return arg;
}

#define NUM_TYPE_MAPPINGS	2
const char *type_mapping_table[NUM_TYPE_MAPPINGS][2] =
{
        { "byte", "uint8" },
        { "rune", "int32" },
};

struct lt_arg* find_arg(struct lt_config_shared *cfg, const char *type,
			struct lt_arg argsdef[], int size, int create)
{
	int i;

	for (i = 0; i < NUM_TYPE_MAPPINGS; i++) {
		if (!strcmp(type, type_mapping_table[i][0])) {
			type = type_mapping_table[i][1];
			break;
		}
	}

	for(i = 0; i < size; i++) {
		struct lt_arg *arg;
		struct lt_arg adef = argsdef[i];

		PRINT_VERBOSE(cfg, 3, "%d. looking for [%s] - [%s]\n",
					i, type, adef.type_name);

		if (strcmp(type, adef.type_name))
			continue;

		if (!create)
			return &argsdef[i];

		arg = argdup(cfg, &adef, NULL);

		PRINT_VERBOSE(cfg, 3, "found %d\n", arg->type_id);
		return arg;
	}

	return NULL;
}

char *normalize_golang_func_name(const char *name) {
	static char fnbuf[1024];
	const char *nptr = name;
	size_t i = 0;

	memset(fnbuf, 0, sizeof(fnbuf));

	while (*nptr) {
		if (*nptr != '.')
			fnbuf[i++] = *nptr;
		else {
			fnbuf[i++] = '_';
			fnbuf[i++] = '_';
		}

		nptr++;
	}

	return fnbuf;
}

struct lt_arg* lt_args_getarg(struct lt_config_shared *cfg, const char *type, 
			const char *name, int pointer, int create, char *enum_name)
{
	struct lt_arg *arg;
	void *xfm_func = NULL;
	char *bitmask = NULL, *fmt = NULL, *name_copy = NULL, *modifier = NULL;
	char *nname = NULL;
	int collapsed = 0;

	if (name) {
		char *nptr;

		bitmask = strchr(name, '|');
		fmt = strchr(name, '/');

		if (strchr(name, '\\')) {

			if (!(nptr = nname = strdup(name)))
				return NULL;

			while (*nptr) {
				if (*nptr == '\\')
					*nptr = '/';
				nptr++;
			}
		}

	}

	if (bitmask && fmt && (bitmask < fmt))
		modifier = bitmask - 1;
	else if (fmt && bitmask && (fmt < bitmask))
		modifier = fmt - 1;
	else if (bitmask)
		modifier = bitmask - 1;
	else if (fmt)
		modifier = fmt - 1;
	else if (name)
		modifier = (char *)&name[strlen(name)-1];

	if (modifier) {
		if (*modifier == '!')
			collapsed = COLLAPSED_BASIC;
		else if (*modifier == '~')
			collapsed = COLLAPSED_TERSE;
		else if (*modifier == '^')
			collapsed = COLLAPSED_BARE;
	}

	if (!collapsed)
		modifier = NULL;

	if (bitmask || fmt || modifier) {
		XSTRDUP_ASSIGN(name_copy, name);
		if (!name_copy)
			return NULL;

		bitmask = strchr(name_copy, '|');
		fmt = strchr(name_copy, '/');

		if (modifier) {
			modifier = name_copy + (modifier - name);
			*modifier = 0;
		}

		if (bitmask)
			*bitmask++ = 0;

		if (fmt)
			*fmt++ = 0;

		name = name_copy;
	}

	if (create) {
		ENTRY e, *ep;
		e.key = (char *)type;

		if (hsearch_r(e, FIND, &ep, &args_struct_xfm_tab))
			xfm_func = ep->data;
	}

	do {
		ENTRY e, *ep;
		int found = 0;

		if ((arg = find_arg(cfg, type,
			args_def_pod, LT_ARGS_DEF_POD_NUM, create))) {
			found = 1;
		} else if ((arg = find_arg(cfg, type,
			args_def_struct, args_def_struct_cnt, create))) {
			found = 1;
		} else if ((arg = find_arg(cfg, type,
			args_def_typedef, args_def_typedef_cnt, create))) {
			found = 1;
		}

		if (found && name) {
			char *nname;

			nname = normalize_golang_func_name(name);
			e.key = nname;

			if (hsearch_r(e, FIND, &ep, &args_func_xfm_tab))
				arg->latrace_custom_func_transformer = (void *)ep->data;

			if (hsearch_r(e, FIND, &ep, &args_func_intercept_tab))
				arg->latrace_custom_func_intercept = (void *)ep->data;
		}

		if (found)
			break;

		if (!create)
			return NULL;

		e.key = (char *)type;

		if (name && xfm_func) {
			arg = find_arg(cfg, "custom_user_struct_transformer", args_def_pod, LT_ARGS_DEF_POD_NUM, create);

			if (arg) {
				arg->latrace_custom_struct_transformer = (void *)ep->data;
				break;
			}

		}

		return NULL;

	} while(0);

	if (!create)
		return arg;

	if (xfm_func)
		arg->latrace_custom_struct_transformer = xfm_func;

	/* Find out the enum definition if the enum 
	   name is provided. */
	if (enum_name) {
		if ((arg->en = getenum(cfg, enum_name)) == NULL) {
			return NULL;
		}

		if (arg->en->bitmask)
			bitmask = enum_name;

		if (!fmt)
			fmt = arg->en->fmt;
		else if (strchr(fmt, 'm'))
			bitmask = enum_name;

	}

	if (nname)
		arg->name = nname;
	else {
		XSTRDUP_ASSIGN(arg->name, name);

		if (!arg->name)
			return NULL;
	}

	/* If the type is already a pointer (could be for typedef), 
	   give it a chance to show up. There's only one pointer for 
	   the arg, since there's no reason to go dreper. */
	if (!arg->pointer)
		arg->pointer = pointer;

	if (fmt && *fmt) {
		XSTRDUP_ASSIGN(arg->fmt, fmt);
		if (!arg->fmt)
			return NULL;
	}

	if (bitmask) {
		XSTRDUP_ASSIGN(arg->bitmask_class, bitmask);
		if (!arg->bitmask_class)
			return NULL;
	}

	if (collapsed)
		arg->collapsed = collapsed;

	if (name_copy)
		XFREE(name_copy);

	return arg;
}

int lt_args_add_typedef(struct lt_config_shared *cfg, const char *base, 
	const char *new, int pointer)
{
	struct lt_arg *arg;
	int i;

	if ((args_def_typedef_cnt + 1) == LT_ARGS_DEF_TYPEDEF_NUM)
		return 2;

	/* check if the typedef name is already 
	   defined as a type */
	if (lt_args_getarg(cfg, new, NULL, 0, 0, NULL))
		return 1;

	do {
		if ((arg = find_arg(cfg, base, 
			args_def_pod, LT_ARGS_DEF_POD_NUM, 0)))
			break;

		if ((arg = find_arg(cfg, base, 
			args_def_typedef, args_def_typedef_cnt, 0)))
			break;

		PRINT_VERBOSE(cfg, 3, "%s not found\n", base);
		return -1;

	} while(0);

	PRINT_VERBOSE(cfg, 3, "got [%s]\n", new);

	args_def_typedef[i = args_def_typedef_cnt++] = *arg;

	arg = &args_def_typedef[i];

	XSTRDUP_ASSIGN(arg->type_name, new);
	if (!arg->type_name)
		return -1;

	arg->pointer = pointer;

	lt_init_list_head(&arg->args_list);

	PRINT_VERBOSE(cfg, 3, "%d.typedef - got [%s] [%s]\n",
			args_def_typedef_cnt, base, arg->type_name);
	return 0;
}

int lt_args_init(struct lt_config_shared *cfg)
{
	static char *file = NULL;

	cfg->sh = cfg;

	if (!file) {
		char *env_dir = getenv("GT_HEADERS_DIR");

		if (env_dir) {
			size_t fsize = strlen(env_dir) + 16;

			XMALLOC_ASSIGN(file, fsize);
			if (!file)
				return -1;

			memset(file, 0, fsize);
			snprintf(file, fsize, "%s/gotrace.go", env_dir);
		} else
			file = GT_CONF_HEADERS_FILE;
	}

	if (!hcreate_r(LT_ARGS_TAB, &cfg->args_tab)) {
		PERROR("Failed to create hash table");
		return -1;
	}

	lt_args_parse_init(cfg, &inc);

	if (*cfg->args_def)
		file = cfg->args_def;

	PRINT_VERBOSE(cfg, 1, "arguments definition file %s\n", file);

	if (lt_inc_open(cfg, &inc, file))
		return -1;

	if (lt_args_parse()) {
		PRINT_ERROR("Failed to parse header file(s) %s\n", file);
		return -1;
	}

#if defined(LT_ARGS_ARCH_CONF)
	/* Some architectures provides specific
	 * configuration file. */
/*	if (lt_inc_open(cfg, &inc, lt_args_arch_conf(cfg)))
		return -1;

	if (lt_args_parse()) {
		PRINT_ERROR("Failed to parse config file %s\n", file);
		return -1;
	} */
#endif

	return 0;
}

static int getstr_addenum(struct lt_config_shared *cfg, struct lt_arg *arg,
			char *argbuf, int alen, long val)
{
	char *enstr = NULL;
	struct lt_enum_elem *elem;

	if (!arg->en)
		return 0;

	if (NULL != (elem = get_enumelem(cfg, val, arg->en)))
		enstr = elem->name;

	if (enstr)
		return snprintf(argbuf, alen, "%s", enstr);

	return 0;
}

static char *massage_string(const unsigned char *s, size_t slen)
{
	char *result;
	size_t rlen, i, d_i;

	if (!slen)
		slen = strlen((char *)s);

	rlen = (slen * 2) + 6;

	XMALLOC_ASSIGN(result, rlen);
	if (!result)
		return NULL;

	memset(result, 0, rlen);

	for (i = 0, d_i = 0; i < slen; i++) {

		if ((rlen - 6) <= d_i) {
			strcat(result, "...");
			break;
		}

		if (!isgraph(s[i]) && !isspace(s[i])) {
			char hexbuf[8];

			snprintf(hexbuf, sizeof(hexbuf), "\\x%.2x", s[i]);
			memcpy(&(result[d_i]), hexbuf, 4);
			d_i += 4;
		}
		else if ((s[i] != '\n') && (s[i] != '\r') && (s[i] != '\t'))
			result[d_i++] = s[i];
		else {
			result[d_i++] = '\\';

			if (s[i] == '\n')
				result[d_i++] = 'n';
			else if (s[i] == '\r')
				result[d_i++] = 'r';
			else if (s[i] == '\t')
				result[d_i++] = 't';
			else
				result[d_i++] = '?';

		}
		
	}

	return result;
}

static int getstr_pod(struct lt_config_shared *cfg, pid_t pid, int dspname, struct lt_arg *arg,
			void *pval, size_t psize, char *argbuf, int *arglen)
{
	int len = 0, alen = *arglen;
	int namelen = strlen(arg->name);
	int is_char = 0;
	int force_type_id = -1;

	PRINT_VERBOSE(cfg, 1, "\t arg '%s %s', pval %p, len %d, pointer %d, dtype %d, type_id %d\n",
			arg->type_name, arg->name, pval, alen, arg->pointer, arg->dtype, arg->type_id);

	if (alen < 5)
		return 0;

#define MAX_SLICE_DISP_SIZE	1024
	if (arg->pointer == -1) {
		char *d1 = dspname ? arg->name : "";
		char *d2 = dspname ? LT_EQUAL : "";
		char *s, *ms = NULL;
		int is_byte_string;

		is_byte_string = ((arg->type_id == LT_ARGS_TYPEID_CHAR) || (arg->type_id == LT_ARGS_TYPEID_INT8) ||
			(arg->type_id == LT_ARGS_TYPEID_UINT8));

		if (!is_byte_string || (psize > MAX_SLICE_DISP_SIZE)) {
			len = snprintf(argbuf, alen, "%s%s[%zu]{...}", d1, d2, psize);
			goto out;
		}

		if ((s = read_string_remote(pid, pval, psize))) {
			if (!psize) {
				len = snprintf(argbuf, alen, "%s%s[%zu]{}", d1, d2, psize);
				// XXX: this should not be a crash! */
//				XFREE(s);
				goto out;
			}

			ms = massage_string((unsigned char *)s, psize);
		} else
			PRINT_ERROR("Error allocating slice of advertised size %zu bytes\n", psize);

		if (!ms)
			len = snprintf(argbuf, alen, "%s%s[%zu]{[..decoding error..]}", d1, d2, psize);
		else {
			len = snprintf(argbuf, alen, "%s%s[%zu]{\"%s\"}", d1, d2, psize, ms);
		}

		if (s)
			XFREE(s);

		if (ms)
			XFREE(ms);

		goto out;
	}
	
	*arglen = 0;

	if (arg->real_type_name && (!strcmp(arg->real_type_name, "_type") &&
			arg->pointer)) {
		const char *dname1, *dname2, *tname;

		dname1 = dspname ? arg->name : "";
		dname2 = dspname ? LT_EQUAL : "";

		if ((tname = lookup_interface(pid, pval, 1))) {
			len = snprintf(argbuf, alen, "%s%s^%s", dname1, dname2, tname);
			goto out;
		}
	} else if (arg->real_type_name && (!strcmp(arg->real_type_name, "_elem") &&
			arg->pointer)) {
		const char *dname1, *dname2, *tname;

		dname1 = dspname ? arg->name : "";
		dname2 = dspname ? LT_EQUAL : "";

		if ((tname = lookup_interface(pid, pval, 0))) {
			len = snprintf(argbuf, alen, "%s%s^%s", dname1, dname2, tname);
			goto out;
		}
	}

	if (arg->real_type_name && is_type_serialization_supported(arg->real_type_name)) {
		const char *dname1, *dname2;
		char *sres;

		dname1 = dspname ? arg->name : "";
		dname2 = dspname ? LT_EQUAL : "";

		if ((sres = call_remote_serializer(-1, arg->real_type_name, pval))) {
			len = snprintf(argbuf, alen, "%s%s%s", dname1, dname2, sres);
			free(sres);
			goto out;
		}
	}

	if (arg->type_id == LT_ARGS_TYPEID_FNPTR) {
		void *fn = pval;
		const char *fname;
		const char *dname1, *dname2;

		dname1 = dspname ? arg->name : "";
		dname2 = dspname ? LT_EQUAL : "";

		if (!fn)
			len = snprintf(argbuf, alen, "%s%sfn@ NULL", dname1, dname2);
		else if ((fname = lookup_addr(fn)))
			len = snprintf(argbuf, alen, "%s%sfn@ %s()", dname1, dname2, fname);
		else
			len = snprintf(argbuf, alen, "%s%sfn@ %p", dname1, dname2, fn);

		goto out;
	}

	if ((dspname) && 
	    (namelen < (alen - 5 - sizeof(LT_EQUAL)))) {
		*arglen  = sprintf(argbuf, "%s"LT_EQUAL, arg->name);
		argbuf  += *arglen;
		alen    -= *arglen;
	}

	/* Get enum resolve for pointers now, the rest 
	   POD is done in ARGS_SPRINTF macro. The char 
	   pointers need special handling later. */
//	is_char = (arg->type_id == LT_ARGS_TYPEID_CHAR) || (arg->type_id == LT_ARGS_TYPEID_UINT8);
	is_char = (arg->type_id == LT_ARGS_TYPEID_CHAR);

	if (arg->pointer && arg->fmt && !strcmp(arg->fmt, "s")) {
		is_char = 1;
		force_type_id = LT_ARGS_TYPEID_CHAR;
	} else
		force_type_id = arg->type_id;

	if ((arg->pointer && !is_char && (arg->type_id != LT_ARGS_TYPEID_STRING)) ||
		((arg->pointer > 1) && is_char)) {

//		void *ptr = *((void**) pval);
		void *ptr = pval;

		/* Try to get enumed value first. */
		len = getstr_addenum(cfg, arg, argbuf, alen, (long)ptr);

		/* If there's no enum resolved, 
		   just display the ptr value */
		if (!len) {
			if (ptr) {
				const char *aname = NULL;
				size_t off = 0;

				if (cfg->resolve_syms)
					aname = get_address_mapping(ptr, NULL, &off);

				if (cfg->resolve_syms && aname) {
					const char *fmt_on = "", *fmt_off = "";

					if (cfg->fmt_colors) {
						fmt_on = BOLD;
						fmt_off = BOLDOFF;
					}

					if (off)
						len = snprintf(argbuf, alen, "%s%s+%zu%s", fmt_on, aname, off, fmt_off);
					else
						len = snprintf(argbuf, alen, "%s%s%s", fmt_on, aname, fmt_off);

				} else
					len = snprintf(argbuf, alen, "%p", ptr);
			} else
				len = snprintf(argbuf, alen, "nil");
		}

		goto out;
	}

#define ARGS_SPRINTF(FMT, TYPE)                                      \
do {                                                                 \
	if (!(len = getstr_addenum(cfg, arg, argbuf, alen,           \
				(long) ((TYPE) (uintptr_t)pval))))            \
		len = snprintf(argbuf, alen, FMT, ((TYPE) (uintptr_t)pval));  \
} while(0)

	if (arg->bitmask_class) {
		char bmstr[1024];

		char *bm = lookup_bitmask_by_class(cfg, arg->bitmask_class, (unsigned long)pval, arg->fmt, bmstr, sizeof(bmstr));
		len = snprintf(argbuf, alen, "%s", bm);
	} else if (arg->fmt && (!strcmp(arg->fmt, "o"))) {
		ARGS_SPRINTF("0%o", unsigned int);
	} else if (arg->fmt && (!strcmp(arg->fmt, "d"))) {
		ARGS_SPRINTF("%d", signed int);
	} else if (arg->fmt && (!strcmp(arg->fmt, "u"))) {
		ARGS_SPRINTF("%d", unsigned int);
	} else if (arg->fmt && (!strcmp(arg->fmt, "x"))) {
		ARGS_SPRINTF("0x%lx", unsigned long);
	} else if (arg->fmt && (!strcmp(arg->fmt, "h"))) {
		char numbuf[32], *nptr;

		memset(numbuf, 0, sizeof(numbuf));
		sprintf(numbuf, "%u", *((unsigned int*)pval));
		len = strlen(numbuf);
		nptr = numbuf + len - 3;

		while (nptr > numbuf) {
			memmove(nptr+1, nptr, len+1 - (nptr - numbuf));
			*nptr = ',';
			nptr -= 3;
		}

		strncpy(argbuf, numbuf, alen);
	} else if (arg->fmt && (!strcmp(arg->fmt, "p"))) {
		if (pval == NULL)
			len = snprintf(argbuf, alen, "nil");
		else
			ARGS_SPRINTF("%p", void *);
	} else if (arg->fmt && (strchr(arg->fmt, 'b'))) {
		char *tok;
#define DEFAULT_BINARY_WIDTH 4
		size_t i = 0, max = DEFAULT_BINARY_WIDTH;

		tok = strchr(arg->fmt, 'b');
		if (tok > arg->fmt) {
			char *widths;
			widths = strndup(arg->fmt, tok-arg->fmt);

			if (!(max = atoi(widths)))
				max = DEFAULT_BINARY_WIDTH;

			XFREE(widths);
		}

		strcat(argbuf, "\"");

		for (i = 0; i < max; i++) {
			char tmpbuf[16];
			unsigned char *bptr;
			bptr = (unsigned char *)pval + i;
			sprintf(tmpbuf, "\\x%.2x", *bptr);
			strcat(argbuf, tmpbuf);
			len = strlen(argbuf);
		}

		strcat(argbuf, "\"");
	} else {

		if ((arg->pointer > 0) && (force_type_id != LT_ARGS_TYPEID_STRING) && (force_type_id != LT_ARGS_TYPEID_CHAR)) {
			ARGS_SPRINTF("%p", void *);
			goto out;
		}

		switch(force_type_id) {
		case LT_ARGS_TYPEID_INT16:   ARGS_SPRINTF("%hd", short); break;
		case LT_ARGS_TYPEID_UINT16:  ARGS_SPRINTF("%hu", uint16_t); break;
		case LT_ARGS_TYPEID_INT32:   ARGS_SPRINTF("%d", int); break;
		case LT_ARGS_TYPEID_UINT32:  ARGS_SPRINTF("%u", uint32_t); break;
		case LT_ARGS_TYPEID_INT:
		case LT_ARGS_TYPEID_INT64:   ARGS_SPRINTF("%ld", int64_t); break;
		case LT_ARGS_TYPEID_UINT:
		case LT_ARGS_TYPEID_UINT64:
		case LT_ARGS_TYPEID_UINTPTR: ARGS_SPRINTF("%lu", uint64_t); break;
		case LT_ARGS_TYPEID_LLONG:   ARGS_SPRINTF("%lld", long long); break;
		case LT_ARGS_TYPEID_ULLONG:  ARGS_SPRINTF("%llu", unsigned long long); break;
//		case LT_ARGS_TYPEID_DOUBLE:  ARGS_SPRINTF("%lf", double); break;
//		case LT_ARGS_TYPEID_FLOAT:   ARGS_SPRINTF("%f", float); break;
	#undef ARGS_SPRINTF
		case LT_ARGS_TYPEID_INT8:
		case LT_ARGS_TYPEID_UINT8:
		{
			unsigned char bbyte = (unsigned char)((uintptr_t)pval);
			char bbuf[8];

			if (isalnum(bbyte) || ispunct(bbyte) || (bbyte == ' '))
				sprintf(bbuf, "'%c'", bbyte);
			else if (bbyte == '\n')
				strcpy(bbuf, "\\n");
			else if (bbyte == '\r')
				strcpy(bbuf, "\\r");
			else if (bbyte == '\t')
				strcpy(bbuf, "\\t");
			else
				sprintf(bbuf, "0x%.2x", bbyte);

			len = snprintf(argbuf, alen, "%s", bbuf);
			break;
		}
		case LT_ARGS_TYPEID_BOOL:
		{
			long bval = (long)pval;

			bval &= 1;
			len = snprintf(argbuf, alen, "%s",  !bval ? "false" : "true");
			break;
		}
		case LT_ARGS_TYPEID_STRING:
		case LT_ARGS_TYPEID_CHAR:
			if (arg->pointer) {
				void *val = pval;

				if (val) {
					char *s = massage_string(val, 0);
					int slen;
					int left = alen;
					int info_len = 0;

					free(val);

					if (!s) {
						len = snprintf(argbuf, alen, "[error reading string]");
						goto out;
					}

					slen = strlen(s);

					if (lt_sh(cfg, args_string_pointer_length)) {
						info_len = snprintf(argbuf, left, "(%p, %zu) ", s, strlen(s));
						left -= info_len;
					}

					if ((slen + 2) > left) {
						snprintf(argbuf + info_len, left, "\"%s", s);
						strncpy(argbuf + left - sizeof("...\"") + 1, "...\"", sizeof("...\""));
					} else {
						strcpy(argbuf + info_len, "\"");
						strcat(argbuf, s);
						strcat(argbuf, "\"");
					}
					XFREE(s);
				} else
					len = snprintf(argbuf, alen, "nil");
			} else {

				if (!isprint(*((char*) pval)))
					len = snprintf(argbuf, alen, "0x%02x",
							*((unsigned char*) pval));
				else
					len = snprintf(argbuf, alen, "0x%02x \'%c\'",
							*((unsigned char*) pval), *((char*) pval));
			}
			break;

		case LT_ARGS_TYPEID_VOID:
//			len = snprintf(argbuf, alen, "void");
			len = 0;
			break;
		}

	}

	if ((force_type_id == arg->type_id) && (LT_ARGS_DTYPE_STRUCT == arg->dtype)) {
		if (pval)
			len = snprintf(argbuf, alen, "v(%p)", pval);
		else
			len = snprintf(argbuf, alen, "v(REG)");
				
	}

out:
	*arglen += strlen(argbuf);

	PRINT_VERBOSE(cfg, 1, "\t arg out len %d - [%s]\n",
			*arglen, argbuf);
	return 0;
}

int lt_args_cb_arg(struct lt_config_shared *cfg, pid_t pid, struct lt_arg *arg, void *pval, size_t psize,
		   struct lt_args_data *data, int last, int dspname, int multi_fmt)
{
	int len = data->arglen;

	PRINT_VERBOSE(cfg, 1, "arg '%s %s', pval %p, last %d\n",
				arg->type_name, arg->name, pval, last);

	getstr_pod(cfg, pid, dspname, arg, pval, psize,
			data->args_buf + data->args_totlen, &len);
	data->args_totlen += len;

	if (!last) {
		char fmtbuf[16];
		size_t max_append;

		if (cfg->fmt_colors) {
			if (multi_fmt)
				snprintf(fmtbuf, sizeof(fmtbuf), "%s, %s", ULINEOFF, ULINE);
			else
				snprintf(fmtbuf, sizeof(fmtbuf), "%s, %s", BOLD, BOLDOFF);
		}
		else
			strcpy(fmtbuf, ", ");

		max_append = data->args_len - data->args_totlen;
		max_append = strlen(fmtbuf) > max_append ? max_append : strlen(fmtbuf);
		strncat(data->args_buf, fmtbuf, max_append);
		data->args_totlen += max_append;
	}

	return 0;
}

/*int lt_args_cb_struct(struct lt_config_shared *cfg, int type, struct lt_arg *arg,
		      void *pval, struct lt_args_data *data, int last)
{
	PRINT_VERBOSE(cfg, 1,
		"type %d, arg '%s %s', pval %p, last %d, pointer %d\n",
		type, arg->type_name, arg->name, pval, last, arg->pointer);

	// initial call for the structure argument
	if (type == LT_ARGS_STRUCT_ITSELF) {

		data->argsd_totlen += sprintf(data->argsd_buf + data->argsd_totlen, 
						"struct %s %s = { ", 
						arg->type_name, arg->name);
		return 0;

	// subsequent calls for all structure arguments
	} else if (type == LT_ARGS_STRUCT_ARG) {

		int len = cfg->args_detail_maxlen - data->argsd_totlen;

		getstr_pod(cfg, pid, 1, arg, pval, 0, data->argsd_buf + data->argsd_totlen, &len);
		data->argsd_totlen += len;

		if (!last) {
			strcat(data->argsd_buf, ", ");
			data->argsd_totlen += 2;
		} else
			data->argsd_totlen += sprintf(data->argsd_buf + 
						      data->argsd_totlen, " }\n");
	}
	
	return 0;
}*/

static int getargs(struct lt_config_shared *cfg, struct lt_args_sym *asym,
		pid_t target, struct user_regs_struct *regs, char *abuf, size_t argblen, char **adbuf, int silent, lt_tsd_t *tsd)
{
	struct lt_args_data data;
	int arglen;
	char *bufd;

//	printf("getargs: %s\n", asym->name);

	memset(&data, 0, sizeof(data));

	if (cfg->args_detailed) {
		XMALLOC_ASSIGN(bufd, cfg->args_detail_maxlen);
		if (!bufd)
			return -1;

		*bufd  = 0;
		*adbuf = bufd;
		data.argsd_buf = bufd;
		data.argsd_len = cfg->args_detail_maxlen;
	}

	/* makeup the final space for each 
	   argument textual representation  */
	arglen = (argblen
		- ((asym->argcnt - 1) * 2)  /* args separating commas */
		 )/ asym->argcnt;


	data.arglen   = arglen;
	data.args_buf = abuf;
	data.args_len = argblen;

	return lt_stack_process(cfg, asym, target, regs, &data, silent, tsd);
}

struct lt_args_sym* lt_args_sym_get(struct lt_config_shared *cfg,
				    const char *sym)
{
	struct lt_args_sym *a;
	ENTRY e, *ep;

	PRINT_VERBOSE(cfg, 1, "request for <%s>\n", sym);

	e.key = (char*) sym;
	hsearch_r(e, FIND, &ep, &cfg->args_tab);
//	printf("lt_args_sym_get: %s / ep = %x\n", sym, ep);

	if (!ep)
		return NULL;

	a = (struct lt_args_sym*) ep->data;

	PRINT_VERBOSE(cfg, 1, "found %p <%s>\n", a, a->name);
	return a;
}

int lt_args_sym_entry(struct lt_config_shared *cfg, struct lt_symbol *sym,
			pid_t target, struct user_regs_struct *regs, char *argbuf, size_t argblen,
			char **argdbuf, int silent, lt_tsd_t *tsd)
{
//	printf("XXX: LT ARGS SYM ENTRY: %p\n", sym);
	struct lt_args_sym *asym = sym ? sym->args : NULL;

	if (!asym)
		return -1;

	return getargs(cfg, asym, target, regs, argbuf, argblen, argdbuf, silent, tsd);
}

static int getargs_ret(struct lt_config_shared *cfg, struct lt_args_sym *asym,
		pid_t target, struct user_regs_struct *iregs, struct user_regs_struct *regs, char *abuf,
		size_t argblen, char **adbuf, int silent, lt_tsd_t *tsd)
{
	struct lt_args_data data;
	int arglen, totlen;
	char *bufd;

	memset(&data, 0, sizeof(data));

	/* TODO get together with getargs function somehow... */
	if (cfg->args_detailed) {
		XMALLOC_ASSIGN(bufd, cfg->args_detail_maxlen);
		if (!bufd)
			return -1;

		*bufd  = 0;
		*adbuf = bufd;
		data.argsd_buf = bufd;
		data.argsd_len = cfg->args_detail_maxlen;
	}

	arglen = argblen - sizeof(LT_EQUAL);
	totlen = sizeof(LT_EQUAL) - 1;
	strcat(abuf, LT_EQUAL);

	data.arglen      = arglen;
	data.args_buf    = abuf;
	data.args_len    = argblen;
	data.args_totlen = totlen;

	return lt_stack_process_ret(cfg, asym, target, iregs, regs, &data, silent, tsd);
}

int lt_args_sym_exit(struct lt_config_shared *cfg, struct lt_symbol *sym,
			pid_t target, struct user_regs_struct *inregs, struct user_regs_struct *outregs,
			char *argbuf, size_t argblen, char **argdbuf, int silent,
			lt_tsd_t *tsd)
{
	struct lt_args_sym *asym = sym ? sym->args : NULL;

	if (!asym)
		return -1;

	return getargs_ret(cfg, asym, target, inregs, outregs, argbuf, argblen, argdbuf, silent, tsd);
}
