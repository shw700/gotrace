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


#ifndef ARGS_H
#define ARGS_H

struct lt_config_shared;
struct lt_symbol;

#define LT_ARGS_DEF_POD_NUM	20

enum {
	LT_ARGS_DTYPE_POD = 1,
	LT_ARGS_DTYPE_STRUCT,
};

enum {
	LT_ARGS_TYPEID_VOID = 1,
	LT_ARGS_TYPEID_INT16,
	LT_ARGS_TYPEID_UINT16,
	LT_ARGS_TYPEID_INT,
	LT_ARGS_TYPEID_UINT,
	LT_ARGS_TYPEID_INT32,
	LT_ARGS_TYPEID_UINT32,
	LT_ARGS_TYPEID_INT64,
	LT_ARGS_TYPEID_UINT64,
	LT_ARGS_TYPEID_CHAR,
	LT_ARGS_TYPEID_UINT8,
	LT_ARGS_TYPEID_STRING,
	LT_ARGS_TYPEID_BOOL,
	LT_ARGS_TYPEID_LLONG,
	LT_ARGS_TYPEID_ULLONG,
	LT_ARGS_TYPEID_DOUBLE,
	LT_ARGS_TYPEID_FLOAT,
	LT_ARGS_TYPEID_UINTPTR,
	LT_ARGS_TYPEID_FNPTR,
	LT_ARGS_TYPEID_USER_DEF,

	LT_ARGS_TYPEID_CUSTOM = 1000
};

struct lt_enum_bm_elem {
	char *name;
	long val;
	struct lt_list_head list;
};

struct lt_enum_bm {
	char *name;
	int cnt;
	struct lt_enum_bm_elem *elems;
};

struct lt_enum_elem {
	char *name;
	char *strval;
	long val;
	int undef;
	int base;
	struct lt_list_head list;
};

struct lt_enum {
	char *name;
	int cnt;
	int bitmask;
	char *fmt;
	struct lt_enum_elem *elems;
};

struct lt_arg {
	/* argument type */
	int dtype;

	/* argument type properties */
	int   type_id;
	u_int type_len;
	char  *type_name;

	/* argument value properties */
	int pointer;
	char *name;

	/* for structures only */
	int mmbcnt;

	/* architecture dependent */
	void *arch;

	/* enum record */
	struct lt_enum *en;

	/* struct arguments head */
	struct lt_list_head *args_head;
	/* nested arguments list if present */
	struct lt_list_head args_list;

	/* auxiliary interpretation parameters */
	char *fmt;
	char *bitmask_class;
	int collapsed;

	/* custom user-defined transformer */
	int (*latrace_custom_struct_transformer)(void *obj, char *buf, size_t blen);
	int (*latrace_custom_func_transformer)(void **args, size_t argscnt, char *buf, size_t blen, void *retval);
	void (*latrace_custom_func_intercept)(void **args, size_t argscnt, void *retval);
};

struct lt_bitmask_value {
	char *literal;
	unsigned long value;
};

struct lt_bitmask_values {
	char *func;
	struct lt_bitmask_value **masks;
};

struct lt_args_sym {
	char *name;

	int argcnt;
	int collapsed;
#define LT_ARGS_RET 0
	struct lt_arg **args;
	struct lt_arg **ret_args;
};

/* used in lt_args_cb_struct for argument type */
enum {
	LT_ARGS_STRUCT_ITSELF = 0,
	LT_ARGS_STRUCT_ARG
};

struct lt_args_data {
	int arglen;

	/* function arguments */
	char *args_buf;
	int   args_len;
	int   args_totlen;

	/* detailed structs */
	char *argsd_buf;
	int   argsd_len;
	int   argsd_totlen;
};

/* arguments */
int lt_args_init(struct lt_config_shared *cfg);
struct lt_args_sym* lt_args_sym_get(struct lt_config_shared *cfg,
					const char *sym);
int lt_args_sym_entry(struct lt_config_shared *cfg, struct lt_symbol *sym,
			pid_t target, struct user_regs_struct *regs, char *argbuf, size_t argblen,
			char **argdbuf, int silent, lt_tsd_t *tsd);
int lt_args_sym_exit(struct lt_config_shared *cfg, struct lt_symbol *sym,
			pid_t target, struct user_regs_struct *inregs, struct user_regs_struct *outregs,
			char *argbuf, size_t argblen, char **argdbuf,
			int silent, lt_tsd_t *tsd);
int lt_args_add_enum(struct lt_config_shared *cfg, char *name, int bitmask,
			struct lt_list_head *h);
int lt_args_add_enum_bm(struct lt_config_shared *cfg, char *name,
			struct lt_list_head *h);
struct lt_enum_elem* lt_args_get_enum(struct lt_config_shared *cfg, char *name, char *val);
struct lt_enum_bm_elem* lt_args_get_enum_bm(struct lt_config_shared *cfg, const char *name, const char *val);
int lt_args_add_struct(struct lt_config_shared *cfg, char *type_name,
			struct lt_list_head *h);
int lt_args_add_sym(struct lt_config_shared *cfg, struct lt_arg *sym,
			struct lt_list_head *h, int collapsed, struct lt_args_sym **psym);
int lt_args_add_sym_mret(struct lt_config_shared *cfg, struct lt_arg *sym, struct lt_arg **retn,
			struct lt_list_head *h, int collapsed);
int lt_args_add_typedef(struct lt_config_shared *cfg, const char *base,
	const char *new, int pointer);
int lt_args_buf_open(struct lt_config_shared *cfg, char *file);
int lt_args_buf_close(struct lt_config_shared *cfg);
struct lt_arg* lt_args_getarg(struct lt_config_shared *cfg, const char *type,
				const char *name, int pointer, int create, char *enum_name);
int lt_args_cb_arg(struct lt_config_shared *cfg, struct lt_arg *arg,
			void *pval, struct lt_args_data *data, int last,
			int dspname, int multi_fmt);
int lt_args_cb_struct(struct lt_config_shared *cfg, int type,
			struct lt_arg *arg, void *pval,
			struct lt_args_data *data, int last);

/* stack handling */
int lt_stack_process(struct lt_config_shared *cfg, struct lt_args_sym *asym,
			pid_t target, struct user_regs_struct *regs, struct lt_args_data *data,
			int silent, lt_tsd_t *tsd);
int lt_stack_process_ret(struct lt_config_shared *cfg, struct lt_args_sym *asym,
			pid_t target, struct user_regs_struct *iregs, struct user_regs_struct *regs,
			struct lt_args_data *data, int silent, lt_tsd_t *tsd);

#endif /* ARGS_H */
