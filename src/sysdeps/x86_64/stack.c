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


#include "config.h"
#include "stack.h"
#include <stdlib.h>
#include <sys/user.h>


typedef struct argument_watch {
	char *funcname;
	int do_entry;
	int do_exit;
	size_t nbytes;
} argument_watch_t;

argument_watch_t argument_watchlist[] = {
//	{ "runtime.epollwait", 1, 0, 48}
};


#define ASS_CLEANUP() \
do { \
	tsd->ass_integer = tsd->ass_memory = 0; \
} while(0)

/* INTEGER registers used for function arguments. */
static long ass_regs_integer[] = {
	LT_64_REG_RDI,
	LT_64_REG_RSI,
	LT_64_REG_RDX,
	LT_64_REG_RCX,
	LT_64_REG_R8,
	LT_64_REG_R9,
};
#define ASS_REGS_INTEGER_CNT  (sizeof(ass_regs_integer)/sizeof(long))
#define ASS_REGS_INTEGER_SIZE (sizeof(ass_regs_integer))

/* INTEGER registers used for function return arguments. */
static long ass_regs_integer_ret[] = {
	LT_64_REG_RAX,
	LT_64_REG_RDX,
};
#define ASS_REGS_INTEGER_RET_CNT  (sizeof(ass_regs_integer_ret)/sizeof(long))
#define ASS_REGS_INTEGER_RET_SIZE (sizeof(ass_regs_integer_ret))

static int classificate_arg(struct lt_config_shared *cfg, struct lt_arg *arg,
				int ret, int align, lt_tsd_t *tsd);

static int classificate_memory(struct lt_config_shared *cfg,
			struct lt_arg *arg, int align, lt_tsd_t *tsd)
{

	if (align)
		tsd->ass_memory = LT_STACK_ALIGN(tsd->ass_memory);
	else {
		int naligned = tsd->ass_memory % arg->type_len;

		if (naligned)
			tsd->ass_memory += arg->type_len - naligned;
	}

	PRINT_VERBOSE(cfg, 2, "%s - ass %d\n",
			arg->name, tsd->ass_memory);

	ARCH_SET(arg, ARCH_FLAG_MEM, tsd->ass_memory);

	if (arg->pointer)
		tsd->ass_memory += sizeof(void*);
	else
		tsd->ass_memory += arg->type_len;
		
	return 0;
}

static int classificate_integer(struct lt_config_shared *cfg,
			struct lt_arg *arg, int align, int regs_size,
			lt_tsd_t *tsd)
{

	if (!align) {
		int ass = LT_STACK_ALIGN(tsd->ass_integer);
		int naligned = tsd->ass_integer % arg->type_len;

		if (naligned)
			tsd->ass_integer += arg->type_len - naligned;

		if ((tsd->ass_integer + arg->type_len) > ass)
			tsd->ass_integer = LT_STACK_ALIGN(tsd->ass_integer);
	}

	PRINT_VERBOSE(cfg, 2,
			"ass %s - reg size %d - ass_integer %d\n", 
			arg->name, regs_size, tsd->ass_integer);

	if (tsd->ass_integer >= regs_size)
		return -1;

	ARCH_SET(arg, ARCH_FLAG_REG_INTEGER, tsd->ass_integer);

	if (arg->pointer)
		tsd->ass_integer += sizeof(void*);
	else
		tsd->ass_integer += align ? sizeof(void*) : arg->type_len;

	return 0;
}

static void struct_arch(struct lt_config_shared *cfg, struct lt_arg *sarg,
			struct lt_arg *farg)
{
	if (sarg->pointer)
		return;

	/* Structures passed by value dont have the arch assigned by default.
	   If the first argument is returned in memory, the structure takes
	   this pointer, if it is register, we keep it NULL, and lt_args_cb_arg
	    will print out the REG kw for value.*/
	PRINT_VERBOSE(cfg, 2,
			"first argument for struct %s has flag: %d\n", 
			sarg->name, ARCH_GET_FLAG(farg));

	if (ARCH_GET_FLAG(farg) == ARCH_FLAG_MEM)
		sarg->arch = farg->arch;
	else
		ARCH_SET(sarg, ARCH_FLAG_SVREG, 0);
}


static int classificate_struct_try(struct lt_config_shared *cfg,
			struct lt_arg *arg, int allmem, int ret,
			lt_tsd_t *tsd)
{
	struct lt_arg *a;
	int first = 1;
	int saved_ass_integer = tsd->ass_integer;
	int saved_ass_memory  = tsd->ass_memory;

	lt_list_for_each_entry(a, arg->args_head, args_list) {

		if (allmem)
			classificate_memory(cfg, a, first, tsd);
		else {
			if (-1 == classificate_arg(cfg, a, ret, 0, tsd))
				return -1;

			if (ARCH_GET_FLAG(arg) == ARCH_FLAG_MEM) {
				/* There is not enough registers, reset to 
				   have the structure in memory only. */
				tsd->ass_integer = saved_ass_integer;
				tsd->ass_memory  = saved_ass_memory;
				return -1;
			}

		}

		if (first) {
			struct_arch(cfg, arg, a);
			first = 0;
		}
	}

	return 0;
}

static int get_sizeof(struct lt_config_shared *cfg, struct lt_arg *arg)
{
	struct lt_arg *a;
	int size = 0;

	lt_list_for_each_entry(a, arg->args_head, args_list) {

		int naligned = (u_int) size % a->type_len;

		if (naligned)
			size += a->type_len - naligned;

		size += a->type_len;
	}

	PRINT_VERBOSE(cfg, 2, "sizeof(struct %s) = %d\n",
		arg->type_name, size);

	return size;
}

static int classificate_struct(struct lt_config_shared *cfg, struct lt_arg *arg,
				int ret, lt_tsd_t *tsd)
{
	int allmem = 0;
	int size = get_sizeof(cfg, arg);

	/* If the structure is bigger than 16B or passed as pointer then 
	   it is in the memory (no registers). If the structure is up to 
	   16B and passed by value, we might need t classificate its members,
	   because they could fit in registers. */
	if ((size > 16) || (arg->pointer))
		allmem = 1;

	PRINT_VERBOSE(cfg, 2,
		"struct %s - length sum %d - allmem %d\n", 
		arg->type_name, arg->type_len, allmem);

	if (-1 == classificate_struct_try(cfg, arg, allmem, ret, tsd))
		classificate_struct_try(cfg, arg, 1, ret, tsd);

	return 0;
}

static int classificate_arg_type(struct lt_config_shared *cfg,
				struct lt_arg *arg)
{
	int class;

	do {
		/* pointers are INTEGER class by default */
		if (arg->pointer) {
			class = LT_CLASS_INTEGER;
			break;
		}

		switch(arg->type_id) {
		case LT_ARGS_TYPEID_BOOL:
		case LT_ARGS_TYPEID_CHAR:
		case LT_ARGS_TYPEID_UINT8:
		case LT_ARGS_TYPEID_INT16:
		case LT_ARGS_TYPEID_UINT16:
		case LT_ARGS_TYPEID_INT:
		case LT_ARGS_TYPEID_UINT:
		case LT_ARGS_TYPEID_INT32:
		case LT_ARGS_TYPEID_UINT32:
		case LT_ARGS_TYPEID_INT64:
		case LT_ARGS_TYPEID_UINT64:
			class = LT_CLASS_INTEGER;
			break;

		case LT_ARGS_TYPEID_FLOAT32:
		case LT_ARGS_TYPEID_FLOAT64:
		case LT_ARGS_TYPEID_COMPLEX64:
		case LT_ARGS_TYPEID_COMPLEX128:
			// XXX:
			break;

		default:
			class = LT_CLASS_NONE;
			break;
		}

	} while(0);

	PRINT_VERBOSE(cfg, 2,
			"argument %s dtype %d - type %s(%d) - class %d\n", 
			arg->name, arg->dtype, arg->type_name, arg->type_id, 
			class);
	return class;
}

static int classificate_arg(struct lt_config_shared *cfg, struct lt_arg *arg,
				int ret, int align, lt_tsd_t *tsd)
{
	int class;
	int class_failed = 0;

	PRINT_VERBOSE(cfg, 2, "got arg \"%s\"\n",
			arg->name);

	ARCH_ZERO(arg);

	if (arg->dtype != LT_ARGS_DTYPE_POD) {

		if (-1 == classificate_struct(cfg, arg, ret, tsd))
			return -1;

		/* If the structure is passed by pointer, we 
		   still need the pointer classification. */
		if (!arg->pointer)
			return 0;
	}

	class = classificate_arg_type(cfg, arg);
	if (-1 == class)
		return -1;

	/* Nothing to be done for NONE class (void type) */
	if (LT_CLASS_NONE == class)
		return 0;

	switch(class) {
	case LT_CLASS_INTEGER:
		class_failed = classificate_integer(cfg, arg, align,
				(ret ? ASS_REGS_INTEGER_RET_SIZE :
				      ASS_REGS_INTEGER_SIZE), tsd);
		break;

	case LT_CLASS_MEMORY:
		classificate_memory(cfg, arg, 1, tsd);
		break;
	}

	/* If class INTEGER or SSE ran out of registers, 
	   then arg is in memory. */
	if (class_failed)
		classificate_memory(cfg, arg, 1, tsd);

	return 0;
}

static int classificate(struct lt_config_shared *cfg, struct lt_args_sym *sym, lt_tsd_t *tsd)
{
	int i;
	struct lt_arg *arg = sym->args[LT_ARGS_RET];

	PRINT_VERBOSE(cfg, 2, "got symbol \"%s\"\n",
			sym->name);

	ASS_CLEANUP();

	/* Classificate the return value first. */
	if (-1 == classificate_arg(cfg, arg, 1, 1, tsd))
		return -1;

	ASS_CLEANUP();

	/* If the return value is memory class, 
	   then the edi register is used as a first hidden arg.*/
	if (ARCH_GET_FLAG(arg) == ARCH_FLAG_MEM)
		tsd->ass_integer += 8;

	for(i = 1; i < sym->argcnt; i++) {
		arg = sym->args[i];

		if (-1 == classificate_arg(cfg, arg, 0, 1, tsd))
			return -1;
	}

	return 0;
}

/*static void *get_value_mem(struct lt_config_shared *cfg, struct lt_arg *arg,
			void *regs, int ret)
{
	long offset = ARCH_GET_OFFSET(arg);
	void *pval = NULL;

	if (ret) {
//		void *base = (void*) ((struct user_regs_struct *) regs)->lrv_rax;
//		pval = base + offset;
	} else {
//		void *base = (void*) ((struct struct user_regs_struct *) regs)->lr_rsp;
//		pval = base +            // current stack pointer
//		       sizeof(void*) +   // return function address
//		       offset;
	}

	PRINT_VERBOSE(cfg, 2, "offset = %ld, %s = %p, ret = %d\n",
			offset, arg->name, pval, ret);
	return pval;
}*/

/*static void *get_value_reg_integer(struct lt_config_shared *cfg,
			struct lt_arg *arg, void *regs, int ret)
{
//	struct user_regs_struct *regs_ret = regs;
//	struct user_regs_struct *regs_in  = regs;
	void *pval  = NULL;
	long offset = ARCH_GET_OFFSET(arg);
	long qoff   = offset % sizeof(long);
	long reg    = ret ? ass_regs_integer_ret[offset / sizeof(long)] :
			    ass_regs_integer[offset / sizeof(long)];
			

	PRINT_VERBOSE(cfg, 2,
			"offset %ld - reg %ld - qoff %ld - ASS_REGS_CNT %ld - ret %d\n", 
			offset, reg, qoff, ASS_REGS_INTEGER_CNT, ret);

	switch(reg) {
	case LT_64_REG_RAX:
//		pval = &regs_ret->lrv_rax;
		break;
	case LT_64_REG_RDX:
//		pval = ret ? &regs_ret->lrv_rdx : &regs_in->lr_rdx;
		break;
	case LT_64_REG_RDI:
//		pval = &regs_in->lr_rdi;
		break;
	case LT_64_REG_RSI:
//		pval = &regs_in->lr_rsi;
		break;
	case LT_64_REG_RCX:
//		pval = &regs_in->lr_rcx;
		break;
	case LT_64_REG_R8:
//		pval = &regs_in->lr_r8;
		break;
	case LT_64_REG_R9:
//		pval = &regs_in->lr_r9;
		break;
	}

	pval += qoff;

	PRINT_VERBOSE(cfg, 2, "argument %s = %p (%lx)\n",
			arg->name, pval, *((u_long*)pval));
	return pval;
}*/

char *
read_string_remote(pid_t pid, char *addr, size_t slen) {
	char *result, *raddr = addr;
	size_t nread = 0;

//	if (slen) {
		if (!(result = xmalloc(slen+1))) {
			PRINT_ERROR("xmalloc(%zu): %s\n", slen+1, strerror(errno));
			return NULL;
		}

		memset(result, 0, slen+1);
//	}

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

static void *get_value(struct lt_config_shared *cfg, struct lt_arg *arg, pid_t target,
	struct user_regs_struct *regs, size_t offset, size_t *psize, size_t *next_off, int *err, int fixed)
{
//	void *pval = NULL;
	long val, sp_off = regs->rsp;
	size_t extra_off = 0, vsize = 0;
	int req_align = 0;

	*err = 1;

	/* Skip the return value for first parameter */
	if (!fixed && !offset)
		extra_off += sizeof(void *);

	sp_off += offset + extra_off;

	// If we've been reading smaller data types off the stack but then require a word sized one,
	// we need to skip over the remaining stack space to align our request.
	req_align = (arg->pointer == -1) || (arg->pointer > 0) || (arg->type_id == LT_ARGS_TYPEID_STRING);

	if (req_align && (sp_off % sizeof(void *))) {
		extra_off += (sp_off % sizeof(void *));
		sp_off += (sp_off % sizeof(void *));
	}

	PTRACE_PEEK(val, PTRACE_PEEKDATA, target, sp_off, NULL, PT_RETERROR);

	// Deal with slice
	if (arg->pointer == -1) {
		unsigned long ssize;

		PTRACE_PEEK(ssize, PTRACE_PEEKDATA, target, sp_off+sizeof(void *), NULL, PT_RETERROR);

		if (next_off)
			*next_off = offset + extra_off + (sizeof(void *) * 2);

		if (psize)
			*psize = ssize;

		*err = 0;
		return (void *)val;
	}

	if (arg->type_id == LT_ARGS_TYPEID_STRING) {
		char *str;
		long slen;

		if (!val) {
			if (psize)
				*psize = 0;

			return strdup("");
		}

		sp_off += sizeof(void *);
		PTRACE_PEEK(slen, PTRACE_PEEKDATA, target, sp_off, NULL, PT_RETERROR);

		if (slen > MAX_STRING_ALLOC_SIZE) {
			// XXX: Do something.
		}

		if (!(str = read_string_remote(target, (void *)val, slen))) {
			PRINT_ERROR("Error reading string (%s) of advertised size %zu bytes\n",
				arg->name, slen);
			return NULL;
		}

		if (next_off)
			*next_off = offset + extra_off + (sizeof(void *) * 2);

		if (psize)
			*psize = slen;

		*err = 0;
		return str;
	}

	// XXX: This conditional shouldn't be structured like this
	if (next_off) {
//		unsigned long oval=val;

		if ((arg->type_id == LT_ARGS_TYPEID_INT32 || (arg->type_id == LT_ARGS_TYPEID_UINT32)) && !arg->pointer) {
			*next_off = offset + extra_off + sizeof(int32_t);
//			val >>= 32;
			val &= 0x00000000ffffffff;
			vsize = 4;
		} else if ((arg->type_id == LT_ARGS_TYPEID_INT16 || (arg->type_id == LT_ARGS_TYPEID_UINT16)) && !arg->pointer) {
			*next_off = offset + extra_off + sizeof(int16_t);
//			val >>= 48;
			val &= 0x000000000000ffff;
			vsize = 2;
		} else if ((arg->type_id == LT_ARGS_TYPEID_INT8 || (arg->type_id == LT_ARGS_TYPEID_UINT8)) && !arg->pointer) {
			*next_off = offset + extra_off + sizeof(int8_t);
			val &= 0x00000000000000ff;
			vsize = 1;
		} else {
			*next_off = offset + extra_off + sizeof(void *);
			vsize = sizeof(void *);
		}
	}

	if (psize)
		*psize = vsize;

	*err = 0;
	return (void *)val;


/*	PRINT_VERBOSE(cfg, 2, "get value for %s - arch = %lx, flag = %d\n",
			arg->name, ARCH_GET(arg), ARCH_GET_FLAG(arg));

	switch(ARCH_GET_FLAG(arg)) {
	case ARCH_FLAG_MEM:
		pval = get_value_mem(cfg, arg, regs, ret);
		break;

	case ARCH_FLAG_REG_INTEGER:
		pval = get_value_reg_integer(cfg, arg, regs, ret);
		break;

	}

	return pval;*/
}

/* Process structure stored completelly in the 
   memory - pointed to by 'pval' arg. */
/*static int process_struct_mem(struct lt_config_shared *cfg, struct lt_arg *arg,
				void *pval, struct lt_args_data *data)
{
	struct lt_arg *a;
	int i = 0;

	PRINT_VERBOSE(cfg, 2, "for %s - arch = %llx\n",
			arg->name, ARCH_GET(arg));

	lt_args_cb_struct(cfg, LT_ARGS_STRUCT_ITSELF, arg, NULL, data, 0);

	lt_list_for_each_entry(a, arg->args_head, args_list) {
		int last = (i + 1) == arg->mmbcnt;
		void *pv = pval + ARCH_GET_OFFSET(a);

		lt_args_cb_struct(cfg, LT_ARGS_STRUCT_ARG, a, pv, data, last);

		i++;
	}

	return 0;
}*/

/*static int process_struct_arg(struct lt_config_shared *cfg, struct lt_arg *arg,
			void *regs, struct lt_args_data *data, int ret)
{
	struct lt_arg *a;
	int i = 0;

	return 0;

	PRINT_VERBOSE(cfg, 2, "for %s - arch = %llx\n",
			arg->name, ARCH_GET(arg));

	lt_args_cb_struct(cfg, LT_ARGS_STRUCT_ITSELF, arg, NULL, data, 0);

	lt_list_for_each_entry(a, arg->args_head, args_list) {
		int last = (i + 1) == arg->mmbcnt;
		void *pval = NULL;

//		pval = get_value(cfg, a, regs, ret);

		lt_args_cb_struct(cfg, LT_ARGS_STRUCT_ARG, a, pval, data, last);
		i++;
	}

	return 0;
}*/

/*static void process_detailed_struct(struct lt_config_shared *cfg,
		struct lt_arg *arg, void *pval, struct lt_args_data *data, 
		void *regs, int ret)
{
	if (arg->pointer)
		pval = *((void**) pval);

	if (ARCH_GET_FLAG(arg) == ARCH_FLAG_MEM) {
		process_struct_mem(cfg, arg, pval, data);
	} else {
		if (arg->pointer)
			process_struct_mem(cfg, arg, pval, data);
		else
			process_struct_arg(cfg, arg, regs, data, ret);
	}
}*/

static void
enter_transformer_callstack(char *symname, struct user_regs_struct *inregs, void **args, size_t argcnt, lt_tsd_t *tsd)
{

	if (!tsd->xfm_call_stack_max)
	{
		tsd->xfm_call_stack_max = 8;
		tsd->xfm_call_stack_sz = 0;
		tsd->xfm_call_stack = malloc(sizeof(*tsd->xfm_call_stack) * tsd->xfm_call_stack_max);
	} else if (tsd->xfm_call_stack_sz == tsd->xfm_call_stack_max) {
		size_t new_size;

		tsd->xfm_call_stack_max *= 2;
		new_size = sizeof(*tsd->xfm_call_stack) * tsd->xfm_call_stack_max;
		tsd->xfm_call_stack = realloc(tsd->xfm_call_stack, new_size);
	}

	if (!tsd->xfm_call_stack) {
		PERROR("Error allocating space for call stack");
		return;
	}

	tsd->xfm_call_stack[tsd->xfm_call_stack_sz].fn_name = symname;
	tsd->xfm_call_stack[tsd->xfm_call_stack_sz].args = args;
	tsd->xfm_call_stack[tsd->xfm_call_stack_sz].argcnt = argcnt;
//	memcpy(&tsd->xfm_call_stack[tsd->xfm_call_stack_sz].registers, inregs, sizeof(*inregs));
	tsd->xfm_call_stack_sz++;

	return;
}

static int
exit_transformer_callstack(char *symname, struct user_regs_struct *inregs, void ***pargs, size_t *pargcnt, lt_tsd_t *tsd)
{
	int i;

	if (!tsd->xfm_call_stack_max || !tsd->xfm_call_stack_sz) {
		PRINT_ERROR_SAFE("%s", "Whoops: could not find entry on transformer call stack.\n");
		return -1;
	}

	for (i = tsd->xfm_call_stack_sz; i > 0; i--) {

		if (strcmp(tsd->xfm_call_stack[i-1].fn_name, symname))
			continue;

//		if (memcmp(&(tsd->xfm_call_stack[i-1].registers), inregs, sizeof(*inregs)))
//			continue;

		*pargs = tsd->xfm_call_stack[i-1].args;
		*pargcnt = tsd->xfm_call_stack[i-1].argcnt;

		memcpy(&(tsd->xfm_call_stack[i-1]), &(tsd->xfm_call_stack[i]),
			(sizeof(fn_call_t) * (tsd->xfm_call_stack_sz - i)));

		tsd->xfm_call_stack_sz--;
		return 0;
	}

	return -1;
}

void
stack_dump(void *buf, size_t bsize, size_t increment) {
	unsigned char *bptr = (unsigned char *)buf;
	size_t i, nleft = bsize;

	PRINT_ERROR("Dump buffer (%zu bytes): ", bsize);

	while (nleft) {
		size_t maxread;

		maxread = nleft >= increment ? increment : nleft;

		for (i = 0; i < maxread; i++) {
			PRINT_ERROR("%.2x", *bptr);
			bptr++;
		}

		PRINT_ERROR("%s", " ");

		if (nleft <= increment)
			break;

		nleft -= increment;
	}

	PRINT_ERROR("%s", "\n");
	return;
}

int lt_stack_process(struct lt_config_shared *cfg, struct lt_args_sym *asym, 
			pid_t target, struct user_regs_struct *regs, struct lt_args_data *data, int silent,
			lt_tsd_t *tsd)
{
	int i;

	for (i = 0; i < sizeof(argument_watchlist)/sizeof(argument_watchlist[0]); i++) {

		if (argument_watchlist[i].do_entry && (!strcmp(argument_watchlist[i].funcname, asym->name))) {
			void *stack_data;

			stack_data = read_string_remote(target, (void *)regs->rsp, argument_watchlist[i].nbytes);

			if (!stack_data) {
				PRINT_ERROR("Error reading debug bytes from stack for function entry point: %s\n", asym->name);
				break;
			}

			stack_dump(stack_data, argument_watchlist[i].nbytes, 4);
			free(stack_data);
			break;
		}

	}


//	printf("+++ lt_stack_process(): %s\n", asym->name);
//	printf("+++ sp = %p\n", (void *)regs->rsp);

	if (asym->args[LT_ARGS_RET]->latrace_custom_func_transformer ||
		asym->args[LT_ARGS_RET]->latrace_custom_func_intercept) {
		void **targs;
		int tres = -1;

		if (!ARCH_GET(asym->args[LT_ARGS_RET]) &&
		    (-1 == classificate(cfg, asym, tsd)))
			return -1;

		if (!(targs = malloc(sizeof(void *) * asym->argcnt)))
			return -1;

		size_t cur_off = 0;

		for(i = 1; i < asym->argcnt; i++) {
			void *pval = NULL;
			struct lt_arg *arg = asym->args[i];
			int is_err;

//			size_t old = cur_off;
			pval = get_value(cfg, arg, target, regs, cur_off, NULL, &cur_off, &is_err, 0);
//			fprintf(stderr, "HEH: started with %zu, ended with %zu (%x)\n", old, cur_off
			targs[i-1] = pval;
		}

		if (asym->args[LT_ARGS_RET]->latrace_custom_func_intercept) {
			if (tsd->fault_reason) {
				PRINT_ERROR("Error: caught fatal condition in custom func intercept entry for %s: %s\n",
					asym->name, tsd->fault_reason);
				tsd->fault_reason = NULL;
			} else
				asym->args[LT_ARGS_RET]->latrace_custom_func_intercept(targs, asym->argcnt-1, NULL);

		}

		if (!silent && asym->args[LT_ARGS_RET]->latrace_custom_func_transformer) {

			if (tsd->fault_reason) {
				PRINT_ERROR("Error: caught fatal condition in custom func transformer entry for %s: %s\n",
					asym->name, tsd->fault_reason);
				tsd->fault_reason = NULL;
			} else {
				tres = asym->args[LT_ARGS_RET]->latrace_custom_func_transformer(targs,
					asym->argcnt-1, data->args_buf+data->args_totlen, data->args_len-data->args_totlen, NULL);
			}

		}

/*		if (silent) {
			free(targs);
			return 0;
		} */

		enter_transformer_callstack(asym->name, regs, targs, asym->argcnt-1, tsd);

		if (silent)
			return 0;

		if (!tres) {
			data->args_totlen += strlen(data->args_buf+data->args_totlen);
			return tres;
		}

	}

	if (!ARCH_GET(asym->args[LT_ARGS_RET]) &&
	    (-1 == classificate(cfg, asym, tsd)))
		return -1;

	if (asym->argcnt == 1) {
		snprintf(data->args_buf+data->args_totlen, data->args_len-data->args_totlen, " ");
		data->args_totlen += strlen(data->args_buf+data->args_totlen);
		return 0;
	}

	size_t cur_off = 0;

	for(i = 1; i < asym->argcnt; i++) {
		void *pval = NULL;
		size_t psize;
		struct lt_arg *arg = asym->args[i];
		int last = (i + 1) == asym->argcnt, is_err;

		pval = get_value(cfg, arg, target, regs, cur_off, &psize, &cur_off, &is_err, 0);

		if (!is_err && arg->latrace_custom_struct_transformer && (!arg->fmt || !*(arg->fmt))) {
			void *pvald = *((void**) pval);
			size_t left, saved_totlen;
			int result;
			static size_t seplen_color = 0;

			if (!seplen_color)
				seplen_color = strlen(BOLD) + strlen(BOLDOFF) + 2;

			saved_totlen = data->args_totlen;
//			left = data->arglen - data->args_totlen;
			if ((i * data->arglen) < data->args_len)
				left = (i * data->arglen) - data->args_totlen;
			else
				left = data->args_len - data->args_totlen;

			memset(data->args_buf+data->args_totlen, 0, left);
			left--;
			result = snprintf(data->args_buf+data->args_totlen, left, "%s = ", arg->name);
			data->args_totlen += result;
			left -= result;

			if (i+1 < asym->argcnt)
				left -= (cfg->fmt_colors ? seplen_color : 2);

			if (tsd->fault_reason) {
				PRINT_ERROR("Error: caught fatal condition in custom func transformer entry for %s: %s\n",
					asym->name, tsd->fault_reason);
				tsd->fault_reason = NULL;
			} else {
				result = arg->latrace_custom_struct_transformer(pvald, data->args_buf+data->args_totlen, left);

				if (!result) {
					data->args_totlen += strlen(data->args_buf+data->args_totlen);

					if (i+1 < asym->argcnt) {
						char fmtbuf[16];
						size_t max_append;

						if (cfg->fmt_colors)
							snprintf(fmtbuf, sizeof(fmtbuf), "%s, %s", BOLD, BOLDOFF);
						else
							strcpy(fmtbuf, ", ");

						max_append = data->args_len - data->args_totlen;
						max_append = strlen(fmtbuf) > max_append ? max_append : strlen(fmtbuf);
						strncat(data->args_buf+data->args_totlen, fmtbuf, max_append);
						data->args_totlen += max_append;
					}

					continue;
				} else {
					data->args_totlen = saved_totlen;
					memset(data->args_buf+data->args_totlen, 0, left);
				}

			}

		}

		if ((is_err) && 
		    (arg->pointer || ((LT_ARGS_DTYPE_STRUCT != arg->dtype) &&
		    (arg->type_id != LT_ARGS_TYPEID_FNPTR)))) {
			PRINT_VERBOSE(cfg, 2,
				"THIS SHOULD NEVER HAPPEN - arg '%s %s'\n",
				arg->type_name, arg->name);
			continue;
		}

		lt_args_cb_arg(cfg, target, arg, pval, psize, data, last, 1, 0);

/*		if ((cfg->args_detailed) &&
		    (LT_ARGS_DTYPE_STRUCT == arg->dtype))
			process_detailed_struct(cfg, arg, pval, data, regs, 0);*/
	}

	return 0;
}

int lt_stack_process_ret(struct lt_config_shared *cfg, struct lt_args_sym *asym,
			pid_t target, struct user_regs_struct *iregs, struct user_regs_struct *regs, struct lt_args_data *data, int silent,
			lt_tsd_t *tsd)
{
	struct lt_arg *arg;
	void *pval;
	size_t ret_offset = 0, i;
	int needs_callstack = 0;

	for(i = 1; i < asym->argcnt; i++) {
		struct lt_arg *arg = asym->args[i];

		ret_offset += sizeof(void *);

		// XXX: This should be calling a version of get_value() that only returns offsets.

		// Slice
		if (arg->pointer == -1)
			ret_offset += sizeof(void *) * 2;
		else if (arg->type_id == LT_ARGS_TYPEID_STRING)
			ret_offset += sizeof(void *);

	}

	for (i = 0; i < sizeof(argument_watchlist)/sizeof(argument_watchlist[0]); i++) {

		if (argument_watchlist[i].do_exit && (!strcmp(argument_watchlist[i].funcname, asym->name))) {
			void *stack_data;

			stack_data = read_string_remote(target, (void *)regs->rsp + ret_offset, argument_watchlist[i].nbytes);

			if (!stack_data) {
				PRINT_ERROR("Error reading debug bytes from stack for function entry point: %s\n", asym->name);
				break;
			}

			stack_dump(stack_data, argument_watchlist[i].nbytes, 4);
			free(stack_data);
			break;
		}

	}


/*	if (ret_offset != asym->stacksz) {
		PRINT_ERROR("Warning: stack size mismatch for %s() between calculations and expectations: %zu vs %u bytes\n",
			asym->name, ret_offset, asym->stacksz);
	}*/

	for (i = 0; i < asym->rargcnt; i++) {
		size_t psize;
		int last = (i == asym->rargcnt-1), is_err;

		arg = asym->ret_args[i];
		pval = get_value(cfg, arg, target, regs, ret_offset, &psize, &ret_offset, &is_err, 0);

		// XXX: This is a stop-gap special condition fix. This sorely needs to be fixed.
		if (asym->rargcnt == 1) {
			ret_offset = 0;
			pval = get_value(cfg, arg, target, regs, ret_offset, &psize, &ret_offset, &is_err, 1);
		}

/*		if (is_err) {
			PRINT_ERROR("Unexpected error occurred decoding return value from function!\n");
			return -1;
		} */

		needs_callstack = ((asym->args[LT_ARGS_RET]->latrace_custom_func_transformer != NULL) ||
			(asym->args[LT_ARGS_RET]->latrace_custom_func_intercept != NULL));

		if (needs_callstack || asym->args[LT_ARGS_RET]->latrace_custom_struct_transformer) {
			void **inargs = NULL;
			void *retval = pval;
			size_t inargs_size = 0;
			int tres = -1;

	//		if (!silent && exit_transformer_callstack(asym->name, iregs, &inargs, &inargs_size, tsd) < 0) {
			if (needs_callstack && exit_transformer_callstack(asym->name, iregs, &inargs, &inargs_size, tsd) < 0) {
				PRINT_ERROR_SAFE("%s", "Error retrieving function entry arguments from transformer call stack\n");
				inargs = NULL;
				inargs_size = 0;
			}

			/* Special null value for functions that are declared to return type void */
			retval = !retval ? (void *)-1 : retval;

			if (asym->args[LT_ARGS_RET]->latrace_custom_func_intercept) {

				if (tsd->fault_reason) {
					PRINT_ERROR("Error: caught fatal condition in custom func intercept exit for %s: %s\n",
						asym->name, tsd->fault_reason);
					tsd->fault_reason = NULL;
				} else
					asym->args[LT_ARGS_RET]->latrace_custom_func_intercept(inargs, inargs_size, retval);

			}

			if (!silent && asym->args[LT_ARGS_RET]->latrace_custom_func_transformer) {

				if (tsd->fault_reason) {
					PRINT_ERROR("Error: caught fatal condition in custom func transformer exit for %s: %s\n",
						asym->name, tsd->fault_reason);
					tsd->fault_reason = NULL;
				} else {
					tres = asym->args[LT_ARGS_RET]->latrace_custom_func_transformer(inargs,
						inargs_size, data->args_buf+data->args_totlen, data->args_len-data->args_totlen, retval);
				}

			}

			if (!silent && (tres < 0) && asym->args[LT_ARGS_RET]->latrace_custom_struct_transformer && !is_err &&
				(!asym->args[LT_ARGS_RET]->fmt || !*(asym->args[LT_ARGS_RET]->fmt))) {

				if (tsd->fault_reason) {
					PRINT_ERROR("Error: caught fatal condition in custom struct transformer exit for %s: %s\n",
						asym->name, tsd->fault_reason);
					tsd->fault_reason = NULL;
				} else {
					tres = asym->args[LT_ARGS_RET]->latrace_custom_struct_transformer(*((void**) pval), data->args_buf+data->args_totlen, data->args_len-data->args_totlen);
				}

			}

			if (inargs)
				free(inargs);

			if (silent)
				return 0;

			if (!tres) {
				data->args_totlen += strlen(data->args_buf+data->args_totlen);
				return tres;
			}

		}

		if ((arg->type_id != LT_ARGS_TYPEID_VOID) || (arg->pointer)) {
			int dspname = !(arg == asym->args[LT_ARGS_RET]);

//			if ((asym->rargcnt == 1) && (!strncmp(asym->args[0]->name, ANON_PREFIX, strlen(ANON_PREFIX))))
			if ((asym->rargcnt == 1) && (arg == asym->ret_args[0]))
				dspname = 0;

			lt_args_cb_arg(cfg, target, arg, pval, psize, data, last, dspname, 1);
		}

/*		if ((cfg->args_detailed) && (LT_ARGS_DTYPE_STRUCT == arg->dtype))
			process_detailed_struct(cfg, arg, pval, data, regs, 0);*/

	}

	if (cfg->fmt_colors) {
		char *fmtptr;
		size_t left = data->args_len - data->args_totlen;

		if (left < strlen(ULINEOFF))
			fmtptr = data->args_buf + data->args_totlen - (strlen(ULINEOFF) + 1);
		else
			fmtptr = data->args_buf + data->args_totlen;

		strcpy(fmtptr, ULINEOFF);
		data->args_totlen += strlen(ULINEOFF);
	}

	return 0;
}
