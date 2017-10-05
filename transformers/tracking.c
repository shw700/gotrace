#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <dlfcn.h>

/*
 * Example of custom user transformers and intercepts that can be used to
 * map out dynamically allocated addresses for subsequent address
 * resolution in latrace output.
 */


#define GET_NEXT_COUNTER(x)	(++counters.n_##x)

struct fn_counters {
	unsigned int n_persistentalloc;
	unsigned int n_chans;
};

static __thread struct fn_counters counters;


void misc_transformer_init() __attribute__((constructor));
const char *call_lookup_addr(void *addr, char *outbuf, size_t bufsize);

void *(*sym_lookup_addr)(void *) = NULL;
void (*sym_add_address_mapping)(void *, size_t, const char *) = NULL;
void (*sym_remove_address_mapping)(void *, size_t, const char *, int) = NULL;


void (*latrace_bind_add_address_mapping)(void *, size_t, const char *) = NULL;


int latrace_func_to_str_runtime__persistentalloc(void **args, size_t argscnt, char *buf, size_t blen, void *retval);
int latrace_func_to_str_runtime__makechan(void **args, size_t argscnt, char *buf, size_t blen, void *retval);


void misc_transformer_init()
{
	fprintf(stderr, "Initializing golang trackers module (%d)\n", getpid());

	memset(&counters, 0, sizeof(counters));
	sym_lookup_addr = (void *) dlsym(NULL, "lookup_addr");
	sym_add_address_mapping = (void *) dlsym(NULL, "add_address_mapping");
	sym_remove_address_mapping = (void *) dlsym(NULL, "remove_address_mapping");

	return;
}

const char *call_lookup_addr(void *addr, char *outbuf, size_t bufsize)
{
	char *fname = NULL;

	if (!addr)
		return "NULL";

	if (addr && sym_lookup_addr)
		fname = sym_lookup_addr(addr);

	if (fname)
		return fname;

	snprintf(outbuf, bufsize, "%p", addr);
	return outbuf;
}


int latrace_func_to_str_runtime__persistentalloc(void **args, size_t argscnt, char *buf, size_t blen, void *retval)
{

	if (!sym_add_address_mapping || !retval || (argscnt != 3))
		return -1;

	if (retval) {
		char tokbuf[32];
		unsigned int cnt;

		cnt = GET_NEXT_COUNTER(persistentalloc);
		snprintf(tokbuf, sizeof(tokbuf), "persistentalloc_%u", cnt);
		sym_add_address_mapping(retval, (size_t)args[0], tokbuf);
		snprintf(buf, blen, "%s (tracking %p)", tokbuf, retval);
		return 0;
	}

	return -1;
}

int latrace_func_to_str_runtime__makechan(void **args, size_t argscnt, char *buf, size_t blen, void *retval)
{

	if (!sym_add_address_mapping || !retval || (argscnt != 2))
		return -1;

	if (retval) {
		char tokbuf[32];
		unsigned int cnt;

		cnt = GET_NEXT_COUNTER(chans);
		snprintf(tokbuf, sizeof(tokbuf), "chan_%u", cnt);
		sym_add_address_mapping(retval, 0, tokbuf);
		snprintf(buf, blen, "%s (tracking %p)", tokbuf, retval);
		return 0;
	}

	return -1;
}
