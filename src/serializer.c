#include <stdlib.h>
#include <string.h>

#include "gomod_print/gomod_print.h"


golang_func_t golang_function_table[] = {
	{ "runtime.osinit",			NULL, 0, 1, "" },
	{ "runtime.tracebackinit",		NULL, 0, 1, "" },
//	{ "runtime.moduledataverify",		NULL, 0, 1, "" },
	{ "runtime.stackinit",			NULL, 0, 1, "" },
	{ "runtime.mallocinit",			NULL, 0, 1, "" },
	{ "runtime.init.3",			NULL, 0, 1, "" },
	{ "runtime/debug.setMaxThreads",	NULL, 0, 1, "" },
	{ "runtime.mcommoninit",		NULL, 0, 1, "" },
	{ "runtime.clearpools",			NULL, 0, 1, "" },
//	{ "runtime.gcinit",			NULL, 0, 1, "" },
	{ "runtime.procresize",			NULL, 0xd, 1, "" },
	{ "main.gotrace_print_net__TCPConn",	NULL, 0xdeadbeef, 0, "net.TCPConn" },
	{ "", 					NULL, 0, 0, "" }
};


void *
get_golang_serializer(const char *typename) {
	golang_func_t *sptr = golang_function_table;

	while ((*sptr).func_name[0]) {
		if (!strcmp((*sptr).type_name, typename))
			return ((*sptr).address);

		sptr++;
	}

	return NULL;
}

int
is_type_serialization_supported(const char *typename) {
	golang_func_t *sptr = golang_function_table;

	while ((*sptr).func_name[0]) {
		if (!strcmp((*sptr).type_name, typename))
			return 1;

		sptr++;
	}

	return 0;
}
