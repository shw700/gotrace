#include <stdlib.h>
#include <string.h>

#include "gomod_print/gomod_print.h"


golang_type_serializer_t golang_serializer_table[] = {
	STBLENT("net.TCPConn", gotrace_print_net__TCPConn),
	STBLENT(NULL, NULL)
};


golang_serializer_func
get_golang_serializer(const char *typename) {
	golang_type_serializer_t *sptr = golang_serializer_table;

	while ((*sptr).name != NULL) {
		if (!strcmp((*sptr).name, typename))
			return ((*sptr).serializer);

		sptr++;
	}

	return NULL;
}

int
is_type_serialization_supported(const char *typename) {
	golang_type_serializer_t *sptr = golang_serializer_table;

	while ((*sptr).name != NULL) {
		if (!strcmp((*sptr).name, typename))
			return 1;

		sptr++;
	}

	return 0;
}
