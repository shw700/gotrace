#include "config.h"


void
perror_pid(const char *msg, pid_t pid) {
	char outbuf[1024];

	memset(outbuf, 0, sizeof(outbuf));
	snprintf(outbuf, sizeof(outbuf), "%sError in %s (%d)%s",
		BOLDRED, msg, pid, RESET);
	perror(outbuf);
	return;
}

pid_t
gettid(void) {
	return (pid_t)(syscall(SYS_gettid));
}
