#include <sys/types.h>
#include <sys/socket.h>

#include "config.h"


ssize_t
xsend(pid_t pid, int sockfd, const void *buf, size_t len) {
	ssize_t result;

	if ((result = send(sockfd, buf, len, 0)) == -1)
		perror_pid("send", pid);
	else if (result != len) {
		PRINT_ERROR("%s", "Error sending data to gomod socket.\n");
		result = -1;
	}

	return result;
}

ssize_t
xrecv(pid_t pid, int sockfd, void *buf, size_t len) {
	ssize_t result;

	if ((result = recv(sockfd, buf, len, MSG_WAITALL)) != len) {
		if (result == -1)
			perror_pid("recv", pid);
		else
	                PRINT_ERROR("%s", "Error encountered in reading data from gomod socket.\n");

		result = -1;
	}

	return result;
}

int
send_gt_msg(pid_t pid, int fd, int reqtype, void *data, size_t dlen) {
	gomod_data_hdr_t hdr;

	if (dlen > 0xffff) {
		PRINT_ERROR("Error calling sending golang socket data with oversized buffer (%zu bytes)\n", dlen);
		return -1;
	}

	memset(&hdr, 0, sizeof(hdr));
	hdr.magic = GOMOD_DATA_MAGIC;
	hdr.size = dlen;
	hdr.reqtype = reqtype;

	if (xsend(pid, fd, &hdr, sizeof(hdr)) < 0)
		return -1;

	if (xsend(pid, fd, data, dlen) < 0)
		return -1;

	return 0;
}

void *
recv_gt_msg(pid_t pid, int fd, int reqtype, size_t *plen, int *preqtype) {
	void *result;
	gomod_data_hdr_t hdr;

	if (xrecv(pid, fd, &hdr, sizeof(hdr)) < 0)
		return NULL;

	if (preqtype)
		*preqtype = hdr.reqtype;

	if (hdr.magic != GOMOD_DATA_MAGIC) {
		PRINT_ERROR("%s", "Error retrieving gomod function result with unexpected data formatting.\n");
		return NULL;
	} else if ((reqtype != -1) && (hdr.reqtype != reqtype)) {
		PRINT_ERROR("%s", "Error retrieving gomod function result with mismatched request type.\n");
		return NULL;
	} else if ((reqtype == -1) && (hdr.reqtype != GOMOD_RT_SET_INTERCEPT) &&
			(hdr.reqtype != GOMOD_RT_SERIALIZE_DATA)) {
		PRINT_ERROR("%s", "Error retrieving gomod function result with invalid request type.\n");
		return NULL;
	}

	PRINT_ERROR("GO MOD RETURN SIZE = %u bytes\n", hdr.size);

	if (!(result = malloc(hdr.size))) {
		perror_pid("malloc", pid);
		return NULL;
	}

	if (xrecv(pid, fd, result, hdr.size) < 0) {
		PRINT_ERROR("%s", "Error encountered in retrieving remote result body of gomod function.\n");
		free(result);
		return NULL;
	}

	if (plen)
		*plen = hdr.size;

	return result;
}


//       ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags);

