#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "config.h"


ssize_t
recv_with_pid(pid_t pid, int fd, const void *buf, size_t len, pid_t *pout) {
	ssize_t result;
	struct msghdr msgh;
	struct iovec iov;
	struct ucred *ucred;
	int optval = 1;
	struct cmsghdr *cmsg;

	union {
		struct cmsghdr cmh;
		char control[CMSG_SPACE(sizeof(struct ucred))];
	} c_un;

	if (setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &optval, sizeof(optval)) == -1) {
		perror_pid("setsockopt(SO_PASSCRED)", pid);
		return -1;
	}

	memset(&c_un, 0, sizeof(c_un));
	c_un.cmh.cmsg_len = CMSG_LEN(sizeof(struct ucred));
	c_un.cmh.cmsg_level = SOL_SOCKET;
	c_un.cmh.cmsg_type = SCM_CREDENTIALS;

	memset(&msgh, 0, sizeof(msgh));
	msgh.msg_control = c_un.control;
	msgh.msg_controllen = sizeof(c_un.control);
	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;

	memset(&iov, 0, sizeof(iov));
	iov.iov_base = (void *)buf;
	iov.iov_len = len;

	if ((result = recvmsg(fd, &msgh, MSG_WAITALL)) == -1) {
		perror_pid("recvmsg", pid);
		return -1;
	} else if (result != len) {
		PRINT_ERROR("%s", "Error receiving control message from gomod socket.\n");
		return -1;
	}

	cmsg = CMSG_FIRSTHDR(&msgh);
	if (!cmsg  || (cmsg->cmsg_len != CMSG_LEN(sizeof(struct ucred)))) {
		PRINT_ERROR("%s", "Error receiving control message with unexpected message length\n");
		return -1;
	}

	if ((cmsg->cmsg_level != SOL_SOCKET) || (cmsg->cmsg_type != SCM_CREDENTIALS)) {
		PRINT_ERROR("%s", "Error receiving control message with unexpected data type\n");
		return -1;
	}

	ucred = (struct ucred *)CMSG_DATA(cmsg);

	// ucred->uid, ucred->gid
	if (pout)
		*pout = ucred->pid;

	return result;
}

ssize_t
send_with_pid(pid_t pid, int fd, const void *buf, size_t len) {
	ssize_t result;
	struct msghdr msgh;
	struct iovec iov;

	memset(&msgh, 0, sizeof(msgh));
	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;
//	msgh.msg_name = NULL;
//	msgh.msg_namelen = 0;
//	msgh.msg_control = NULL;
//	msgh.msg_controllen = 0;

	memset(&iov, 0, sizeof(iov));
	iov.iov_base = (void *)buf;
	iov.iov_len = len;

	if ((result = sendmsg(fd, &msgh, 0)) == -1)
		perror_pid("sendmsg", pid);
	else if (result != len) {
		PRINT_ERROR("%s", "Error sending control message to gomod socket.\n");
		result = -1;
	}

	return result;
}

ssize_t
xsend(pid_t pid, int sockfd, const void *buf, size_t len, int do_ctl) {
	ssize_t result;

	if (do_ctl)
		return (send_with_pid(pid, sockfd, buf, len));

	if ((result = send(sockfd, buf, len, 0)) == -1)
		perror_pid("send", pid);
	else if (result != len) {
		PRINT_ERROR("%s", "Error sending data to gomod socket.\n");
		result = -1;
	}

	return result;
}

ssize_t
xrecv(pid_t pid, int sockfd, void *buf, size_t len, int do_ctl, pid_t *pout) {
	ssize_t result;

	if (do_ctl)
		return (recv_with_pid(pid, sockfd, buf, len, pout));

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
send_gt_msg(pid_t pid, int fd, int reqtype, void *data, size_t dlen, int do_ctl) {
	gomod_data_hdr_t hdr;

	if (dlen > 0xffff) {
		PRINT_ERROR("Error calling sending golang socket data with oversized buffer (%zu bytes)\n", dlen);
		return -1;
	}

	memset(&hdr, 0, sizeof(hdr));
	hdr.magic = GOMOD_DATA_MAGIC;
	hdr.size = dlen;
	hdr.reqtype = reqtype;

	if (xsend(pid, fd, &hdr, sizeof(hdr), do_ctl) < 0)
		return -1;

	if (xsend(pid, fd, data, dlen, 0) < 0)
		return -1;

	return 0;
}

void *
recv_gt_msg(pid_t pid, int fd, int reqtype, size_t *plen, int *preqtype, int do_ctl, pid_t *pout) {
	void *result;
	gomod_data_hdr_t hdr;

	if (xrecv(pid, fd, &hdr, sizeof(hdr), do_ctl, pout) < 0)
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

	if (xrecv(pid, fd, result, hdr.size, 0, NULL) < 0) {
		PRINT_ERROR("%s", "Error encountered in retrieving remote result body of gomod function.\n");
		free(result);
		return NULL;
	}

	if (plen)
		*plen = hdr.size;

	return result;
}


//       ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags);

