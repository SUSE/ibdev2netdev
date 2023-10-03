#include <sys/socket.h>
#include <linux/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include "nl.h"

#define BUF_SIZE 8192

struct nl_req_s
{
	struct nlmsghdr hdr;
	struct rtgenmsg gen;
};

int nl_setup()
{
	int fd, b;
	struct sockaddr_nl local;

	memset(&local, 0, sizeof(local));

	local.nl_family = AF_NETLINK;
	local.nl_pid = getpid();
	local.nl_groups = 0;

	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (fd < 0)
		return -1;

	b = bind(fd, (struct sockaddr *)&local, sizeof(local));
	if (b < 0)
		return -2;
	return fd;
}

int nl_request_links(int fd)
{
	struct sockaddr_nl kernel;
	struct msghdr msg;
	struct nl_req_s req;
	struct iovec iov;

	memset(&kernel, 0, sizeof(kernel));
	memset(&msg, 0, sizeof(msg));
	memset(&req, 0, sizeof(req));

	kernel.nl_family = AF_NETLINK;

	req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtgenmsg));
	req.hdr.nlmsg_type = RTM_GETLINK;
	req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req.hdr.nlmsg_pid = getpid();
	req.hdr.nlmsg_seq = 1;
	req.gen.rtgen_family = AF_PACKET;

	iov.iov_base = &req;
	iov.iov_len = req.hdr.nlmsg_len;

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_name = &kernel;
	msg.msg_namelen = sizeof(kernel);

	return sendmsg(fd, (struct msghdr *)&msg, 0);
}

int nl_iterate_links(int fd, int (*fn)(const struct if_info*, void*), void* arg)
{
	char buf[BUF_SIZE];
	struct nl_req_s
	{
		struct nlmsghdr hdr;
		struct rtgenmsg gen;
	};

	while (1) {
		int msg_len;
		struct nlmsghdr *nlmsg_ptr;

		msg_len = recv(fd, buf, BUF_SIZE, 0);
		if (msg_len < 0)
			return msg_len;

		nlmsg_ptr = (struct nlmsghdr *)buf;
		if(nlmsg_ptr->nlmsg_type == NLMSG_DONE)
			return 0;

		while(NLMSG_OK(nlmsg_ptr, msg_len)) {
			struct ifinfomsg *ifi_ptr;
			struct rtattr *attr_ptr;
			int attr_len;

			struct if_info infos;
			memset(&infos, 0, sizeof(infos));

			if(nlmsg_ptr->nlmsg_type != RTM_NEWLINK)
				continue;

			ifi_ptr = NLMSG_DATA(nlmsg_ptr);
			attr_ptr = IFLA_RTA(ifi_ptr);
			attr_len = nlmsg_ptr->nlmsg_len - NLMSG_LENGTH(sizeof(*ifi_ptr));

			infos.ifi_flags = ifi_ptr->ifi_flags;

			while(RTA_OK(attr_ptr, attr_len)) {
				switch(attr_ptr->rta_type) {
				case IFLA_IFNAME:
					infos.if_name = (const char *)RTA_DATA(attr_ptr);
					break;
				case IFLA_ADDRESS:
					infos.mac_len = RTA_PAYLOAD(attr_ptr);
					infos.mac = (const char*)RTA_DATA(attr_ptr);
					break;
				case IFLA_OPERSTATE:
					infos.operstate = *(unsigned char*)RTA_DATA(attr_ptr);
					break;
				}
				attr_ptr = RTA_NEXT(attr_ptr, attr_len);
			}
			if (fn(&infos, arg) < 0)
				return -1;

			nlmsg_ptr = NLMSG_NEXT(nlmsg_ptr, msg_len);
		}
	}
}
