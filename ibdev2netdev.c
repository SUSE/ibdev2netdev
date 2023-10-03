#include <infiniband/verbs.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#define BUF_SIZE 8192
#define GID_LEN 16

struct nl_req_s
{
	struct nlmsghdr hdr;
	struct rtgenmsg gen;
};

struct if_info
{
	unsigned ifi_flags;
	const char *if_name;
	uint32_t mac_len;
	const char *mac;
};

struct gid_hash_entry {
	struct ibv_device *device;
	uint32_t port;
	struct ibv_port_attr port_attr;
	union ibv_gid gid;
};

typedef union gid_hash_u
{
	union gid_hash_u *sub;
	struct gid_hash_entry *entry;
} gid_hash_t;

gid_hash_t *gid_hash;

static int null_gid(union ibv_gid *gid)
{
	return !(gid->raw[4] | gid->raw[5] | gid->raw[6] | gid->raw[7] |
		gid->raw[8] | gid->raw[9] | gid->raw[10] | gid->raw[11] |
		gid->raw[12] | gid->raw[13] | gid->raw[14] | gid->raw[15]);
}

void print_formated_gid(union ibv_gid *gid, int i)
{
	printf("\t\t\tGID[%3d]:\t\t%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
		i, gid->raw[0], gid->raw[1], gid->raw[2],
		gid->raw[3], gid->raw[4], gid->raw[5], gid->raw[6],
		gid->raw[7], gid->raw[8], gid->raw[9], gid->raw[10],
		gid->raw[11], gid->raw[12], gid->raw[13], gid->raw[14],
		gid->raw[15]);
}

void init_gid_hash(gid_hash_t *h[]){
	*h = calloc(256,  sizeof(gid_hash_t));
}

static void _add_gid_entry(gid_hash_t h[], const unsigned char gid[],
			const struct gid_hash_entry *entry, int depth)
{
	const unsigned char key = gid[depth];

	if(depth == GID_LEN - 1) {
		h[key].entry = malloc(sizeof(struct gid_hash_entry));
		memcpy(h[key].entry, entry, sizeof(*entry));;
		return;
	}
	// We need to go deeper
	if (!h[key].sub){
		h[key].sub = calloc(256, sizeof(gid_hash_t));
	}
	_add_gid_entry(h[key].sub, gid, entry, depth + 1);
}

void add_gid_entry(gid_hash_t h[], const unsigned char gid[],
		const struct gid_hash_entry *entry)
{
	_add_gid_entry(h, gid, entry, 0);
}

static const struct gid_hash_entry* _load_entry(const gid_hash_t h[], const unsigned char gid[], int depth)
{
	const unsigned char key = gid[depth];

	if(depth == GID_LEN - 1)
		return h[key].entry;

	if (!h[key].sub)
		return NULL;

	return _load_entry(h[key].sub, gid, depth + 1);
}

const struct gid_hash_entry* load_entry(const gid_hash_t h[], const unsigned char gid[])
{
	return _load_entry(h, gid, 0);
}

static const struct gid_hash_entry*
_search_entry(const gid_hash_t h[], const unsigned char gid[], uint64_t mask, int depth)
{
	unsigned char key = gid[depth];
	const int mask_set = !!(mask & (1ULL << depth));

	if(depth == GID_LEN - 1)
		return h[key].entry;

	if (mask_set){
		if (!h[key].sub)
			return NULL;

		return _search_entry(h[key].sub, gid, mask, depth + 1);
	} else {
		const struct gid_hash_entry* res = NULL;

		for (int k = 0; k < 256; ++k){
			if (!h[k].sub)
				continue;
			res = _search_entry(h[k].sub, gid, mask, depth + 1);
			if(res)
				return res;
		}
		return NULL;
	}
}

const struct gid_hash_entry* search_entry(const gid_hash_t h[], const unsigned char gid[], uint64_t mask)
{
	return _search_entry(h, gid, mask, 0);
}

static void _dump_gid_hash(gid_hash_t h[], int depth, char prefix[GID_LEN])
{
	if (depth == GID_LEN) {
		struct gid_hash_entry* entry = (struct gid_hash_entry*) h;
		for(int i = 0; i < GID_LEN; ++i)
			printf("%02hhx ", prefix[i]);
		printf(": %s \n",entry->device->name);
		return;
	}
	for (int i = 0; i < 256; ++i){
		if (h[i].sub) {
			prefix[depth] = i;
			_dump_gid_hash(h[i].sub, depth +1, prefix);
		}
	}
}

void dump_gid_hash(gid_hash_t h[])
{
	char pref[GID_LEN] = { 0 };
	_dump_gid_hash(h, 0, pref);
}

static int load_ib_port_gid(gid_hash_t *h, struct gid_hash_entry *entry,
			struct ibv_context *ctx, uint32_t port, int gid_id)
{
	union ibv_gid gid;

	if (ibv_query_gid(ctx, port, gid_id, &gid)) {
		fprintf(stderr, "Failed to query gid to port %u, index %d\n",
			port, gid_id);
		return 0;
	}
	if (!null_gid(&gid)) {
		entry->gid = gid;
#ifdef DEBUG
		print_formated_gid(&gid, gid_id);
#endif
		add_gid_entry(h, gid.raw, entry);
	}
	return 0;
}

static int load_ib_port_gids(gid_hash_t *h, struct gid_hash_entry *entry,
			struct ibv_context *ctx,
			uint32_t port)
{
	struct ibv_port_attr port_attr;
	int gid_id;

	if (ibv_query_port(ctx, port, &port_attr)) {
		fprintf(stderr, "Failed to query port %u props\n", port);
		return -1;
	}
#ifdef DEBUG
	printf("\tOpened port %d\n", port);
#endif

	entry->port = port;
	entry->port_attr = port_attr;

	for (gid_id = 0; gid_id < port_attr.gid_tbl_len; ++gid_id)
		if (load_ib_port_gid(h, entry, ctx, port, gid_id) < 0)
			return -1;

	return 0;
}

static int load_ib_dev_gids(gid_hash_t *h, struct ibv_device *dev)
{
	const char *dev_name;
	struct ibv_context *ctx;
	struct ibv_device_attr_ex dev_attr = {};
	uint32_t port;
	struct gid_hash_entry entry;

	entry.device = dev;
	dev_name = ibv_get_device_name(dev);

	ctx = ibv_open_device(dev);
	if (!ctx) {
		fprintf(stderr, "Failed to open device %s\n", dev_name);
		return -1;
	}
#ifdef DEBUG
	printf("Opened device %s\n", dev_name);
#endif
	if (ibv_query_device_ex(ctx, NULL, &dev_attr)) {
		fprintf(stderr, "Failed to query device props of %s\n", dev_name);
		goto cleanup;
	}

	for (port = 1; port <= dev_attr.orig_attr.phys_port_cnt; ++port) {
		if (load_ib_port_gids(h, &entry, ctx, port) < 0) {
			goto cleanup;
		}

	}
 cleanup:
	ibv_close_device(ctx);
	return 0;
}

int load_ib_gids(gid_hash_t *h)
{
	int i;
	int num_devices = 0;
	struct ibv_device ** devlist;

	devlist = ibv_get_device_list(&num_devices);
	if (!devlist)
		return errno;
	if (!num_devices)
		return 0;

	for (i = 0; i < num_devices; ++i) {
		struct ibv_device *dev;

		dev = devlist[i];
		load_ib_dev_gids(h, dev);
	}
	ibv_free_device_list(devlist);
	return 0;
}

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

int nl_iterate_links(int fd, int (*fn)(const struct if_info*))
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
				}
				attr_ptr = RTA_NEXT(attr_ptr, attr_len);
			}
			if (fn(&infos) < 0)
				return -1;

			nlmsg_ptr = NLMSG_NEXT(nlmsg_ptr, msg_len);
		}
	}
}

void print_line(const struct gid_hash_entry *entry, const struct if_info *infos)
{
	printf("%s port %d <===> %s (%s)\n", ibv_get_device_name(entry->device),
		entry->port, infos->if_name, 
		(infos->ifi_flags & IFF_UP) ? "Up" : "Down");
}

int mac_lookup(const struct if_info *infos)
{
	const struct gid_hash_entry *entry;
	unsigned char gid[GID_LEN] = {0};

	if(infos->mac_len == 20) {
		/* In that case, we want to match the last 8B to the GID interface_id */


		memcpy(&gid[GID_LEN - 8], &infos->mac[20 - 8], 8);
		entry = search_entry(gid_hash, gid, ~0xffULL);
		if (!entry)
			return 0;

		print_line(entry, infos);
		return 1;

	} else if (infos->mac_len == 6){
		uint64_t mask = (uint64_t)(~0xffULL);

		gid[GID_LEN - 8] = infos->mac[0] ^ 0x2;
		gid[GID_LEN - 7] = infos->mac[1];
		gid[GID_LEN - 6] = infos->mac[2];
		mask = mask & ~(1ULL << (GID_LEN - 5));
		mask = mask & ~(1ULL << (GID_LEN - 4));
		gid[GID_LEN - 3] = infos->mac[3];
		gid[GID_LEN - 2] = infos->mac[4];
		gid[GID_LEN - 1] = infos->mac[5];

#ifdef DEBUG
		printf("If: %s MAC: %02hhx%02hhx%02hhx%02hhx%02hhx%02hhx, GID:\n",
			infos->if_name,
			infos->mac[0], infos->mac[1],
			infos->mac[2], infos->mac[3],
			infos->mac[4], infos->mac[5]);
		union ibv_gid dgid;
		memcpy(dgid.raw, gid, sizeof(gid));
		print_formated_gid(&dgid, 0);
#endif

		entry = search_entry(gid_hash, gid, mask);
		if (!entry) {
			/* Some interfaces seems to have a weird behaviour (at least seen on irdma)
			 * where their gid is the (mac << 2) set as the subnet_prefix and that's it...
			 * Try for that, just in case */
			memcpy(gid, infos->mac, 6);
			memset(gid + 6, 0, sizeof(gid) - 6);
			entry = load_entry(gid_hash, gid);
			if(!entry)
				return 0;
		}

		print_line(entry, infos);
		return 1;
	} else {
		fprintf(stderr, "Unsupported MAC len %d\n", infos->mac_len);
		return -1;
	}

	return 0;
}

int main()
{
	int fd;

	init_gid_hash(&gid_hash);
	load_ib_gids(gid_hash);

	fd = nl_setup();
	if (fd < 0) {
		fprintf(stderr, "Failed to connect to netlink\n");
		return -1;
	}

	if (nl_request_links(fd) <= 0) {
		fprintf(stderr, "Failed to requet links\n");
		return -1;
	}

	nl_iterate_links(fd, mac_lookup);

	close(fd);
	return 0;
}
