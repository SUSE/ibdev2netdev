#include <infiniband/verbs.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <linux/if.h>

#include "hash.h"
#include "nl.h"
#include "verbs.h"

static const char *oper_states[] = {
	"unknown", "notpresent", "down", "lowerlayerdown",
	"testing", "dormant",	 "up"
};

void print_line(const struct gid_hash_entry *entry, const struct if_info *infos)
{
	printf("%s/%d gid #%d (%s) <===> %s (%s)\n",
		ibv_get_device_name(entry->device),
		entry->port, entry->gid_id,
		ibv_port_state_str(entry->port_attr.state),
		infos->if_name, oper_states[infos->operstate]);
}

int mac_lookup(const struct if_info *infos, void* arg)
{
	gid_hash_t *h = (gid_hash_t*)arg;
	const struct gid_hash_entry *entry;
	unsigned char gid[GID_LEN] = {0};

	if(infos->mac_len == 20) {
		/* In that case, we want to match the last 8B to the GID interface_id
		 * so offset the mac to drop the first 4 extra bytes and use the mask
		 * to only match the last 8 ones. */
		entry = hash_search_entry(h, infos->mac + 20 - GID_LEN, ~0xffULL);
		if (!entry)
			return 0;

		print_line(entry, infos);
		return 1;

	} else if (infos->mac_len == 6){
		uint64_t mask = (uint64_t)(~0xffULL);

		/* There's some fancy computations here that were found in
		 *  the MOFED doc and in the original ibdev2netdev. It works,
		 * so let's use it:
		 * gid Byte 8 9 10 13 14 are computed from mac[012345]
		 * (or the other way around)
		 * 2 bytes are lost in translation, so disable them from the bitmask
		 */
		gid[GID_LEN - 8] = infos->mac[0] ^ 0x2;
		gid[GID_LEN - 7] = infos->mac[1];
		gid[GID_LEN - 6] = infos->mac[2];
		mask = mask & ~(1ULL << (GID_LEN - 5));
		mask = mask & ~(1ULL << (GID_LEN - 4));
		gid[GID_LEN - 3] = infos->mac[3];
		gid[GID_LEN - 2] = infos->mac[4];
		gid[GID_LEN - 1] = infos->mac[5];

		entry = hash_search_entry(h, gid, mask);
		if (!entry) {
			/* Some interfaces seems to have a weird behaviour (at least seen on irdma)
			 * where their gid is the (mac << 2) set as the subnet_prefix and that's it...
			 * Try for that, just in case */
			memcpy(gid, infos->mac, 6);
			memset(gid + 6, 0, sizeof(gid) - 6);
			entry = hash_load_entry(h, gid);
			if(!entry)
				return 0;
		}

		print_line(entry, infos);
		return 1;
	} else if (infos->mac_len == 0){
		/* Pure IP stuff like tun0. It is not linked to a RDMA device anyway */
	} else {
		fprintf(stderr, "Unsupported MAC len %d for interface %s\n", infos->mac_len, infos->if_name);
		return -1;
	}

	return 0;
}

void nl_close(int fd)
{
	close(fd);
}

int main()
{
	int fd;
	gid_hash_t *gid_hash;

	gid_hash = hash_alloc();
	if (!gid_hash) {
		fprintf(stderr, "Failed to allocate hash\n");
		return -1;
	}

	if (load_ib_gids(gid_hash)) {
		fprintf(stderr, "Failed to load RDMA device list\n");
		return -1;
	}

	fd = nl_setup();
	if (fd < 0) {
		fprintf(stderr, "Failed to connect to netlink\n");
		return -1;
	}

	if (nl_request_links(fd) <= 0) {
		fprintf(stderr, "Failed to requet links\n");
		return -1;
	}

	nl_iterate_links(fd, mac_lookup, gid_hash);

	nl_close(fd);
	hash_free(gid_hash);
	return 0;
}
