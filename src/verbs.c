/* Copyright (c) 2024 SUSE LLC
   Author: Nicolas Morey <nicolas.morey@suse.com>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation in version 2 of the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License along
   with this program; if not, see <http://www.gnu.org/licenses/>. */

#include <infiniband/verbs.h>
#include <stdio.h>
#include "hash.h"
#include "verbs.h"

static int null_gid(union ibv_gid *gid)
{
	return !(gid->global.interface_id | (gid->global.subnet_prefix & 0xffff0000ULL));
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
		entry->gid_id = gid_id;
		hash_add_gid_entry(h, gid.raw, entry);
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
