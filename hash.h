#ifndef __HASH_H__
#define __HASH_H__

#define GID_LEN (sizeof(union ibv_gid))

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


gid_hash_t *hash_alloc();
void hash_free(gid_hash_t h[]);

void hash_add_gid_entry(gid_hash_t h[], const unsigned char gid[],
			const struct gid_hash_entry *entry);

const struct gid_hash_entry*
hash_load_entry(const gid_hash_t h[], const unsigned char gid[]);

const struct gid_hash_entry*
hash_search_entry(const gid_hash_t h[], const unsigned char gid[], uint64_t mask);

void hash_dump_gid_hash(gid_hash_t h[]);

static inline void print_formated_gid(union ibv_gid *gid, int i)
{
	printf("\t\t\tGID[%3d]:\t\t%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
		i, gid->raw[0], gid->raw[1], gid->raw[2],
		gid->raw[3], gid->raw[4], gid->raw[5], gid->raw[6],
		gid->raw[7], gid->raw[8], gid->raw[9], gid->raw[10],
		gid->raw[11], gid->raw[12], gid->raw[13], gid->raw[14],
		gid->raw[15]);
}

#endif /* __HASH_H__ */
