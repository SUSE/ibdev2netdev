#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <infiniband/verbs.h>

#include "hash.h"

gid_hash_t *hash_alloc(void)
{
	return calloc(256,  sizeof(gid_hash_t));
}

static void _hash_free(gid_hash_t h[], int depth)
{
	for (int i = 0; i < 256; ++i){
		if (h[i].sub) {
			if (depth < GID_LEN - 1)
				_hash_free(h[i].sub, depth + 1);
			free(h[i].sub);
		}
	}
}

void hash_free(gid_hash_t h[])
{
	_hash_free(h, 0);
	free(h);
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

void hash_add_gid_entry(gid_hash_t h[], const unsigned char gid[],
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

const struct gid_hash_entry* hash_load_entry(const gid_hash_t h[], const unsigned char gid[])
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

const struct gid_hash_entry* hash_search_entry(const gid_hash_t h[], const unsigned char gid[], uint64_t mask)
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

void hash_dump_gid_hash(gid_hash_t h[])
{
	char pref[GID_LEN] = { 0 };
	_dump_gid_hash(h, 0, pref);
}
