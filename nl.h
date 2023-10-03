#ifndef __NL_H__
#define __NL_H__


struct if_info
{
	unsigned ifi_flags;
	const char *if_name;
	uint32_t mac_len;
	const char *mac;
	unsigned char operstate;
};

int nl_setup();
int nl_request_links(int fd);
int nl_iterate_links(int fd, int (*fn)(const struct if_info*, void*), void* arg);

#endif /* __NL_H__ */
