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

int nl_setup(void);
int nl_request_links(int fd);
int nl_iterate_links(int fd, int (*fn)(const struct if_info*, void*), void* arg);
void nl_close(int fd);

#endif /* __NL_H__ */
