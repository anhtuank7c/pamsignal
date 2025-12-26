#ifndef HOST_UTIL_H
#define HOST_UTIL_H

char **get_ipv4_list(int *count);
char **get_ipv6_list(int *count);
char *get_hostname();
void free_ip_list(char **list, int count);

#endif