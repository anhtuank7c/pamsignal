#define _POSIX_C_SOURCE 200809L

#include "host_util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

char **get_ipv4_list(int *count)
{
  struct ifaddrs *ifaddr = NULL, *ifa = NULL;
  char **result = NULL;
  int capacity = 4;
  int found = 0;

  if (count == NULL) {
    return NULL;
  }

  *count = 0;

  if (getifaddrs(&ifaddr) == -1) {
    perror("getifaddrs");
    return NULL;
  }

  result = (char **)malloc(capacity * sizeof(char *));
  if (result == NULL) {
    perror("malloc");
    freeifaddrs(ifaddr);
    return NULL;
  }

  for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr == NULL) {
      continue;
    }

    if (ifa->ifa_addr->sa_family == AF_INET) {
      struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
      char ip_str[INET_ADDRSTRLEN];

      if (inet_ntop(AF_INET, &addr->sin_addr, ip_str, INET_ADDRSTRLEN) == NULL) {
        continue;
      }

      if (strcmp(ip_str, "127.0.0.1") == 0) {
        continue;
      }

      if (found >= capacity) {
        capacity *= 2;
        char **temp = (char **)realloc((void *)result, capacity * sizeof(char *));
        if (temp == NULL) {
          perror("realloc");
          free_ip_list(result, found);
          freeifaddrs(ifaddr);
          return NULL;
        }
        result = temp;
      }

      result[found] = strdup(ip_str);
      if (result[found] == NULL) {
        perror("strdup");
        free_ip_list(result, found);
        freeifaddrs(ifaddr);
        return NULL;
      }
      found++;
    }
  }

  freeifaddrs(ifaddr);

  *count = found;
  return result;
}

char **get_ipv6_list(int *count)
{
  struct ifaddrs *ifaddr = NULL, *ifa = NULL;
  char **result = NULL;
  int capacity = 4;
  int found = 0;

  if (count == NULL) {
    return NULL;
  }

  *count = 0;

  if (getifaddrs(&ifaddr) == -1) {
    perror("getifaddrs");
    return NULL;
  }

  result = (char **)malloc(capacity * sizeof(char *));
  if (result == NULL) {
    perror("malloc");
    freeifaddrs(ifaddr);
    return NULL;
  }

  for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr == NULL) {
      continue;
    }

    if (ifa->ifa_addr->sa_family == AF_INET6) {
      struct sockaddr_in6 *addr = (struct sockaddr_in6 *)ifa->ifa_addr;
      char ip_str[INET6_ADDRSTRLEN];

      if (inet_ntop(AF_INET6, &addr->sin6_addr, ip_str, INET6_ADDRSTRLEN) == NULL) {
        continue;
      }

      if (strcmp(ip_str, "::1") == 0 || strncmp(ip_str, "fe80:", 5) == 0) {
        continue;
      }

      if (found >= capacity) {
        capacity *= 2;
        char **temp = (char **)realloc((void *)result, capacity * sizeof(char *));
        if (temp == NULL) {
          perror("realloc");
          free_ip_list(result, found);
          freeifaddrs(ifaddr);
          return NULL;
        }
        result = temp;
      }

      result[found] = strdup(ip_str);
      if (result[found] == NULL) {
        perror("strdup");
        free_ip_list(result, found);
        freeifaddrs(ifaddr);
        return NULL;
      }
      found++;
    }
  }

  freeifaddrs(ifaddr);

  *count = found;
  return result;
}

char *get_hostname()
{
  static char hostname[256];

  if (gethostname(hostname, sizeof(hostname)) == -1) {
    perror("gethostname");
    return "unknown";
  }

  return hostname;
}

void free_ip_list(char **list, int count)
{
  if (list == NULL) {
    return;
  }

  for (int i = 0; i < count; i++) {
    free(list[i]);
  }
  free((void *)list);
}
