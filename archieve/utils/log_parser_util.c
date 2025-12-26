#define _POSIX_C_SOURCE 200809L

#include "log_parser_util.h"

#include <stddef.h> // NOLINT(misc-include-cleaner) - provides size_t
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h> // NOLINT(misc-include-cleaner) - provides ssize_t

SSHLoginEvent *parse_auth_log(FILE *log_fd, int *event_count)
{
  // Handle NULL parameters
  if (!log_fd || !event_count) {
    if (event_count) {
      *event_count = 0;
    }
    return NULL;
  }

  char *line = NULL;
  size_t len = 0;   // NOLINT(misc-include-cleaner)
  ssize_t read = 0; // NOLINT(misc-include-cleaner)

  // Initial capacity for events array
  int capacity = 10;
  int count = 0;
  SSHLoginEvent *events = malloc(capacity * sizeof(SSHLoginEvent));
  if (!events) {
    *event_count = 0;
    return NULL;
  }

  // Read lines from the auth log
  // NOLINTNEXTLINE(clang-analyzer-deadcode.DeadStores,misc-include-cleaner)
  while ((read = getline(&line, &len, log_fd)) != -1) {
    // Check for successful SSH authentication patterns
    const char *auth_method = NULL;
    if (strstr(line, "Accepted password") != NULL) {
      auth_method = "password";
    } else if (strstr(line, "Accepted publickey") != NULL) {
      auth_method = "publickey";
    }

    if (auth_method == NULL) {
      continue;
    }
    // Expand array if needed
    if (count >= capacity) {
      capacity *= 2;
      SSHLoginEvent *new_events = realloc(events, capacity * sizeof(SSHLoginEvent));
      if (!new_events) {
        free(events);
        free(line);
        *event_count = 0;
        return NULL;
      }
      events = new_events;
    }

    // Extract username and IP address from the log line
    // Typical format: "Dec 22 10:30:45 server sshd[1234]: Accepted password for username from IP
    // port PORT ssh2"
    char username[256] = {0};
    char ip_address[64] = {0};

    // Parse the log line to extract username and IP using safer string functions
    // Find " for " keyword
    const char *for_ptr = strstr(line, " for ");
    if (!for_ptr) {
      continue;
    }
    for_ptr += 5; // Move past " for "

    // Extract username (up to next space or " from ")
    const char *from_ptr = strstr(for_ptr, " from ");
    if (!from_ptr) {
      continue;
    }

    size_t username_len = from_ptr - for_ptr;
    if (username_len == 0 || username_len >= sizeof(username)) {
      continue;
    }

    strncpy(username, for_ptr, username_len);
    username[username_len] = '\0';

    from_ptr += 6; // Move past " from "

    // Extract IP address (up to next space)
    const char *space_ptr = strchr(from_ptr, ' ');
    if (!space_ptr) {
      continue;
    }

    size_t ip_len = space_ptr - from_ptr;
    if (ip_len == 0 || ip_len >= sizeof(ip_address)) {
      continue;
    }

    strncpy(ip_address, from_ptr, ip_len);
    ip_address[ip_len] = '\0';

    // Extract timestamp from log line
    // Support two formats:
    // 1. ISO 8601: "2025-12-22T09:23:25.920453+07:00 ..." (timestamp up to first space)
    // 2. Syslog: "Dec 22 14:40:59 ..." (timestamp up to third space)
    char timestamp[64] = {0};
    const char *ptr = line;
    int space_count = 0;
    size_t timestamp_len = 0;

    // Detect format: ISO 8601 starts with a digit, syslog starts with a letter
    int is_iso_format = (*ptr >= '0' && *ptr <= '9');
    int target_spaces = is_iso_format ? 1 : 3;

    while (*ptr && space_count < target_spaces) {
      if (*ptr == ' ') {
        space_count++;
      }
      ptr++;
      timestamp_len++;
    }

    // Remove trailing space from timestamp
    if (timestamp_len > 0 && line[timestamp_len - 1] == ' ') {
      timestamp_len--;
    }

    if (timestamp_len > 0 && timestamp_len < sizeof(timestamp)) {
      strncpy(timestamp, line, timestamp_len);
      timestamp[timestamp_len] = '\0';
    }

    // Store the event data
    strncpy(events[count].username, username, sizeof(events[count].username) - 1);
    strncpy(events[count].ip_address, ip_address, sizeof(events[count].ip_address) - 1);
    strncpy(events[count].auth_method, auth_method, sizeof(events[count].auth_method) - 1);
    strncpy(events[count].timestamp, timestamp, sizeof(events[count].timestamp) - 1);
    strncpy(events[count].log_line, line, sizeof(events[count].log_line) - 1);
    count++;
  }

  // Free the allocated line buffer
  free(line);

  *event_count = count;
  return events;
}
