#ifndef LOG_PARSER_UTIL_H
#define LOG_PARSER_UTIL_H

#include <stdio.h>

// Structure to hold parsed SSH login information
typedef struct {
  char username[256];
  char ip_address[64];
  char auth_method[32]; // "password" or "publickey"
  char timestamp[64];   // Extracted timestamp (ISO 8601 or syslog format)
  char log_line[1024];  // Full log line for reference
} SSHLoginEvent;

// Function to parse auth log lines and extract SSH login events
// Returns: Pointer to array of events (must be freed by caller)
// event_count: Output parameter for number of events found
SSHLoginEvent *parse_auth_log(FILE *log_fd, int *event_count);

#endif // LOG_PARSER_UTIL_H
