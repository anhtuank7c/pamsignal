#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>
#include <stdint.h>

#include "pam_event.h"

// Extract value portion from journal "FIELD=value" data
const char *ps_field_value(const char *data, size_t length);

// Parse a journal MESSAGE string into a PAM event
// Returns 0 on successful match, -1 if message is unrecognized
int ps_parse_message(const char *message, ps_pam_event_t *event);

// Format microsecond timestamp to "YYYY-MM-DD HH:MM:SS"
void ps_format_timestamp(uint64_t usec, char *buf, size_t buflen);

// Enum to string conversions
const char *ps_event_type_str(ps_event_type_t type);
const char *ps_service_str(ps_service_t service);
const char *ps_auth_method_str(ps_auth_method_t method);

#endif /* UTILS_H */
