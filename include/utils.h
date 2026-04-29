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

// --- ECS (Elastic Common Schema) mapping helpers ---
//
// Free-form `event.action` value, past-tense lowercase per ECS recommendation.
// Examples: "session_opened", "login_success", "brute_force_detected".
const char *ps_event_action_str(ps_event_type_t type);

// Comma-separated `event.category` values (ECS expects an array, but our
// formatters render this as a JSON array literal directly).
const char *ps_event_category_str(ps_event_type_t type);

// `event.kind`: "event" for normal observations; "alert" for high-severity
// security signals (currently brute-force only).
const char *ps_event_kind_str(ps_event_type_t type);

// `event.outcome`: "success", "failure", or "unknown".
const char *ps_event_outcome_str(ps_event_type_t type);

// `event.severity` numeric value on the syslog-aligned scale used here:
// 3=info, 4=notice, 5=warning, 8=alert.
int ps_event_severity_num(ps_event_type_t type);

// Fixed-width severity bracket for human-readable chat output, e.g.
// "[INFO]  ", "[NOTICE]", "[WARN]  ", "[ALERT] ". 8 chars including the
// trailing space pad so columns align in monospace renderings.
const char *ps_event_severity_label(ps_event_type_t type);

#endif /* UTILS_H */
