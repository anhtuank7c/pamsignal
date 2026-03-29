#ifndef NOTIFY_H
#define NOTIFY_H

#include <stdint.h>

#include "config.h"
#include "pam_event.h"

// Send alert for a PAM event (login success/fail, session open/close).
void ps_notify_event(const ps_config_t *cfg, const ps_pam_event_t *event);

// Send alert for brute-force detection.
void ps_notify_brute_force(const ps_config_t *cfg, const char *source_ip,
                           int attempts, int window_sec,
                           const char *last_username, const char *hostname,
                           uint64_t timestamp_usec);

#endif /* NOTIFY_H */
