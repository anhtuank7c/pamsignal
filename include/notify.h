#ifndef NOTIFY_H
#define NOTIFY_H

#include <stdint.h>
#include <sys/types.h>

#include "config.h"
#include "pam_event.h"

// Send alert for a PAM event (login success/fail, session open/close).
void ps_notify_event(const ps_config_t *cfg, const ps_pam_event_t *event);

// Send alert for brute-force detection. last_pid is the failing sshd auth
// child from the breaching attempt — included for forensic context, even
// though the process is typically already reaped by the time the alert
// reaches the operator.
void ps_notify_brute_force(const ps_config_t *cfg, const char *source_ip,
                           int attempts, int window_sec,
                           const char *last_username, const char *hostname,
                           uint64_t timestamp_usec, pid_t last_pid);

// Brute-force on a local elevation service (sudo/su) where there is no
// remote source IP. actor_username is the user pressing keys (`ruser=` in
// the pam_unix message); target_username is the user being elevated to
// (`user=`). service distinguishes sudo vs su in the alert payload.
void ps_notify_local_brute_force(const ps_config_t *cfg, ps_service_t service,
                                 const char *actor_username,
                                 const char *target_username, int attempts,
                                 int window_sec, const char *hostname,
                                 uint64_t timestamp_usec, pid_t last_pid);

// Send alert for a successful login that follows a run of failures from the
// same source IP — a likely guessed password. event is the LOGIN_SUCCESS
// event; failures is the length of the run that preceded it.
void ps_notify_login_after_failures(const ps_config_t *cfg,
                                    const ps_pam_event_t *event, int failures,
                                    int window_sec);

// Send a test message to every configured channel and wait for each curl to
// finish, printing one result line per channel to stdout. Unlike the alert
// paths above this is synchronous and treats an HTTP error status as a
// failure; it must not be called once SIGCHLD is ignored (i.e. only from the
// --test-alert one-shot mode, never from the running daemon).
// Returns the number of channels that failed, or -1 if none is configured.
int ps_notify_test(const ps_config_t *cfg, const char *hostname,
                   uint64_t timestamp_usec);

#endif /* NOTIFY_H */
