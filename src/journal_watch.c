#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <systemd/sd-journal.h>

#include "config.h"
#include "init.h"
#include "journal_watch.h"
#include "notify.h"
#include "pam_event.h"
#include "utils.h"

// --- Failed login tracking ---

// Key kind for an entry. Sshd brute-force is keyed by source IP (and so is
// any sudo/su that inherits an rhost from a calling SSH session). Pure local
// sudo/su brute-force has no rhost, so we key by the local actor (ruser).
typedef enum {
    PS_FAIL_KEY_IP,
    PS_FAIL_KEY_LOCAL_USER,
} ps_fail_key_type_t;

typedef struct {
    // Key holds either an IPv4/IPv6 literal (key_type == PS_FAIL_KEY_IP) or a
    // local username (key_type == PS_FAIL_KEY_LOCAL_USER). 64 bytes fits both
    // INET6_ADDRSTRLEN (46) and the project's 64-byte username buffer.
    char key[64];
    ps_fail_key_type_t key_type;
    // For local-user entries, service distinguishes sudo from su in the alert
    // payload. For IP entries it's typically PS_SERVICE_SSHD but we record
    // whatever the latest event reported.
    ps_service_t service;
    // For local-user entries, the latest target user (the user the actor was
    // trying to elevate to). Empty for IP entries.
    char target_username[64];
    int count;
    uint64_t first_attempt_usec;
    uint64_t last_attempt_usec;
    uint64_t last_brute_alert_usec;
} ps_fail_entry_t;

static ps_fail_entry_t *fail_table = NULL;
static int fail_table_count = 0;
static int fail_table_capacity = 0;

int ps_fail_table_init(int capacity) {
    if (capacity <= 0)
        return PS_ERR_INIT;

    ps_fail_entry_t *t = calloc((size_t)capacity, sizeof(ps_fail_entry_t));
    if (!t)
        return PS_ERR_INIT;

    if (fail_table) {
        // copy_count is also the final fail_table_count. The lower clamp is
        // defensive — fail_table_count is monotonically non-negative by
        // construction, but the explicit floor lets clang-analyzer prove
        // the post-state is in [0, capacity] and rules out a negative-index
        // path on the next write to fail_table.
        int copy_count = fail_table_count;
        if (copy_count > capacity)
            copy_count = capacity;
        if (copy_count < 0)
            copy_count = 0;
        memcpy(t, fail_table, (size_t)copy_count * sizeof(ps_fail_entry_t));
        fail_table_count = copy_count;
    } else {
        fail_table_count = 0;
    }

    free(fail_table);
    fail_table = t;
    fail_table_capacity = capacity;
    return PS_OK;
}

void ps_fail_table_reset(void) {
    if (ps_fail_table_init(g_config.max_tracked_ips) != PS_OK) {
        sd_journal_print(LOG_WARNING,
                         "pamsignal: fail_table reset failed; "
                         "brute-force tracking continues with prior state");
    }
}

// Derive the (key, key_type) tuple from an event. Returns 0 if the event has
// no trackable identity (no source IP and not a sudo/su local-actor case).
static int derive_fail_key(const ps_pam_event_t *event, const char **out_key,
                           ps_fail_key_type_t *out_type) {
    if (event->source_ip[0] != '\0') {
        *out_key = event->source_ip;
        *out_type = PS_FAIL_KEY_IP;
        return 1;
    }
    if ((event->service == PS_SERVICE_SUDO ||
         event->service == PS_SERVICE_SU) &&
        event->username[0] != '\0') {
        *out_key = event->username;
        *out_type = PS_FAIL_KEY_LOCAL_USER;
        return 1;
    }
    return 0;
}

// Initialise a fail_table entry from the event that just exceeded threshold.
// Centralised so create-new-entry and evict-and-reuse paths stay in sync.
static void fail_entry_init(ps_fail_entry_t *e, const char *key,
                            ps_fail_key_type_t key_type,
                            const ps_pam_event_t *event) {
    snprintf(e->key, sizeof(e->key), "%s", key);
    e->key_type = key_type;
    e->service = event->service;
    snprintf(e->target_username, sizeof(e->target_username), "%s",
             event->target_username);
    e->count = 1;
    e->first_attempt_usec = event->timestamp_usec;
    e->last_attempt_usec = event->timestamp_usec;
    e->last_brute_alert_usec = 0;
}

static void emit_brute_force_alert(const ps_fail_entry_t *entry,
                                   const ps_pam_event_t *event,
                                   int notify_allowed) {
    char attempts_str[16];
    char window_str[16];
    snprintf(attempts_str, sizeof(attempts_str), "%d", entry->count);
    snprintf(window_str, sizeof(window_str), "%d", g_config.fail_window_sec);

    if (entry->key_type == PS_FAIL_KEY_IP) {
        sd_journal_send(
            "MESSAGE=pamsignal: BRUTE_FORCE_DETECTED ip=%s attempts=%s "
            "window=%ss user=%s",
            entry->key, attempts_str, window_str, event->username,
            "PRIORITY=%d", LOG_WARNING, "SYSLOG_IDENTIFIER=pamsignal",
            // Legacy PAMSIGNAL_* fields kept for backward compat with any
            // existing journalctl queries; retired in v0.3.0.
            "PAMSIGNAL_EVENT=BRUTE_FORCE_DETECTED", "PAMSIGNAL_SOURCE_IP=%s",
            entry->key, "PAMSIGNAL_ATTEMPTS=%s", attempts_str,
            "PAMSIGNAL_WINDOW_SEC=%s", window_str, "PAMSIGNAL_USERNAME=%s",
            event->username, "PAMSIGNAL_HOSTNAME=%s", event->hostname,
            // ECS-aligned structured fields. event.kind=alert here because
            // brute-force detection is a security alert per ECS.
            "EVENT_ACTION=brute_force_detected",
            "EVENT_CATEGORY=authentication,intrusion_detection",
            "EVENT_KIND=alert", "EVENT_OUTCOME=unknown", "EVENT_SEVERITY=8",
            "EVENT_MODULE=pamsignal", "USER_NAME=%s", event->username,
            "SOURCE_IP=%s", entry->key, "HOST_HOSTNAME=%s", event->hostname,
            NULL);

        if (notify_allowed) {
            ps_notify_brute_force(&g_config, entry->key, entry->count,
                                  g_config.fail_window_sec, event->username,
                                  event->hostname, event->timestamp_usec,
                                  event->pid);
        }
    } else {
        // Local sudo/su brute-force. No source.ip; ECS user.target.name
        // captures the elevation target.
        sd_journal_send(
            "MESSAGE=pamsignal: BRUTE_FORCE_DETECTED actor=%s target=%s "
            "service=%s attempts=%s window=%ss",
            entry->key, entry->target_username, ps_service_str(entry->service),
            attempts_str, window_str, "PRIORITY=%d", LOG_WARNING,
            "SYSLOG_IDENTIFIER=pamsignal",
            // Legacy PAMSIGNAL_* fields kept for backward compat.
            "PAMSIGNAL_EVENT=BRUTE_FORCE_DETECTED", "PAMSIGNAL_USERNAME=%s",
            entry->key, "PAMSIGNAL_TARGET_USER=%s", entry->target_username,
            "PAMSIGNAL_SERVICE=%s", ps_service_str(entry->service),
            "PAMSIGNAL_ATTEMPTS=%s", attempts_str, "PAMSIGNAL_WINDOW_SEC=%s",
            window_str, "PAMSIGNAL_HOSTNAME=%s", event->hostname,
            // ECS fields. user.name = actor (the one pressing keys);
            // user.target.name = the user being elevated to. No source.* —
            // there's no remote host for a pure-local sudo brute-force.
            "EVENT_ACTION=brute_force_detected",
            "EVENT_CATEGORY=authentication,intrusion_detection",
            "EVENT_KIND=alert", "EVENT_OUTCOME=unknown", "EVENT_SEVERITY=8",
            "EVENT_MODULE=pamsignal", "USER_NAME=%s", entry->key,
            "USER_TARGET_NAME=%s", entry->target_username, "SERVICE_NAME=%s",
            ps_service_str(entry->service), "HOST_HOSTNAME=%s", event->hostname,
            NULL);

        if (notify_allowed) {
            ps_notify_local_brute_force(
                &g_config, entry->service, entry->key, entry->target_username,
                entry->count, g_config.fail_window_sec, event->hostname,
                event->timestamp_usec, event->pid);
        }
    }
}

static void ps_track_failed_login(const ps_pam_event_t *event) {
    const char *ev_key;
    ps_fail_key_type_t ev_key_type;
    if (!derive_fail_key(event, &ev_key, &ev_key_type) || !fail_table)
        return;

    uint64_t window_usec = (uint64_t)g_config.fail_window_sec * 1000000ULL;

    // Search for existing entry. (key_type, key) is the unique tuple — an IP
    // and a local username with the same string never collide.
    for (int i = 0; i < fail_table_count; i++) {
        if (fail_table[i].key_type != ev_key_type ||
            strcmp(fail_table[i].key, ev_key) != 0)
            continue;

        // Refresh service + target_username on each attempt so the alert
        // reflects the latest target if the actor is jumping between
        // multiple targets within the window.
        fail_table[i].service = event->service;
        snprintf(fail_table[i].target_username,
                 sizeof(fail_table[i].target_username), "%s",
                 event->target_username);

        // Reset if window expired
        if (event->timestamp_usec - fail_table[i].first_attempt_usec >
            window_usec) {
            fail_table[i].count = 1;
            fail_table[i].first_attempt_usec = event->timestamp_usec;
        } else {
            fail_table[i].count++;
        }
        fail_table[i].last_attempt_usec = event->timestamp_usec;

        if (fail_table[i].count >= g_config.fail_threshold) {
            // Per-key cooldown: don't spam alerts for the same source. The
            // journal log entry is written every time so post-mortem
            // forensics still see every threshold breach; only the outbound
            // notification is rate-limited.
            //
            // last_brute_alert_usec == 0 means "never alerted for this key" —
            // treat as cooldown-elapsed so the first breach always fires
            // regardless of how recently after epoch the event arrived.
            uint64_t cooldown_usec =
                (uint64_t)g_config.alert_cooldown_sec * 1000000ULL;
            int notify_allowed =
                (g_config.alert_cooldown_sec <= 0) ||
                (fail_table[i].last_brute_alert_usec == 0) ||
                (event->timestamp_usec - fail_table[i].last_brute_alert_usec >=
                 cooldown_usec);

            emit_brute_force_alert(&fail_table[i], event, notify_allowed);
            if (notify_allowed)
                fail_table[i].last_brute_alert_usec = event->timestamp_usec;

            fail_table[i].count = 0;
            fail_table[i].first_attempt_usec = event->timestamp_usec;
        }
        return;
    }

    // New entry
    if (fail_table_count < fail_table_capacity) {
        fail_entry_init(&fail_table[fail_table_count++], ev_key, ev_key_type,
                        event);
        return;
    }

    // Table full: evict oldest entry
    int oldest = 0;
    for (int i = 1; i < fail_table_capacity; i++) {
        if (fail_table[i].last_attempt_usec <
            fail_table[oldest].last_attempt_usec)
            oldest = i;
    }
    fail_entry_init(&fail_table[oldest], ev_key, ev_key_type, event);
}

// --- Event processing ---

static void ps_log_event(const ps_pam_event_t *event) {
    char timebuf[32];
    ps_format_timestamp(event->timestamp_usec, timebuf, sizeof(timebuf));

    char msg[512];
    char port_str[16];
    char pid_str[32];
    char uid_str[32];
    char severity_str[16];

    snprintf(port_str, sizeof(port_str), "%d", event->port);
    snprintf(pid_str, sizeof(pid_str), "%d", (int)event->pid);
    snprintf(uid_str, sizeof(uid_str), "%d", (int)event->uid);
    snprintf(severity_str, sizeof(severity_str), "%d",
             ps_event_severity_num(event->type));

    if (event->type == PS_EVENT_SESSION_OPEN ||
        event->type == PS_EVENT_SESSION_CLOSE) {
        snprintf(msg, sizeof(msg), "pamsignal: %s user=%s service=%s at %s",
                 ps_event_type_str(event->type), event->username,
                 ps_service_str(event->service), timebuf);

        sd_journal_send(
            "MESSAGE=%s", msg, "PRIORITY=%d", LOG_NOTICE,
            "SYSLOG_IDENTIFIER=pamsignal",
            // Legacy PAMSIGNAL_* fields (retired in v0.3.0)
            "PAMSIGNAL_EVENT=%s", ps_event_type_str(event->type),
            "PAMSIGNAL_USERNAME=%s", event->username, "PAMSIGNAL_SERVICE=%s",
            ps_service_str(event->service), "PAMSIGNAL_HOSTNAME=%s",
            event->hostname, "PAMSIGNAL_PID=%s", pid_str, "PAMSIGNAL_UID=%s",
            uid_str,
            // ECS-aligned structured fields
            "EVENT_ACTION=%s", ps_event_action_str(event->type),
            "EVENT_CATEGORY=%s", ps_event_category_str(event->type),
            "EVENT_KIND=%s", ps_event_kind_str(event->type), "EVENT_OUTCOME=%s",
            ps_event_outcome_str(event->type), "EVENT_SEVERITY=%s",
            severity_str, "EVENT_MODULE=pamsignal", "USER_NAME=%s",
            event->username, "SERVICE_NAME=%s", ps_service_str(event->service),
            "HOST_HOSTNAME=%s", event->hostname, "PROCESS_PID=%s", pid_str,
            NULL);
    } else {
        snprintf(msg, sizeof(msg),
                 "pamsignal: %s user=%s from=%s port=%d service=%s auth=%s "
                 "at %s",
                 ps_event_type_str(event->type), event->username,
                 event->source_ip, event->port, ps_service_str(event->service),
                 ps_auth_method_str(event->auth_method), timebuf);

        sd_journal_send(
            "MESSAGE=%s", msg, "PRIORITY=%d", LOG_NOTICE,
            "SYSLOG_IDENTIFIER=pamsignal",
            // Legacy PAMSIGNAL_* fields (retired in v0.3.0)
            "PAMSIGNAL_EVENT=%s", ps_event_type_str(event->type),
            "PAMSIGNAL_USERNAME=%s", event->username, "PAMSIGNAL_SOURCE_IP=%s",
            event->source_ip, "PAMSIGNAL_PORT=%s", port_str,
            "PAMSIGNAL_SERVICE=%s", ps_service_str(event->service),
            "PAMSIGNAL_AUTH_METHOD=%s", ps_auth_method_str(event->auth_method),
            "PAMSIGNAL_HOSTNAME=%s", event->hostname, "PAMSIGNAL_PID=%s",
            pid_str, "PAMSIGNAL_UID=%s", uid_str,
            // ECS-aligned structured fields
            "EVENT_ACTION=%s", ps_event_action_str(event->type),
            "EVENT_CATEGORY=%s", ps_event_category_str(event->type),
            "EVENT_KIND=%s", ps_event_kind_str(event->type), "EVENT_OUTCOME=%s",
            ps_event_outcome_str(event->type), "EVENT_SEVERITY=%s",
            severity_str, "EVENT_MODULE=pamsignal", "USER_NAME=%s",
            event->username, "SOURCE_IP=%s", event->source_ip, "SOURCE_PORT=%s",
            port_str, "SERVICE_NAME=%s", ps_service_str(event->service),
            "HOST_HOSTNAME=%s", event->hostname, "PROCESS_PID=%s", pid_str,
            NULL);
    }
}

static void ps_process_entry(sd_journal *j) {
    const void *data;
    size_t length;

    // Extract MESSAGE field
    int r = sd_journal_get_data(j, "MESSAGE", &data, &length);
    if (r < 0)
        return;

    const char *msg_val = ps_field_value(data, length);
    if (!msg_val)
        return;

    // Copy message to null-terminated buffer
    size_t msg_len = length - (size_t)(msg_val - (const char *)data);
    char message[2048];
    if (msg_len >= sizeof(message))
        msg_len = sizeof(message) - 1;
    memcpy(message, msg_val, msg_len);
    message[msg_len] = '\0';

    // Parse the message
    ps_pam_event_t event;
    if (ps_parse_message(message, &event) != PS_OK)
        return;

    // Extract additional metadata into null-terminated buffers
    char fieldbuf[256];

    // Prevent log spoofing by verifying the executable path.
    // Unprivileged users can inject logs via logger(1), but systemd-journald
    // records the actual executable path in _EXE. We only trust known paths.
    if (sd_journal_get_data(j, "_EXE", &data, &length) == 0) {
        const char *val = ps_field_value(data, length);
        if (val) {
            size_t vlen = length - (size_t)(val - (const char *)data);
            if (vlen >= sizeof(fieldbuf))
                vlen = sizeof(fieldbuf) - 1;
            memcpy(fieldbuf, val, vlen);
            fieldbuf[vlen] = '\0';

            int is_trusted = 0;
            // Require the executable to be in a system path to prevent
            // execution from /tmp or /home by an unprivileged user spoofing the
            // daemon name.
            if (strncmp(fieldbuf, "/usr/", 5) == 0 ||
                strncmp(fieldbuf, "/bin/", 5) == 0 ||
                strncmp(fieldbuf, "/sbin/", 6) == 0 ||
                strncmp(fieldbuf, "/lib/", 5) == 0 ||
                strncmp(fieldbuf, "/lib64/", 7) == 0 ||
                strncmp(fieldbuf, "/opt/", 5) == 0) {

                const char *base = strrchr(fieldbuf, '/');
                if (base) {
                    base++;
                    if (strcmp(base, "sshd") == 0 ||
                        strcmp(base, "sudo") == 0 || strcmp(base, "su") == 0 ||
                        strcmp(base, "login") == 0 ||
                        strcmp(base, "systemd-logind") == 0) {
                        is_trusted = 1;
                    }
                }
            }
            if (!is_trusted) {
                return;
            }
        }
    } else {
        // If _EXE is missing entirely, this is likely spoofed from /dev/log.
        return;
    }

    if (sd_journal_get_data(j, "_PID", &data, &length) == 0) {
        const char *val = ps_field_value(data, length);
        if (val) {
            size_t vlen = length - (size_t)(val - (const char *)data);
            if (vlen >= sizeof(fieldbuf))
                vlen = sizeof(fieldbuf) - 1;
            memcpy(fieldbuf, val, vlen);
            fieldbuf[vlen] = '\0';
            char *end;
            errno = 0;
            long pid_val = strtol(fieldbuf, &end, 10);
            if (end != fieldbuf && errno != ERANGE && pid_val >= 0 &&
                pid_val <= INT_MAX)
                event.pid = (pid_t)pid_val;
        }
    }

    if (sd_journal_get_data(j, "_UID", &data, &length) == 0) {
        const char *val = ps_field_value(data, length);
        if (val) {
            size_t vlen = length - (size_t)(val - (const char *)data);
            if (vlen >= sizeof(fieldbuf))
                vlen = sizeof(fieldbuf) - 1;
            memcpy(fieldbuf, val, vlen);
            fieldbuf[vlen] = '\0';
            char *end;
            errno = 0;
            long uid_val = strtol(fieldbuf, &end, 10);
            if (end != fieldbuf && errno != ERANGE && uid_val >= 0 &&
                uid_val <= INT_MAX)
                event.uid = (uid_t)uid_val;
        }
    }

    if (sd_journal_get_data(j, "_HOSTNAME", &data, &length) == 0) {
        const char *val = ps_field_value(data, length);
        if (val) {
            size_t hlen = length - (size_t)(val - (const char *)data);
            if (hlen >= sizeof(event.hostname))
                hlen = sizeof(event.hostname) - 1;
            memcpy(event.hostname, val, hlen);
            event.hostname[hlen] = '\0';
            // Sanitize control characters
            for (char *c = event.hostname; *c; c++) {
                if (*c < 0x20 || *c == 0x7f)
                    *c = '?';
            }
        }
    }

    sd_journal_get_realtime_usec(j, &event.timestamp_usec);

    ps_log_event(&event);

    // For sudo/su LOGIN_FAILED, suppress the per-event chat alert: a single
    // mistyped password would otherwise produce one Telegram/Slack ping per
    // keypress, drowning out the actually-meaningful brute-force alert that
    // ps_track_failed_login emits when the threshold is crossed. The journal
    // entry from ps_log_event still records every individual failure, so the
    // forensic trail is intact.
    int suppress_event_alert =
        event.type == PS_EVENT_LOGIN_FAILED &&
        (event.service == PS_SERVICE_SUDO || event.service == PS_SERVICE_SU);
    if (!suppress_event_alert)
        ps_notify_event(&g_config, &event);

    if (event.type == PS_EVENT_LOGIN_FAILED)
        ps_track_failed_login(&event);
}

// --- Public API ---

int ps_journal_watch_init(sd_journal **j) {
    int r = sd_journal_open(j, SD_JOURNAL_LOCAL_ONLY);
    if (r < 0) {
        sd_journal_print(LOG_ERR, "pamsignal: failed to open journal: %s",
                         strerror(-r));
        return PS_ERR_JOURNAL;
    }

    r = sd_journal_seek_tail(*j);
    if (r < 0) {
        sd_journal_print(LOG_ERR, "pamsignal: failed to seek to tail: %s",
                         strerror(-r));
        sd_journal_close(*j);
        return PS_ERR_JOURNAL;
    }

    // Move back one entry so we don't re-process the last existing entry
    r = sd_journal_previous(*j);
    if (r < 0) {
        sd_journal_print(LOG_WARNING,
                         "pamsignal: failed to step back in journal: %s",
                         strerror(-r));
        // Non-fatal: worst case we re-process one entry on startup
    }

    // Add filters: match any of these syslog identifiers.
    // Include both sshd and sshd-session (newer OpenSSH splits them),
    // and both ssh.service (Ubuntu/Debian) and sshd.service (Fedora/RHEL).
    sd_journal_add_match(*j, "SYSLOG_IDENTIFIER=sshd", 0);
    sd_journal_add_disjunction(*j);
    sd_journal_add_match(*j, "SYSLOG_IDENTIFIER=sshd-session", 0);
    sd_journal_add_disjunction(*j);
    sd_journal_add_match(*j, "SYSLOG_IDENTIFIER=sudo", 0);
    sd_journal_add_disjunction(*j);
    sd_journal_add_match(*j, "SYSLOG_IDENTIFIER=su", 0);
    sd_journal_add_disjunction(*j);
    sd_journal_add_match(*j, "SYSLOG_IDENTIFIER=login", 0);
    sd_journal_add_disjunction(*j);
    sd_journal_add_match(*j, "_SYSTEMD_UNIT=sshd.service", 0);
    sd_journal_add_disjunction(*j);
    sd_journal_add_match(*j, "_SYSTEMD_UNIT=ssh.service", 0);

    return PS_OK;
}

int ps_journal_watch_run(sd_journal *j) {
    while (running) {
        if (reload_requested) {
            reload_requested = 0;

            // Block signals around the swap so a second SIGHUP cannot land
            // mid-copy and leave g_config / fail_table out of sync. The
            // pending signal is delivered when sigprocmask restores the mask.
            sigset_t newmask, oldmask;
            sigemptyset(&newmask);
            sigaddset(&newmask, SIGHUP);
            sigaddset(&newmask, SIGINT);
            sigaddset(&newmask, SIGTERM);
            sigprocmask(SIG_BLOCK, &newmask, &oldmask);

            ps_config_t tmp;
            if (ps_config_load(g_config_path, &tmp) == PS_OK) {
                g_config = tmp;
                ps_fail_table_reset();
                sd_journal_print(LOG_INFO, "pamsignal: config reloaded");
            } else {
                sd_journal_print(LOG_WARNING,
                                 "pamsignal: config reload failed, "
                                 "keeping current config");
            }

            sigprocmask(SIG_SETMASK, &oldmask, NULL);
        }

        int r = sd_journal_wait(j, 1000000); // 1 second timeout
        if (r < 0) {
            sd_journal_print(LOG_ERR, "pamsignal: journal wait error: %s",
                             strerror(-r));
            continue;
        }

        if (r == SD_JOURNAL_NOP)
            continue;

        while (sd_journal_next(j) > 0) {
            ps_process_entry(j);
        }
    }

    return PS_OK;
}

void ps_journal_watch_cleanup(sd_journal *j) {
    if (j)
        sd_journal_close(j);
    free(fail_table);
    fail_table = NULL;
    fail_table_count = 0;
    fail_table_capacity = 0;
}
