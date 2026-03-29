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

typedef struct {
    char ip[INET6_ADDRSTRLEN];
    int count;
    uint64_t first_attempt_usec;
    uint64_t last_attempt_usec;
} ps_fail_entry_t;

static ps_fail_entry_t *fail_table = NULL;
static int fail_table_count = 0;
static int fail_table_capacity = 0;

int ps_fail_table_init(int capacity) {
    free(fail_table);
    fail_table = calloc((size_t)capacity, sizeof(ps_fail_entry_t));
    if (!fail_table)
        return PS_ERR_INIT;
    fail_table_count = 0;
    fail_table_capacity = capacity;
    return PS_OK;
}

void ps_fail_table_reset(void) {
    ps_fail_table_init(g_config.max_tracked_ips);
}

static void ps_track_failed_login(const ps_pam_event_t *event) {
    if (event->source_ip[0] == '\0' || !fail_table)
        return;

    uint64_t window_usec = (uint64_t)g_config.fail_window_sec * 1000000ULL;

    // Search for existing entry
    for (int i = 0; i < fail_table_count; i++) {
        if (strcmp(fail_table[i].ip, event->source_ip) == 0) {
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
                char attempts_str[16];
                char window_str[16];
                snprintf(attempts_str, sizeof(attempts_str), "%d",
                         fail_table[i].count);
                snprintf(window_str, sizeof(window_str), "%d",
                         g_config.fail_window_sec);

                sd_journal_send(
                    "MESSAGE=pamsignal: BRUTE_FORCE_DETECTED ip=%s attempts=%s "
                    "window=%ss user=%s",
                    fail_table[i].ip, attempts_str, window_str, event->username,
                    "PRIORITY=%d", LOG_WARNING, "SYSLOG_IDENTIFIER=pamsignal",
                    "PAMSIGNAL_EVENT=BRUTE_FORCE_DETECTED",
                    "PAMSIGNAL_SOURCE_IP=%s", fail_table[i].ip,
                    "PAMSIGNAL_ATTEMPTS=%s", attempts_str,
                    "PAMSIGNAL_WINDOW_SEC=%s", window_str,
                    "PAMSIGNAL_USERNAME=%s", event->username,
                    "PAMSIGNAL_HOSTNAME=%s", event->hostname, NULL);

                ps_notify_brute_force(&g_config, fail_table[i].ip,
                                      fail_table[i].count,
                                      g_config.fail_window_sec, event->username,
                                      event->hostname, event->timestamp_usec);

                fail_table[i].count = 0;
                fail_table[i].first_attempt_usec = event->timestamp_usec;
            }
            return;
        }
    }

    // New entry
    if (fail_table_count < fail_table_capacity) {
        ps_fail_entry_t *e = &fail_table[fail_table_count++];
        snprintf(e->ip, sizeof(e->ip), "%s", event->source_ip);
        e->count = 1;
        e->first_attempt_usec = event->timestamp_usec;
        e->last_attempt_usec = event->timestamp_usec;
        return;
    }

    // Table full: evict oldest entry
    int oldest = 0;
    for (int i = 1; i < fail_table_capacity; i++) {
        if (fail_table[i].last_attempt_usec <
            fail_table[oldest].last_attempt_usec)
            oldest = i;
    }
    ps_fail_entry_t *e = &fail_table[oldest];
    snprintf(e->ip, sizeof(e->ip), "%s", event->source_ip);
    e->count = 1;
    e->first_attempt_usec = event->timestamp_usec;
    e->last_attempt_usec = event->timestamp_usec;
}

// --- Event processing ---

static void ps_log_event(const ps_pam_event_t *event) {
    char timebuf[32];
    ps_format_timestamp(event->timestamp_usec, timebuf, sizeof(timebuf));

    char msg[512];
    char port_str[16];
    char pid_str[32];
    char uid_str[32];

    snprintf(port_str, sizeof(port_str), "%d", event->port);
    snprintf(pid_str, sizeof(pid_str), "%d", (int)event->pid);
    snprintf(uid_str, sizeof(uid_str), "%d", (int)event->uid);

    if (event->type == PS_EVENT_SESSION_OPEN ||
        event->type == PS_EVENT_SESSION_CLOSE) {
        snprintf(msg, sizeof(msg), "pamsignal: %s user=%s service=%s at %s",
                 ps_event_type_str(event->type), event->username,
                 ps_service_str(event->service), timebuf);

        sd_journal_send("MESSAGE=%s", msg, "PRIORITY=%d", LOG_NOTICE,
                        "SYSLOG_IDENTIFIER=pamsignal", "PAMSIGNAL_EVENT=%s",
                        ps_event_type_str(event->type), "PAMSIGNAL_USERNAME=%s",
                        event->username, "PAMSIGNAL_SERVICE=%s",
                        ps_service_str(event->service), "PAMSIGNAL_HOSTNAME=%s",
                        event->hostname, "PAMSIGNAL_PID=%s", pid_str,
                        "PAMSIGNAL_UID=%s", uid_str, NULL);
    } else {
        snprintf(msg, sizeof(msg),
                 "pamsignal: %s user=%s from=%s port=%d service=%s auth=%s "
                 "at %s",
                 ps_event_type_str(event->type), event->username,
                 event->source_ip, event->port, ps_service_str(event->service),
                 ps_auth_method_str(event->auth_method), timebuf);

        sd_journal_send(
            "MESSAGE=%s", msg, "PRIORITY=%d", LOG_NOTICE,
            "SYSLOG_IDENTIFIER=pamsignal", "PAMSIGNAL_EVENT=%s",
            ps_event_type_str(event->type), "PAMSIGNAL_USERNAME=%s",
            event->username, "PAMSIGNAL_SOURCE_IP=%s", event->source_ip,
            "PAMSIGNAL_PORT=%s", port_str, "PAMSIGNAL_SERVICE=%s",
            ps_service_str(event->service), "PAMSIGNAL_AUTH_METHOD=%s",
            ps_auth_method_str(event->auth_method), "PAMSIGNAL_HOSTNAME=%s",
            event->hostname, "PAMSIGNAL_PID=%s", pid_str, "PAMSIGNAL_UID=%s",
            uid_str, NULL);
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

    if (sd_journal_get_data(j, "_PID", &data, &length) == 0) {
        const char *val = ps_field_value(data, length);
        if (val) {
            size_t vlen = length - (size_t)(val - (const char *)data);
            if (vlen >= sizeof(fieldbuf))
                vlen = sizeof(fieldbuf) - 1;
            memcpy(fieldbuf, val, vlen);
            fieldbuf[vlen] = '\0';
            char *end;
            long pid_val = strtol(fieldbuf, &end, 10);
            if (end != fieldbuf)
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
            long uid_val = strtol(fieldbuf, &end, 10);
            if (end != fieldbuf)
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
