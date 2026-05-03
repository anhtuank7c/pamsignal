// clearenv(), memfd_create(), and close_range() are GNU extensions exposed by
// _GNU_SOURCE, which is defined globally via meson.build.

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <syslog.h>
#include <systemd/sd-journal.h>
#include <time.h>
#include <unistd.h>

#include "notify.h"
#include "utils.h"

// --- JSON escaping ---
//
// RFC 8259 §7 requires escaping for `"`, `\`, and the control range 0x00–0x1F.
// Upstream sanitize_string() already replaces control bytes with `?`, but we
// escape them defensively here too: a sanitization regression must not be
// able to inject raw control characters into an alert payload.

static size_t json_escape(const char *src, char *dst, size_t dst_len) {
    static const char hex[] = "0123456789abcdef";
    size_t j = 0;
    for (size_t i = 0; src[i] && j + 6 < dst_len; i++) {
        unsigned char c = (unsigned char)src[i];
        switch (c) {
        case '"':
            dst[j++] = '\\';
            dst[j++] = '"';
            break;
        case '\\':
            dst[j++] = '\\';
            dst[j++] = '\\';
            break;
        case '\b':
            dst[j++] = '\\';
            dst[j++] = 'b';
            break;
        case '\f':
            dst[j++] = '\\';
            dst[j++] = 'f';
            break;
        case '\n':
            dst[j++] = '\\';
            dst[j++] = 'n';
            break;
        case '\r':
            dst[j++] = '\\';
            dst[j++] = 'r';
            break;
        case '\t':
            dst[j++] = '\\';
            dst[j++] = 't';
            break;
        default:
            if (c < 0x20) {
                dst[j++] = '\\';
                dst[j++] = 'u';
                dst[j++] = '0';
                dst[j++] = '0';
                dst[j++] = hex[(c >> 4) & 0xF];
                dst[j++] = hex[c & 0xF];
            } else {
                dst[j++] = (char)c;
            }
            break;
        }
    }
    dst[j] = '\0';
    return j;
}

// --- Truncation-safe snprintf ---
//
// snprintf returns the would-be length, so n >= size means the result was
// truncated. Truncated alerts are dropped — sending a partial JSON body or a
// half-formed URL is worse than silently doing nothing, and validated config
// values mean truncation only happens on logic bugs.

#define PS_FMT_OK(buf, fmt, ...)                                   \
    ({                                                             \
        int _n = snprintf((buf), sizeof(buf), (fmt), __VA_ARGS__); \
        (_n >= 0 && (size_t)_n < sizeof(buf));                     \
    })

// --- Curl invocation ---
//
// Secrets (webhook URLs, bearer tokens, Telegram bot tokens) MUST NOT appear
// in the curl child's argv: argv is exposed via /proc/<pid>/cmdline to every
// local user. We write a curl config file to a memfd and pass it to curl as
// "-K /dev/fd/<N>". The memfd has CLOEXEC cleared via dup2 so it survives
// execv; everything else is closed in the child before exec.

static int build_secrets_memfd(const char *url, const char *auth_header) {
    int fd = memfd_create("pamsignal-curl", MFD_CLOEXEC);
    if (fd < 0) {
        sd_journal_print(LOG_WARNING,
                         "pamsignal: memfd_create failed: %m, dropping alert");
        return -1;
    }

    char buf[2048];
    int n;
    if (auth_header) {
        n = snprintf(buf, sizeof(buf), "url = \"%s\"\nheader = \"%s\"\n", url,
                     auth_header);
    } else {
        n = snprintf(buf, sizeof(buf), "url = \"%s\"\n", url);
    }
    if (n < 0 || (size_t)n >= sizeof(buf)) {
        close(fd);
        return -1;
    }

    ssize_t total = 0;
    while (total < n) {
        ssize_t w = write(fd, buf + total, (size_t)(n - total));
        if (w < 0) {
            close(fd);
            return -1;
        }
        total += w;
    }
    if (lseek(fd, 0, SEEK_SET) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static void fire_curl(int memfd, char *body) {
    pid_t pid = fork();
    if (pid < 0) {
        sd_journal_print(LOG_WARNING, "pamsignal: fork failed for alert");
        if (memfd >= 0)
            close(memfd);
        return;
    }
    if (pid == 0) {
        // Child: pin memfd at fd 9 (dup2 clears CLOEXEC on the destination)
        // so curl inherits it across execv.
        const int target_fd = 9;
        if (memfd >= 0 && memfd != target_fd) {
            if (dup2(memfd, target_fd) < 0)
                _exit(127);
        }

        // Close every other inherited fd (journal stream, pidfile, etc.).
        // close_range avoids the RLIMIT_NOFILE>1024 leak hazard of a manual
        // loop. We split into two ranges so we keep target_fd. Fall back to a
        // bounded loop if the kernel doesn't have close_range (Linux <5.9).
#ifdef SYS_close_range
        if (syscall(SYS_close_range, 3, (unsigned)target_fd - 1, 0) != 0 &&
            errno == ENOSYS) {
            for (int fd = 3; fd < target_fd; fd++)
                close(fd);
        }
        if (syscall(SYS_close_range, (unsigned)target_fd + 1, ~0U, 0) != 0 &&
            errno == ENOSYS) {
            for (int fd = target_fd + 1; fd < 1024; fd++)
                close(fd);
        }
#else
        for (int fd = 3; fd < 1024; fd++) {
            if (fd == target_fd)
                continue;
            close(fd);
        }
#endif

        // Reset signal handlers inherited from the parent.
        signal(SIGTERM, SIG_DFL);
        signal(SIGHUP, SIG_DFL);
        signal(SIGINT, SIG_DFL);

        // Sanitize the environment so a tampered PATH or LD_PRELOAD cannot
        // redirect the curl invocation.
        clearenv();
        setenv("PATH", "/usr/bin:/bin", 1);

        char fdpath[32];
        snprintf(fdpath, sizeof(fdpath), "/dev/fd/%d", target_fd);

        char *argv[] = {"curl",
                        "-s",
                        "-S",
                        "--max-time",
                        "10",
                        "--proto",
                        "=https",
                        "--proto-redir",
                        "=https",
                        "-H",
                        "Content-Type: application/json",
                        "-K",
                        fdpath,
                        "-d",
                        body,
                        NULL};

        // Absolute path: avoid PATH search even though we just sanitized PATH.
        execv("/usr/bin/curl", argv);
        _exit(127);
    }
    // Parent: fire-and-forget; SIGCHLD is set to SIG_IGN | SA_NOCLDWAIT so
    // the kernel reaps the child.
    if (memfd >= 0)
        close(memfd);
}

static void post_alert(const char *url, const char *auth_header, char *body) {
    int memfd = build_secrets_memfd(url, auth_header);
    if (memfd < 0)
        return;
    fire_curl(memfd, body);
}

// --- Message formatting ---
//
// Output format follows Elastic Common Schema (ECS) conventions:
//   - chat text: severity-prefixed key=value pairs in a fixed field order
//   - JSON webhook: nested ECS objects (event.*, host.*, user.*, source.*,
//     service.*, process.*) plus pamsignal.* for vendor-specific fields
//
// Field order in chat text is intentional: severity → action → identity
// → location → metadata → pid → ts. PID is placed immediately before ts so
// `kill <pid>` is an easy copy-paste from any alert message.

static void format_event_text(const ps_config_t *cfg,
                              const ps_pam_event_t *event, char *buf,
                              size_t len) {
    char timebuf[32];
    ps_format_timestamp(event->timestamp_usec, timebuf, sizeof(timebuf));

    const char *severity = ps_event_severity_label(event->type);
    const char *action = ps_event_action_str(event->type);

    char context[256] = "";
    if (cfg->provider[0] || cfg->service_name[0]) {
        if (cfg->provider[0] && cfg->service_name[0]) {
            snprintf(context, sizeof(context), " provider=%s service_name=%s",
                     cfg->provider, cfg->service_name);
        } else if (cfg->provider[0]) {
            snprintf(context, sizeof(context), " provider=%s", cfg->provider);
        } else {
            snprintf(context, sizeof(context), " service_name=%s",
                     cfg->service_name);
        }
    }

    if (event->type == PS_EVENT_SESSION_OPEN ||
        event->type == PS_EVENT_SESSION_CLOSE) {
        snprintf(
            buf, len, "%s auth.%s user=%s host=%s service=%s pid=%d ts=%s%s",
            severity, action, event->username, event->hostname,
            ps_service_str(event->service), (int)event->pid, timebuf, context);
    } else {
        snprintf(buf, len,
                 "%s auth.%s user=%s src=%s:%d host=%s service=%s "
                 "auth=%s pid=%d ts=%s%s",
                 severity, action, event->username, event->source_ip,
                 event->port, event->hostname, ps_service_str(event->service),
                 ps_auth_method_str(event->auth_method), (int)event->pid,
                 timebuf, context);
    }
}

static void format_brute_text(const ps_config_t *cfg, const char *ip,
                              int attempts, int window, const char *user,
                              const char *host, uint64_t ts, pid_t last_pid,
                              char *buf, size_t len) {
    char timebuf[32];
    ps_format_timestamp(ts, timebuf, sizeof(timebuf));

    char context[256] = "";
    if (cfg->provider[0] || cfg->service_name[0]) {
        if (cfg->provider[0] && cfg->service_name[0]) {
            snprintf(context, sizeof(context), " provider=%s service_name=%s",
                     cfg->provider, cfg->service_name);
        } else if (cfg->provider[0]) {
            snprintf(context, sizeof(context), " provider=%s", cfg->provider);
        } else {
            snprintf(context, sizeof(context), " service_name=%s",
                     cfg->service_name);
        }
    }

    snprintf(buf, len,
             "[ALERT]  auth.brute_force_detected src=%s attempts=%d "
             "window=%ds user=%s host=%s pid=%d ts=%s%s",
             ip, attempts, window, user, host, (int)last_pid, timebuf, context);
}

static void format_event_json(const ps_config_t *cfg,
                              const ps_pam_event_t *event, char *buf,
                              size_t len) {
    char timebuf[32];
    char esc_user[128], esc_host[512];
    ps_format_timestamp(event->timestamp_usec, timebuf, sizeof(timebuf));
    json_escape(event->username, esc_user, sizeof(esc_user));
    json_escape(event->hostname, esc_host, sizeof(esc_host));

    char labels_json[256] = "";
    if (cfg->provider[0] || cfg->service_name[0]) {
        char esc_prov[128] = "", esc_srv[128] = "";
        json_escape(cfg->provider, esc_prov, sizeof(esc_prov));
        json_escape(cfg->service_name, esc_srv, sizeof(esc_srv));
        if (cfg->provider[0] && cfg->service_name[0]) {
            snprintf(
                labels_json, sizeof(labels_json),
                ",\"labels\":{\"provider\":\"%s\",\"service_name\":\"%s\"}",
                esc_prov, esc_srv);
        } else if (cfg->provider[0]) {
            snprintf(labels_json, sizeof(labels_json),
                     ",\"labels\":{\"provider\":\"%s\"}", esc_prov);
        } else {
            snprintf(labels_json, sizeof(labels_json),
                     ",\"labels\":{\"service_name\":\"%s\"}", esc_srv);
        }
    }

    // ECS event.category is an array. For session events it's
    // ["authentication","session"]; for login events ["authentication"].
    const char *category_array = (event->type == PS_EVENT_SESSION_OPEN ||
                                  event->type == PS_EVENT_SESSION_CLOSE)
                                     ? "[\"authentication\",\"session\"]"
                                     : "[\"authentication\"]";

    if (event->type == PS_EVENT_SESSION_OPEN ||
        event->type == PS_EVENT_SESSION_CLOSE) {
        snprintf(buf, len,
                 "{\"@timestamp\":\"%s\","
                 "\"event\":{\"action\":\"%s\",\"category\":%s,"
                 "\"kind\":\"%s\",\"outcome\":\"%s\",\"severity\":%d,"
                 "\"module\":\"pamsignal\",\"dataset\":\"pamsignal.events\"},"
                 "\"host\":{\"hostname\":\"%s\"},"
                 "\"user\":{\"name\":\"%s\"},"
                 "\"service\":{\"name\":\"%s\"},"
                 "\"process\":{\"pid\":%d,\"user\":{\"id\":\"%d\"}},"
                 "\"pamsignal\":{\"event_type\":\"%s\"}%s}",
                 timebuf, ps_event_action_str(event->type), category_array,
                 ps_event_kind_str(event->type),
                 ps_event_outcome_str(event->type),
                 ps_event_severity_num(event->type), esc_host, esc_user,
                 ps_service_str(event->service), (int)event->pid,
                 (int)event->uid, ps_event_type_str(event->type), labels_json);
    } else {
        snprintf(
            buf, len,
            "{\"@timestamp\":\"%s\","
            "\"event\":{\"action\":\"%s\",\"category\":%s,"
            "\"kind\":\"%s\",\"outcome\":\"%s\",\"severity\":%d,"
            "\"module\":\"pamsignal\",\"dataset\":\"pamsignal.events\"},"
            "\"host\":{\"hostname\":\"%s\"},"
            "\"user\":{\"name\":\"%s\"},"
            "\"service\":{\"name\":\"%s\"},"
            "\"source\":{\"ip\":\"%s\",\"port\":%d},"
            "\"process\":{\"pid\":%d,\"user\":{\"id\":\"%d\"}},"
            "\"pamsignal\":{\"event_type\":\"%s\","
            "\"auth_method\":\"%s\"}%s}",
            timebuf, ps_event_action_str(event->type), category_array,
            ps_event_kind_str(event->type), ps_event_outcome_str(event->type),
            ps_event_severity_num(event->type), esc_host, esc_user,
            ps_service_str(event->service), event->source_ip, event->port,
            (int)event->pid, (int)event->uid, ps_event_type_str(event->type),
            ps_auth_method_str(event->auth_method), labels_json);
    }
}

static void format_local_brute_text(const ps_config_t *cfg,
                                    ps_service_t service, const char *actor,
                                    const char *target, int attempts,
                                    int window, const char *host, uint64_t ts,
                                    pid_t last_pid, char *buf, size_t len) {
    char timebuf[32];
    ps_format_timestamp(ts, timebuf, sizeof(timebuf));

    char context[256] = "";
    if (cfg->provider[0] || cfg->service_name[0]) {
        if (cfg->provider[0] && cfg->service_name[0]) {
            snprintf(context, sizeof(context), " provider=%s service_name=%s",
                     cfg->provider, cfg->service_name);
        } else if (cfg->provider[0]) {
            snprintf(context, sizeof(context), " provider=%s", cfg->provider);
        } else {
            snprintf(context, sizeof(context), " service_name=%s",
                     cfg->service_name);
        }
    }

    snprintf(buf, len,
             "[ALERT]  auth.brute_force_detected actor=%s target=%s "
             "attempts=%d window=%ds service=%s host=%s pid=%d ts=%s%s",
             actor, target, attempts, window, ps_service_str(service), host,
             (int)last_pid, timebuf, context);
}

static void format_local_brute_json(const ps_config_t *cfg,
                                    ps_service_t service, const char *actor,
                                    const char *target, int attempts,
                                    int window, const char *host, uint64_t ts,
                                    pid_t last_pid, char *buf, size_t len) {
    char timebuf[32];
    char esc_actor[128], esc_target[128], esc_host[512];
    ps_format_timestamp(ts, timebuf, sizeof(timebuf));
    json_escape(actor, esc_actor, sizeof(esc_actor));
    json_escape(target, esc_target, sizeof(esc_target));
    json_escape(host, esc_host, sizeof(esc_host));

    char labels_json[256] = "";
    if (cfg->provider[0] || cfg->service_name[0]) {
        char esc_prov[128] = "", esc_srv[128] = "";
        json_escape(cfg->provider, esc_prov, sizeof(esc_prov));
        json_escape(cfg->service_name, esc_srv, sizeof(esc_srv));
        if (cfg->provider[0] && cfg->service_name[0]) {
            snprintf(
                labels_json, sizeof(labels_json),
                ",\"labels\":{\"provider\":\"%s\",\"service_name\":\"%s\"}",
                esc_prov, esc_srv);
        } else if (cfg->provider[0]) {
            snprintf(labels_json, sizeof(labels_json),
                     ",\"labels\":{\"provider\":\"%s\"}", esc_prov);
        } else {
            snprintf(labels_json, sizeof(labels_json),
                     ",\"labels\":{\"service_name\":\"%s\"}", esc_srv);
        }
    }

    // ECS: user.name = actor, user.target.name = the elevation target. No
    // source.* (no remote endpoint for a pure-local elevation attempt).
    snprintf(buf, len,
             "{\"@timestamp\":\"%s\","
             "\"event\":{\"action\":\"brute_force_detected\","
             "\"category\":[\"authentication\",\"intrusion_detection\"],"
             "\"kind\":\"alert\",\"outcome\":\"unknown\","
             "\"severity\":8,\"module\":\"pamsignal\","
             "\"dataset\":\"pamsignal.events\"},"
             "\"host\":{\"hostname\":\"%s\"},"
             "\"user\":{\"name\":\"%s\",\"target\":{\"name\":\"%s\"}},"
             "\"service\":{\"name\":\"%s\"},"
             "\"process\":{\"pid\":%d},"
             "\"pamsignal\":{\"event_type\":\"BRUTE_FORCE_DETECTED\","
             "\"attempts\":%d,\"window_sec\":%d}%s}",
             timebuf, esc_host, esc_actor, esc_target, ps_service_str(service),
             (int)last_pid, attempts, window, labels_json);
}

static void format_brute_json(const ps_config_t *cfg, const char *ip,
                              int attempts, int window, const char *user,
                              const char *host, uint64_t ts, pid_t last_pid,
                              char *buf, size_t len) {
    char timebuf[32];
    char esc_user[128], esc_host[512];
    ps_format_timestamp(ts, timebuf, sizeof(timebuf));
    json_escape(user, esc_user, sizeof(esc_user));
    json_escape(host, esc_host, sizeof(esc_host));

    char labels_json[256] = "";
    if (cfg->provider[0] || cfg->service_name[0]) {
        char esc_prov[128] = "", esc_srv[128] = "";
        json_escape(cfg->provider, esc_prov, sizeof(esc_prov));
        json_escape(cfg->service_name, esc_srv, sizeof(esc_srv));
        if (cfg->provider[0] && cfg->service_name[0]) {
            snprintf(
                labels_json, sizeof(labels_json),
                ",\"labels\":{\"provider\":\"%s\",\"service_name\":\"%s\"}",
                esc_prov, esc_srv);
        } else if (cfg->provider[0]) {
            snprintf(labels_json, sizeof(labels_json),
                     ",\"labels\":{\"provider\":\"%s\"}", esc_prov);
        } else {
            snprintf(labels_json, sizeof(labels_json),
                     ",\"labels\":{\"service_name\":\"%s\"}", esc_srv);
        }
    }

    snprintf(buf, len,
             "{\"@timestamp\":\"%s\","
             "\"event\":{\"action\":\"brute_force_detected\","
             "\"category\":[\"authentication\",\"intrusion_detection\"],"
             "\"kind\":\"alert\",\"outcome\":\"unknown\","
             "\"severity\":8,\"module\":\"pamsignal\","
             "\"dataset\":\"pamsignal.events\"},"
             "\"host\":{\"hostname\":\"%s\"},"
             "\"user\":{\"name\":\"%s\"},"
             "\"source\":{\"ip\":\"%s\"},"
             "\"process\":{\"pid\":%d},"
             "\"pamsignal\":{\"event_type\":\"BRUTE_FORCE_DETECTED\","
             "\"attempts\":%d,\"window_sec\":%d}%s}",
             timebuf, esc_host, esc_user, ip, (int)last_pid, attempts, window,
             labels_json);
}

// --- Per-channel senders ---

static void send_telegram(const ps_config_t *cfg, const char *text) {
    if (!cfg->telegram_bot_token[0] || !cfg->telegram_chat_id[0])
        return;

    char url[768];
    if (!PS_FMT_OK(url, "https://api.telegram.org/bot%s/sendMessage",
                   cfg->telegram_bot_token)) {
        sd_journal_print(LOG_WARNING,
                         "pamsignal: telegram URL truncated, dropping alert");
        return;
    }

    char esc_text[2048];
    json_escape(text, esc_text, sizeof(esc_text));

    char body[2560];
    if (!PS_FMT_OK(body, "{\"chat_id\":\"%s\",\"text\":\"%s\"}",
                   cfg->telegram_chat_id, esc_text)) {
        sd_journal_print(LOG_WARNING,
                         "pamsignal: telegram body truncated, dropping alert");
        return;
    }

    post_alert(url, NULL, body);
}

static void send_simple_webhook(const char *url, const char *text_key,
                                const char *text) {
    char esc_text[2048];
    json_escape(text, esc_text, sizeof(esc_text));

    char body[2560];
    if (!PS_FMT_OK(body, "{\"%s\":\"%s\"}", text_key, esc_text)) {
        sd_journal_print(LOG_WARNING,
                         "pamsignal: webhook body truncated, dropping alert");
        return;
    }

    post_alert(url, NULL, body);
}

static void send_whatsapp(const ps_config_t *cfg, const char *text) {
    if (!cfg->whatsapp_access_token[0] || !cfg->whatsapp_phone_number_id[0] ||
        !cfg->whatsapp_recipient[0])
        return;

    char url[256];
    if (!PS_FMT_OK(url, "https://graph.facebook.com/v21.0/%s/messages",
                   cfg->whatsapp_phone_number_id)) {
        sd_journal_print(LOG_WARNING,
                         "pamsignal: whatsapp URL truncated, dropping alert");
        return;
    }

    char auth[576];
    if (!PS_FMT_OK(auth, "Authorization: Bearer %s",
                   cfg->whatsapp_access_token)) {
        sd_journal_print(LOG_WARNING, "pamsignal: whatsapp auth header "
                                      "truncated, dropping alert");
        return;
    }

    char esc_text[2048];
    json_escape(text, esc_text, sizeof(esc_text));

    char body[2560];
    if (!PS_FMT_OK(body,
                   "{\"messaging_product\":\"whatsapp\",\"to\":\"%s\","
                   "\"type\":\"text\",\"text\":{\"body\":\"%s\"}}",
                   cfg->whatsapp_recipient, esc_text)) {
        sd_journal_print(LOG_WARNING,
                         "pamsignal: whatsapp body truncated, dropping alert");
        return;
    }

    post_alert(url, auth, body);
}

// --- Cooldown ---
//
// Cooldown is split per event class: a flood of login events cannot suppress
// a brute-force alert (or vice versa). Per-source-IP cooldown for brute-force
// is handled by the caller in journal_watch.c using fail_entry state.

static time_t last_event_alert = 0;

static int event_cooled_down(const ps_config_t *cfg) {
    if (cfg->alert_cooldown_sec <= 0)
        return 1;
    time_t now = time(NULL);
    if (now - last_event_alert < cfg->alert_cooldown_sec)
        return 0;
    last_event_alert = now;
    return 1;
}

// --- Public API ---

void ps_notify_event(const ps_config_t *cfg, const ps_pam_event_t *event) {
    if (!event_cooled_down(cfg))
        return;

    char text[1024];
    format_event_text(cfg, event, text, sizeof(text));

    send_telegram(cfg, text);
    if (cfg->slack_webhook_url[0])
        send_simple_webhook(cfg->slack_webhook_url, "text", text);
    if (cfg->teams_webhook_url[0])
        send_simple_webhook(cfg->teams_webhook_url, "text", text);
    send_whatsapp(cfg, text);
    if (cfg->discord_webhook_url[0])
        send_simple_webhook(cfg->discord_webhook_url, "content", text);

    if (cfg->webhook_url[0]) {
        char json[2048];
        format_event_json(cfg, event, json, sizeof(json));
        post_alert(cfg->webhook_url, NULL, json);
    }
}

void ps_notify_brute_force(const ps_config_t *cfg, const char *source_ip,
                           int attempts, int window_sec,
                           const char *last_username, const char *hostname,
                           uint64_t timestamp_usec, pid_t last_pid) {
    // Caller (journal_watch.c) applies the per-source-IP cooldown using
    // fail_entry state, so we don't gate brute-force alerts here. Suppressing
    // them globally would let a chatty login flood mute brute-force signals.
    char text[1024];
    format_brute_text(cfg, source_ip, attempts, window_sec, last_username,
                      hostname, timestamp_usec, last_pid, text, sizeof(text));

    send_telegram(cfg, text);
    if (cfg->slack_webhook_url[0])
        send_simple_webhook(cfg->slack_webhook_url, "text", text);
    if (cfg->teams_webhook_url[0])
        send_simple_webhook(cfg->teams_webhook_url, "text", text);
    send_whatsapp(cfg, text);
    if (cfg->discord_webhook_url[0])
        send_simple_webhook(cfg->discord_webhook_url, "content", text);

    if (cfg->webhook_url[0]) {
        char json[2048];
        format_brute_json(cfg, source_ip, attempts, window_sec, last_username,
                          hostname, timestamp_usec, last_pid, json,
                          sizeof(json));
        post_alert(cfg->webhook_url, NULL, json);
    }
}

void ps_notify_local_brute_force(const ps_config_t *cfg, ps_service_t service,
                                 const char *actor_username,
                                 const char *target_username, int attempts,
                                 int window_sec, const char *hostname,
                                 uint64_t timestamp_usec, pid_t last_pid) {
    // Caller (journal_watch.c) applies the per-actor cooldown using
    // fail_entry state, mirroring the IP-based path above.
    char text[1024];
    format_local_brute_text(cfg, service, actor_username, target_username,
                            attempts, window_sec, hostname, timestamp_usec,
                            last_pid, text, sizeof(text));

    send_telegram(cfg, text);
    if (cfg->slack_webhook_url[0])
        send_simple_webhook(cfg->slack_webhook_url, "text", text);
    if (cfg->teams_webhook_url[0])
        send_simple_webhook(cfg->teams_webhook_url, "text", text);
    send_whatsapp(cfg, text);
    if (cfg->discord_webhook_url[0])
        send_simple_webhook(cfg->discord_webhook_url, "content", text);

    if (cfg->webhook_url[0]) {
        char json[2048];
        format_local_brute_json(cfg, service, actor_username, target_username,
                                attempts, window_sec, hostname, timestamp_usec,
                                last_pid, json, sizeof(json));
        post_alert(cfg->webhook_url, NULL, json);
    }
}
