#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <systemd/sd-journal.h>
#include <time.h>
#include <unistd.h>

#include "notify.h"
#include "utils.h"

// --- JSON escaping ---

static size_t json_escape(const char *src, char *dst, size_t dst_len) {
    size_t j = 0;
    for (size_t i = 0; src[i] && j + 6 < dst_len; i++) {
        switch (src[i]) {
        case '"':
            dst[j++] = '\\';
            dst[j++] = '"';
            break;
        case '\\':
            dst[j++] = '\\';
            dst[j++] = '\\';
            break;
        default:
            dst[j++] = src[i];
            break;
        }
    }
    dst[j] = '\0';
    return j;
}

// --- Fork+exec core ---

static void fire_curl(char *const argv[]) {
    pid_t pid = fork();
    if (pid < 0) {
        sd_journal_print(LOG_WARNING, "pamsignal: fork failed for alert");
        return;
    }
    if (pid == 0) {
        // Child: close inherited fds (journal fd, pidfile fd, etc.)
        for (int fd = 3; fd < 1024; fd++)
            close(fd);

        // Reset signal handlers
        signal(SIGTERM, SIG_DFL);
        signal(SIGHUP, SIG_DFL);
        signal(SIGINT, SIG_DFL);

        execvp("curl", argv);
        _exit(127); // exec failed
    }
    // Parent: returns immediately, child is fire-and-forget
}

// --- Message formatting ---

static void format_event_text(const ps_pam_event_t *event, char *buf,
                              size_t len) {
    char timebuf[32];
    ps_format_timestamp(event->timestamp_usec, timebuf, sizeof(timebuf));

    const char *type = ps_event_type_str(event->type);

    if (event->type == PS_EVENT_SESSION_OPEN ||
        event->type == PS_EVENT_SESSION_CLOSE) {
        snprintf(buf, len, "%s | User: %s | Service: %s | Host: %s | %s", type,
                 event->username, ps_service_str(event->service),
                 event->hostname, timebuf);
    } else {
        snprintf(buf, len,
                 "%s | User: %s | From: %s:%d | Service: %s | Auth: %s | "
                 "Host: %s | %s",
                 type, event->username, event->source_ip, event->port,
                 ps_service_str(event->service),
                 ps_auth_method_str(event->auth_method), event->hostname,
                 timebuf);
    }
}

static void format_brute_text(const char *ip, int attempts, int window,
                              const char *user, const char *host, uint64_t ts,
                              char *buf, size_t len) {
    char timebuf[32];
    ps_format_timestamp(ts, timebuf, sizeof(timebuf));
    snprintf(buf, len,
             "BRUTE_FORCE_DETECTED | IP: %s | Attempts: %d | Window: %ds | "
             "Last user: %s | Host: %s | %s",
             ip, attempts, window, user, host, timebuf);
}

static void format_event_json(const ps_pam_event_t *event, char *buf,
                              size_t len) {
    char timebuf[32];
    char esc_user[128], esc_host[512];
    ps_format_timestamp(event->timestamp_usec, timebuf, sizeof(timebuf));
    json_escape(event->username, esc_user, sizeof(esc_user));
    json_escape(event->hostname, esc_host, sizeof(esc_host));

    snprintf(buf, len,
             "{\"event\":\"%s\",\"username\":\"%s\",\"source_ip\":\"%s\","
             "\"port\":%d,\"service\":\"%s\",\"auth_method\":\"%s\","
             "\"hostname\":\"%s\",\"timestamp\":\"%s\","
             "\"timestamp_usec\":%llu,\"pid\":%d,\"uid\":%d}",
             ps_event_type_str(event->type), esc_user, event->source_ip,
             event->port, ps_service_str(event->service),
             ps_auth_method_str(event->auth_method), esc_host, timebuf,
             (unsigned long long)event->timestamp_usec, (int)event->pid,
             (int)event->uid);
}

static void format_brute_json(const char *ip, int attempts, int window,
                              const char *user, const char *host, uint64_t ts,
                              char *buf, size_t len) {
    char timebuf[32];
    char esc_user[128], esc_host[512];
    ps_format_timestamp(ts, timebuf, sizeof(timebuf));
    json_escape(user, esc_user, sizeof(esc_user));
    json_escape(host, esc_host, sizeof(esc_host));

    snprintf(buf, len,
             "{\"event\":\"BRUTE_FORCE_DETECTED\",\"source_ip\":\"%s\","
             "\"attempts\":%d,\"window_sec\":%d,\"last_username\":\"%s\","
             "\"hostname\":\"%s\",\"timestamp\":\"%s\","
             "\"timestamp_usec\":%llu}",
             ip, attempts, window, esc_user, esc_host, timebuf,
             (unsigned long long)ts);
}

// --- Per-channel senders ---

static void send_telegram(const ps_config_t *cfg, const char *text) {
    if (!cfg->telegram_bot_token[0] || !cfg->telegram_chat_id[0])
        return;

    char url[768];
    snprintf(url, sizeof(url), "https://api.telegram.org/bot%s/sendMessage",
             cfg->telegram_bot_token);

    char esc_text[2048];
    json_escape(text, esc_text, sizeof(esc_text));

    char body[2560];
    snprintf(body, sizeof(body),
             "{\"chat_id\":\"%s\",\"text\":\"%s\",\"parse_mode\":\"HTML\"}",
             cfg->telegram_chat_id, esc_text);

    char *argv[] = {"curl",
                    "-s",
                    "-S",
                    "--max-time",
                    "10",
                    "-H",
                    "Content-Type: application/json",
                    "-d",
                    body,
                    url,
                    NULL};
    fire_curl(argv);
}

static void send_slack(const ps_config_t *cfg, const char *text) {
    if (!cfg->slack_webhook_url[0])
        return;

    char esc_text[2048];
    json_escape(text, esc_text, sizeof(esc_text));

    char body[2560];
    snprintf(body, sizeof(body), "{\"text\":\"%s\"}", esc_text);

    char *argv[] = {"curl",
                    "-s",
                    "-S",
                    "--max-time",
                    "10",
                    "-H",
                    "Content-Type: application/json",
                    "-d",
                    body,
                    (char *)cfg->slack_webhook_url,
                    NULL};
    fire_curl(argv);
}

static void send_teams(const ps_config_t *cfg, const char *text) {
    if (!cfg->teams_webhook_url[0])
        return;

    char esc_text[2048];
    json_escape(text, esc_text, sizeof(esc_text));

    char body[2560];
    snprintf(body, sizeof(body), "{\"text\":\"%s\"}", esc_text);

    char *argv[] = {"curl",
                    "-s",
                    "-S",
                    "--max-time",
                    "10",
                    "-H",
                    "Content-Type: application/json",
                    "-d",
                    body,
                    (char *)cfg->teams_webhook_url,
                    NULL};
    fire_curl(argv);
}

static void send_whatsapp(const ps_config_t *cfg, const char *text) {
    if (!cfg->whatsapp_access_token[0] || !cfg->whatsapp_phone_number_id[0] ||
        !cfg->whatsapp_recipient[0])
        return;

    char url[256];
    snprintf(url, sizeof(url), "https://graph.facebook.com/v21.0/%s/messages",
             cfg->whatsapp_phone_number_id);

    char auth[576];
    snprintf(auth, sizeof(auth), "Authorization: Bearer %s",
             cfg->whatsapp_access_token);

    char esc_text[2048];
    json_escape(text, esc_text, sizeof(esc_text));

    char body[2560];
    snprintf(body, sizeof(body),
             "{\"messaging_product\":\"whatsapp\",\"to\":\"%s\","
             "\"type\":\"text\",\"text\":{\"body\":\"%s\"}}",
             cfg->whatsapp_recipient, esc_text);

    char *argv[] = {"curl",
                    "-s",
                    "-S",
                    "--max-time",
                    "10",
                    "-H",
                    "Content-Type: application/json",
                    "-H",
                    auth,
                    "-d",
                    body,
                    url,
                    NULL};
    fire_curl(argv);
}

static void send_discord(const ps_config_t *cfg, const char *text) {
    if (!cfg->discord_webhook_url[0])
        return;

    char esc_text[2048];
    json_escape(text, esc_text, sizeof(esc_text));

    char body[2560];
    snprintf(body, sizeof(body), "{\"content\":\"%s\"}", esc_text);

    char *argv[] = {"curl",
                    "-s",
                    "-S",
                    "--max-time",
                    "10",
                    "-H",
                    "Content-Type: application/json",
                    "-d",
                    body,
                    (char *)cfg->discord_webhook_url,
                    NULL};
    fire_curl(argv);
}

static void send_webhook(const ps_config_t *cfg, const char *json) {
    if (!cfg->webhook_url[0])
        return;

    char *argv[] = {"curl",
                    "-s",
                    "-S",
                    "--max-time",
                    "10",
                    "-H",
                    "Content-Type: application/json",
                    "-d",
                    (char *)json,
                    (char *)cfg->webhook_url,
                    NULL};
    fire_curl(argv);
}

// --- Cooldown ---

static time_t last_alert_time = 0;

static int is_cooled_down(const ps_config_t *cfg) {
    if (cfg->alert_cooldown_sec <= 0)
        return 1;
    time_t now = time(NULL);
    if (now - last_alert_time < cfg->alert_cooldown_sec)
        return 0;
    last_alert_time = now;
    return 1;
}

// --- Public API ---

void ps_notify_event(const ps_config_t *cfg, const ps_pam_event_t *event) {
    if (!is_cooled_down(cfg))
        return;

    char text[1024];
    format_event_text(event, text, sizeof(text));

    send_telegram(cfg, text);
    send_slack(cfg, text);
    send_teams(cfg, text);
    send_whatsapp(cfg, text);
    send_discord(cfg, text);

    char json[2048];
    format_event_json(event, json, sizeof(json));
    send_webhook(cfg, json);
}

void ps_notify_brute_force(const ps_config_t *cfg, const char *source_ip,
                           int attempts, int window_sec,
                           const char *last_username, const char *hostname,
                           uint64_t timestamp_usec) {
    if (!is_cooled_down(cfg))
        return;

    char text[1024];
    format_brute_text(source_ip, attempts, window_sec, last_username, hostname,
                      timestamp_usec, text, sizeof(text));

    send_telegram(cfg, text);
    send_slack(cfg, text);
    send_teams(cfg, text);
    send_whatsapp(cfg, text);
    send_discord(cfg, text);

    char json[2048];
    format_brute_json(source_ip, attempts, window_sec, last_username, hostname,
                      timestamp_usec, json, sizeof(json));
    send_webhook(cfg, json);
}
