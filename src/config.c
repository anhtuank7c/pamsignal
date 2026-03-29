#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <systemd/sd-journal.h>

#include "config.h"
#include "init.h"

ps_config_t g_config;
const char *g_config_path = PS_DEFAULT_CONFIG_PATH;

void ps_config_defaults(ps_config_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->fail_threshold = PS_DEFAULT_FAIL_THRESHOLD;
    cfg->fail_window_sec = PS_DEFAULT_FAIL_WINDOW_SEC;
    cfg->max_tracked_ips = PS_DEFAULT_MAX_TRACKED_IPS;
    cfg->alert_cooldown_sec = PS_DEFAULT_ALERT_COOLDOWN_SEC;
}

static char *trim(char *s) {
    while (isspace((unsigned char)*s))
        s++;
    if (*s == '\0')
        return s;
    char *end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end))
        *end-- = '\0';
    return s;
}

static int parse_int_range(const char *val, int min, int max, int *out) {
    char *end;
    errno = 0;
    long v = strtol(val, &end, 10);
    if (end == val || *end != '\0' || errno == ERANGE)
        return -1;
    if (v < min || v > max)
        return -1;
    *out = (int)v;
    return 0;
}

int ps_config_load(const char *path, ps_config_t *cfg) {
    ps_config_defaults(cfg);

    FILE *f = fopen(path, "r");
    if (!f) {
        if (errno == ENOENT) {
            sd_journal_print(LOG_INFO,
                             "pamsignal: config file not found: %s "
                             "(using defaults)",
                             path);
            return PS_OK;
        }
        sd_journal_print(LOG_ERR, "pamsignal: cannot open config: %s: %s", path,
                         strerror(errno));
        return PS_ERR_CONFIG;
    }

    char line[1024];
    int lineno = 0;
    int errors = 0;

    while (fgets(line, sizeof(line), f)) {
        lineno++;

        char *p = trim(line);
        if (*p == '\0' || *p == '#')
            continue;

        char *eq = strchr(p, '=');
        if (!eq) {
            sd_journal_print(
                LOG_ERR, "pamsignal: config:%d: missing '=' in: %s", lineno, p);
            errors++;
            continue;
        }

        *eq = '\0';
        char *key = trim(p);
        char *val = trim(eq + 1);

        if (strcmp(key, "telegram_bot_token") == 0) {
            snprintf(cfg->telegram_bot_token, sizeof(cfg->telegram_bot_token),
                     "%s", val);
        } else if (strcmp(key, "telegram_chat_id") == 0) {
            snprintf(cfg->telegram_chat_id, sizeof(cfg->telegram_chat_id), "%s",
                     val);
        } else if (strcmp(key, "slack_webhook_url") == 0) {
            snprintf(cfg->slack_webhook_url, sizeof(cfg->slack_webhook_url),
                     "%s", val);
        } else if (strcmp(key, "teams_webhook_url") == 0) {
            snprintf(cfg->teams_webhook_url, sizeof(cfg->teams_webhook_url),
                     "%s", val);
        } else if (strcmp(key, "whatsapp_access_token") == 0) {
            snprintf(cfg->whatsapp_access_token,
                     sizeof(cfg->whatsapp_access_token), "%s", val);
        } else if (strcmp(key, "whatsapp_phone_number_id") == 0) {
            snprintf(cfg->whatsapp_phone_number_id,
                     sizeof(cfg->whatsapp_phone_number_id), "%s", val);
        } else if (strcmp(key, "whatsapp_recipient") == 0) {
            snprintf(cfg->whatsapp_recipient, sizeof(cfg->whatsapp_recipient),
                     "%s", val);
        } else if (strcmp(key, "discord_webhook_url") == 0) {
            snprintf(cfg->discord_webhook_url, sizeof(cfg->discord_webhook_url),
                     "%s", val);
        } else if (strcmp(key, "webhook_url") == 0) {
            snprintf(cfg->webhook_url, sizeof(cfg->webhook_url), "%s", val);
        } else if (strcmp(key, "fail_threshold") == 0) {
            if (parse_int_range(val, 1, 10000, &cfg->fail_threshold) < 0) {
                sd_journal_print(
                    LOG_ERR,
                    "pamsignal: config:%d: fail_threshold must be 1..10000",
                    lineno);
                errors++;
            }
        } else if (strcmp(key, "fail_window_sec") == 0) {
            if (parse_int_range(val, 1, 86400, &cfg->fail_window_sec) < 0) {
                sd_journal_print(
                    LOG_ERR,
                    "pamsignal: config:%d: fail_window_sec must be 1..86400",
                    lineno);
                errors++;
            }
        } else if (strcmp(key, "max_tracked_ips") == 0) {
            if (parse_int_range(val, 1, 100000, &cfg->max_tracked_ips) < 0) {
                sd_journal_print(
                    LOG_ERR,
                    "pamsignal: config:%d: max_tracked_ips must be 1..100000",
                    lineno);
                errors++;
            }
        } else if (strcmp(key, "alert_cooldown_sec") == 0) {
            if (parse_int_range(val, 0, 86400, &cfg->alert_cooldown_sec) < 0) {
                sd_journal_print(
                    LOG_ERR,
                    "pamsignal: config:%d: alert_cooldown_sec must be 0..86400",
                    lineno);
                errors++;
            }
        } else {
            sd_journal_print(LOG_WARNING,
                             "pamsignal: config:%d: unknown key: %s", lineno,
                             key);
        }
    }

    fclose(f);

    if (errors > 0) {
        sd_journal_print(LOG_ERR, "pamsignal: config has %d error(s)", errors);
        return PS_ERR_CONFIG;
    }

    sd_journal_print(LOG_INFO,
                     "pamsignal: config loaded: telegram=%s slack=%s teams=%s "
                     "whatsapp=%s discord=%s webhook=%s "
                     "fail_threshold=%d fail_window_sec=%d "
                     "max_tracked_ips=%d alert_cooldown_sec=%d",
                     cfg->telegram_bot_token[0] ? "on" : "off",
                     cfg->slack_webhook_url[0] ? "on" : "off",
                     cfg->teams_webhook_url[0] ? "on" : "off",
                     cfg->whatsapp_access_token[0] ? "on" : "off",
                     cfg->discord_webhook_url[0] ? "on" : "off",
                     cfg->webhook_url[0] ? "on" : "off", cfg->fail_threshold,
                     cfg->fail_window_sec, cfg->max_tracked_ips,
                     cfg->alert_cooldown_sec);
    return PS_OK;
}
