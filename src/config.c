#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stddef.h>
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

// --- Config key mapping table ---

typedef enum { CFG_STRING, CFG_INT } cfg_type_t;

typedef struct {
    const char *key;
    cfg_type_t type;
    size_t offset; // offset into ps_config_t
    size_t size;   // buffer size for strings
    int min;       // for int range validation
    int max;
} cfg_entry_t;

#define CFG_STR(name)                  \
    {#name,                            \
     CFG_STRING,                       \
     offsetof(ps_config_t, name),      \
     sizeof(((ps_config_t *)0)->name), \
     0,                                \
     0}
#define CFG_INT(name, lo, hi) \
    {#name, CFG_INT, offsetof(ps_config_t, name), 0, lo, hi}

static const cfg_entry_t config_keys[] = {
    CFG_STR(telegram_bot_token),
    CFG_STR(telegram_chat_id),
    CFG_STR(slack_webhook_url),
    CFG_STR(teams_webhook_url),
    CFG_STR(whatsapp_access_token),
    CFG_STR(whatsapp_phone_number_id),
    CFG_STR(whatsapp_recipient),
    CFG_STR(discord_webhook_url),
    CFG_STR(webhook_url),
    CFG_INT(fail_threshold, 1, 10000),
    CFG_INT(fail_window_sec, 1, 86400),
    CFG_INT(max_tracked_ips, 1, 100000),
    CFG_INT(alert_cooldown_sec, 0, 86400),
};

static const size_t config_keys_count =
    sizeof(config_keys) / sizeof(config_keys[0]);

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

        int found = 0;
        for (size_t i = 0; i < config_keys_count; i++) {
            if (strcmp(key, config_keys[i].key) != 0)
                continue;
            found = 1;

            if (config_keys[i].type == CFG_STRING) {
                char *dst = (char *)cfg + config_keys[i].offset;
                snprintf(dst, config_keys[i].size, "%s", val);
            } else {
                int *dst = (int *)((char *)cfg + config_keys[i].offset);
                if (parse_int_range(val, config_keys[i].min, config_keys[i].max,
                                    dst) < 0) {
                    sd_journal_print(
                        LOG_ERR, "pamsignal: config:%d: %s must be %d..%d",
                        lineno, key, config_keys[i].min, config_keys[i].max);
                    errors++;
                }
            }
            break;
        }

        if (!found) {
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
