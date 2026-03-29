#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>

#define PS_DEFAULT_CONFIG_PATH "/etc/pamsignal/pamsignal.conf"

// Defaults for brute-force detection
#define PS_DEFAULT_FAIL_THRESHOLD     5
#define PS_DEFAULT_FAIL_WINDOW_SEC    300
#define PS_DEFAULT_MAX_TRACKED_IPS    256
#define PS_DEFAULT_ALERT_COOLDOWN_SEC 60

typedef struct {
    // Webhook
    char webhook_url[512];  // empty = disabled

    // Brute-force detection
    int fail_threshold;     // 1..10000
    int fail_window_sec;    // 1..86400
    int max_tracked_ips;    // 1..100000

    // Alert rate limiting
    int alert_cooldown_sec; // 0..86400 (0 = no cooldown)
} ps_config_t;

// Fill cfg with compiled defaults
void ps_config_defaults(ps_config_t *cfg);

// Parse config file into cfg.
// Returns PS_OK on success (including file not found — defaults kept).
// Returns PS_ERR_CONFIG on parse/validation error.
int ps_config_load(const char *path, ps_config_t *cfg);

// Global config and config path
extern ps_config_t g_config;
extern const char *g_config_path;

#endif /* CONFIG_H */
