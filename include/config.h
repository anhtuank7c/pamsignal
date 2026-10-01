#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>

#include "paths.h"

// Defaults for brute-force detection
#define PS_DEFAULT_FAIL_THRESHOLD     5
#define PS_DEFAULT_FAIL_WINDOW_SEC    300
#define PS_DEFAULT_MAX_TRACKED_IPS    256
#define PS_DEFAULT_ALERT_COOLDOWN_SEC 60

// Default for login-after-failures detection: a successful login from an IP
// with at least this many recent failures is flagged as a likely guessed
// password. 0 disables the detection.
#define PS_DEFAULT_SUCCESS_AFTER_FAIL_THRESHOLD 3

// Upper bound on trusted_sources entries. Fixed-size so ps_config_t stays a
// plain value type that SIGHUP reload can swap with a struct assignment.
#define PS_MAX_TRUSTED_SOURCES 32

// Notification-type filter bits. enable_notification_type is a bitmask of
// these flags; default is PS_NOTIFY_ALL so existing deployments keep their
// behaviour. Filters only affect chat dispatch (Telegram/Slack/Teams/
// WhatsApp/Discord/webhook); the local systemd-journal trail emitted by
// ps_log_event is unaffected.
#define PS_NOTIFY_LOGIN_SUCCESS        0x01u
#define PS_NOTIFY_LOGIN_FAILED         0x02u
#define PS_NOTIFY_SESSION_OPEN         0x04u
#define PS_NOTIFY_SESSION_CLOSE        0x08u
#define PS_NOTIFY_BRUTE_FORCE          0x10u
#define PS_NOTIFY_LOGIN_AFTER_FAILURES 0x20u
#define PS_NOTIFY_ALL                                   \
    (PS_NOTIFY_LOGIN_SUCCESS | PS_NOTIFY_LOGIN_FAILED | \
     PS_NOTIFY_SESSION_OPEN | PS_NOTIFY_SESSION_CLOSE | \
     PS_NOTIFY_BRUTE_FORCE | PS_NOTIFY_LOGIN_AFTER_FAILURES)

// How chat alerts are laid out. Compact is the one-line key=value text;
// pretty is a multi-line message with bold labels and monospace values in
// each platform's own markup. The custom webhook's JSON is unaffected.
typedef enum {
    PS_MESSAGE_STYLE_COMPACT,
    PS_MESSAGE_STYLE_PRETTY
} ps_message_style_t;

// One trusted_sources entry: an IPv4 or IPv6 network in CIDR form. addr holds
// the network-order address bytes (4 used for AF_INET, 16 for AF_INET6).
typedef struct {
    int family; // AF_INET or AF_INET6
    uint8_t addr[16];
    uint8_t prefix_len; // 1..32 for AF_INET, 1..128 for AF_INET6
} ps_cidr_t;

typedef struct {
    // Alert channels (empty = disabled)
    char telegram_bot_token[256];
    char telegram_chat_id[64];
    char slack_webhook_url[512];
    char teams_webhook_url[512];
    char whatsapp_access_token[512];
    char whatsapp_phone_number_id[64];
    char whatsapp_recipient[32];
    char discord_webhook_url[512];
    char webhook_url[512];
    char webhook_auth_header[512];
    char webhook_client_cert[512];
    char webhook_client_key[512];
    char webhook_ca_bundle[512];

    // Brute-force detection
    int fail_threshold;  // 1..10000
    int fail_window_sec; // 1..86400
    int max_tracked_ips; // 1..100000

    // Login-after-failures detection: failures from one IP inside
    // fail_window_sec that make a following successful login suspicious.
    int success_after_fail_threshold; // 0..10000 (0 = disabled)

    // Sources whose routine login events never reach chat (office, VPN,
    // bastion). Brute-force and login-after-failures alerts still fire.
    ps_cidr_t trusted_sources[PS_MAX_TRUSTED_SOURCES];
    int trusted_sources_count;

    // Context tags
    char provider[64];
    char service_name[64];

    // Alert rate limiting
    int alert_cooldown_sec; // 0..86400 (0 = no cooldown)

    // Chat-dispatch filter (bitmask of PS_NOTIFY_*). Default PS_NOTIFY_ALL.
    unsigned int enable_notification_type;

    // Chat message layout. Default PS_MESSAGE_STYLE_COMPACT.
    ps_message_style_t message_style;
} ps_config_t;

// Fill cfg with compiled defaults
void ps_config_defaults(ps_config_t *cfg);

// Parse config file into cfg.
// Returns PS_OK on success (including file not found — defaults kept).
// Returns PS_ERR_CONFIG on parse/validation error.
int ps_config_load(const char *path, ps_config_t *cfg);

// Mirror config diagnostics to stderr as well as the journal. Used by
// --check-config / --test-alert, where the operator is at a terminal.
void ps_config_log_to_stderr(int enabled);

// Returns 1 if ip (an IPv4/IPv6 literal) falls inside any trusted_sources
// network, 0 otherwise (including an empty or unparseable ip).
int ps_config_ip_trusted(const ps_config_t *cfg, const char *ip);

// Global config and config path
extern ps_config_t g_config;
extern const char *g_config_path;

#endif /* CONFIG_H */
