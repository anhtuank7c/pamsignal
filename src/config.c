#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <syslog.h>
#include <systemd/sd-journal.h>
#include <unistd.h>

#include "config.h"
#include "init.h"
#include "ps_cleanup.h"

ps_config_t g_config;
const char *g_config_path = PS_DEFAULT_CONFIG_PATH;

void ps_config_defaults(ps_config_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->fail_threshold = PS_DEFAULT_FAIL_THRESHOLD;
    cfg->fail_window_sec = PS_DEFAULT_FAIL_WINDOW_SEC;
    cfg->max_tracked_ips = PS_DEFAULT_MAX_TRACKED_IPS;
    cfg->alert_cooldown_sec = PS_DEFAULT_ALERT_COOLDOWN_SEC;
    cfg->enable_notification_type = PS_NOTIFY_ALL;
}

// Locale-independent whitespace classifier. Avoids the ctype.h __ctype_b_loc
// table lookup (whose tainted-index access trips clang-analyzer-security.
// ArrayBound) and guarantees the same parse regardless of LC_CTYPE.
static int is_ws(unsigned char c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' ||
           c == '\f';
}

static char *trim(char *s) {
    while (is_ws((unsigned char)*s))
        s++;
    if (*s == '\0')
        return s;
    char *end = s + strlen(s) - 1;
    while (end > s && is_ws((unsigned char)*end))
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

// Parse a comma-separated notification-type list ("login_success,brute_force",
// "all", etc.) into a bitmask. Returns -1 on unknown token, empty value, or
// an empty list element (we want "a,,b" to be a hard error, not silently
// coalesced into {a,b} — strtok_r would skip the empty element, so we split
// by hand). Whitespace around each element is tolerated. Case-insensitive.
static int parse_notification_mask(const char *val, unsigned int *out) {
    if (!val || !*val)
        return -1;

    static const struct {
        const char *name;
        unsigned int flag;
    } tokens[] = {
        {"login_success", PS_NOTIFY_LOGIN_SUCCESS},
        {"login_failed", PS_NOTIFY_LOGIN_FAILED},
        {"session_open", PS_NOTIFY_SESSION_OPEN},
        {"session_close", PS_NOTIFY_SESSION_CLOSE},
        {"brute_force", PS_NOTIFY_BRUTE_FORCE},
        {"all", PS_NOTIFY_ALL},
    };

    char buf[256];
    if (snprintf(buf, sizeof(buf), "%s", val) >= (int)sizeof(buf))
        return -1;

    unsigned int mask = 0;
    int matched_any = 0;
    char *p = buf;
    while (1) {
        char *comma = strchr(p, ',');
        if (comma)
            *comma = '\0';

        char *t = trim(p);
        if (*t == '\0')
            return -1;
        for (char *q = t; *q; q++)
            *q = (char)tolower((unsigned char)*q);

        int found = 0;
        for (size_t i = 0; i < sizeof(tokens) / sizeof(tokens[0]); i++) {
            if (strcmp(t, tokens[i].name) == 0) {
                mask |= tokens[i].flag;
                found = 1;
                matched_any = 1;
                break;
            }
        }
        if (!found)
            return -1;

        if (!comma)
            break;
        p = comma + 1;
    }
    if (!matched_any)
        return -1;
    *out = mask;
    return 0;
}

// --- Config key mapping table ---

typedef enum { CFG_STRING, CFG_INT, CFG_NOTIFY_MASK } cfg_type_t;

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
#define CFG_NOTIFY(name) \
    {#name, CFG_NOTIFY_MASK, offsetof(ps_config_t, name), 0, 0, 0}

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
    CFG_STR(webhook_auth_header),
    CFG_STR(webhook_client_cert),
    CFG_STR(webhook_client_key),
    CFG_STR(webhook_ca_bundle),
    CFG_STR(provider),
    CFG_STR(service_name),
    CFG_INT(fail_threshold, 1, 10000),
    CFG_INT(fail_window_sec, 1, 86400),
    CFG_INT(max_tracked_ips, 1, 100000),
    CFG_INT(alert_cooldown_sec, 0, 86400),
    CFG_NOTIFY(enable_notification_type),
};

static const size_t config_keys_count =
    sizeof(config_keys) / sizeof(config_keys[0]);

// --- Value validators ---
//
// Webhook URLs and bearer tokens are interpolated into the curl invocation.
// We refuse anything that could smuggle whitespace, CR/LF, shell
// metacharacters, or non-https schemes — each value passes an explicit
// per-field allowlist before the daemon will start with it.

static int has_only_chars(const char *s, int (*pred)(int)) {
    if (!s || !*s)
        return 0;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if (!pred((int)*p))
            return 0;
    }
    return 1;
}

static int is_digit_int(int c) {
    return isdigit(c);
}

static int is_token_char(int c) {
    return isalnum(c) || c == '_' || c == '-' || c == '.' || c == '=';
}

static int is_https_url_char(int c) {
    if (c <= 0x20 || c == 0x7F)
        return 0;
    // RFC 3986 unreserved + reserved, minus characters that have meaning to a
    // shell or curl-config parser even though curl itself accepts them.
    return strchr("\"'`|<>\\{}^ \t\r\n", c) == NULL;
}

static int is_https_url(const char *url) {
    if (!url || strncmp(url, "https://", 8) != 0)
        return 0;
    if (!url[8])
        return 0;
    return has_only_chars(url, is_https_url_char);
}

static int is_telegram_bot_token(const char *t) {
    if (!t || !*t)
        return 0;
    const char *colon = strchr(t, ':');
    if (!colon || colon == t)
        return 0;
    for (const char *p = t; p < colon; p++) {
        if (!isdigit((unsigned char)*p))
            return 0;
    }
    const char *suffix = colon + 1;
    if (strlen(suffix) < 20)
        return 0;
    for (const char *p = suffix; *p; p++) {
        if (!isalnum((unsigned char)*p) && *p != '_' && *p != '-')
            return 0;
    }
    return 1;
}

// Validates a single HTTP header in `Name: value` form before it is written
// into the curl -K config file. Header injection (CR/LF) would let an
// attacker who controls the config inject extra request headers; `"` and `\`
// would break out of the quoted value in curl's config parser.
static int is_http_header(const char *h) {
    if (!h || !*h)
        return 0;
    const char *colon = strchr(h, ':');
    if (!colon || colon == h)
        return 0;
    for (const char *p = h; p < colon; p++) {
        unsigned char c = (unsigned char)*p;
        if (!isalnum(c) && !strchr("!#$%&'*+-.^_`|~", c))
            return 0;
    }
    for (const char *p = colon + 1; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c < 0x20 || c == 0x7F)
            return 0;
        if (c == '"' || c == '\\')
            return 0;
    }
    return 1;
}

static int is_telegram_chat_id(const char *s) {
    if (!s || !*s)
        return 0;
    if (*s == '@') {
        if (!s[1])
            return 0;
        for (const char *p = s + 1; *p; p++) {
            if (!isalnum((unsigned char)*p) && *p != '_')
                return 0;
        }
        return 1;
    }
    const char *p = s;
    if (*p == '-')
        p++;
    if (!*p)
        return 0;
    for (; *p; p++) {
        if (!isdigit((unsigned char)*p))
            return 0;
    }
    return 1;
}

// Validates a filesystem path that pamsignal will hand to curl as
// --cert / --key / --cacert. Refuses symlinks, non-regular files, ownership
// outside {root, euid}. The `private` flag tightens to "no group/world read"
// for the client key — certs and CA bundles are public material so we leave
// their read-perms to the operator's discretion. Existence is required (a
// missing cert file would surface as a curl runtime error long after startup,
// hiding the misconfiguration).
//
// Also refuses `"`, `\`, and control chars in the path itself so the path
// can be safely written into a curl -K config file as a quoted value
// (the same constraint applied to webhook_auth_header).
static int validate_tls_path(const char *path, const char *label, int private) {
    for (const unsigned char *p = (const unsigned char *)path; *p; p++) {
        if (*p < 0x20 || *p == 0x7F || *p == '"' || *p == '\\') {
            sd_journal_print(LOG_ERR,
                             "pamsignal: config: %s: path contains a control "
                             "character, quote, or backslash",
                             label);
            return -1;
        }
    }

    _cleanup_close_ int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ELOOP) {
            sd_journal_print(LOG_ERR,
                             "pamsignal: config: %s: refusing to follow "
                             "symlink at %s",
                             label, path);
        } else {
            sd_journal_print(LOG_ERR,
                             "pamsignal: config: %s: cannot open %s: %s", label,
                             path, strerror(errno));
        }
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        sd_journal_print(LOG_ERR, "pamsignal: config: %s: fstat(%s) failed: %s",
                         label, path, strerror(errno));
        return -1;
    }

    if (!S_ISREG(st.st_mode)) {
        sd_journal_print(LOG_ERR,
                         "pamsignal: config: %s: %s is not a regular file",
                         label, path);
        return -1;
    }

    if (st.st_uid != 0 && st.st_uid != geteuid()) {
        sd_journal_print(LOG_ERR,
                         "pamsignal: config: %s: %s must be owned by root or "
                         "the daemon user (uid=%u)",
                         label, path, (unsigned)st.st_uid);
        return -1;
    }

    if (private && (st.st_mode & (S_IRGRP | S_IROTH))) {
        sd_journal_print(LOG_ERR,
                         "pamsignal: config: %s: %s must not be group- or "
                         "world-readable (mode 0%o); private keys belong to "
                         "the daemon only",
                         label, path, st.st_mode & 0777);
        return -1;
    }

    return 0;
}

static int validate_webhook_tls(const ps_config_t *cfg) {
    int errors = 0;
    int has_cert = cfg->webhook_client_cert[0] != '\0';
    int has_key = cfg->webhook_client_key[0] != '\0';
    int has_ca = cfg->webhook_ca_bundle[0] != '\0';

    if (!has_cert && !has_key && !has_ca)
        return 0;

    if (!cfg->webhook_url[0]) {
        sd_journal_print(LOG_ERR,
                         "pamsignal: config: webhook TLS keys "
                         "(webhook_client_cert/key/ca_bundle) are set but "
                         "webhook_url is not configured");
        errors++;
    }

    if (has_cert != has_key) {
        sd_journal_print(LOG_ERR, "pamsignal: config: webhook_client_cert and "
                                  "webhook_client_key must be set together");
        errors++;
    }

    if (has_cert && validate_tls_path(cfg->webhook_client_cert,
                                      "webhook_client_cert", 0) < 0)
        errors++;
    if (has_key &&
        validate_tls_path(cfg->webhook_client_key, "webhook_client_key", 1) < 0)
        errors++;
    if (has_ca &&
        validate_tls_path(cfg->webhook_ca_bundle, "webhook_ca_bundle", 0) < 0)
        errors++;

    return errors;
}

static int validate_alert_targets(const ps_config_t *cfg) {
    int errors = 0;

    if (cfg->telegram_bot_token[0]) {
        if (!is_telegram_bot_token(cfg->telegram_bot_token)) {
            sd_journal_print(
                LOG_ERR, "pamsignal: config: telegram_bot_token "
                         "format invalid (expected NNNN:[A-Za-z0-9_-]{20+})");
            errors++;
        }
        if (!cfg->telegram_chat_id[0] ||
            !is_telegram_chat_id(cfg->telegram_chat_id)) {
            sd_journal_print(LOG_ERR, "pamsignal: config: telegram_chat_id "
                                      "missing or invalid");
            errors++;
        }
    }

    if (cfg->whatsapp_access_token[0]) {
        if (!has_only_chars(cfg->whatsapp_access_token, is_token_char)) {
            sd_journal_print(LOG_ERR,
                             "pamsignal: config: whatsapp_access_token "
                             "contains disallowed characters");
            errors++;
        }
        if (!has_only_chars(cfg->whatsapp_phone_number_id, is_digit_int)) {
            sd_journal_print(LOG_ERR,
                             "pamsignal: config: whatsapp_phone_number_id "
                             "must be digits only");
            errors++;
        }
        if (!has_only_chars(cfg->whatsapp_recipient, is_digit_int)) {
            sd_journal_print(LOG_ERR, "pamsignal: config: whatsapp_recipient "
                                      "must be digits only");
            errors++;
        }
    }

    const struct {
        const char *name;
        const char *value;
    } urls[] = {
        {"slack_webhook_url", cfg->slack_webhook_url},
        {"teams_webhook_url", cfg->teams_webhook_url},
        {"discord_webhook_url", cfg->discord_webhook_url},
        {"webhook_url", cfg->webhook_url},
    };
    for (size_t i = 0; i < sizeof(urls) / sizeof(urls[0]); i++) {
        if (urls[i].value[0] && !is_https_url(urls[i].value)) {
            sd_journal_print(LOG_ERR,
                             "pamsignal: config: %s must be an https:// URL "
                             "with no whitespace or shell metacharacters",
                             urls[i].name);
            errors++;
        }
    }

    if (cfg->webhook_auth_header[0]) {
        if (!cfg->webhook_url[0]) {
            sd_journal_print(LOG_ERR,
                             "pamsignal: config: webhook_auth_header is set "
                             "but webhook_url is not configured");
            errors++;
        }
        if (!is_http_header(cfg->webhook_auth_header)) {
            sd_journal_print(LOG_ERR,
                             "pamsignal: config: webhook_auth_header must be "
                             "in 'Name: value' form with no control chars, "
                             "quotes, or backslashes");
            errors++;
        }
    }

    errors += validate_webhook_tls(cfg);

    return errors;
}

// Open the config file with O_NOFOLLOW (refuse symlinks) and verify the
// permissions look sane: not group/world-writable, owned by either root or
// the current effective uid. Returns a FILE* on success, NULL on failure
// (with errno set on the !found path so the caller can distinguish ENOENT).
static FILE *open_config_secure(const char *path) {
    _cleanup_close_ int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return NULL;

    struct stat st;
    if (fstat(fd, &st) < 0)
        return NULL;

    if (!S_ISREG(st.st_mode)) {
        sd_journal_print(LOG_ERR, "pamsignal: config %s is not a regular file",
                         path);
        errno = EINVAL;
        return NULL;
    }

    if (st.st_mode & (S_IWGRP | S_IWOTH)) {
        sd_journal_print(LOG_ERR,
                         "pamsignal: config %s must not be group- or "
                         "world-writable (mode 0%o)",
                         path, st.st_mode & 0777);
        errno = EACCES;
        return NULL;
    }

    if (st.st_uid != 0 && st.st_uid != geteuid()) {
        sd_journal_print(LOG_ERR,
                         "pamsignal: config %s must be owned by root or the "
                         "daemon user (uid=%u)",
                         path, (unsigned)st.st_uid);
        errno = EACCES;
        return NULL;
    }

    /* Ownership transfer: fdopen takes ownership of the fd. We must disarm
     * the close attribute before returning the FILE*.
     */
    FILE *f = fdopen(fd, "r");
    if (!f)
        return NULL;

    // Disarm _cleanup_close_: FILE* now owns the fd. The store is read by
    // ps_closep through __attribute__((cleanup)), which clang-analyzer
    // cannot see — suppress the dead-store false positive.
    // NOLINTNEXTLINE(clang-analyzer-deadcode.DeadStores)
    fd = -1;
    return f;
}

int ps_config_load(const char *path, ps_config_t *cfg) {
    ps_config_defaults(cfg);

    _cleanup_fclose_ FILE *f = open_config_secure(path);
    if (!f) {
        if (errno == ENOENT) {
            sd_journal_print(LOG_INFO,
                             "pamsignal: config file not found: %s "
                             "(using defaults)",
                             path);
            return PS_OK;
        }
        if (errno == ELOOP) {
            sd_journal_print(LOG_ERR,
                             "pamsignal: refusing to follow symlink for "
                             "config: %s",
                             path);
        } else if (errno != EACCES && errno != EINVAL) {
            sd_journal_print(LOG_ERR, "pamsignal: cannot open config: %s: %s",
                             path, strerror(errno));
        }
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
                LOG_ERR, "pamsignal: config:%d: missing '=' separator", lineno);
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
            } else if (config_keys[i].type == CFG_INT) {
                int *dst = (int *)((char *)cfg + config_keys[i].offset);
                if (parse_int_range(val, config_keys[i].min, config_keys[i].max,
                                    dst) < 0) {
                    sd_journal_print(
                        LOG_ERR, "pamsignal: config:%d: %s must be %d..%d",
                        lineno, key, config_keys[i].min, config_keys[i].max);
                    errors++;
                }
            } else {
                unsigned int *dst =
                    (unsigned int *)((char *)cfg + config_keys[i].offset);
                if (parse_notification_mask(val, dst) < 0) {
                    sd_journal_print(
                        LOG_ERR,
                        "pamsignal: config:%d: %s must be a comma-separated "
                        "list of login_success, login_failed, session_open, "
                        "session_close, brute_force, or 'all'",
                        lineno, key);
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

    errors += validate_alert_targets(cfg);

    if (errors > 0) {
        sd_journal_print(LOG_ERR, "pamsignal: config has %d error(s)", errors);
        return PS_ERR_CONFIG;
    }

    sd_journal_print(LOG_INFO,
                     "pamsignal: config loaded: telegram=%s slack=%s teams=%s "
                     "whatsapp=%s discord=%s webhook=%s webhook_auth=%s "
                     "webhook_mtls=%s fail_threshold=%d fail_window_sec=%d "
                     "max_tracked_ips=%d alert_cooldown_sec=%d "
                     "enable_notification_type=0x%02x "
                     "provider=%s service_name=%s",
                     cfg->telegram_bot_token[0] ? "on" : "off",
                     cfg->slack_webhook_url[0] ? "on" : "off",
                     cfg->teams_webhook_url[0] ? "on" : "off",
                     cfg->whatsapp_access_token[0] ? "on" : "off",
                     cfg->discord_webhook_url[0] ? "on" : "off",
                     cfg->webhook_url[0] ? "on" : "off",
                     cfg->webhook_auth_header[0] ? "on" : "off",
                     cfg->webhook_client_cert[0] ? "on" : "off",
                     cfg->fail_threshold, cfg->fail_window_sec,
                     cfg->max_tracked_ips, cfg->alert_cooldown_sec,
                     cfg->enable_notification_type,
                     cfg->provider[0] ? cfg->provider : "none",
                     cfg->service_name[0] ? cfg->service_name : "none");
    return PS_OK;
}
