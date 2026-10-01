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
#include <sys/wait.h>
#include <syslog.h>
#include <systemd/sd-journal.h>
#include <time.h>
#include <unistd.h>

#include "notify.h"
#include "ps_cleanup.h"
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
//
// TLS client-cert paths are not themselves secret (the file *contents* are,
// and stay on disk under the daemon's trust boundary), but we route them
// through the same memfd config so argv stays minimal and uniform.

typedef struct {
    const char *url;
    const char *auth_header; // optional
    const char *client_cert; // optional
    const char *client_key;  // optional, paired with client_cert
    const char *ca_bundle;   // optional
} curl_config_t;

static int build_secrets_memfd(const curl_config_t *cfg) {
    _cleanup_close_ int fd = memfd_create("pamsignal-curl", MFD_CLOEXEC);
    if (fd < 0) {
        sd_journal_print(LOG_WARNING,
                         "pamsignal: memfd_create failed: %m, dropping alert");
        return -1;
    }

    char buf[4096];
    int n = snprintf(buf, sizeof(buf), "url = \"%s\"\n", cfg->url);
    if (n < 0 || (size_t)n >= sizeof(buf))
        return -1;

    if (cfg->auth_header) {
        int m = snprintf(buf + n, sizeof(buf) - (size_t)n, "header = \"%s\"\n",
                         cfg->auth_header);
        if (m < 0 || (size_t)n + (size_t)m >= sizeof(buf))
            return -1;
        n += m;
    }
    if (cfg->client_cert) {
        int m = snprintf(buf + n, sizeof(buf) - (size_t)n, "cert = \"%s\"\n",
                         cfg->client_cert);
        if (m < 0 || (size_t)n + (size_t)m >= sizeof(buf))
            return -1;
        n += m;
    }
    if (cfg->client_key) {
        int m = snprintf(buf + n, sizeof(buf) - (size_t)n, "key = \"%s\"\n",
                         cfg->client_key);
        if (m < 0 || (size_t)n + (size_t)m >= sizeof(buf))
            return -1;
        n += m;
    }
    if (cfg->ca_bundle) {
        int m = snprintf(buf + n, sizeof(buf) - (size_t)n, "cacert = \"%s\"\n",
                         cfg->ca_bundle);
        if (m < 0 || (size_t)n + (size_t)m >= sizeof(buf))
            return -1;
        n += m;
    }

    ssize_t total = 0;
    while (total < n) {
        ssize_t w = write(fd, buf + total, (size_t)(n - total));
        if (w < 0)
            return -1;
        total += w;
    }
    if (lseek(fd, 0, SEEK_SET) < 0)
        return -1;

    /* Ownership transfer: the caller will dup2 and manage lifetime.
     * Disarm _cleanup_close_ — the store is read by ps_closep through
     * __attribute__((cleanup)), which clang-analyzer cannot see.
     */
    int ret = fd;
    // NOLINTNEXTLINE(clang-analyzer-deadcode.DeadStores)
    fd = -1;
    return ret;
}

// --test-alert support. Normal dispatch is fire-and-forget; in sync mode the
// parent waits for each curl child and records its exit code here so the
// operator gets a per-channel verdict. PS_SYNC_NOT_RUN means no curl was
// started for the channel (alert dropped before the fork).
#define PS_SYNC_NOT_RUN (-1)

static int sync_dispatch = 0;
static int sync_result = PS_SYNC_NOT_RUN;

static void fire_curl(int raw_memfd, char *body) {
    _cleanup_close_ int memfd =
        raw_memfd; /* RAII close on all function exits (parent path) */
    pid_t pid = fork();
    if (pid < 0) {
        sd_journal_print(LOG_WARNING, "pamsignal: fork failed for alert");
        return; /* memfd closed automatically by _cleanup_close_ */
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

        char *argv[20];
        int argc = 0;
        argv[argc++] = "curl";
        argv[argc++] = "-s";
        argv[argc++] = "-S";
        if (sync_dispatch) {
            // --test-alert: make an HTTP error status (bad token, revoked
            // webhook) a non-zero exit, and keep the response body off the
            // operator's terminal.
            argv[argc++] = "-f";
            argv[argc++] = "-o";
            argv[argc++] = "/dev/null";
        }
        argv[argc++] = "--max-time";
        argv[argc++] = "10";
        argv[argc++] = "--proto";
        argv[argc++] = "=https";
        argv[argc++] = "--proto-redir";
        argv[argc++] = "=https";
        argv[argc++] = "-H";
        argv[argc++] = "Content-Type: application/json";
        argv[argc++] = "-K";
        argv[argc++] = fdpath;
        argv[argc++] = "-d";
        argv[argc++] = body;
        argv[argc] = NULL;

        // Absolute path: avoid PATH search even though we just sanitized PATH.
        execv("/usr/bin/curl", argv);
        _exit(127);
    }

    if (sync_dispatch) {
        int status = 0;
        pid_t w;
        do {
            w = waitpid(pid, &status, 0);
        } while (w < 0 && errno == EINTR);
        // 128 stands in for "killed by a signal / could not be reaped" so it
        // can never be mistaken for a curl exit code of 0.
        sync_result =
            (w == pid && WIFEXITED(status)) ? WEXITSTATUS(status) : 128;
        return;
    }
    // Parent: fire-and-forget; SIGCHLD is set to SIG_IGN | SA_NOCLDWAIT so
    // the kernel reaps the child.
    // memfd is closed automatically by the _cleanup_close_ parameter.
}

static void post_alert(const curl_config_t *cc, char *body) {
    int memfd = build_secrets_memfd(cc);
    if (memfd < 0)
        return;
    fire_curl(memfd, body); /* ownership transferred; closed inside fire_curl
                               via local _cleanup_close_ */
}

static curl_config_t webhook_curl_config(const ps_config_t *cfg) {
    return (curl_config_t){
        .url = cfg->webhook_url,
        .auth_header =
            cfg->webhook_auth_header[0] ? cfg->webhook_auth_header : NULL,
        .client_cert =
            cfg->webhook_client_cert[0] ? cfg->webhook_client_cert : NULL,
        .client_key =
            cfg->webhook_client_key[0] ? cfg->webhook_client_key : NULL,
        .ca_bundle = cfg->webhook_ca_bundle[0] ? cfg->webhook_ca_bundle : NULL,
    };
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

// Render the optional provider / service_name tags as a " key=value" suffix
// for chat text. Leaves buf empty when neither tag is configured.
static void format_context_text(const ps_config_t *cfg, char *buf, size_t len) {
    buf[0] = '\0';
    if (cfg->provider[0] && cfg->service_name[0]) {
        snprintf(buf, len, " provider=%s service_name=%s", cfg->provider,
                 cfg->service_name);
    } else if (cfg->provider[0]) {
        snprintf(buf, len, " provider=%s", cfg->provider);
    } else if (cfg->service_name[0]) {
        snprintf(buf, len, " service_name=%s", cfg->service_name);
    }
}

// Render the same tags as a `,"labels":{...}` JSON fragment.
static void format_labels_json(const ps_config_t *cfg, char *buf, size_t len) {
    buf[0] = '\0';
    char esc_prov[128] = "", esc_srv[128] = "";
    json_escape(cfg->provider, esc_prov, sizeof(esc_prov));
    json_escape(cfg->service_name, esc_srv, sizeof(esc_srv));
    if (cfg->provider[0] && cfg->service_name[0]) {
        snprintf(buf, len,
                 ",\"labels\":{\"provider\":\"%s\",\"service_name\":\"%s\"}",
                 esc_prov, esc_srv);
    } else if (cfg->provider[0]) {
        snprintf(buf, len, ",\"labels\":{\"provider\":\"%s\"}", esc_prov);
    } else if (cfg->service_name[0]) {
        snprintf(buf, len, ",\"labels\":{\"service_name\":\"%s\"}", esc_srv);
    }
}

static void format_login_after_failures_text(const ps_config_t *cfg,
                                             const ps_pam_event_t *event,
                                             int failures, int window,
                                             char *buf, size_t len) {
    char timebuf[32];
    char context[256];
    ps_format_timestamp(event->timestamp_usec, timebuf, sizeof(timebuf));
    format_context_text(cfg, context, sizeof(context));

    snprintf(buf, len,
             "[CRIT]   auth.login_after_failures user=%s src=%s:%d "
             "failures=%d window=%ds host=%s service=%s auth=%s pid=%d "
             "ts=%s%s",
             event->username, event->source_ip, event->port, failures, window,
             event->hostname, ps_service_str(event->service),
             ps_auth_method_str(event->auth_method), (int)event->pid, timebuf,
             context);
}

static void format_login_after_failures_json(const ps_config_t *cfg,
                                             const ps_pam_event_t *event,
                                             int failures, int window,
                                             char *buf, size_t len) {
    char timebuf[32];
    char esc_user[128], esc_host[512];
    // 2 x 127 escaped bytes plus the fixed JSON scaffolding: 256 could
    // truncate mid-string and emit malformed JSON for quote-heavy tags.
    char labels_json[320];
    ps_format_timestamp(event->timestamp_usec, timebuf, sizeof(timebuf));
    json_escape(event->username, esc_user, sizeof(esc_user));
    json_escape(event->hostname, esc_host, sizeof(esc_host));
    format_labels_json(cfg, labels_json, sizeof(labels_json));

    // event.outcome is "success" — the login itself succeeded; event.kind
    // "alert" plus the intrusion_detection category mark it as a detection.
    snprintf(buf, len,
             "{\"@timestamp\":\"%s\","
             "\"event\":{\"action\":\"login_after_failures\","
             "\"category\":[\"authentication\",\"intrusion_detection\"],"
             "\"kind\":\"alert\",\"outcome\":\"success\","
             "\"severity\":9,\"module\":\"pamsignal\","
             "\"dataset\":\"pamsignal.events\"},"
             "\"host\":{\"hostname\":\"%s\"},"
             "\"user\":{\"name\":\"%s\"},"
             "\"service\":{\"name\":\"%s\"},"
             "\"source\":{\"ip\":\"%s\",\"port\":%d},"
             "\"process\":{\"pid\":%d},"
             "\"pamsignal\":{\"event_type\":\"LOGIN_AFTER_FAILURES\","
             "\"auth_method\":\"%s\",\"failures\":%d,\"window_sec\":%d}%s}",
             timebuf, esc_host, esc_user, ps_service_str(event->service),
             event->source_ip, event->port, (int)event->pid,
             ps_auth_method_str(event->auth_method), failures, window,
             labels_json);
}

static void format_test_text(const ps_config_t *cfg, const char *host,
                             uint64_t ts, char *buf, size_t len) {
    char timebuf[32];
    char context[256];
    ps_format_timestamp(ts, timebuf, sizeof(timebuf));
    format_context_text(cfg, context, sizeof(context));

    snprintf(buf, len,
             "[INFO]   pamsignal.test_alert host=%s ts=%s%s msg=\"test message "
             "from pamsignal --test-alert; this channel is working\"",
             host, timebuf, context);
}

static void format_test_json(const ps_config_t *cfg, const char *host,
                             uint64_t ts, char *buf, size_t len) {
    char timebuf[32];
    char esc_host[512];
    // 2 x 127 escaped bytes plus the fixed JSON scaffolding: 256 could
    // truncate mid-string and emit malformed JSON for quote-heavy tags.
    char labels_json[320];
    ps_format_timestamp(ts, timebuf, sizeof(timebuf));
    json_escape(host, esc_host, sizeof(esc_host));
    format_labels_json(cfg, labels_json, sizeof(labels_json));

    snprintf(buf, len,
             "{\"@timestamp\":\"%s\","
             "\"event\":{\"action\":\"test_alert\","
             "\"category\":[\"configuration\"],"
             "\"kind\":\"event\",\"outcome\":\"success\","
             "\"severity\":3,\"module\":\"pamsignal\","
             "\"dataset\":\"pamsignal.events\"},"
             "\"host\":{\"hostname\":\"%s\"},"
             "\"pamsignal\":{\"event_type\":\"TEST_ALERT\"}%s}",
             timebuf, esc_host, labels_json);
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

    post_alert(&(curl_config_t){.url = url}, body);
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

    post_alert(&(curl_config_t){.url = url}, body);
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

    post_alert(&(curl_config_t){.url = url, .auth_header = auth}, body);
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

// Map a PAM event type onto its PS_NOTIFY_* category bit. Returns 0 for
// events we don't classify (e.g. PS_EVENT_UNKNOWN), which keeps unknown
// kinds from ever firing a chat alert.
static unsigned int event_notify_bit(ps_event_type_t type) {
    switch (type) {
    case PS_EVENT_LOGIN_SUCCESS:
        return PS_NOTIFY_LOGIN_SUCCESS;
    case PS_EVENT_LOGIN_FAILED:
        return PS_NOTIFY_LOGIN_FAILED;
    case PS_EVENT_SESSION_OPEN:
        return PS_NOTIFY_SESSION_OPEN;
    case PS_EVENT_SESSION_CLOSE:
        return PS_NOTIFY_SESSION_CLOSE;
    case PS_EVENT_UNKNOWN:
        break;
    }
    return 0;
}

void ps_notify_event(const ps_config_t *cfg, const ps_pam_event_t *event) {
    unsigned int bit = event_notify_bit(event->type);
    if ((cfg->enable_notification_type & bit) == 0)
        return;
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
        curl_config_t cc = webhook_curl_config(cfg);
        post_alert(&cc, json);
    }
}

void ps_notify_brute_force(const ps_config_t *cfg, const char *source_ip,
                           int attempts, int window_sec,
                           const char *last_username, const char *hostname,
                           uint64_t timestamp_usec, pid_t last_pid) {
    if ((cfg->enable_notification_type & PS_NOTIFY_BRUTE_FORCE) == 0)
        return;
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
        curl_config_t cc = webhook_curl_config(cfg);
        post_alert(&cc, json);
    }
}

void ps_notify_local_brute_force(const ps_config_t *cfg, ps_service_t service,
                                 const char *actor_username,
                                 const char *target_username, int attempts,
                                 int window_sec, const char *hostname,
                                 uint64_t timestamp_usec, pid_t last_pid) {
    if ((cfg->enable_notification_type & PS_NOTIFY_BRUTE_FORCE) == 0)
        return;
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
        curl_config_t cc = webhook_curl_config(cfg);
        post_alert(&cc, json);
    }
}

void ps_notify_login_after_failures(const ps_config_t *cfg,
                                    const ps_pam_event_t *event, int failures,
                                    int window_sec) {
    if ((cfg->enable_notification_type & PS_NOTIFY_LOGIN_AFTER_FAILURES) == 0)
        return;
    // Caller (journal_watch.c) applies the per-source-IP cooldown using
    // fail_entry state, mirroring the brute-force paths above.
    char text[1024];
    format_login_after_failures_text(cfg, event, failures, window_sec, text,
                                     sizeof(text));

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
        format_login_after_failures_json(cfg, event, failures, window_sec, json,
                                         sizeof(json));
        curl_config_t cc = webhook_curl_config(cfg);
        post_alert(&cc, json);
    }
}

// --- Test alert (--test-alert) ---

// Print the verdict for the channel that was just dispatched in sync mode.
// Returns 1 if it failed, 0 if curl reported success.
static int report_test_result(const char *channel) {
    int failed = 1;
    if (sync_result == 0) {
        printf("%-9s ok\n", channel);
        failed = 0;
    } else if (sync_result == PS_SYNC_NOT_RUN) {
        printf("%-9s FAILED (alert could not be built or curl could not be "
               "started)\n",
               channel);
    } else if (sync_result == 127) {
        printf("%-9s FAILED (cannot execute /usr/bin/curl; is curl "
               "installed?)\n",
               channel);
    } else {
        printf("%-9s FAILED (curl exit code %d; see the curl message above)\n",
               channel, sync_result);
    }
    fflush(stdout);
    sync_result = PS_SYNC_NOT_RUN;
    return failed;
}

int ps_notify_test(const ps_config_t *cfg, const char *hostname,
                   uint64_t timestamp_usec) {
    char text[1024];
    format_test_text(cfg, hostname, timestamp_usec, text, sizeof(text));

    int configured = 0;
    int failed = 0;
    sync_dispatch = 1;
    sync_result = PS_SYNC_NOT_RUN;

    if (cfg->telegram_bot_token[0]) {
        configured++;
        send_telegram(cfg, text);
        failed += report_test_result("telegram");
    }
    if (cfg->slack_webhook_url[0]) {
        configured++;
        send_simple_webhook(cfg->slack_webhook_url, "text", text);
        failed += report_test_result("slack");
    }
    if (cfg->teams_webhook_url[0]) {
        configured++;
        send_simple_webhook(cfg->teams_webhook_url, "text", text);
        failed += report_test_result("teams");
    }
    if (cfg->whatsapp_access_token[0]) {
        configured++;
        send_whatsapp(cfg, text);
        failed += report_test_result("whatsapp");
    }
    if (cfg->discord_webhook_url[0]) {
        configured++;
        send_simple_webhook(cfg->discord_webhook_url, "content", text);
        failed += report_test_result("discord");
    }
    if (cfg->webhook_url[0]) {
        configured++;
        char json[2048];
        format_test_json(cfg, hostname, timestamp_usec, json, sizeof(json));
        curl_config_t cc = webhook_curl_config(cfg);
        post_alert(&cc, json);
        failed += report_test_result("webhook");
    }

    sync_dispatch = 0;
    return configured ? failed : -1;
}
