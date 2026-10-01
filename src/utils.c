#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "init.h"
#include "utils.h"

// Replace control characters with '?' to prevent log injection
static void sanitize_string(char *str) {
    for (; *str; str++) {
        if (iscntrl((unsigned char)*str) && *str != '\0')
            *str = '?';
    }
}

// Validate that a string is a plausible IP address (IPv4 or IPv6)
static int is_valid_ip(const char *str) {
    unsigned char buf[sizeof(struct in6_addr)];
    if (inet_pton(AF_INET, str, buf) == 1)
        return 1;
    if (inet_pton(AF_INET6, str, buf) == 1)
        return 1;
    return 0;
}

const char *ps_field_value(const char *data, size_t length) {
    const char *eq = memchr(data, '=', length);
    if (!eq)
        return NULL;
    return eq + 1;
}

// Extract the service name from pam_unix(SERVICE:session) pattern
static ps_service_t parse_service_from_pam(const char *msg) {
    const char *start = strstr(msg, "pam_unix(");
    if (!start)
        return PS_SERVICE_OTHER;

    start += 9; // skip "pam_unix("
    if (strncmp(start, "sshd:", 5) == 0)
        return PS_SERVICE_SSHD;
    if (strncmp(start, "sudo:", 5) == 0)
        return PS_SERVICE_SUDO;
    if (strncmp(start, "su:", 3) == 0)
        return PS_SERVICE_SU;
    if (strncmp(start, "login:", 6) == 0)
        return PS_SERVICE_LOGIN;

    return PS_SERVICE_OTHER;
}

// Extract username from "for user USERNAME" or "for USERNAME from"
// Handles newer PAM format: "for user root(uid=0)" -> "root"
//
// On truncation (input longer than the output buffer), the last byte is
// overwritten with '+' so alerts and journal entries visibly mark the
// truncation rather than letting two distinct long usernames silently alias
// to the same prefix.
static void extract_username(const char *start, char *username, size_t len) {
    if (len == 0)
        return;
    size_t i = 0;
    while (*start && *start != ' ' && *start != '\n' && *start != '(' &&
           i < len - 1) {
        username[i++] = *start++;
    }
    username[i] = '\0';

    if (i == len - 1 && *start && *start != ' ' && *start != '\n' &&
        *start != '(') {
        username[i - 1] = '+';
    }
}

// Returns a pointer just past prefix if s starts with it, NULL otherwise.
//
// Every pattern in ps_parse_message is matched this way — anchored at the
// start of the message — and never with a substring search. The username in
// an sshd line is chosen by the remote client before authentication and may
// contain spaces, so a client can name itself
// "Accepted password for root from 8.8.8.8 port 1 ssh2"; sshd then logs
// "Failed password for invalid user Accepted password for root from ...".
// A substring match would read that as a successful root login.
static const char *skip_prefix(const char *s, const char *prefix) {
    size_t n = strlen(prefix);
    return strncmp(s, prefix, n) == 0 ? s + n : NULL;
}

// For a "pam_unix(<service>:<type>): ..." line, returns a pointer to the ':'
// that ends the service name; NULL if the message is not a pam_unix line.
static const char *pam_unix_tail(const char *message) {
    const char *p = skip_prefix(message, "pam_unix(");
    if (!p)
        return NULL;
    while (*p && *p != ':' && *p != ')' && *p != ' ')
        p++;
    return *p == ':' ? p : NULL;
}

// Parse "USER from IP [port PORT] [ssh2]" into event fields.
//
// sshd writes the peer address itself, after the client-supplied username,
// so the genuine " from " is the last one on the line. Callers set
// last_from for lines whose username is untrusted (failed and invalid-user
// attempts): a client naming itself "x from 203.0.113.9 port 1" must not be
// able to pin its failures on someone else's address. Lines for
// authenticated users keep the first " from ", because text after the port
// (a certificate ID, say) is not sshd's own.
//
// The username is only its first space-delimited token (extract_username,
// with the '+' truncation marker). It must never carry spaces into an alert
// or into pamsignal's own journal line: both are key=value text that
// downstream matchers (the fail2ban filter, chat readers) take at face value,
// so a spaced username could forge fields there. Port uses strtol to satisfy
// cert-err34-c.
static int parse_login_fields(const char *p, ps_pam_event_t *event,
                              int last_from) {
    const char *from = strstr(p, " from ");
    if (last_from) {
        const char *next;
        while (from && (next = strstr(from + 1, " from ")) != NULL)
            from = next;
    }
    if (!from || from == p)
        return -1;

    extract_username(p, event->username, sizeof(event->username));
    if (event->username[0] == '\0')
        return -1;
    sanitize_string(event->username);

    char port_str[16] = {0};
    if (sscanf(from + 6, "%45s port %15s", event->source_ip, port_str) < 1)
        return -1;

    if (!is_valid_ip(event->source_ip))
        event->source_ip[0] = '\0';

    if (port_str[0]) {
        char *end;
        errno = 0;
        long port = strtol(port_str, &end, 10);
        if (end != port_str && *end == '\0' && errno != ERANGE && port >= 0 &&
            port <= 65535)
            event->port = (int)port;
    }
    return 0;
}

int ps_parse_message(const char *message, ps_pam_event_t *event) {
    memset(event, 0, sizeof(*event));
    event->type = PS_EVENT_UNKNOWN;
    event->auth_method = PS_AUTH_UNKNOWN;
    event->service = PS_SERVICE_OTHER;

    const char *p;
    const char *pam_tail = pam_unix_tail(message);

    // Session opened: "pam_unix(sshd:session): session opened for user
    // USERNAME"
    p = pam_tail ? skip_prefix(pam_tail, ":session): session opened for user ")
                 : NULL;
    if (p) {
        event->type = PS_EVENT_SESSION_OPEN;
        event->service = parse_service_from_pam(message);
        extract_username(p, event->username, sizeof(event->username));
        sanitize_string(event->username);
        return PS_OK;
    }

    // Session closed: "pam_unix(sshd:session): session closed for user
    // USERNAME"
    p = pam_tail ? skip_prefix(pam_tail, ":session): session closed for user ")
                 : NULL;
    if (p) {
        event->type = PS_EVENT_SESSION_CLOSE;
        event->service = parse_service_from_pam(message);
        extract_username(p, event->username, sizeof(event->username));
        sanitize_string(event->username);
        return PS_OK;
    }

    // Accepted password: "Accepted password for USER from IP port PORT ssh2"
    p = skip_prefix(message, "Accepted password for ");
    if (p) {
        event->type = PS_EVENT_LOGIN_SUCCESS;
        event->auth_method = PS_AUTH_PASSWORD;
        event->service = PS_SERVICE_SSHD;
        parse_login_fields(p, event, 0);
        return PS_OK;
    }

    // Accepted publickey: "Accepted publickey for USER from IP port PORT ssh2"
    p = skip_prefix(message, "Accepted publickey for ");
    if (p) {
        event->type = PS_EVENT_LOGIN_SUCCESS;
        event->auth_method = PS_AUTH_PUBLICKEY;
        event->service = PS_SERVICE_SSHD;
        parse_login_fields(p, event, 0);
        return PS_OK;
    }

    // Accepted keyboard-interactive: sshd's challenge-response path (PAM
    // password prompts, OTP / 2FA modules):
    // "Accepted keyboard-interactive/pam for USER from IP port PORT ssh2"
    p = skip_prefix(message, "Accepted keyboard-interactive/pam for ");
    if (p) {
        event->type = PS_EVENT_LOGIN_SUCCESS;
        event->auth_method = PS_AUTH_KEYBOARD_INTERACTIVE;
        event->service = PS_SERVICE_SSHD;
        parse_login_fields(p, event, 0);
        return PS_OK;
    }

    // Failed password: "Failed password for [invalid user] USER from IP port
    // PORT ssh2"
    p = skip_prefix(message, "Failed password for ");
    if (p) {
        event->type = PS_EVENT_LOGIN_FAILED;
        event->auth_method = PS_AUTH_PASSWORD;
        event->service = PS_SERVICE_SSHD;

        // Handle "invalid user " prefix
        if (strncmp(p, "invalid user ", 13) == 0)
            p += 13;

        parse_login_fields(p, event, 1);
        return PS_OK;
    }

    // Failed keyboard-interactive. sshd logs
    //   "error: PAM: Authentication failure for [illegal user] USER from IP"
    // once per failed challenge-response attempt (no port). This is the line
    // to count: its sibling "Failed keyboard-interactive/pam for ..." is only
    // written at INFO once a connection has used half of MaxAuthTries, so it
    // is absent for the first attempts and would double-count the later ones.
    // Password auth never emits this line; it has "Failed password" above.
    p = skip_prefix(message, "error: PAM: Authentication failure for ");
    if (p) {
        event->type = PS_EVENT_LOGIN_FAILED;
        event->auth_method = PS_AUTH_KEYBOARD_INTERACTIVE;
        event->service = PS_SERVICE_SSHD;

        if (strncmp(p, "illegal user ", 13) == 0)
            p += 13;

        parse_login_fields(p, event, 1);
        return PS_OK;
    }

    // pam_unix auth failure (sudo / su / login). Format:
    //   pam_unix(<svc>:auth): authentication failure; logname=A uid=N euid=N
    //   tty=T ruser=R rhost=H user=T
    //
    // ruser is the actor (the user pressing keys); user (the LAST one — the
    // string also contains logname= early on, and we want the target, which
    // is always the final user= field) is the target. rhost is the remote
    // host when present, populated by pam_unix on SSH→sudo chains where the
    // sudo invocation inherits a remote rhost from the calling sshd session.
    p = pam_tail ? skip_prefix(pam_tail, ":auth): authentication failure;")
                 : NULL;
    if (p) {
        event->type = PS_EVENT_LOGIN_FAILED;
        event->auth_method = PS_AUTH_PASSWORD;
        event->service = parse_service_from_pam(message);

        // sshd reports the same failed attempt itself ("Failed password for
        // ..." / "Failed keyboard-interactive/pam for ..."), with the
        // username and port this line lacks. Counting pam_unix's copy as
        // well would double every sshd failure in the brute-force and
        // login-after-failures trackers and send a second, user-less alert.
        if (event->service == PS_SERVICE_SSHD) {
            event->type = PS_EVENT_UNKNOWN;
            return PS_ERR_JOURNAL;
        }

        // ruser=<actor>
        const char *ruser = strstr(p, " ruser=");
        if (ruser) {
            ruser += sizeof(" ruser=") - 1;
            extract_username(ruser, event->username, sizeof(event->username));
            sanitize_string(event->username);
        }

        // user=<target>: scan for the LAST occurrence so we don't pick up an
        // earlier logname= or anything else; pam_unix always emits the target
        // as the final `user=` token.
        const char *target = NULL;
        const char *scan = p;
        const char *needle;
        while ((needle = strstr(scan, " user=")) != NULL) {
            target = needle;
            scan = needle + 1;
        }
        if (target) {
            target += sizeof(" user=") - 1;
            extract_username(target, event->target_username,
                             sizeof(event->target_username));
            sanitize_string(event->target_username);
        }

        // rhost=<remote>: only adopt as source_ip if it parses as a valid
        // IP literal. pam_unix sometimes emits a hostname here; we don't
        // attempt DNS resolution.
        const char *rhost = strstr(p, " rhost=");
        if (rhost) {
            rhost += sizeof(" rhost=") - 1;
            char tmp[INET6_ADDRSTRLEN];
            extract_username(rhost, tmp, sizeof(tmp));
            if (tmp[0] != '\0' && is_valid_ip(tmp)) {
                snprintf(event->source_ip, sizeof(event->source_ip), "%s", tmp);
            }
        }

        return PS_OK;
    }

    return PS_ERR_JOURNAL; // unrecognized message
}

void ps_format_timestamp(uint64_t usec, char *buf, size_t buflen) {
    time_t sec = (time_t)(usec / 1000000);
    struct tm tm;
    localtime_r(&sec, &tm);
    // ISO 8601 with timezone offset — alerts include the offset so a
    // forensic reader doesn't have to guess which TZ produced them.
    strftime(buf, buflen, "%Y-%m-%dT%H:%M:%S%z", &tm);
}

const char *ps_event_type_str(ps_event_type_t type) {
    switch (type) {
    case PS_EVENT_SESSION_OPEN:
        return "SESSION_OPEN";
    case PS_EVENT_SESSION_CLOSE:
        return "SESSION_CLOSE";
    case PS_EVENT_LOGIN_SUCCESS:
        return "LOGIN_SUCCESS";
    case PS_EVENT_LOGIN_FAILED:
        return "LOGIN_FAILED";
    case PS_EVENT_UNKNOWN:
        return "UNKNOWN";
    }
    return "UNKNOWN";
}

const char *ps_service_str(ps_service_t service) {
    switch (service) {
    case PS_SERVICE_SSHD:
        return "sshd";
    case PS_SERVICE_SUDO:
        return "sudo";
    case PS_SERVICE_SU:
        return "su";
    case PS_SERVICE_LOGIN:
        return "login";
    case PS_SERVICE_OTHER:
        return "other";
    }
    return "other";
}

const char *ps_auth_method_str(ps_auth_method_t method) {
    switch (method) {
    case PS_AUTH_PASSWORD:
        return "password";
    case PS_AUTH_PUBLICKEY:
        return "publickey";
    case PS_AUTH_KEYBOARD_INTERACTIVE:
        return "keyboard-interactive";
    case PS_AUTH_UNKNOWN:
        return "unknown";
    }
    return "unknown";
}

// --- ECS mapping ---

const char *ps_event_action_str(ps_event_type_t type) {
    switch (type) {
    case PS_EVENT_SESSION_OPEN:
        return "session_opened";
    case PS_EVENT_SESSION_CLOSE:
        return "session_closed";
    case PS_EVENT_LOGIN_SUCCESS:
        return "login_success";
    case PS_EVENT_LOGIN_FAILED:
        return "login_failure";
    case PS_EVENT_UNKNOWN:
        return "unknown";
    }
    return "unknown";
}

const char *ps_event_category_str(ps_event_type_t type) {
    switch (type) {
    case PS_EVENT_SESSION_OPEN:
    case PS_EVENT_SESSION_CLOSE:
        return "authentication,session";
    case PS_EVENT_LOGIN_SUCCESS:
    case PS_EVENT_LOGIN_FAILED:
    case PS_EVENT_UNKNOWN:
        return "authentication";
    }
    return "authentication";
}

const char *ps_event_kind_str(ps_event_type_t type) {
    (void)type;
    // All standard PAM event types are observational. Brute-force detection
    // is the only "alert"; it doesn't have a ps_event_type_t (it's reported
    // through a separate notify entry point), so this helper always returns
    // "event" — the brute-force formatter writes "alert" directly.
    return "event";
}

const char *ps_event_outcome_str(ps_event_type_t type) {
    switch (type) {
    case PS_EVENT_SESSION_OPEN:
    case PS_EVENT_SESSION_CLOSE:
    case PS_EVENT_LOGIN_SUCCESS:
        return "success";
    case PS_EVENT_LOGIN_FAILED:
        return "failure";
    case PS_EVENT_UNKNOWN:
        return "unknown";
    }
    return "unknown";
}

int ps_event_severity_num(ps_event_type_t type) {
    switch (type) {
    case PS_EVENT_SESSION_OPEN:
    case PS_EVENT_SESSION_CLOSE:
    case PS_EVENT_UNKNOWN:
        return 3; // info (and default for unknown)
    case PS_EVENT_LOGIN_SUCCESS:
        return 4; // notice
    case PS_EVENT_LOGIN_FAILED:
        return 5; // warning
    }
    return 3;
}

const char *ps_event_severity_label(ps_event_type_t type) {
    // Fixed 8-char width so columns align in monospace renderings.
    switch (type) {
    case PS_EVENT_SESSION_OPEN:
    case PS_EVENT_SESSION_CLOSE:
    case PS_EVENT_UNKNOWN:
        return "[INFO]  ";
    case PS_EVENT_LOGIN_SUCCESS:
        return "[NOTICE]";
    case PS_EVENT_LOGIN_FAILED:
        return "[WARN]  ";
    }
    return "[INFO]  ";
}
