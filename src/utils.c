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
static void extract_username(const char *start, char *username, size_t len) {
    if (len == 0)
        return;
    size_t i = 0;
    while (*start && *start != ' ' && *start != '\n' && *start != '(' &&
           i < len - 1) {
        username[i++] = *start++;
    }
    username[i] = '\0';
}

// Parse "USER from IP port PORT [ssh2]" into event fields.
// Uses strtol for port to satisfy cert-err34-c (sscanf doesn't report
// conversion errors for integers).
static int parse_login_fields(const char *p, ps_pam_event_t *event) {
    char port_str[16] = {0};
    if (sscanf(p, "%63s from %45s port %15s", event->username, event->source_ip,
               port_str) < 2)
        return -1;

    sanitize_string(event->username);
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

    // Session opened: "pam_unix(sshd:session): session opened for user
    // USERNAME"
    p = strstr(message, "session opened for user ");
    if (p) {
        event->type = PS_EVENT_SESSION_OPEN;
        event->service = parse_service_from_pam(message);
        p += 24; // skip "session opened for user "
        extract_username(p, event->username, sizeof(event->username));
        sanitize_string(event->username);
        return PS_OK;
    }

    // Session closed: "pam_unix(sshd:session): session closed for user
    // USERNAME"
    p = strstr(message, "session closed for user ");
    if (p) {
        event->type = PS_EVENT_SESSION_CLOSE;
        event->service = parse_service_from_pam(message);
        p += 24; // skip "session closed for user "
        extract_username(p, event->username, sizeof(event->username));
        sanitize_string(event->username);
        return PS_OK;
    }

    // Accepted password: "Accepted password for USER from IP port PORT ssh2"
    p = strstr(message, "Accepted password for ");
    if (p) {
        event->type = PS_EVENT_LOGIN_SUCCESS;
        event->auth_method = PS_AUTH_PASSWORD;
        event->service = PS_SERVICE_SSHD;
        p += 22; // skip "Accepted password for "
        parse_login_fields(p, event);
        return PS_OK;
    }

    // Accepted publickey: "Accepted publickey for USER from IP port PORT ssh2"
    p = strstr(message, "Accepted publickey for ");
    if (p) {
        event->type = PS_EVENT_LOGIN_SUCCESS;
        event->auth_method = PS_AUTH_PUBLICKEY;
        event->service = PS_SERVICE_SSHD;
        p += 23; // skip "Accepted publickey for "
        parse_login_fields(p, event);
        return PS_OK;
    }

    // Failed password: "Failed password for [invalid user] USER from IP port
    // PORT ssh2"
    p = strstr(message, "Failed password for ");
    if (p) {
        event->type = PS_EVENT_LOGIN_FAILED;
        event->auth_method = PS_AUTH_PASSWORD;
        event->service = PS_SERVICE_SSHD;
        p += 20; // skip "Failed password for "

        // Handle "invalid user " prefix
        if (strncmp(p, "invalid user ", 13) == 0)
            p += 13;

        parse_login_fields(p, event);
        return PS_OK;
    }

    return PS_ERR_JOURNAL; // unrecognized message
}

void ps_format_timestamp(uint64_t usec, char *buf, size_t buflen) {
    time_t sec = (time_t)(usec / 1000000);
    struct tm tm;
    localtime_r(&sec, &tm);
    strftime(buf, buflen, "%Y-%m-%d %H:%M:%S", &tm);
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
    case PS_AUTH_UNKNOWN:
        return "unknown";
    }
    return "unknown";
}
