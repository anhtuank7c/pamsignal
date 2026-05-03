#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <cmocka.h>

#include "init.h"
#include "pam_event.h"
#include "utils.h"

// --- ps_field_value ---

static void test_field_value_basic(void **state) {
    (void)state;
    const char *data = "MESSAGE=hello world";
    const char *val = ps_field_value(data, strlen(data));
    assert_non_null(val);
    assert_string_equal(val, "hello world");
}

static void test_field_value_empty(void **state) {
    (void)state;
    const char *data = "KEY=";
    const char *val = ps_field_value(data, strlen(data));
    assert_non_null(val);
    assert_string_equal(val, "");
}

static void test_field_value_no_equals(void **state) {
    (void)state;
    const char *data = "no equals here";
    const char *val = ps_field_value(data, strlen(data));
    assert_null(val);
}

static void test_field_value_multiple_equals(void **state) {
    (void)state;
    const char *data = "KEY=val=ue";
    const char *val = ps_field_value(data, strlen(data));
    assert_non_null(val);
    assert_string_equal(val, "val=ue");
}

// --- ps_parse_message: session events ---

static void test_parse_session_open_sshd(void **state) {
    (void)state;
    ps_pam_event_t event;
    int ret = ps_parse_message(
        "pam_unix(sshd:session): session opened for user root", &event);
    assert_int_equal(ret, PS_OK);
    assert_int_equal(event.type, PS_EVENT_SESSION_OPEN);
    assert_int_equal(event.service, PS_SERVICE_SSHD);
    assert_string_equal(event.username, "root");
}

static void test_parse_session_open_sudo(void **state) {
    (void)state;
    ps_pam_event_t event;
    int ret = ps_parse_message(
        "pam_unix(sudo:session): session opened for user root by admin(uid=0)",
        &event);
    assert_int_equal(ret, PS_OK);
    assert_int_equal(event.type, PS_EVENT_SESSION_OPEN);
    assert_int_equal(event.service, PS_SERVICE_SUDO);
    assert_string_equal(event.username, "root");
}

static void test_parse_session_open_su(void **state) {
    (void)state;
    ps_pam_event_t event;
    int ret = ps_parse_message(
        "pam_unix(su:session): session opened for user www-data", &event);
    assert_int_equal(ret, PS_OK);
    assert_int_equal(event.type, PS_EVENT_SESSION_OPEN);
    assert_int_equal(event.service, PS_SERVICE_SU);
    assert_string_equal(event.username, "www-data");
}

static void test_parse_session_open_login(void **state) {
    (void)state;
    ps_pam_event_t event;
    int ret = ps_parse_message(
        "pam_unix(login:session): session opened for user tty1user", &event);
    assert_int_equal(ret, PS_OK);
    assert_int_equal(event.type, PS_EVENT_SESSION_OPEN);
    assert_int_equal(event.service, PS_SERVICE_LOGIN);
    assert_string_equal(event.username, "tty1user");
}

static void test_parse_session_close(void **state) {
    (void)state;
    ps_pam_event_t event;
    int ret = ps_parse_message(
        "pam_unix(sshd:session): session closed for user admin", &event);
    assert_int_equal(ret, PS_OK);
    assert_int_equal(event.type, PS_EVENT_SESSION_CLOSE);
    assert_int_equal(event.service, PS_SERVICE_SSHD);
    assert_string_equal(event.username, "admin");
}

static void test_parse_session_open_uid_suffix(void **state) {
    (void)state;
    ps_pam_event_t event;
    int ret = ps_parse_message(
        "pam_unix(sshd:session): session opened for user root(uid=0)", &event);
    assert_int_equal(ret, PS_OK);
    assert_int_equal(event.type, PS_EVENT_SESSION_OPEN);
    assert_string_equal(event.username, "root");
}

// --- ps_parse_message: login success ---

static void test_parse_accepted_password(void **state) {
    (void)state;
    ps_pam_event_t event;
    int ret = ps_parse_message(
        "Accepted password for admin from 192.168.1.100 port 52341 ssh2",
        &event);
    assert_int_equal(ret, PS_OK);
    assert_int_equal(event.type, PS_EVENT_LOGIN_SUCCESS);
    assert_int_equal(event.auth_method, PS_AUTH_PASSWORD);
    assert_int_equal(event.service, PS_SERVICE_SSHD);
    assert_string_equal(event.username, "admin");
    assert_string_equal(event.source_ip, "192.168.1.100");
    assert_int_equal(event.port, 52341);
}

static void test_parse_accepted_publickey(void **state) {
    (void)state;
    ps_pam_event_t event;
    int ret = ps_parse_message(
        "Accepted publickey for deploy from 10.0.0.5 port 22 ssh2", &event);
    assert_int_equal(ret, PS_OK);
    assert_int_equal(event.type, PS_EVENT_LOGIN_SUCCESS);
    assert_int_equal(event.auth_method, PS_AUTH_PUBLICKEY);
    assert_string_equal(event.username, "deploy");
    assert_string_equal(event.source_ip, "10.0.0.5");
    assert_int_equal(event.port, 22);
}

static void test_parse_accepted_password_ipv6(void **state) {
    (void)state;
    ps_pam_event_t event;
    int ret = ps_parse_message(
        "Accepted password for user1 from ::1 port 443 ssh2", &event);
    assert_int_equal(ret, PS_OK);
    assert_int_equal(event.type, PS_EVENT_LOGIN_SUCCESS);
    assert_string_equal(event.username, "user1");
    assert_string_equal(event.source_ip, "::1");
    assert_int_equal(event.port, 443);
}

static void test_parse_accepted_publickey_ipv6_full(void **state) {
    (void)state;
    ps_pam_event_t event;
    int ret = ps_parse_message(
        "Accepted publickey for admin from 2001:db8::1 port 8022 ssh2", &event);
    assert_int_equal(ret, PS_OK);
    assert_string_equal(event.source_ip, "2001:db8::1");
}

// --- ps_parse_message: login failed ---

static void test_parse_failed_password(void **state) {
    (void)state;
    ps_pam_event_t event;
    int ret = ps_parse_message(
        "Failed password for root from 203.0.113.50 port 39182 ssh2", &event);
    assert_int_equal(ret, PS_OK);
    assert_int_equal(event.type, PS_EVENT_LOGIN_FAILED);
    assert_int_equal(event.auth_method, PS_AUTH_PASSWORD);
    assert_string_equal(event.username, "root");
    assert_string_equal(event.source_ip, "203.0.113.50");
    assert_int_equal(event.port, 39182);
}

static void test_parse_failed_password_invalid_user(void **state) {
    (void)state;
    ps_pam_event_t event;
    int ret = ps_parse_message(
        "Failed password for invalid user hacker from 198.51.100.1 port 12345 "
        "ssh2",
        &event);
    assert_int_equal(ret, PS_OK);
    assert_int_equal(event.type, PS_EVENT_LOGIN_FAILED);
    assert_string_equal(event.username, "hacker");
    assert_string_equal(event.source_ip, "198.51.100.1");
    assert_int_equal(event.port, 12345);
}

static void test_parse_failed_password_ipv6(void **state) {
    (void)state;
    ps_pam_event_t event;
    int ret = ps_parse_message(
        "Failed password for root from fe80::1 port 22 ssh2", &event);
    assert_int_equal(ret, PS_OK);
    assert_int_equal(event.type, PS_EVENT_LOGIN_FAILED);
    assert_string_equal(event.source_ip, "fe80::1");
}

// --- ps_parse_message: pam_unix auth failure (sudo / su) ---

static void test_parse_sudo_auth_failure_local(void **state) {
    (void)state;
    ps_pam_event_t event;
    // Pure local sudo: rhost is empty (the double-space between the equals
    // sign and the next field is what pam_unix actually emits).
    int ret = ps_parse_message(
        "pam_unix(sudo:auth): authentication failure; logname=alice "
        "uid=1000 euid=0 tty=/dev/pts/0 ruser=alice rhost=  user=root",
        &event);
    assert_int_equal(ret, PS_OK);
    assert_int_equal(event.type, PS_EVENT_LOGIN_FAILED);
    assert_int_equal(event.service, PS_SERVICE_SUDO);
    assert_int_equal(event.auth_method, PS_AUTH_PASSWORD);
    assert_string_equal(event.username, "alice");
    assert_string_equal(event.target_username, "root");
    assert_string_equal(event.source_ip, "");
}

static void test_parse_sudo_auth_failure_with_rhost_ip(void **state) {
    (void)state;
    ps_pam_event_t event;
    // SSH→sudo chain: pam_unix carries the SSH-client IP into rhost.
    int ret = ps_parse_message(
        "pam_unix(sudo:auth): authentication failure; logname=alice "
        "uid=1000 euid=0 tty=/dev/pts/0 ruser=alice rhost=192.0.2.5 user=root",
        &event);
    assert_int_equal(ret, PS_OK);
    assert_int_equal(event.type, PS_EVENT_LOGIN_FAILED);
    assert_int_equal(event.service, PS_SERVICE_SUDO);
    assert_string_equal(event.username, "alice");
    assert_string_equal(event.target_username, "root");
    assert_string_equal(event.source_ip, "192.0.2.5");
}

static void test_parse_sudo_auth_failure_rhost_hostname_dropped(void **state) {
    (void)state;
    ps_pam_event_t event;
    // rhost can be a hostname instead of an IP — we don't resolve, so
    // source_ip must stay empty rather than carry an unparsed string into
    // downstream IP-based fields.
    int ret = ps_parse_message(
        "pam_unix(sudo:auth): authentication failure; logname=alice "
        "ruser=alice rhost=client.example.com user=root",
        &event);
    assert_int_equal(ret, PS_OK);
    assert_string_equal(event.source_ip, "");
}

static void test_parse_su_auth_failure(void **state) {
    (void)state;
    ps_pam_event_t event;
    int ret = ps_parse_message(
        "pam_unix(su:auth): authentication failure; logname=alice "
        "uid=1000 euid=0 tty=pts/0 ruser=alice rhost=  user=postgres",
        &event);
    assert_int_equal(ret, PS_OK);
    assert_int_equal(event.type, PS_EVENT_LOGIN_FAILED);
    assert_int_equal(event.service, PS_SERVICE_SU);
    assert_string_equal(event.username, "alice");
    assert_string_equal(event.target_username, "postgres");
}

static void test_parse_auth_failure_target_is_last_user(void **state) {
    (void)state;
    ps_pam_event_t event;
    // The string contains an embedded "user=" inside an unusual logname
    // value before the canonical target. Our parser must pick the LAST
    // " user=" token, not the first.
    int ret = ps_parse_message(
        "pam_unix(sudo:auth): authentication failure; logname=miguser "
        "ruser=miguser rhost=  user=root",
        &event);
    assert_int_equal(ret, PS_OK);
    assert_string_equal(event.username, "miguser");
    assert_string_equal(event.target_username, "root");
}

static void test_parse_auth_failure_username_with_hyphen(void **state) {
    (void)state;
    ps_pam_event_t event;
    int ret = ps_parse_message(
        "pam_unix(sudo:auth): authentication failure; logname=svc-deploy "
        "ruser=svc-deploy rhost=  user=www-data",
        &event);
    assert_int_equal(ret, PS_OK);
    assert_string_equal(event.username, "svc-deploy");
    assert_string_equal(event.target_username, "www-data");
}

// --- ps_parse_message: edge cases ---

static void test_parse_unrecognized_message(void **state) {
    (void)state;
    ps_pam_event_t event;
    int ret = ps_parse_message("some random log message", &event);
    assert_int_equal(ret, PS_ERR_JOURNAL);
    assert_int_equal(event.type, PS_EVENT_UNKNOWN);
}

static void test_parse_empty_message(void **state) {
    (void)state;
    ps_pam_event_t event;
    int ret = ps_parse_message("", &event);
    assert_int_equal(ret, PS_ERR_JOURNAL);
    assert_int_equal(event.type, PS_EVENT_UNKNOWN);
}

static void test_parse_invalid_ip_cleared(void **state) {
    (void)state;
    ps_pam_event_t event;
    int ret = ps_parse_message(
        "Accepted password for user1 from not-an-ip port 22 ssh2", &event);
    assert_int_equal(ret, PS_OK);
    assert_int_equal(event.type, PS_EVENT_LOGIN_SUCCESS);
    assert_string_equal(event.username, "user1");
    assert_string_equal(event.source_ip, "");
}

static void test_parse_long_username_truncated(void **state) {
    (void)state;
    ps_pam_event_t event;
    // Build a message with a 100-char username (field is 64 bytes)
    char msg[512];
    char long_user[101];
    memset(long_user, 'a', 100);
    long_user[100] = '\0';
    snprintf(msg, sizeof(msg),
             "Accepted password for %s from 10.0.0.1 port 22 ssh2", long_user);

    int ret = ps_parse_message(msg, &event);
    assert_int_equal(ret, PS_OK);
    assert_int_equal(strlen(event.username), 63);
    // Truncation marker: the last byte is replaced with '+' so two distinct
    // long usernames cannot silently alias to the same prefix in alerts.
    assert_int_equal(event.username[62], '+');
}

static void test_parse_username_at_boundary_no_marker(void **state) {
    (void)state;
    ps_pam_event_t event;
    // Username exactly fills the buffer to len-1 with the natural delimiter
    // following — should NOT receive the truncation marker.
    char msg[512];
    char user63[64];
    memset(user63, 'b', 63);
    user63[63] = '\0';
    snprintf(msg, sizeof(msg),
             "Accepted password for %s from 10.0.0.1 port 22 ssh2", user63);

    int ret = ps_parse_message(msg, &event);
    assert_int_equal(ret, PS_OK);
    assert_int_equal(strlen(event.username), 63);
    assert_int_equal(event.username[62], 'b');
}

static void test_parse_control_chars_sanitized(void **state) {
    (void)state;
    ps_pam_event_t event;
    // Username with control characters embedded
    int ret = ps_parse_message(
        "pam_unix(sshd:session): session opened for user te\x01st", &event);
    assert_int_equal(ret, PS_OK);
    // Control char should be replaced with '?'
    assert_string_equal(event.username, "te?st");
}

static void test_parse_event_zeroed(void **state) {
    (void)state;
    ps_pam_event_t event;
    memset(&event, 0xFF, sizeof(event));
    ps_parse_message("Accepted password for root from 1.2.3.4 port 22 ssh2",
                     &event);
    // Fields not set by this message should be zeroed
    assert_int_equal(event.pid, 0);
    assert_int_equal(event.uid, 0);
    assert_string_equal(event.hostname, "");
}

static void test_parse_invalid_port_ignored(void **state) {
    (void)state;
    ps_pam_event_t event;
    int ret = ps_parse_message(
        "Accepted password for root from 1.2.3.4 port notanum ssh2", &event);
    assert_int_equal(ret, PS_OK);
    assert_int_equal(event.type, PS_EVENT_LOGIN_SUCCESS);
    assert_string_equal(event.username, "root");
    assert_int_equal(event.port, 0); // invalid port, stays at default
}

static void test_parse_port_out_of_range(void **state) {
    (void)state;
    ps_pam_event_t event;
    int ret = ps_parse_message(
        "Accepted password for root from 1.2.3.4 port 99999 ssh2", &event);
    assert_int_equal(ret, PS_OK);
    assert_int_equal(event.port, 0); // out of range, stays at default
}

// --- ps_format_timestamp ---

static void test_format_timestamp(void **state) {
    (void)state;
    char buf[32];
    // 2024-01-01 00:00:00 UTC = 1704067200 seconds
    ps_format_timestamp(1704067200ULL * 1000000, buf, sizeof(buf));
    // ISO 8601 with timezone offset: "YYYY-MM-DDTHH:MM:SS+HHMM" = 24 chars,
    // or "...HHMMSS-HHMM" depending on TZ sign.
    assert_int_equal(strlen(buf), 24);
    assert_int_equal(buf[4], '-');
    assert_int_equal(buf[7], '-');
    assert_int_equal(buf[10], 'T');
    assert_int_equal(buf[13], ':');
    assert_int_equal(buf[16], ':');
    // Position 19 is '+' or '-' (the timezone sign).
    assert_true(buf[19] == '+' || buf[19] == '-');
}

// --- ps_event_type_str ---

static void test_event_type_str(void **state) {
    (void)state;
    assert_string_equal(ps_event_type_str(PS_EVENT_SESSION_OPEN),
                        "SESSION_OPEN");
    assert_string_equal(ps_event_type_str(PS_EVENT_SESSION_CLOSE),
                        "SESSION_CLOSE");
    assert_string_equal(ps_event_type_str(PS_EVENT_LOGIN_SUCCESS),
                        "LOGIN_SUCCESS");
    assert_string_equal(ps_event_type_str(PS_EVENT_LOGIN_FAILED),
                        "LOGIN_FAILED");
    assert_string_equal(ps_event_type_str(PS_EVENT_UNKNOWN), "UNKNOWN");
}

// --- ps_service_str ---

static void test_service_str(void **state) {
    (void)state;
    assert_string_equal(ps_service_str(PS_SERVICE_SSHD), "sshd");
    assert_string_equal(ps_service_str(PS_SERVICE_SUDO), "sudo");
    assert_string_equal(ps_service_str(PS_SERVICE_SU), "su");
    assert_string_equal(ps_service_str(PS_SERVICE_LOGIN), "login");
    assert_string_equal(ps_service_str(PS_SERVICE_OTHER), "other");
}

// --- ps_auth_method_str ---

static void test_auth_method_str(void **state) {
    (void)state;
    assert_string_equal(ps_auth_method_str(PS_AUTH_PASSWORD), "password");
    assert_string_equal(ps_auth_method_str(PS_AUTH_PUBLICKEY), "publickey");
    assert_string_equal(ps_auth_method_str(PS_AUTH_UNKNOWN), "unknown");
}

// --- ECS mapping helpers ---

static void test_event_action_str(void **state) {
    (void)state;
    assert_string_equal(ps_event_action_str(PS_EVENT_SESSION_OPEN),
                        "session_opened");
    assert_string_equal(ps_event_action_str(PS_EVENT_SESSION_CLOSE),
                        "session_closed");
    assert_string_equal(ps_event_action_str(PS_EVENT_LOGIN_SUCCESS),
                        "login_success");
    assert_string_equal(ps_event_action_str(PS_EVENT_LOGIN_FAILED),
                        "login_failure");
}

static void test_event_category_str(void **state) {
    (void)state;
    assert_string_equal(ps_event_category_str(PS_EVENT_SESSION_OPEN),
                        "authentication,session");
    assert_string_equal(ps_event_category_str(PS_EVENT_LOGIN_FAILED),
                        "authentication");
}

static void test_event_outcome_str(void **state) {
    (void)state;
    assert_string_equal(ps_event_outcome_str(PS_EVENT_SESSION_OPEN), "success");
    assert_string_equal(ps_event_outcome_str(PS_EVENT_LOGIN_SUCCESS),
                        "success");
    assert_string_equal(ps_event_outcome_str(PS_EVENT_LOGIN_FAILED), "failure");
    assert_string_equal(ps_event_outcome_str(PS_EVENT_UNKNOWN), "unknown");
}

static void test_event_severity_num(void **state) {
    (void)state;
    assert_int_equal(ps_event_severity_num(PS_EVENT_SESSION_OPEN), 3);
    assert_int_equal(ps_event_severity_num(PS_EVENT_SESSION_CLOSE), 3);
    assert_int_equal(ps_event_severity_num(PS_EVENT_LOGIN_SUCCESS), 4);
    assert_int_equal(ps_event_severity_num(PS_EVENT_LOGIN_FAILED), 5);
}

static void test_event_severity_label_fixed_width(void **state) {
    (void)state;
    // All labels must be exactly 8 chars so columns align in monospace.
    assert_int_equal(strlen(ps_event_severity_label(PS_EVENT_SESSION_OPEN)), 8);
    assert_int_equal(strlen(ps_event_severity_label(PS_EVENT_LOGIN_SUCCESS)),
                     8);
    assert_int_equal(strlen(ps_event_severity_label(PS_EVENT_LOGIN_FAILED)), 8);
    assert_string_equal(ps_event_severity_label(PS_EVENT_LOGIN_SUCCESS),
                        "[NOTICE]");
    assert_string_equal(ps_event_severity_label(PS_EVENT_LOGIN_FAILED),
                        "[WARN]  ");
}

static void test_event_kind_str(void **state) {
    (void)state;
    // All ps_event_type_t values map to "event" — brute-force is the only
    // "alert" but it doesn't have a ps_event_type_t value.
    assert_string_equal(ps_event_kind_str(PS_EVENT_SESSION_OPEN), "event");
    assert_string_equal(ps_event_kind_str(PS_EVENT_LOGIN_FAILED), "event");
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // ps_field_value
        cmocka_unit_test(test_field_value_basic),
        cmocka_unit_test(test_field_value_empty),
        cmocka_unit_test(test_field_value_no_equals),
        cmocka_unit_test(test_field_value_multiple_equals),

        // ps_parse_message: session events
        cmocka_unit_test(test_parse_session_open_sshd),
        cmocka_unit_test(test_parse_session_open_sudo),
        cmocka_unit_test(test_parse_session_open_su),
        cmocka_unit_test(test_parse_session_open_login),
        cmocka_unit_test(test_parse_session_close),
        cmocka_unit_test(test_parse_session_open_uid_suffix),

        // ps_parse_message: login success
        cmocka_unit_test(test_parse_accepted_password),
        cmocka_unit_test(test_parse_accepted_publickey),
        cmocka_unit_test(test_parse_accepted_password_ipv6),
        cmocka_unit_test(test_parse_accepted_publickey_ipv6_full),

        // ps_parse_message: login failed
        cmocka_unit_test(test_parse_failed_password),
        cmocka_unit_test(test_parse_failed_password_invalid_user),
        cmocka_unit_test(test_parse_failed_password_ipv6),
        cmocka_unit_test(test_parse_sudo_auth_failure_local),
        cmocka_unit_test(test_parse_sudo_auth_failure_with_rhost_ip),
        cmocka_unit_test(test_parse_sudo_auth_failure_rhost_hostname_dropped),
        cmocka_unit_test(test_parse_su_auth_failure),
        cmocka_unit_test(test_parse_auth_failure_target_is_last_user),
        cmocka_unit_test(test_parse_auth_failure_username_with_hyphen),

        // ps_parse_message: edge cases
        cmocka_unit_test(test_parse_unrecognized_message),
        cmocka_unit_test(test_parse_empty_message),
        cmocka_unit_test(test_parse_invalid_ip_cleared),
        cmocka_unit_test(test_parse_long_username_truncated),
        cmocka_unit_test(test_parse_username_at_boundary_no_marker),
        cmocka_unit_test(test_parse_control_chars_sanitized),
        cmocka_unit_test(test_parse_event_zeroed),
        cmocka_unit_test(test_parse_invalid_port_ignored),
        cmocka_unit_test(test_parse_port_out_of_range),

        // ps_format_timestamp
        cmocka_unit_test(test_format_timestamp),

        // enum to string
        cmocka_unit_test(test_event_type_str),
        cmocka_unit_test(test_service_str),
        cmocka_unit_test(test_auth_method_str),

        // ECS mapping helpers
        cmocka_unit_test(test_event_action_str),
        cmocka_unit_test(test_event_category_str),
        cmocka_unit_test(test_event_outcome_str),
        cmocka_unit_test(test_event_severity_num),
        cmocka_unit_test(test_event_severity_label_fixed_width),
        cmocka_unit_test(test_event_kind_str),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
