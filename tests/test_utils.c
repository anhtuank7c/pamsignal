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

// --- ps_format_timestamp ---

static void test_format_timestamp(void **state) {
    (void)state;
    char buf[32];
    // 2024-01-01 00:00:00 UTC = 1704067200 seconds
    ps_format_timestamp(1704067200ULL * 1000000, buf, sizeof(buf));
    // Just verify it produces a non-empty, correctly formatted string
    assert_int_equal(strlen(buf), 19); // "YYYY-MM-DD HH:MM:SS"
    assert_int_equal(buf[4], '-');
    assert_int_equal(buf[7], '-');
    assert_int_equal(buf[10], ' ');
    assert_int_equal(buf[13], ':');
    assert_int_equal(buf[16], ':');
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

        // ps_parse_message: edge cases
        cmocka_unit_test(test_parse_unrecognized_message),
        cmocka_unit_test(test_parse_empty_message),
        cmocka_unit_test(test_parse_invalid_ip_cleared),
        cmocka_unit_test(test_parse_long_username_truncated),
        cmocka_unit_test(test_parse_control_chars_sanitized),
        cmocka_unit_test(test_parse_event_zeroed),

        // ps_format_timestamp
        cmocka_unit_test(test_format_timestamp),

        // enum to string
        cmocka_unit_test(test_event_type_str),
        cmocka_unit_test(test_service_str),
        cmocka_unit_test(test_auth_method_str),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
