// Tests for notify.c formatting functions.
//
// We #include the source file directly so the suite can call file-static
// helpers (format_event_json, format_brute_json, format_local_brute_json,
// json_escape) without exposing them in the public header. The matching
// meson target must NOT also link src/notify.c — that would yield duplicate
// symbols.

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <cmocka.h>

// NOLINTNEXTLINE(bugprone-suspicious-include)
#include "../src/notify.c"

// --- Helpers ---

static void make_cfg_default(ps_config_t *cfg) {
    ps_config_defaults(cfg);
}

static void make_cfg_with_labels(ps_config_t *cfg, const char *provider,
                                 const char *service_name) {
    ps_config_defaults(cfg);
    if (provider)
        snprintf(cfg->provider, sizeof(cfg->provider), "%s", provider);
    if (service_name)
        snprintf(cfg->service_name, sizeof(cfg->service_name), "%s",
                 service_name);
}

static ps_pam_event_t make_login_failed(void) {
    ps_pam_event_t e;
    memset(&e, 0, sizeof(e));
    e.type = PS_EVENT_LOGIN_FAILED;
    e.auth_method = PS_AUTH_PASSWORD;
    e.service = PS_SERVICE_SSHD;
    strncpy(e.username, "alice", sizeof(e.username) - 1);
    strncpy(e.source_ip, "192.0.2.1", sizeof(e.source_ip) - 1);
    e.port = 22;
    e.pid = 1234;
    e.uid = 1000;
    strncpy(e.hostname, "webserver01", sizeof(e.hostname) - 1);
    e.timestamp_usec = 1700000000000000ULL;
    return e;
}

static ps_pam_event_t make_login_success(void) {
    ps_pam_event_t e = make_login_failed();
    e.type = PS_EVENT_LOGIN_SUCCESS;
    e.auth_method = PS_AUTH_PUBLICKEY;
    return e;
}

static ps_pam_event_t make_session_open(void) {
    ps_pam_event_t e;
    memset(&e, 0, sizeof(e));
    e.type = PS_EVENT_SESSION_OPEN;
    e.auth_method = PS_AUTH_PASSWORD;
    e.service = PS_SERVICE_SSHD;
    strncpy(e.username, "bob", sizeof(e.username) - 1);
    e.pid = 5678;
    e.uid = 1000;
    strncpy(e.hostname, "dbserver", sizeof(e.hostname) - 1);
    e.timestamp_usec = 1700000000000000ULL;
    return e;
}

// --- json_escape tests ---

static void test_json_escape_plain(void **state) {
    (void)state;
    char buf[64];
    json_escape("hello", buf, sizeof(buf));
    assert_string_equal(buf, "hello");
}

static void test_json_escape_quotes(void **state) {
    (void)state;
    char buf[64];
    json_escape("say \"hi\"", buf, sizeof(buf));
    assert_string_equal(buf, "say \\\"hi\\\"");
}

static void test_json_escape_backslash(void **state) {
    (void)state;
    char buf[64];
    json_escape("a\\b", buf, sizeof(buf));
    assert_string_equal(buf, "a\\\\b");
}

static void test_json_escape_control_chars(void **state) {
    (void)state;
    char buf[64];
    json_escape("\n\t\r", buf, sizeof(buf));
    assert_string_equal(buf, "\\n\\t\\r");
}

static void test_json_escape_low_control(void **state) {
    (void)state;
    char buf[64];
    // 0x01 should become \u0001
    json_escape("\x01", buf, sizeof(buf));
    assert_string_equal(buf, "\\u0001");
}

static void test_json_escape_empty(void **state) {
    (void)state;
    char buf[64];
    json_escape("", buf, sizeof(buf));
    assert_string_equal(buf, "");
}

static void test_json_escape_truncation(void **state) {
    (void)state;
    // Buffer too small — should not overflow and must null-terminate.
    // With dst_len=4, the loop condition (j + 6 < dst_len) is false from the
    // start for any character that might need 6-byte escape, so output is
    // empty (j stays at 0, dst[0] = '\0').
    char buf[4] = {0x7f, 0x7f, 0x7f, 0x7f};
    json_escape("abcdef", buf, sizeof(buf));
    // Must have a NUL within the buffer
    assert_non_null(memchr(buf, '\0', sizeof(buf)));
    assert_true(strlen(buf) < sizeof(buf));
    // No orphan backslash at truncation point
    size_t len = strlen(buf);
    if (len > 0)
        assert_int_not_equal(buf[len - 1], '\\');
}

// --- format_event_json tests ---

static void test_format_event_json_login_failed(void **state) {
    (void)state;
    ps_config_t cfg;
    make_cfg_default(&cfg);
    ps_pam_event_t e = make_login_failed();

    char buf[2048];
    format_event_json(&cfg, &e, buf, sizeof(buf));

    // Verify key ECS fields
    assert_non_null(strstr(buf, "\"event\":{\"action\":\"login_failure\""));
    assert_non_null(strstr(buf, "\"kind\":\"event\""));
    assert_non_null(strstr(buf, "\"outcome\":\"failure\""));
    assert_non_null(strstr(buf, "\"host\":{\"hostname\":\"webserver01\"}"));
    assert_non_null(strstr(buf, "\"user\":{\"name\":\"alice\"}"));
    assert_non_null(
        strstr(buf, "\"source\":{\"ip\":\"192.0.2.1\",\"port\":22}"));
    assert_non_null(strstr(buf, "\"process\":{\"pid\":1234"));
    assert_non_null(strstr(buf, "\"auth_method\":\"password\""));
    assert_non_null(strstr(buf, "\"event_type\":\"LOGIN_FAILED\""));
    assert_non_null(strstr(buf, "\"service\":{\"name\":\"sshd\"}"));
    assert_non_null(strstr(buf, "\"category\":[\"authentication\"]"));
    // No labels when provider/service_name empty
    assert_null(strstr(buf, "\"labels\""));
}

static void test_format_event_json_login_success(void **state) {
    (void)state;
    ps_config_t cfg;
    make_cfg_default(&cfg);
    ps_pam_event_t e = make_login_success();

    char buf[2048];
    format_event_json(&cfg, &e, buf, sizeof(buf));

    assert_non_null(strstr(buf, "\"action\":\"login_success\""));
    assert_non_null(strstr(buf, "\"outcome\":\"success\""));
    assert_non_null(strstr(buf, "\"auth_method\":\"publickey\""));
}

static void test_format_event_json_session_open(void **state) {
    (void)state;
    ps_config_t cfg;
    make_cfg_default(&cfg);
    ps_pam_event_t e = make_session_open();

    char buf[2048];
    format_event_json(&cfg, &e, buf, sizeof(buf));

    assert_non_null(strstr(buf, "\"action\":\"session_opened\""));
    assert_non_null(
        strstr(buf, "\"category\":[\"authentication\",\"session\"]"));
    assert_non_null(strstr(buf, "\"user\":{\"name\":\"bob\"}"));
    // Session events have no source.ip
    assert_null(strstr(buf, "\"source\""));
}

static void test_format_event_json_with_provider(void **state) {
    (void)state;
    ps_config_t cfg;
    make_cfg_with_labels(&cfg, "aws", NULL);
    ps_pam_event_t e = make_login_failed();

    char buf[2048];
    format_event_json(&cfg, &e, buf, sizeof(buf));

    assert_non_null(strstr(buf, "\"labels\":{\"provider\":\"aws\"}"));
}

static void test_format_event_json_with_service_name(void **state) {
    (void)state;
    ps_config_t cfg;
    make_cfg_with_labels(&cfg, NULL, "prod-api");
    ps_pam_event_t e = make_login_failed();

    char buf[2048];
    format_event_json(&cfg, &e, buf, sizeof(buf));

    assert_non_null(strstr(buf, "\"labels\":{\"service_name\":\"prod-api\"}"));
}

static void test_format_event_json_with_both_labels(void **state) {
    (void)state;
    ps_config_t cfg;
    make_cfg_with_labels(&cfg, "gcp", "staging");
    ps_pam_event_t e = make_login_failed();

    char buf[2048];
    format_event_json(&cfg, &e, buf, sizeof(buf));

    assert_non_null(strstr(
        buf, "\"labels\":{\"provider\":\"gcp\",\"service_name\":\"staging\"}"));
}

static void test_format_event_json_special_chars_username(void **state) {
    (void)state;
    ps_config_t cfg;
    make_cfg_default(&cfg);
    ps_pam_event_t e = make_login_failed();
    strncpy(e.username, "user\"evil", sizeof(e.username) - 1);

    char buf[2048];
    format_event_json(&cfg, &e, buf, sizeof(buf));

    // Quote should be escaped in JSON
    assert_non_null(strstr(buf, "user\\\"evil"));
}

static void test_format_event_json_ipv6(void **state) {
    (void)state;
    ps_config_t cfg;
    make_cfg_default(&cfg);
    ps_pam_event_t e = make_login_failed();
    strncpy(e.source_ip, "2001:db8::1", sizeof(e.source_ip) - 1);

    char buf[2048];
    format_event_json(&cfg, &e, buf, sizeof(buf));

    assert_non_null(strstr(buf, "\"ip\":\"2001:db8::1\""));
}

// --- format_brute_json tests ---

static void test_format_brute_json_basic(void **state) {
    (void)state;
    ps_config_t cfg;
    make_cfg_default(&cfg);

    char buf[2048];
    format_brute_json(&cfg, "10.0.0.1", 5, 300, "root", "myhost",
                      1700000000000000ULL, 9999, buf, sizeof(buf));

    assert_non_null(strstr(buf, "\"action\":\"brute_force_detected\""));
    assert_non_null(strstr(buf, "\"kind\":\"alert\""));
    assert_non_null(strstr(buf, "\"severity\":8"));
    assert_non_null(strstr(buf, "\"host\":{\"hostname\":\"myhost\"}"));
    assert_non_null(strstr(buf, "\"user\":{\"name\":\"root\"}"));
    assert_non_null(strstr(buf, "\"source\":{\"ip\":\"10.0.0.1\"}"));
    assert_non_null(strstr(buf, "\"attempts\":5"));
    assert_non_null(strstr(buf, "\"window_sec\":300"));
    assert_non_null(strstr(buf, "\"pid\":9999"));
    assert_non_null(strstr(buf, "\"event_type\":\"BRUTE_FORCE_DETECTED\""));
    assert_non_null(strstr(
        buf, "\"category\":[\"authentication\",\"intrusion_detection\"]"));
}

static void test_format_brute_json_with_labels(void **state) {
    (void)state;
    ps_config_t cfg;
    make_cfg_with_labels(&cfg, "hetzner", "web-cluster");

    char buf[2048];
    format_brute_json(&cfg, "10.0.0.1", 10, 60, "admin", "srv1",
                      1700000000000000ULL, 42, buf, sizeof(buf));

    assert_non_null(strstr(buf, "\"labels\":{\"provider\":\"hetzner\","
                                "\"service_name\":\"web-cluster\"}"));
}

static void test_format_brute_json_ipv6(void **state) {
    (void)state;
    ps_config_t cfg;
    make_cfg_default(&cfg);

    char buf[2048];
    format_brute_json(&cfg, "fe80::1", 3, 120, "user", "host",
                      1700000000000000ULL, 100, buf, sizeof(buf));

    assert_non_null(strstr(buf, "\"ip\":\"fe80::1\""));
}

// --- format_local_brute_json tests ---

static void test_format_local_brute_json_sudo(void **state) {
    (void)state;
    ps_config_t cfg;
    make_cfg_default(&cfg);

    char buf[2048];
    format_local_brute_json(&cfg, PS_SERVICE_SUDO, "bob", "root", 5, 300,
                            "devbox", 1700000000000000ULL, 7777, buf,
                            sizeof(buf));

    assert_non_null(strstr(buf, "\"action\":\"brute_force_detected\""));
    assert_non_null(strstr(buf, "\"kind\":\"alert\""));
    assert_non_null(strstr(
        buf, "\"user\":{\"name\":\"bob\",\"target\":{\"name\":\"root\"}}"));
    assert_non_null(strstr(buf, "\"service\":{\"name\":\"sudo\"}"));
    assert_non_null(strstr(buf, "\"host\":{\"hostname\":\"devbox\"}"));
    assert_non_null(strstr(buf, "\"attempts\":5"));
    assert_non_null(strstr(buf, "\"window_sec\":300"));
    // No source.ip for local brute-force
    assert_null(strstr(buf, "\"source\""));
}

static void test_format_local_brute_json_su(void **state) {
    (void)state;
    ps_config_t cfg;
    make_cfg_default(&cfg);

    char buf[2048];
    format_local_brute_json(&cfg, PS_SERVICE_SU, "carol", "admin", 3, 60,
                            "host2", 1700000000000000ULL, 8888, buf,
                            sizeof(buf));

    assert_non_null(strstr(buf, "\"service\":{\"name\":\"su\"}"));
    assert_non_null(strstr(
        buf, "\"user\":{\"name\":\"carol\",\"target\":{\"name\":\"admin\"}}"));
}

static void test_format_local_brute_json_with_labels(void **state) {
    (void)state;
    ps_config_t cfg;
    make_cfg_with_labels(&cfg, "do", "db-prod");

    char buf[2048];
    format_local_brute_json(&cfg, PS_SERVICE_SUDO, "eve", "root", 10, 600,
                            "dbhost", 1700000000000000ULL, 1111, buf,
                            sizeof(buf));

    assert_non_null(strstr(
        buf, "\"labels\":{\"provider\":\"do\",\"service_name\":\"db-prod\"}"));
}

// --- format_event_text tests ---

static void test_format_event_text_login_failed(void **state) {
    (void)state;
    ps_config_t cfg;
    make_cfg_default(&cfg);
    ps_pam_event_t e = make_login_failed();

    char buf[1024];
    format_event_text(&cfg, &e, buf, sizeof(buf));

    assert_non_null(strstr(buf, "auth.login_failure"));
    assert_non_null(strstr(buf, "user=alice"));
    assert_non_null(strstr(buf, "src=192.0.2.1:22"));
    assert_non_null(strstr(buf, "host=webserver01"));
    assert_non_null(strstr(buf, "service=sshd"));
    assert_non_null(strstr(buf, "auth=password"));
    assert_non_null(strstr(buf, "pid=1234"));
}

static void test_format_event_text_session_open(void **state) {
    (void)state;
    ps_config_t cfg;
    make_cfg_default(&cfg);
    ps_pam_event_t e = make_session_open();

    char buf[1024];
    format_event_text(&cfg, &e, buf, sizeof(buf));

    assert_non_null(strstr(buf, "auth.session_opened"));
    assert_non_null(strstr(buf, "user=bob"));
    assert_non_null(strstr(buf, "host=dbserver"));
    // Session text should NOT have src= field
    assert_null(strstr(buf, "src="));
}

static void test_format_event_text_with_context(void **state) {
    (void)state;
    ps_config_t cfg;
    make_cfg_with_labels(&cfg, "aws", "prod");
    ps_pam_event_t e = make_login_failed();

    char buf[1024];
    format_event_text(&cfg, &e, buf, sizeof(buf));

    assert_non_null(strstr(buf, "provider=aws"));
    assert_non_null(strstr(buf, "service_name=prod"));
}

// --- Public API smoke tests (no channels configured) ---

static void test_notify_event_no_channels(void **state) {
    (void)state;
    ps_config_t cfg;
    make_cfg_default(&cfg);
    cfg.alert_cooldown_sec = 0; // avoid polluting file-static last_event_alert
    ps_pam_event_t e = make_login_failed();
    ps_notify_event(&cfg, &e);
}

static void test_notify_brute_no_channels(void **state) {
    (void)state;
    ps_config_t cfg;
    make_cfg_default(&cfg);
    ps_notify_brute_force(&cfg, "192.0.2.99", 5, 60, "alice", "host",
                          1700000000000000ULL, 12345);
}

static void test_notify_local_brute_no_channels(void **state) {
    (void)state;
    ps_config_t cfg;
    make_cfg_default(&cfg);
    ps_notify_local_brute_force(&cfg, PS_SERVICE_SUDO, "alice", "root", 5, 60,
                                "host", 1700000000000000ULL, 12345);
}

// Cooldown: first call dispatches, subsequent calls within the cooldown
// window are suppressed. We reset last_event_alert to ensure this test
// exercises the dispatch-then-suppress path regardless of prior test state.
static void test_notify_event_cooldown_repeat(void **state) {
    (void)state;
    ps_config_t cfg;
    make_cfg_default(&cfg);
    cfg.alert_cooldown_sec = 3600;

    // Reset file-static cooldown state so first call goes through dispatch
    last_event_alert = 0;

    ps_pam_event_t e = make_login_failed();
    ps_notify_event(&cfg, &e); // dispatches (bumps last_event_alert)
    ps_notify_event(&cfg, &e); // suppressed by cooldown
    ps_notify_event(&cfg, &e); // suppressed by cooldown
}

// --- enable_notification_type gating ---
//
// We probe gating without a live HTTP channel by observing the file-static
// last_event_alert clock: a real dispatch through ps_notify_event sets it,
// a gated-off call leaves it untouched. Same proxy for brute-force using
// time(NULL) bookkeeping is not available, so we rely on the absence of
// crash + the gating expression being identical to the one we already
// proved through event_notify_bit().

static void test_event_notify_bit_mapping(void **state) {
    (void)state;
    assert_int_equal(event_notify_bit(PS_EVENT_LOGIN_SUCCESS),
                     PS_NOTIFY_LOGIN_SUCCESS);
    assert_int_equal(event_notify_bit(PS_EVENT_LOGIN_FAILED),
                     PS_NOTIFY_LOGIN_FAILED);
    assert_int_equal(event_notify_bit(PS_EVENT_SESSION_OPEN),
                     PS_NOTIFY_SESSION_OPEN);
    assert_int_equal(event_notify_bit(PS_EVENT_SESSION_CLOSE),
                     PS_NOTIFY_SESSION_CLOSE);
    assert_int_equal(event_notify_bit(PS_EVENT_UNKNOWN), 0);
}

static void test_notify_event_gated_off(void **state) {
    (void)state;
    ps_config_t cfg;
    make_cfg_default(&cfg);
    cfg.enable_notification_type = PS_NOTIFY_LOGIN_SUCCESS; // failures off
    cfg.alert_cooldown_sec = 3600;

    last_event_alert = 0;
    ps_pam_event_t e = make_login_failed();
    ps_notify_event(&cfg, &e);
    // Gated off: cooldown clock never advanced.
    assert_int_equal(last_event_alert, 0);
}

static void test_notify_event_gated_on(void **state) {
    (void)state;
    ps_config_t cfg;
    make_cfg_default(&cfg);
    cfg.enable_notification_type = PS_NOTIFY_LOGIN_SUCCESS;
    cfg.alert_cooldown_sec = 3600;

    last_event_alert = 0;
    ps_pam_event_t e = make_login_success();
    ps_notify_event(&cfg, &e);
    // Gated on: cooldown clock advanced because dispatch ran.
    assert_true(last_event_alert > 0);
}

static void test_notify_event_unknown_type_never_dispatches(void **state) {
    (void)state;
    ps_config_t cfg;
    make_cfg_default(&cfg); // all bits set
    cfg.alert_cooldown_sec = 3600;

    last_event_alert = 0;
    ps_pam_event_t e = make_login_success();
    e.type = PS_EVENT_UNKNOWN;
    ps_notify_event(&cfg, &e);
    assert_int_equal(last_event_alert, 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // json_escape
        cmocka_unit_test(test_json_escape_plain),
        cmocka_unit_test(test_json_escape_quotes),
        cmocka_unit_test(test_json_escape_backslash),
        cmocka_unit_test(test_json_escape_control_chars),
        cmocka_unit_test(test_json_escape_low_control),
        cmocka_unit_test(test_json_escape_empty),
        cmocka_unit_test(test_json_escape_truncation),
        // format_event_json
        cmocka_unit_test(test_format_event_json_login_failed),
        cmocka_unit_test(test_format_event_json_login_success),
        cmocka_unit_test(test_format_event_json_session_open),
        cmocka_unit_test(test_format_event_json_with_provider),
        cmocka_unit_test(test_format_event_json_with_service_name),
        cmocka_unit_test(test_format_event_json_with_both_labels),
        cmocka_unit_test(test_format_event_json_special_chars_username),
        cmocka_unit_test(test_format_event_json_ipv6),
        // format_brute_json
        cmocka_unit_test(test_format_brute_json_basic),
        cmocka_unit_test(test_format_brute_json_with_labels),
        cmocka_unit_test(test_format_brute_json_ipv6),
        // format_local_brute_json
        cmocka_unit_test(test_format_local_brute_json_sudo),
        cmocka_unit_test(test_format_local_brute_json_su),
        cmocka_unit_test(test_format_local_brute_json_with_labels),
        // format_event_text
        cmocka_unit_test(test_format_event_text_login_failed),
        cmocka_unit_test(test_format_event_text_session_open),
        cmocka_unit_test(test_format_event_text_with_context),
        // Public API smoke tests
        cmocka_unit_test(test_notify_event_no_channels),
        cmocka_unit_test(test_notify_brute_no_channels),
        cmocka_unit_test(test_notify_local_brute_no_channels),
        cmocka_unit_test(test_notify_event_cooldown_repeat),
        // enable_notification_type gating
        cmocka_unit_test(test_event_notify_bit_mapping),
        cmocka_unit_test(test_notify_event_gated_off),
        cmocka_unit_test(test_notify_event_gated_on),
        cmocka_unit_test(test_notify_event_unknown_type_never_dispatches),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
