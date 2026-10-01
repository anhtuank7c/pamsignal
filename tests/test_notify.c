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

// provider / service_name are operator-controlled 63-byte strings; when every
// byte needs escaping the labels fragment is ~294 bytes. Every JSON formatter
// must still emit a complete object rather than truncating mid-string.
static void test_format_json_labels_worst_case_not_truncated(void **state) {
    (void)state;
    char quotes[64];
    memset(quotes, '"', sizeof(quotes) - 1);
    quotes[sizeof(quotes) - 1] = '\0';

    ps_config_t cfg;
    make_cfg_with_labels(&cfg, quotes, quotes);
    ps_pam_event_t e = make_login_success();
    char buf[2048];

    format_event_json(&cfg, &e, buf, sizeof(buf));
    assert_non_null(strstr(buf, "\\\"\"}}"));
    assert_int_equal(buf[strlen(buf) - 1], '}');

    format_brute_json(&cfg, "10.0.0.1", 5, 300, "root", "h",
                      1700000000000000ULL, 1, buf, sizeof(buf));
    assert_non_null(strstr(buf, "\\\"\"}}"));

    format_local_brute_json(&cfg, PS_SERVICE_SUDO, "alice", "root", 5, 300, "h",
                            1700000000000000ULL, 1, buf, sizeof(buf));
    assert_non_null(strstr(buf, "\\\"\"}}"));

    format_login_after_failures_json(&cfg, &e, 3, 300, buf, sizeof(buf));
    assert_non_null(strstr(buf, "\\\"\"}}"));

    format_test_json(&cfg, "h", 1700000000000000ULL, buf, sizeof(buf));
    assert_non_null(strstr(buf, "\\\"\"}}"));
}

// --- Pretty messages (message_style = pretty) ---

static void test_pretty_event_rows(void **state) {
    (void)state;
    ps_config_t cfg;
    make_cfg_with_labels(&cfg, "aws", "web-api");
    ps_pam_event_t e = make_login_success();

    ps_pretty_msg_t m;
    build_pretty_event(&cfg, &e, &m);
    assert_string_equal(m.title, "Login success");
    assert_string_equal(m.rows[0].label, "Host");
    assert_string_equal(m.rows[0].value, "webserver01");
    assert_string_equal(m.rows[1].label, "User");
    assert_string_equal(m.rows[1].value, "alice");
    assert_string_equal(m.rows[2].label, "Source");
    assert_string_equal(m.rows[2].value, "192.0.2.1:22");
    assert_string_equal(m.rows[3].label, "Auth");
    assert_string_equal(m.rows[3].value, "publickey (sshd)");
    assert_string_equal(m.rows[4].label, "PID");
    assert_string_equal(m.rows[5].label, "Time");
    assert_string_equal(m.rows[6].label, "Provider");
    assert_string_equal(m.rows[6].value, "aws");
    assert_string_equal(m.rows[7].label, "Service name");
    assert_int_equal(m.row_count, 8);
}

// "2026-03-29T14:23:01+0000" is shown as "2026-03-29 14:23:01 +0000".
static void test_pretty_time_is_spaced(void **state) {
    (void)state;
    ps_config_t cfg;
    make_cfg_default(&cfg);
    ps_pretty_msg_t m;
    build_pretty_test(&cfg, "h", 1700000000000000ULL, &m);
    const char *t = m.rows[1].value;
    assert_string_equal(m.rows[1].label, "Time");
    assert_int_equal(strlen(t), 25);
    assert_int_equal(t[10], ' ');
    assert_int_equal(t[19], ' ');
    assert_null(strchr(t, 'T'));
}

static void test_pretty_session_and_local_events_have_no_source(void **state) {
    (void)state;
    ps_config_t cfg;
    make_cfg_default(&cfg);
    ps_pretty_msg_t m;

    ps_pam_event_t s = make_session_open();
    build_pretty_event(&cfg, &s, &m);
    assert_string_equal(m.title, "Session opened");
    for (int i = 0; i < m.row_count; i++)
        assert_string_not_equal(m.rows[i].label, "Source");

    // sudo failure with no rhost: no remote endpoint to show.
    ps_pam_event_t f = make_login_failed();
    f.service = PS_SERVICE_SUDO;
    f.source_ip[0] = '\0';
    build_pretty_event(&cfg, &f, &m);
    for (int i = 0; i < m.row_count; i++)
        assert_string_not_equal(m.rows[i].label, "Source");
}

static void test_render_pretty_markup_per_platform(void **state) {
    (void)state;
    ps_config_t cfg;
    make_cfg_default(&cfg);
    ps_pretty_msg_t m;
    build_pretty_brute(&cfg, "203.0.113.50", 12, 300, "root", "web-01",
                       1700000000000000ULL, &m);
    char buf[PS_CHAT_TEXT_MAX];

    assert_int_equal(render_pretty(&m, PS_MARKUP_TELEGRAM, buf, sizeof(buf)),
                     0);
    assert_non_null(strstr(buf, "<b>Brute force detected</b>"));
    assert_non_null(strstr(buf, "\n<b>Source:</b> <code>203.0.113.50</code>"));
    assert_non_null(strstr(buf, "\n<b>Attempts:</b> <code>12 in 300s</code>"));

    assert_int_equal(render_pretty(&m, PS_MARKUP_SLACK, buf, sizeof(buf)), 0);
    assert_non_null(strstr(buf, " *Brute force detected*\n"));
    assert_non_null(strstr(buf, "\n*Host:* `web-01`"));

    assert_int_equal(render_pretty(&m, PS_MARKUP_WHATSAPP, buf, sizeof(buf)),
                     0);
    assert_non_null(strstr(buf, "\n*User:* `root`"));

    assert_int_equal(render_pretty(&m, PS_MARKUP_DISCORD, buf, sizeof(buf)), 0);
    assert_non_null(strstr(buf, " **Brute force detected**\n"));
    assert_non_null(strstr(buf, "\n**Source:** `203.0.113.50`"));

    // Teams folds single newlines, so rows are separated by a blank line.
    assert_int_equal(render_pretty(&m, PS_MARKUP_TEAMS, buf, sizeof(buf)), 0);
    assert_non_null(strstr(buf, "**\n\n**Host:** `web-01`\n\n**Source:**"));
}

static void test_render_pretty_note_line(void **state) {
    (void)state;
    ps_config_t cfg;
    make_cfg_default(&cfg);
    ps_pam_event_t e = make_login_success();
    ps_pretty_msg_t m;
    build_pretty_login_after_failures(&cfg, &e, 7, 300, &m);
    char buf[PS_CHAT_TEXT_MAX];
    assert_int_equal(render_pretty(&m, PS_MARKUP_SLACK, buf, sizeof(buf)), 0);
    assert_non_null(strstr(buf, "*Login after failed attempts*\n"
                                "Possible guessed password\n*Host:*"));
    assert_non_null(strstr(buf, "*Failures:* `7 in 300s`"));
}

// Usernames and hostnames are attacker-influenced. Whatever they contain must
// stay inert text inside its code span on every platform.
static void test_render_pretty_neutralises_hostile_values(void **state) {
    (void)state;
    ps_config_t cfg;
    make_cfg_default(&cfg);
    ps_pam_event_t e = make_login_failed();
    snprintf(e.username, sizeof(e.username), "%s",
             "</code><a>&<!channel>`*x*`@everyone");
    ps_pretty_msg_t m;
    build_pretty_event(&cfg, &e, &m);
    char buf[PS_CHAT_TEXT_MAX];

    // Telegram HTML: no raw tag survives, so the code span cannot be closed.
    assert_int_equal(render_pretty(&m, PS_MARKUP_TELEGRAM, buf, sizeof(buf)),
                     0);
    assert_non_null(strstr(buf, "<code>&lt;/code&gt;&lt;a&gt;&amp;&lt;!channel"
                                "&gt;"));
    assert_null(strstr(buf, "<a>"));
    assert_null(strstr(buf, "</code><"));

    // Slack: <!channel> needs a literal '<'; backticks cannot close the span.
    assert_int_equal(render_pretty(&m, PS_MARKUP_SLACK, buf, sizeof(buf)), 0);
    assert_null(strstr(buf, "<!channel>"));
    assert_non_null(strstr(buf, "&lt;!channel&gt;'*x*'@everyone`"));

    // Discord / WhatsApp: the only way out of a code span is a backtick.
    assert_int_equal(render_pretty(&m, PS_MARKUP_DISCORD, buf, sizeof(buf)), 0);
    assert_non_null(strstr(buf, "**User:** `</code><a>&<!channel>'*x*'"
                                "@everyone`\n"));

    assert_int_equal(render_pretty(&m, PS_MARKUP_TEAMS, buf, sizeof(buf)), 0);
    assert_null(strstr(buf, "<a>"));
}

static void test_render_pretty_control_chars_and_empty_value(void **state) {
    (void)state;
    ps_pretty_msg_t m;
    memset(&m, 0, sizeof(m));
    m.emoji = "!";
    m.title = "T";
    pretty_add(&m, "A", "%s", "x\ny\x7f");
    pretty_add(&m, "B", "%s", "");
    char buf[256];
    assert_int_equal(render_pretty(&m, PS_MARKUP_DISCORD, buf, sizeof(buf)), 0);
    assert_string_equal(buf, "! **T**\n**A:** `x?y?`\n**B:** `-`");
}

// A message that does not fit is reported, never silently cut mid-markup.
static void test_render_pretty_overflow_reported(void **state) {
    (void)state;
    ps_config_t cfg;
    make_cfg_default(&cfg);
    ps_pretty_msg_t m;
    build_pretty_brute(&cfg, "203.0.113.50", 12, 300, "root", "web-01",
                       1700000000000000ULL, &m);
    char small[64];
    assert_int_equal(
        render_pretty(&m, PS_MARKUP_TELEGRAM, small, sizeof(small)), -1);
    assert_true(strlen(small) < sizeof(small));
    char zero[1];
    assert_int_equal(render_pretty(&m, PS_MARKUP_TELEGRAM, zero, 0), -1);
}

static void test_pretty_rows_capped(void **state) {
    (void)state;
    ps_pretty_msg_t m;
    memset(&m, 0, sizeof(m));
    for (int i = 0; i < PS_PRETTY_MAX_ROWS + 5; i++)
        pretty_add(&m, "L", "%d", i);
    assert_int_equal(m.row_count, PS_PRETTY_MAX_ROWS);
}

static void test_sb_put_entity_escaped(void **state) {
    (void)state;
    char buf[64];
    buf[0] = '\0';
    ps_strbuf_t sb = {.buf = buf, .size = sizeof(buf)};
    sb_put_entity_escaped(&sb, "a<!here>&b");
    assert_int_equal(sb.overflow, 0);
    assert_string_equal(buf, "a&lt;!here&gt;&amp;b");

    char tiny[8];
    tiny[0] = '\0';
    ps_strbuf_t sb2 = {.buf = tiny, .size = sizeof(tiny)};
    sb_put_entity_escaped(&sb2, "<<<<<<");
    assert_int_equal(sb2.overflow, 1);
    assert_true(strlen(tiny) < sizeof(tiny));
}

static void test_notify_pretty_no_channels(void **state) {
    (void)state;
    ps_config_t cfg;
    make_cfg_default(&cfg);
    cfg.message_style = PS_MESSAGE_STYLE_PRETTY;
    cfg.alert_cooldown_sec = 0;
    ps_pam_event_t e = make_login_success();
    ps_notify_event(&cfg, &e);
    ps_notify_brute_force(&cfg, "192.0.2.99", 5, 60, "alice", "host",
                          1700000000000000ULL, 12345);
    ps_notify_local_brute_force(&cfg, PS_SERVICE_SUDO, "alice", "root", 5, 60,
                                "host", 1700000000000000ULL, 12345);
    ps_notify_login_after_failures(&cfg, &e, 5, 300);
    assert_int_equal(ps_notify_test(&cfg, "host", 1700000000000000ULL), -1);
}

// --- Rendering hardening ---

static void test_utf8_decode(void **state) {
    (void)state;
    uint32_t cp = 0;
    assert_int_equal(utf8_decode((const unsigned char *)"A", &cp), 1);
    assert_int_equal(cp, 'A');
    assert_int_equal(utf8_decode((const unsigned char *)"\xC3\xA9", &cp), 2);
    assert_int_equal(cp, 0xE9);
    assert_int_equal(utf8_decode((const unsigned char *)"\xE2\x80\xA8", &cp),
                     3);
    assert_int_equal(cp, 0x2028);
    assert_int_equal(
        utf8_decode((const unsigned char *)"\xF0\x9F\x9A\xA8", &cp), 4);
    assert_int_equal(cp, 0x1F6A8);

    // Malformed: stray continuation, truncated, overlong, surrogate, too big,
    // invalid lead byte.
    assert_int_equal(utf8_decode((const unsigned char *)"\x80", &cp), 0);
    assert_int_equal(utf8_decode((const unsigned char *)"\xC3", &cp), 0);
    assert_int_equal(utf8_decode((const unsigned char *)"\xE2\x80", &cp), 0);
    assert_int_equal(utf8_decode((const unsigned char *)"\xC0\xAF", &cp), 0);
    assert_int_equal(utf8_decode((const unsigned char *)"\xE0\x80\xAF", &cp),
                     0);
    assert_int_equal(utf8_decode((const unsigned char *)"\xED\xA0\x80", &cp),
                     0);
    assert_int_equal(
        utf8_decode((const unsigned char *)"\xF4\x90\x80\x80", &cp), 0);
    assert_int_equal(utf8_decode((const unsigned char *)"\xFF", &cp), 0);
}

// One invalid byte must not make the whole JSON body unparseable.
static void test_json_escape_replaces_invalid_utf8(void **state) {
    (void)state;
    char buf[64];
    json_escape("a\xFFz", buf, sizeof(buf));
    assert_string_equal(buf, "a?z");
    json_escape("caf\xC3\xA9 \xF0\x9F\x9A\xA8", buf, sizeof(buf));
    assert_string_equal(buf, "caf\xC3\xA9 \xF0\x9F\x9A\xA8");
    // A lead byte whose continuation is missing is dropped on its own; the
    // byte after it is still processed.
    json_escape("\xE2\x80\"", buf, sizeof(buf));
    assert_string_equal(buf, "??\\\"");
}

static void test_json_escape_reports_truncation(void **state) {
    (void)state;
    char buf[16];
    int truncated = -1;
    json_escape_ex("short", buf, sizeof(buf), &truncated);
    assert_int_equal(truncated, 0);
    assert_string_equal(buf, "short");

    json_escape_ex("this text is far too long", buf, sizeof(buf), &truncated);
    assert_int_equal(truncated, 1);
    assert_true(strlen(buf) < sizeof(buf));

    char none[1];
    json_escape_ex("x", none, 0, &truncated);
    assert_int_equal(truncated, 1);
}

static void render_value(ps_markup_t markup, const char *value, char *buf,
                         size_t size) {
    buf[0] = '\0';
    ps_strbuf_t sb = {.buf = buf, .size = size};
    sb_put_value(&sb, markup, value);
    assert_int_equal(sb.overflow, 0);
}

// Characters that change layout instead of content never reach the client:
// a line separator would start a forged row, a bidi override would reorder
// the visible text, zero-width characters hide content.
static void test_value_strips_layout_controls(void **state) {
    (void)state;
    char buf[128];
    render_value(PS_MARKUP_DISCORD,
                 "a\xE2\x80\xA8"
                 "b",
                 buf, sizeof(buf));
    assert_string_equal(buf, "a?b"); // U+2028 LINE SEPARATOR
    render_value(PS_MARKUP_DISCORD,
                 "a\xE2\x80\xA9"
                 "b",
                 buf, sizeof(buf));
    assert_string_equal(buf, "a?b"); // U+2029 PARAGRAPH SEPARATOR
    render_value(PS_MARKUP_DISCORD,
                 "a\xE2\x80\xAE"
                 "b",
                 buf, sizeof(buf));
    assert_string_equal(buf, "a?b"); // U+202E RIGHT-TO-LEFT OVERRIDE
    render_value(PS_MARKUP_DISCORD,
                 "a\xE2\x81\xA6"
                 "b",
                 buf, sizeof(buf));
    assert_string_equal(buf, "a?b"); // U+2066 LEFT-TO-RIGHT ISOLATE
    render_value(PS_MARKUP_DISCORD,
                 "a\xE2\x80\x8B"
                 "b",
                 buf, sizeof(buf));
    assert_string_equal(buf, "a?b"); // U+200B ZERO WIDTH SPACE
    render_value(PS_MARKUP_DISCORD,
                 "a\xEF\xBB\xBF"
                 "b",
                 buf, sizeof(buf));
    assert_string_equal(buf, "a?b"); // U+FEFF
    render_value(PS_MARKUP_DISCORD,
                 "a\xC2\x85"
                 "b",
                 buf, sizeof(buf));
    assert_string_equal(buf, "a?b"); // U+0085 NEXT LINE (C1)
    render_value(PS_MARKUP_DISCORD, "a\r\n\tb\x7f", buf, sizeof(buf));
    assert_string_equal(buf, "a???b?");
    render_value(PS_MARKUP_DISCORD,
                 "a\xFF\xC3"
                 "b",
                 buf, sizeof(buf));
    assert_string_equal(buf, "a??b"); // malformed UTF-8
}

// Ordinary non-ASCII text (an operator's provider tag, say) is preserved.
static void test_value_keeps_legitimate_unicode(void **state) {
    (void)state;
    char buf[128];
    const char *vn = "m\xC3\xA1y ch\xE1\xBB\xA7 Vi\xE1\xBB\x87t";
    render_value(PS_MARKUP_TELEGRAM, vn, buf, sizeof(buf));
    assert_string_equal(buf, vn);
    render_value(PS_MARKUP_SLACK, "\xE6\x97\xA5\xE6\x9C\xAC", buf, sizeof(buf));
    assert_string_equal(buf, "\xE6\x97\xA5\xE6\x9C\xAC");
}

static void test_render_compact_is_one_code_span(void **state) {
    (void)state;
    char buf[PS_CHAT_TEXT_MAX];
    const char *line = "[WARN]   auth.login_failure user=bob src=192.0.2.1:22";

    assert_int_equal(render_compact(line, PS_MARKUP_TELEGRAM, buf, sizeof(buf)),
                     0);
    assert_string_equal(
        buf,
        "<code>[WARN]   auth.login_failure user=bob src=192.0.2.1:22</code>");

    static const ps_markup_t backtick_markups[] = {
        PS_MARKUP_SLACK, PS_MARKUP_TEAMS, PS_MARKUP_WHATSAPP,
        PS_MARKUP_DISCORD};
    for (size_t i = 0; i < 4; i++) {
        assert_int_equal(
            render_compact(line, backtick_markups[i], buf, sizeof(buf)), 0);
        assert_string_equal(
            buf, "`[WARN]   auth.login_failure user=bob src=192.0.2.1:22`");
    }

    char small[16];
    assert_int_equal(
        render_compact(line, PS_MARKUP_DISCORD, small, sizeof(small)), -1);
}

// A username is one space-free token, which is enough to write a masked
// link, a bare URL, a mention or a bot command. In the compact line it must
// stay inside the code span, where no platform acts on it.
static void test_render_compact_keeps_links_and_mentions_inert(void **state) {
    (void)state;
    char buf[PS_CHAT_TEXT_MAX];
    const char *line = "[WARN]   auth.login_failure "
                       "user=[reset](https://evil.example)`@everyone`"
                       "<!channel>&/start src=192.0.2.1:22";

    assert_int_equal(render_compact(line, PS_MARKUP_DISCORD, buf, sizeof(buf)),
                     0);
    // Exactly the opening and closing backtick: nothing can end the span.
    int ticks = 0;
    for (const char *p = buf; *p; p++)
        ticks += *p == '`';
    assert_int_equal(ticks, 2);
    assert_int_equal(buf[0], '`');
    assert_int_equal(buf[strlen(buf) - 1], '`');
    assert_non_null(strstr(buf, "'@everyone'"));

    assert_int_equal(render_compact(line, PS_MARKUP_SLACK, buf, sizeof(buf)),
                     0);
    assert_null(strchr(buf, '<'));
    assert_null(strchr(buf, '>'));
    assert_non_null(strstr(buf, "&lt;!channel&gt;&amp;/start"));

    assert_int_equal(render_compact(line, PS_MARKUP_TELEGRAM, buf, sizeof(buf)),
                     0);
    assert_non_null(strstr(buf, "&lt;!channel&gt;&amp;/start"));
    assert_int_equal(strncmp(buf, "<code>", 6), 0);
    assert_string_equal(buf + strlen(buf) - 7, "</code>");
    // The only tags present are the wrapper itself.
    assert_null(strchr(buf + 6, '<') == buf + strlen(buf) - 7
                    ? NULL
                    : strchr(buf + 6, '<'));
}

// --- Property test: no input can break out of its code span ---
//
// Feeds pseudo-random usernames, hostnames and tags, weighted towards the
// characters that are syntax somewhere, through every renderer and checks
// the structural invariants that make the output safe, instead of checking
// particular strings.

static uint32_t prng_state = 0x9E3779B9u;
static uint32_t prng_next(void) {
    prng_state = prng_state * 1664525u + 1013904223u;
    return prng_state >> 8;
}

static void fill_hostile(char *dst, size_t size) {
    static const char syntax[] = "```<>&&*_~[]()|\\\"'@!#/:;\n\r\t -=.";
    static const char *const multi[] = {
        "\xE2\x80\xA8", "\xE2\x80\xAE", "\xE2\x80\x8B",
        "\xC2\x85",     "\xC3\xA9",     "\xF0\x9F\x9A\xA8",
        "</code>",      "<b>",          "&lt;",
        "&amp;",        "<!channel>",   "@everyone",
        "](http://e)",  "\xEF\xBB\xBF",
    };
    size_t len = prng_next() % size;
    size_t i = 0;
    while (i < len) {
        uint32_t r = prng_next();
        if (r % 4 == 0) {
            const char *m =
                multi[(r >> 4) % (sizeof(multi) / sizeof(multi[0]))];
            size_t n = strlen(m);
            if (i + n >= size)
                break;
            memcpy(dst + i, m, n);
            i += n;
        } else if (r % 4 == 1) {
            dst[i++] = syntax[(r >> 4) % (sizeof(syntax) - 1)];
        } else {
            unsigned char c = (unsigned char)(r >> 4);
            dst[i++] = c ? (char)c : 'x'; // any byte, including invalid UTF-8
        }
    }
    dst[i < size ? i : size - 1] = '\0';
}

static int count_sub(const char *s, const char *needle) {
    int n = 0;
    size_t len = strlen(needle);
    for (const char *p = strstr(s, needle); p; p = strstr(p + len, needle))
        n++;
    return n;
}

static void assert_safe_output(const char *out, ps_markup_t markup,
                               int expected_spans, int expected_newlines) {
    // 1. Well-formed UTF-8, and no layout-changing code point other than the
    //    newlines the renderer itself wrote.
    int newlines = 0;
    for (const unsigned char *p = (const unsigned char *)out; *p;) {
        uint32_t cp;
        int n = utf8_decode(p, &cp);
        assert_true(n > 0);
        if (cp == '\n')
            newlines++;
        else
            assert_false(is_unsafe_display_codepoint(cp));
        p += n;
    }
    assert_int_equal(newlines, expected_newlines);

    if (markup == PS_MARKUP_TELEGRAM) {
        // 2a. HTML: the only tags are the renderer's own, properly paired, and
        //     every '&' starts one of the three entities we emit.
        assert_int_equal(count_sub(out, "<code>"), expected_spans);
        assert_int_equal(count_sub(out, "</code>"), expected_spans);
        int lt = 0;
        int gt = 0;
        for (const char *p = out; *p; p++) {
            lt += *p == '<';
            gt += *p == '>';
            if (*p == '&')
                assert_true(strncmp(p, "&amp;", 5) == 0 ||
                            strncmp(p, "&lt;", 4) == 0 ||
                            strncmp(p, "&gt;", 4) == 0);
        }
        int tags =
            2 * expected_spans + count_sub(out, "<b>") + count_sub(out, "</b>");
        assert_int_equal(lt, tags);
        assert_int_equal(gt, tags);
        assert_int_equal(count_sub(out, "<b>"), count_sub(out, "</b>"));
    } else {
        // 2b. Backtick markups: exactly one opening and one closing backtick
        //     per span, so no value can end its span early.
        int ticks = 0;
        for (const char *p = out; *p; p++)
            ticks += *p == '`';
        assert_int_equal(ticks, 2 * expected_spans);
        if (markup == PS_MARKUP_SLACK || markup == PS_MARKUP_TEAMS) {
            assert_null(strchr(out, '<'));
            assert_null(strchr(out, '>'));
        }
    }
}

static void test_property_no_input_escapes_its_code_span(void **state) {
    (void)state;
    static const ps_markup_t markups[] = {PS_MARKUP_TELEGRAM, PS_MARKUP_SLACK,
                                          PS_MARKUP_TEAMS, PS_MARKUP_WHATSAPP,
                                          PS_MARKUP_DISCORD};
    static char out[8192];
    ps_config_t cfg;
    make_cfg_default(&cfg);
    prng_state = 0x9E3779B9u;

    for (int iter = 0; iter < 20000; iter++) {
        ps_pam_event_t e = make_login_failed();
        fill_hostile(e.username, sizeof(e.username));
        fill_hostile(e.hostname, sizeof(e.hostname));
        fill_hostile(cfg.provider, sizeof(cfg.provider));
        fill_hostile(cfg.service_name, sizeof(cfg.service_name));

        ps_pretty_msg_t m;
        build_pretty_login_after_failures(&cfg, &e, 3, 300, &m);
        char compact[1024];
        format_event_text(&cfg, &e, compact, sizeof(compact));

        for (size_t k = 0; k < sizeof(markups) / sizeof(markups[0]); k++) {
            int sep = markups[k] == PS_MARKUP_TEAMS ? 2 : 1;

            assert_int_equal(render_pretty(&m, markups[k], out, sizeof(out)),
                             0);
            // one newline group before the note and before every row
            assert_safe_output(out, markups[k], m.row_count,
                               sep * (m.row_count + 1));

            assert_int_equal(
                render_compact(compact, markups[k], out, sizeof(out)), 0);
            assert_safe_output(out, markups[k], 1, 0);

            // Whatever was rendered also survives JSON escaping intact.
            static char esc[32768];
            int truncated;
            json_escape_ex(out, esc, sizeof(esc), &truncated);
            assert_int_equal(truncated, 0);
            for (const unsigned char *p = (const unsigned char *)esc; *p; p++)
                assert_true(*p >= 0x20);
        }
    }
}

// --- Login-after-failures formatting ---

static void test_format_login_after_failures_text(void **state) {
    (void)state;
    ps_config_t cfg;
    make_cfg_with_labels(&cfg, "aws", NULL);
    ps_pam_event_t e = make_login_success();

    char buf[1024];
    format_login_after_failures_text(&cfg, &e, 7, 300, buf, sizeof(buf));

    assert_non_null(strstr(buf, "[CRIT]   auth.login_after_failures"));
    assert_non_null(strstr(buf, "user=alice"));
    assert_non_null(strstr(buf, "src=192.0.2.1:22"));
    assert_non_null(strstr(buf, "failures=7 window=300s"));
    assert_non_null(strstr(buf, "host=webserver01"));
    assert_non_null(strstr(buf, "auth=publickey"));
    assert_non_null(strstr(buf, "pid=1234"));
    assert_non_null(strstr(buf, " provider=aws"));
}

static void test_format_login_after_failures_json(void **state) {
    (void)state;
    ps_config_t cfg;
    make_cfg_with_labels(&cfg, "hetzner", "web");
    ps_pam_event_t e = make_login_success();

    char buf[2048];
    format_login_after_failures_json(&cfg, &e, 7, 300, buf, sizeof(buf));

    assert_non_null(strstr(buf, "\"action\":\"login_after_failures\""));
    assert_non_null(strstr(
        buf, "\"category\":[\"authentication\",\"intrusion_detection\"]"));
    assert_non_null(strstr(buf, "\"kind\":\"alert\""));
    assert_non_null(strstr(buf, "\"outcome\":\"success\""));
    assert_non_null(strstr(buf, "\"severity\":9"));
    assert_non_null(strstr(buf, "\"user\":{\"name\":\"alice\"}"));
    assert_non_null(
        strstr(buf, "\"source\":{\"ip\":\"192.0.2.1\",\"port\":22}"));
    assert_non_null(strstr(buf, "\"event_type\":\"LOGIN_AFTER_FAILURES\""));
    assert_non_null(strstr(buf, "\"failures\":7,\"window_sec\":300"));
    assert_non_null(strstr(
        buf, "\"labels\":{\"provider\":\"hetzner\",\"service_name\":\"web\"}"));
    assert_int_equal(buf[strlen(buf) - 1], '}');
}

// A hostile username must not be able to break out of the JSON string.
static void test_format_login_after_failures_json_escapes(void **state) {
    (void)state;
    ps_config_t cfg;
    make_cfg_default(&cfg);
    ps_pam_event_t e = make_login_success();
    snprintf(e.username, sizeof(e.username), "%s", "a\"b\\c");

    char buf[2048];
    format_login_after_failures_json(&cfg, &e, 3, 60, buf, sizeof(buf));
    assert_non_null(strstr(buf, "\"user\":{\"name\":\"a\\\"b\\\\c\"}"));
}

static void test_notify_login_after_failures_no_channels(void **state) {
    (void)state;
    ps_config_t cfg;
    make_cfg_default(&cfg);
    ps_pam_event_t e = make_login_success();
    ps_notify_login_after_failures(&cfg, &e, 5, 300);
}

// --- Test alert (--test-alert) ---

static void test_format_test_text(void **state) {
    (void)state;
    ps_config_t cfg;
    make_cfg_with_labels(&cfg, NULL, "web-api");

    char buf[1024];
    format_test_text(&cfg, "web-01", 1700000000000000ULL, buf, sizeof(buf));
    assert_non_null(strstr(buf, "[INFO]   pamsignal.test_alert host=web-01"));
    assert_non_null(strstr(buf, " service_name=web-api"));
    assert_non_null(strstr(buf, "--test-alert"));
}

static void test_format_test_json(void **state) {
    (void)state;
    ps_config_t cfg;
    make_cfg_default(&cfg);

    char buf[2048];
    format_test_json(&cfg, "web\"01", 1700000000000000ULL, buf, sizeof(buf));
    assert_non_null(strstr(buf, "\"action\":\"test_alert\""));
    assert_non_null(strstr(buf, "\"event_type\":\"TEST_ALERT\""));
    assert_non_null(strstr(buf, "\"host\":{\"hostname\":\"web\\\"01\"}"));
    assert_null(strstr(buf, "\"labels\""));
    assert_int_equal(buf[strlen(buf) - 1], '}');
}

// With no channel configured there is nothing to test: -1, and no curl is
// ever forked.
static void test_notify_test_no_channels(void **state) {
    (void)state;
    ps_config_t cfg;
    make_cfg_default(&cfg);
    assert_int_equal(ps_notify_test(&cfg, "host", 1700000000000000ULL), -1);
    assert_int_equal(sync_dispatch, 0);
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
        cmocka_unit_test(test_format_json_labels_worst_case_not_truncated),
        cmocka_unit_test(test_pretty_event_rows),
        cmocka_unit_test(test_pretty_time_is_spaced),
        cmocka_unit_test(test_pretty_session_and_local_events_have_no_source),
        cmocka_unit_test(test_render_pretty_markup_per_platform),
        cmocka_unit_test(test_render_pretty_note_line),
        cmocka_unit_test(test_render_pretty_neutralises_hostile_values),
        cmocka_unit_test(test_render_pretty_control_chars_and_empty_value),
        cmocka_unit_test(test_render_pretty_overflow_reported),
        cmocka_unit_test(test_pretty_rows_capped),
        cmocka_unit_test(test_sb_put_entity_escaped),
        cmocka_unit_test(test_notify_pretty_no_channels),
        cmocka_unit_test(test_utf8_decode),
        cmocka_unit_test(test_json_escape_replaces_invalid_utf8),
        cmocka_unit_test(test_json_escape_reports_truncation),
        cmocka_unit_test(test_value_strips_layout_controls),
        cmocka_unit_test(test_value_keeps_legitimate_unicode),
        cmocka_unit_test(test_render_compact_is_one_code_span),
        cmocka_unit_test(test_render_compact_keeps_links_and_mentions_inert),
        cmocka_unit_test(test_property_no_input_escapes_its_code_span),
        cmocka_unit_test(test_format_login_after_failures_text),
        cmocka_unit_test(test_format_login_after_failures_json),
        cmocka_unit_test(test_format_login_after_failures_json_escapes),
        cmocka_unit_test(test_notify_login_after_failures_no_channels),
        cmocka_unit_test(test_format_test_text),
        cmocka_unit_test(test_format_test_json),
        cmocka_unit_test(test_notify_test_no_channels),
        cmocka_unit_test(test_notify_event_cooldown_repeat),
        // enable_notification_type gating
        cmocka_unit_test(test_event_notify_bit_mapping),
        cmocka_unit_test(test_notify_event_gated_off),
        cmocka_unit_test(test_notify_event_gated_on),
        cmocka_unit_test(test_notify_event_unknown_type_never_dispatches),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
