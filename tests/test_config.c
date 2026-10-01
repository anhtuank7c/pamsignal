#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cmocka.h>

#include "config.h"
#include "init.h"

// Helper: write a temp config file via mkstemps so the path is unpredictable
// (can't be pre-created by another local user) and the file is opened with
// mode 0600 by libc directly, regardless of the test runner's umask.
static char tmp_path[256];

static int write_tmp_config(const char *content) {
    snprintf(tmp_path, sizeof(tmp_path), "/tmp/pamsignal_test_XXXXXX.conf");
    int fd = mkstemps(tmp_path, 5); // ".conf" = 5 chars
    if (fd < 0)
        return -1;
    FILE *f = fdopen(fd, "w");
    if (!f) {
        close(fd);
        unlink(tmp_path);
        return -1;
    }
    fputs(content, f);
    fclose(f);
    return 0;
}

static void cleanup_tmp(void) {
    unlink(tmp_path);
}

// --- ps_config_defaults ---

static void test_config_defaults(void **state) {
    (void)state;
    ps_config_t cfg;
    ps_config_defaults(&cfg);

    assert_int_equal(cfg.fail_threshold, PS_DEFAULT_FAIL_THRESHOLD);
    assert_int_equal(cfg.fail_window_sec, PS_DEFAULT_FAIL_WINDOW_SEC);
    assert_int_equal(cfg.max_tracked_ips, PS_DEFAULT_MAX_TRACKED_IPS);
    assert_int_equal(cfg.alert_cooldown_sec, PS_DEFAULT_ALERT_COOLDOWN_SEC);

    // All string fields should be empty
    assert_int_equal(cfg.telegram_bot_token[0], '\0');
    assert_int_equal(cfg.slack_webhook_url[0], '\0');
    assert_int_equal(cfg.teams_webhook_url[0], '\0');
    assert_int_equal(cfg.discord_webhook_url[0], '\0');
    assert_int_equal(cfg.webhook_url[0], '\0');
    assert_int_equal(cfg.whatsapp_access_token[0], '\0');
}

// --- ps_config_load: missing file uses defaults ---

static void test_config_load_missing_file(void **state) {
    (void)state;
    ps_config_t cfg;
    int ret = ps_config_load("/tmp/nonexistent_pamsignal_test.conf", &cfg);
    assert_int_equal(ret, PS_OK);
    assert_int_equal(cfg.fail_threshold, PS_DEFAULT_FAIL_THRESHOLD);
    assert_int_equal(cfg.fail_window_sec, PS_DEFAULT_FAIL_WINDOW_SEC);
}

// --- ps_config_load: empty file uses defaults ---

static void test_config_load_empty_file(void **state) {
    (void)state;
    write_tmp_config("");
    ps_config_t cfg;
    int ret = ps_config_load(tmp_path, &cfg);
    assert_int_equal(ret, PS_OK);
    assert_int_equal(cfg.fail_threshold, PS_DEFAULT_FAIL_THRESHOLD);
    cleanup_tmp();
}

// --- ps_config_load: comments and blank lines ---

static void test_config_load_comments_only(void **state) {
    (void)state;
    write_tmp_config("# This is a comment\n"
                     "\n"
                     "  # Another comment\n"
                     "\n");
    ps_config_t cfg;
    int ret = ps_config_load(tmp_path, &cfg);
    assert_int_equal(ret, PS_OK);
    assert_int_equal(cfg.fail_threshold, PS_DEFAULT_FAIL_THRESHOLD);
    cleanup_tmp();
}

// --- ps_config_load: valid config ---

static void test_config_load_valid(void **state) {
    (void)state;
    write_tmp_config(
        "telegram_bot_token = 123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11\n"
        "telegram_chat_id = -10012345\n"
        "fail_threshold = 10\n"
        "fail_window_sec = 600\n"
        "max_tracked_ips = 500\n"
        "alert_cooldown_sec = 30\n");
    ps_config_t cfg;
    int ret = ps_config_load(tmp_path, &cfg);
    assert_int_equal(ret, PS_OK);
    assert_string_equal(cfg.telegram_bot_token,
                        "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11");
    assert_string_equal(cfg.telegram_chat_id, "-10012345");
    assert_int_equal(cfg.fail_threshold, 10);
    assert_int_equal(cfg.fail_window_sec, 600);
    assert_int_equal(cfg.max_tracked_ips, 500);
    assert_int_equal(cfg.alert_cooldown_sec, 30);
    cleanup_tmp();
}

// --- ps_config_load: all alert channels ---

static void test_config_load_all_channels(void **state) {
    (void)state;
    write_tmp_config(
        "telegram_bot_token = 123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11\n"
        "telegram_chat_id = @mychannel\n"
        "slack_webhook_url = https://hooks.slack.com/services/T00/B00/xyz\n"
        "teams_webhook_url = https://outlook.office.com/webhook/abc\n"
        "whatsapp_access_token = EAAabc123_def-456.GHI=jkl\n"
        "whatsapp_phone_number_id = 1234567890\n"
        "whatsapp_recipient = 14155551212\n"
        "discord_webhook_url = https://discord.com/api/webhooks/1/xyz\n"
        "webhook_url = https://example.com/hook\n");
    ps_config_t cfg;
    int ret = ps_config_load(tmp_path, &cfg);
    assert_int_equal(ret, PS_OK);
    assert_string_equal(cfg.telegram_bot_token,
                        "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11");
    assert_string_equal(cfg.telegram_chat_id, "@mychannel");
    assert_string_equal(cfg.slack_webhook_url,
                        "https://hooks.slack.com/services/T00/B00/xyz");
    assert_string_equal(cfg.teams_webhook_url,
                        "https://outlook.office.com/webhook/abc");
    assert_string_equal(cfg.whatsapp_access_token, "EAAabc123_def-456.GHI=jkl");
    assert_string_equal(cfg.whatsapp_phone_number_id, "1234567890");
    assert_string_equal(cfg.whatsapp_recipient, "14155551212");
    assert_string_equal(cfg.discord_webhook_url,
                        "https://discord.com/api/webhooks/1/xyz");
    assert_string_equal(cfg.webhook_url, "https://example.com/hook");
    cleanup_tmp();
}

// --- ps_config_load: whitespace trimming ---

static void test_config_load_whitespace(void **state) {
    (void)state;
    write_tmp_config(
        "  telegram_bot_token  =  123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11  \n"
        "  telegram_chat_id  =  -1001  \n"
        "  fail_threshold  =  20  \n");
    ps_config_t cfg;
    int ret = ps_config_load(tmp_path, &cfg);
    assert_int_equal(ret, PS_OK);
    assert_string_equal(cfg.telegram_bot_token,
                        "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11");
    assert_int_equal(cfg.fail_threshold, 20);
    cleanup_tmp();
}

// Exercises every whitespace character the locale-independent trim() treats
// as space: \t (tab), \r (CR — common when files are saved on Windows and
// shipped over to a Linux host), \v (vertical tab), \f (form feed). \n is
// the line terminator and is consumed by fgets, so it never appears as
// surrounding whitespace in trim's input.
static void test_config_load_whitespace_all_kinds(void **state) {
    (void)state;
    write_tmp_config("\tfail_threshold\t=\t20\t\r\n"
                     "\v\ffail_window_sec\v=\f300\v\f\r\n");
    ps_config_t cfg;
    int ret = ps_config_load(tmp_path, &cfg);
    assert_int_equal(ret, PS_OK);
    assert_int_equal(cfg.fail_threshold, 20);
    assert_int_equal(cfg.fail_window_sec, 300);
    cleanup_tmp();
}

// --- ps_config_load: boundary values ---

static void test_config_load_boundary_min(void **state) {
    (void)state;
    write_tmp_config("fail_threshold = 1\n"
                     "fail_window_sec = 1\n"
                     "max_tracked_ips = 1\n"
                     "alert_cooldown_sec = 0\n");
    ps_config_t cfg;
    int ret = ps_config_load(tmp_path, &cfg);
    assert_int_equal(ret, PS_OK);
    assert_int_equal(cfg.fail_threshold, 1);
    assert_int_equal(cfg.fail_window_sec, 1);
    assert_int_equal(cfg.max_tracked_ips, 1);
    assert_int_equal(cfg.alert_cooldown_sec, 0);
    cleanup_tmp();
}

static void test_config_load_boundary_max(void **state) {
    (void)state;
    write_tmp_config("fail_threshold = 10000\n"
                     "fail_window_sec = 86400\n"
                     "max_tracked_ips = 100000\n"
                     "alert_cooldown_sec = 86400\n");
    ps_config_t cfg;
    int ret = ps_config_load(tmp_path, &cfg);
    assert_int_equal(ret, PS_OK);
    assert_int_equal(cfg.fail_threshold, 10000);
    assert_int_equal(cfg.fail_window_sec, 86400);
    assert_int_equal(cfg.max_tracked_ips, 100000);
    assert_int_equal(cfg.alert_cooldown_sec, 86400);
    cleanup_tmp();
}

// --- ps_config_load: out-of-range values ---

static void test_config_load_out_of_range_high(void **state) {
    (void)state;
    write_tmp_config("fail_threshold = 99999\n");
    ps_config_t cfg;
    int ret = ps_config_load(tmp_path, &cfg);
    assert_int_equal(ret, PS_ERR_CONFIG);
    cleanup_tmp();
}

static void test_config_load_out_of_range_low(void **state) {
    (void)state;
    write_tmp_config("fail_threshold = 0\n");
    ps_config_t cfg;
    int ret = ps_config_load(tmp_path, &cfg);
    assert_int_equal(ret, PS_ERR_CONFIG);
    cleanup_tmp();
}

static void test_config_load_negative_value(void **state) {
    (void)state;
    write_tmp_config("fail_threshold = -5\n");
    ps_config_t cfg;
    int ret = ps_config_load(tmp_path, &cfg);
    assert_int_equal(ret, PS_ERR_CONFIG);
    cleanup_tmp();
}

static void test_config_load_non_numeric(void **state) {
    (void)state;
    write_tmp_config("fail_threshold = abc\n");
    ps_config_t cfg;
    int ret = ps_config_load(tmp_path, &cfg);
    assert_int_equal(ret, PS_ERR_CONFIG);
    cleanup_tmp();
}

// --- ps_config_load: missing equals ---

static void test_config_load_missing_equals(void **state) {
    (void)state;
    write_tmp_config("this line has no equals sign\n");
    ps_config_t cfg;
    int ret = ps_config_load(tmp_path, &cfg);
    assert_int_equal(ret, PS_ERR_CONFIG);
    cleanup_tmp();
}

// --- ps_config_load: unknown key (warning, not error) ---

static void test_config_load_unknown_key(void **state) {
    (void)state;
    write_tmp_config("unknown_key = value\n"
                     "fail_threshold = 5\n");
    ps_config_t cfg;
    int ret = ps_config_load(tmp_path, &cfg);
    // Unknown keys produce warnings but not errors
    assert_int_equal(ret, PS_OK);
    assert_int_equal(cfg.fail_threshold, 5);
    cleanup_tmp();
}

// --- ps_config_load: partial config keeps defaults for unset keys ---

static void test_config_load_partial(void **state) {
    (void)state;
    write_tmp_config("fail_threshold = 42\n");
    ps_config_t cfg;
    int ret = ps_config_load(tmp_path, &cfg);
    assert_int_equal(ret, PS_OK);
    assert_int_equal(cfg.fail_threshold, 42);
    // Other values should remain at defaults
    assert_int_equal(cfg.fail_window_sec, PS_DEFAULT_FAIL_WINDOW_SEC);
    assert_int_equal(cfg.max_tracked_ips, PS_DEFAULT_MAX_TRACKED_IPS);
    assert_int_equal(cfg.alert_cooldown_sec, PS_DEFAULT_ALERT_COOLDOWN_SEC);
    cleanup_tmp();
}

// --- enable_notification_type ---

static void test_notify_type_default_is_all(void **state) {
    (void)state;
    ps_config_t cfg;
    ps_config_defaults(&cfg);
    assert_int_equal(cfg.enable_notification_type, PS_NOTIFY_ALL);
}

static void test_notify_type_single_category(void **state) {
    (void)state;
    write_tmp_config("enable_notification_type = login_success\n");
    ps_config_t cfg;
    int ret = ps_config_load(tmp_path, &cfg);
    assert_int_equal(ret, PS_OK);
    assert_int_equal(cfg.enable_notification_type, PS_NOTIFY_LOGIN_SUCCESS);
    cleanup_tmp();
}

static void test_notify_type_multiple_categories(void **state) {
    (void)state;
    write_tmp_config("enable_notification_type = login_success,brute_force\n");
    ps_config_t cfg;
    int ret = ps_config_load(tmp_path, &cfg);
    assert_int_equal(ret, PS_OK);
    assert_int_equal(cfg.enable_notification_type,
                     PS_NOTIFY_LOGIN_SUCCESS | PS_NOTIFY_BRUTE_FORCE);
    cleanup_tmp();
}

static void test_notify_type_all_sentinel(void **state) {
    (void)state;
    write_tmp_config("enable_notification_type = all\n");
    ps_config_t cfg;
    int ret = ps_config_load(tmp_path, &cfg);
    assert_int_equal(ret, PS_OK);
    assert_int_equal(cfg.enable_notification_type, PS_NOTIFY_ALL);
    cleanup_tmp();
}

static void test_notify_type_whitespace_and_case(void **state) {
    (void)state;
    write_tmp_config("enable_notification_type =  Login_Success , "
                     "Session_Open ,BRUTE_FORCE\n");
    ps_config_t cfg;
    int ret = ps_config_load(tmp_path, &cfg);
    assert_int_equal(ret, PS_OK);
    assert_int_equal(cfg.enable_notification_type, PS_NOTIFY_LOGIN_SUCCESS |
                                                       PS_NOTIFY_SESSION_OPEN |
                                                       PS_NOTIFY_BRUTE_FORCE);
    cleanup_tmp();
}

static void test_notify_type_all_six_categories(void **state) {
    (void)state;
    write_tmp_config("enable_notification_type = login_success,login_failed,"
                     "session_open,session_close,brute_force,"
                     "login_after_failures\n");
    ps_config_t cfg;
    int ret = ps_config_load(tmp_path, &cfg);
    assert_int_equal(ret, PS_OK);
    assert_int_equal(cfg.enable_notification_type, PS_NOTIFY_ALL);
    cleanup_tmp();
}

static void test_notify_type_login_after_failures_token(void **state) {
    (void)state;
    write_tmp_config("enable_notification_type = login_after_failures\n");
    ps_config_t cfg;
    int ret = ps_config_load(tmp_path, &cfg);
    assert_int_equal(ret, PS_OK);
    assert_int_equal(cfg.enable_notification_type,
                     PS_NOTIFY_LOGIN_AFTER_FAILURES);
    cleanup_tmp();
}

// --- success_after_fail_threshold ---

static void test_success_after_fail_threshold_default(void **state) {
    (void)state;
    ps_config_t cfg;
    ps_config_defaults(&cfg);
    assert_int_equal(cfg.success_after_fail_threshold,
                     PS_DEFAULT_SUCCESS_AFTER_FAIL_THRESHOLD);
}

static void test_success_after_fail_threshold_loads(void **state) {
    (void)state;
    write_tmp_config("success_after_fail_threshold = 7\n");
    ps_config_t cfg;
    assert_int_equal(ps_config_load(tmp_path, &cfg), PS_OK);
    assert_int_equal(cfg.success_after_fail_threshold, 7);
    cleanup_tmp();
}

static void test_success_after_fail_threshold_zero_disables(void **state) {
    (void)state;
    write_tmp_config("success_after_fail_threshold = 0\n");
    ps_config_t cfg;
    assert_int_equal(ps_config_load(tmp_path, &cfg), PS_OK);
    assert_int_equal(cfg.success_after_fail_threshold, 0);
    cleanup_tmp();
}

static void test_success_after_fail_threshold_out_of_range(void **state) {
    (void)state;
    ps_config_t cfg;
    write_tmp_config("success_after_fail_threshold = -1\n");
    assert_int_equal(ps_config_load(tmp_path, &cfg), PS_ERR_CONFIG);
    cleanup_tmp();
    write_tmp_config("success_after_fail_threshold = 10001\n");
    assert_int_equal(ps_config_load(tmp_path, &cfg), PS_ERR_CONFIG);
    cleanup_tmp();
}

// --- trusted_sources ---

static void test_trusted_sources_default_empty(void **state) {
    (void)state;
    ps_config_t cfg;
    ps_config_defaults(&cfg);
    assert_int_equal(cfg.trusted_sources_count, 0);
    assert_int_equal(ps_config_ip_trusted(&cfg, "10.0.0.1"), 0);
}

static void test_trusted_sources_ipv4_cidr_and_host(void **state) {
    (void)state;
    write_tmp_config("trusted_sources = 10.0.0.0/8, 203.0.113.7\n");
    ps_config_t cfg;
    assert_int_equal(ps_config_load(tmp_path, &cfg), PS_OK);
    assert_int_equal(cfg.trusted_sources_count, 2);

    assert_int_equal(ps_config_ip_trusted(&cfg, "10.0.0.1"), 1);
    assert_int_equal(ps_config_ip_trusted(&cfg, "10.255.255.255"), 1);
    assert_int_equal(ps_config_ip_trusted(&cfg, "11.0.0.1"), 0);
    // A bare address is a /32: only the exact host matches.
    assert_int_equal(ps_config_ip_trusted(&cfg, "203.0.113.7"), 1);
    assert_int_equal(ps_config_ip_trusted(&cfg, "203.0.113.8"), 0);
    cleanup_tmp();
}

// A prefix that is not a multiple of 8 exercises the partial-byte mask.
static void test_trusted_sources_non_octet_prefix(void **state) {
    (void)state;
    write_tmp_config("trusted_sources = 192.168.16.0/20\n");
    ps_config_t cfg;
    assert_int_equal(ps_config_load(tmp_path, &cfg), PS_OK);

    assert_int_equal(ps_config_ip_trusted(&cfg, "192.168.16.1"), 1);
    assert_int_equal(ps_config_ip_trusted(&cfg, "192.168.31.254"), 1);
    assert_int_equal(ps_config_ip_trusted(&cfg, "192.168.32.1"), 0);
    assert_int_equal(ps_config_ip_trusted(&cfg, "192.168.15.255"), 0);
    cleanup_tmp();
}

// Host bits set in the configured network are ignored, as with ip-route.
static void test_trusted_sources_host_bits_ignored(void **state) {
    (void)state;
    write_tmp_config("trusted_sources = 10.1.2.3/8\n");
    ps_config_t cfg;
    assert_int_equal(ps_config_load(tmp_path, &cfg), PS_OK);
    assert_int_equal(ps_config_ip_trusted(&cfg, "10.200.0.1"), 1);
    cleanup_tmp();
}

static void test_trusted_sources_ipv6(void **state) {
    (void)state;
    write_tmp_config("trusted_sources = 2001:db8::/32, fe80::1\n");
    ps_config_t cfg;
    assert_int_equal(ps_config_load(tmp_path, &cfg), PS_OK);
    assert_int_equal(cfg.trusted_sources_count, 2);

    assert_int_equal(ps_config_ip_trusted(&cfg, "2001:db8:1234::1"), 1);
    assert_int_equal(ps_config_ip_trusted(&cfg, "2001:db9::1"), 0);
    assert_int_equal(ps_config_ip_trusted(&cfg, "fe80::1"), 1);
    assert_int_equal(ps_config_ip_trusted(&cfg, "fe80::2"), 0);
    // Families never cross-match.
    assert_int_equal(ps_config_ip_trusted(&cfg, "32.1.13.184"), 0);
    cleanup_tmp();
}

static void test_trusted_sources_ipv4_mapped_ipv6(void **state) {
    (void)state;
    write_tmp_config("trusted_sources = 10.0.0.0/8\n");
    ps_config_t cfg;
    assert_int_equal(ps_config_load(tmp_path, &cfg), PS_OK);
    assert_int_equal(ps_config_ip_trusted(&cfg, "::ffff:10.1.2.3"), 1);
    assert_int_equal(ps_config_ip_trusted(&cfg, "::ffff:11.1.2.3"), 0);
    cleanup_tmp();
}

static void test_trusted_sources_unparseable_ip_not_trusted(void **state) {
    (void)state;
    write_tmp_config("trusted_sources = 10.0.0.0/8\n");
    ps_config_t cfg;
    assert_int_equal(ps_config_load(tmp_path, &cfg), PS_OK);
    assert_int_equal(ps_config_ip_trusted(&cfg, ""), 0);
    assert_int_equal(ps_config_ip_trusted(&cfg, NULL), 0);
    assert_int_equal(ps_config_ip_trusted(&cfg, "not-an-ip"), 0);
    assert_int_equal(ps_config_ip_trusted(&cfg, "10.0.0.1 "), 0);
    cleanup_tmp();
}

static void test_trusted_sources_empty_value_clears(void **state) {
    (void)state;
    write_tmp_config("trusted_sources = 10.0.0.0/8\n"
                     "trusted_sources =\n");
    ps_config_t cfg;
    assert_int_equal(ps_config_load(tmp_path, &cfg), PS_OK);
    assert_int_equal(cfg.trusted_sources_count, 0);
    cleanup_tmp();
}

static void test_trusted_sources_malformed_rejected(void **state) {
    (void)state;
    static const char *const bad[] = {
        "trusted_sources = 10.0.0.0/33\n",        // prefix too long for IPv4
        "trusted_sources = 2001:db8::/129\n",     // prefix too long for IPv6
        "trusted_sources = 0.0.0.0/0\n",          // would trust everything
        "trusted_sources = ::/0\n",               //
        "trusted_sources = 10.0.0.0/\n",          // empty prefix
        "trusted_sources = 10.0.0.0/ 8\n",        // whitespace in prefix
        "trusted_sources = 10.0.0.0/+8\n",        // signed prefix
        "trusted_sources = 10.0.0.0/8x\n",        // trailing garbage
        "trusted_sources = 10.0.0/8\n",           // short address
        "trusted_sources = example.com\n",        // hostnames are not resolved
        "trusted_sources = 10.0.0.1,,10.0.0.2\n", // empty element
        "trusted_sources = 10.0.0.1,\n",          // trailing comma
        "trusted_sources = /8\n",                 // no address
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        write_tmp_config(bad[i]);
        ps_config_t cfg;
        assert_int_equal(ps_config_load(tmp_path, &cfg), PS_ERR_CONFIG);
        // A rejected list must never leave a partial allowlist behind.
        assert_int_equal(cfg.trusted_sources_count, 0);
        cleanup_tmp();
    }
}

// Write "trusted_sources = 10.0.0.1,10.0.1.1,...\n" with n entries into buf.
// snprintf returns the length it wanted to write, so each append is checked
// against the space left before the offset advances; an oversized request
// fails the test instead of walking the offset past the buffer.
static void build_trusted_sources_line(char *buf, size_t size, int n) {
    int w = snprintf(buf, size, "trusted_sources = ");
    assert_true(w > 0 && (size_t)w < size);
    size_t off = (size_t)w;
    for (int i = 0; i < n; i++) {
        w = snprintf(buf + off, size - off, "%s10.0.%d.1", i ? "," : "", i);
        assert_true(w > 0 && (size_t)w < size - off);
        off += (size_t)w;
    }
    w = snprintf(buf + off, size - off, "\n");
    assert_true(w > 0 && (size_t)w < size - off);
}

static void test_trusted_sources_too_many_rejected(void **state) {
    (void)state;
    char content[1024];
    build_trusted_sources_line(content, sizeof(content),
                               PS_MAX_TRUSTED_SOURCES + 1);
    write_tmp_config(content);
    ps_config_t cfg;
    assert_int_equal(ps_config_load(tmp_path, &cfg), PS_ERR_CONFIG);
    assert_int_equal(cfg.trusted_sources_count, 0);
    cleanup_tmp();
}

static void test_trusted_sources_max_entries_accepted(void **state) {
    (void)state;
    char content[1024];
    build_trusted_sources_line(content, sizeof(content),
                               PS_MAX_TRUSTED_SOURCES);
    write_tmp_config(content);
    ps_config_t cfg;
    assert_int_equal(ps_config_load(tmp_path, &cfg), PS_OK);
    assert_int_equal(cfg.trusted_sources_count, PS_MAX_TRUSTED_SOURCES);
    assert_int_equal(ps_config_ip_trusted(&cfg, "10.0.31.1"), 1);
    cleanup_tmp();
}

static void test_notify_type_unknown_category_rejected(void **state) {
    (void)state;
    write_tmp_config("enable_notification_type = login_success,bogus\n");
    ps_config_t cfg;
    int ret = ps_config_load(tmp_path, &cfg);
    assert_int_equal(ret, PS_ERR_CONFIG);
    cleanup_tmp();
}

static void test_notify_type_empty_value_rejected(void **state) {
    (void)state;
    write_tmp_config("enable_notification_type = \n");
    ps_config_t cfg;
    int ret = ps_config_load(tmp_path, &cfg);
    assert_int_equal(ret, PS_ERR_CONFIG);
    cleanup_tmp();
}

static void test_notify_type_empty_element_rejected(void **state) {
    (void)state;
    write_tmp_config("enable_notification_type = login_success,,brute_force\n");
    ps_config_t cfg;
    int ret = ps_config_load(tmp_path, &cfg);
    assert_int_equal(ret, PS_ERR_CONFIG);
    cleanup_tmp();
}

static void test_notify_type_omitted_keeps_default(void **state) {
    (void)state;
    write_tmp_config("fail_threshold = 7\n");
    ps_config_t cfg;
    int ret = ps_config_load(tmp_path, &cfg);
    assert_int_equal(ret, PS_OK);
    assert_int_equal(cfg.enable_notification_type, PS_NOTIFY_ALL);
    cleanup_tmp();
}

// --- Validators: telegram_bot_token rejection ---

static void test_validate_telegram_token_no_colon(void **state) {
    (void)state;
    write_tmp_config("telegram_bot_token = abc123\n"
                     "telegram_chat_id = 12345\n");
    ps_config_t cfg;
    assert_int_equal(ps_config_load(tmp_path, &cfg), PS_ERR_CONFIG);
    cleanup_tmp();
}

static void test_validate_telegram_token_short_suffix(void **state) {
    (void)state;
    write_tmp_config("telegram_bot_token = 12345:short\n"
                     "telegram_chat_id = 12345\n");
    ps_config_t cfg;
    assert_int_equal(ps_config_load(tmp_path, &cfg), PS_ERR_CONFIG);
    cleanup_tmp();
}

static void test_validate_telegram_token_bad_chars(void **state) {
    (void)state;
    write_tmp_config(
        "telegram_bot_token = 12345:ABCDEFGHIJKLMNOPQRST/sendMessage\n"
        "telegram_chat_id = 12345\n");
    ps_config_t cfg;
    assert_int_equal(ps_config_load(tmp_path, &cfg), PS_ERR_CONFIG);
    cleanup_tmp();
}

static void test_validate_telegram_chat_id_missing(void **state) {
    (void)state;
    write_tmp_config("telegram_bot_token = 12345:ABCDEFGHIJKLMNOPQRSTUVWX\n");
    ps_config_t cfg;
    assert_int_equal(ps_config_load(tmp_path, &cfg), PS_ERR_CONFIG);
    cleanup_tmp();
}

static void test_validate_telegram_chat_id_bad(void **state) {
    (void)state;
    write_tmp_config("telegram_bot_token = 12345:ABCDEFGHIJKLMNOPQRSTUVWX\n"
                     "telegram_chat_id = bad chat id\n");
    ps_config_t cfg;
    assert_int_equal(ps_config_load(tmp_path, &cfg), PS_ERR_CONFIG);
    cleanup_tmp();
}

// --- Validators: webhook URL scheme/charset rejection ---

static void test_validate_webhook_http_scheme(void **state) {
    (void)state;
    write_tmp_config("slack_webhook_url = http://hooks.slack.com/x\n");
    ps_config_t cfg;
    assert_int_equal(ps_config_load(tmp_path, &cfg), PS_ERR_CONFIG);
    cleanup_tmp();
}

static void test_validate_webhook_file_scheme(void **state) {
    (void)state;
    write_tmp_config("webhook_url = file:///etc/passwd\n");
    ps_config_t cfg;
    assert_int_equal(ps_config_load(tmp_path, &cfg), PS_ERR_CONFIG);
    cleanup_tmp();
}

static void test_validate_webhook_no_scheme(void **state) {
    (void)state;
    write_tmp_config("teams_webhook_url = outlook.office.com/webhook/abc\n");
    ps_config_t cfg;
    assert_int_equal(ps_config_load(tmp_path, &cfg), PS_ERR_CONFIG);
    cleanup_tmp();
}

static void test_validate_webhook_with_quote(void **state) {
    (void)state;
    // Embedded double quote would break the curl-config file we generate.
    write_tmp_config("discord_webhook_url = https://discord.com/\"abc\n");
    ps_config_t cfg;
    assert_int_equal(ps_config_load(tmp_path, &cfg), PS_ERR_CONFIG);
    cleanup_tmp();
}

static void test_validate_webhook_with_backslash(void **state) {
    (void)state;
    write_tmp_config("webhook_url = https://example.com/a\\b\n");
    ps_config_t cfg;
    assert_int_equal(ps_config_load(tmp_path, &cfg), PS_ERR_CONFIG);
    cleanup_tmp();
}

// --- webhook mTLS parse + validation ---
//
// Each test writes a small placeholder file as the "cert" or "key" — the
// validator only checks file metadata (existence, regular-file, perms,
// ownership), it doesn't parse PEM. So bytes "dummy" suffice.

static char tls_cert_path[256];
static char tls_key_path[256];
static char tls_ca_path[256];

static int write_tls_file(char *path_buf, size_t buf_len, mode_t mode) {
    snprintf(path_buf, buf_len, "/tmp/pamsignal_test_tls_XXXXXX");
    int fd = mkstemp(path_buf);
    if (fd < 0)
        return -1;
    if (write(fd, "dummy\n", 6) != 6) {
        close(fd);
        unlink(path_buf);
        return -1;
    }
    close(fd);
    if (chmod(path_buf, mode) < 0) {
        unlink(path_buf);
        return -1;
    }
    return 0;
}

static void cleanup_tls_files(void) {
    if (tls_cert_path[0])
        unlink(tls_cert_path);
    if (tls_key_path[0])
        unlink(tls_key_path);
    if (tls_ca_path[0])
        unlink(tls_ca_path);
    tls_cert_path[0] = '\0';
    tls_key_path[0] = '\0';
    tls_ca_path[0] = '\0';
}

static void test_mtls_cert_and_key_load(void **state) {
    (void)state;
    assert_int_equal(write_tls_file(tls_cert_path, sizeof(tls_cert_path), 0644),
                     0);
    assert_int_equal(write_tls_file(tls_key_path, sizeof(tls_key_path), 0600),
                     0);
    char content[1024];
    snprintf(content, sizeof(content),
             "webhook_url = https://example.com/hook\n"
             "webhook_client_cert = %s\n"
             "webhook_client_key = %s\n",
             tls_cert_path, tls_key_path);
    write_tmp_config(content);
    ps_config_t cfg;
    int ret = ps_config_load(tmp_path, &cfg);
    assert_int_equal(ret, PS_OK);
    assert_string_equal(cfg.webhook_client_cert, tls_cert_path);
    assert_string_equal(cfg.webhook_client_key, tls_key_path);
    cleanup_tmp();
    cleanup_tls_files();
}

static void test_mtls_with_ca_bundle(void **state) {
    (void)state;
    assert_int_equal(write_tls_file(tls_cert_path, sizeof(tls_cert_path), 0644),
                     0);
    assert_int_equal(write_tls_file(tls_key_path, sizeof(tls_key_path), 0600),
                     0);
    assert_int_equal(write_tls_file(tls_ca_path, sizeof(tls_ca_path), 0644), 0);
    char content[1536];
    snprintf(content, sizeof(content),
             "webhook_url = https://example.com/hook\n"
             "webhook_client_cert = %s\n"
             "webhook_client_key = %s\n"
             "webhook_ca_bundle = %s\n",
             tls_cert_path, tls_key_path, tls_ca_path);
    write_tmp_config(content);
    ps_config_t cfg;
    int ret = ps_config_load(tmp_path, &cfg);
    assert_int_equal(ret, PS_OK);
    assert_string_equal(cfg.webhook_ca_bundle, tls_ca_path);
    cleanup_tmp();
    cleanup_tls_files();
}

static void test_mtls_cert_without_key_rejected(void **state) {
    (void)state;
    assert_int_equal(write_tls_file(tls_cert_path, sizeof(tls_cert_path), 0644),
                     0);
    char content[1024];
    snprintf(content, sizeof(content),
             "webhook_url = https://example.com/hook\n"
             "webhook_client_cert = %s\n",
             tls_cert_path);
    write_tmp_config(content);
    ps_config_t cfg;
    assert_int_equal(ps_config_load(tmp_path, &cfg), PS_ERR_CONFIG);
    cleanup_tmp();
    cleanup_tls_files();
}

static void test_mtls_key_without_cert_rejected(void **state) {
    (void)state;
    assert_int_equal(write_tls_file(tls_key_path, sizeof(tls_key_path), 0600),
                     0);
    char content[1024];
    snprintf(content, sizeof(content),
             "webhook_url = https://example.com/hook\n"
             "webhook_client_key = %s\n",
             tls_key_path);
    write_tmp_config(content);
    ps_config_t cfg;
    assert_int_equal(ps_config_load(tmp_path, &cfg), PS_ERR_CONFIG);
    cleanup_tmp();
    cleanup_tls_files();
}

static void test_mtls_world_readable_key_rejected(void **state) {
    (void)state;
    assert_int_equal(write_tls_file(tls_cert_path, sizeof(tls_cert_path), 0644),
                     0);
    assert_int_equal(write_tls_file(tls_key_path, sizeof(tls_key_path), 0644),
                     0);
    char content[1024];
    snprintf(content, sizeof(content),
             "webhook_url = https://example.com/hook\n"
             "webhook_client_cert = %s\n"
             "webhook_client_key = %s\n",
             tls_cert_path, tls_key_path);
    write_tmp_config(content);
    ps_config_t cfg;
    assert_int_equal(ps_config_load(tmp_path, &cfg), PS_ERR_CONFIG);
    cleanup_tmp();
    cleanup_tls_files();
}

static void test_mtls_group_readable_key_rejected(void **state) {
    (void)state;
    assert_int_equal(write_tls_file(tls_cert_path, sizeof(tls_cert_path), 0644),
                     0);
    assert_int_equal(write_tls_file(tls_key_path, sizeof(tls_key_path), 0640),
                     0);
    char content[1024];
    snprintf(content, sizeof(content),
             "webhook_url = https://example.com/hook\n"
             "webhook_client_cert = %s\n"
             "webhook_client_key = %s\n",
             tls_cert_path, tls_key_path);
    write_tmp_config(content);
    ps_config_t cfg;
    assert_int_equal(ps_config_load(tmp_path, &cfg), PS_ERR_CONFIG);
    cleanup_tmp();
    cleanup_tls_files();
}

static void test_mtls_symlink_rejected(void **state) {
    (void)state;
    assert_int_equal(write_tls_file(tls_cert_path, sizeof(tls_cert_path), 0644),
                     0);
    assert_int_equal(write_tls_file(tls_key_path, sizeof(tls_key_path), 0600),
                     0);
    char link_path[256];
    snprintf(link_path, sizeof(link_path), "/tmp/pamsignal_test_keylink_%d",
             getpid());
    unlink(link_path);
    if (symlink(tls_key_path, link_path) != 0) {
        cleanup_tls_files();
        skip();
    }
    char content[1024];
    snprintf(content, sizeof(content),
             "webhook_url = https://example.com/hook\n"
             "webhook_client_cert = %s\n"
             "webhook_client_key = %s\n",
             tls_cert_path, link_path);
    write_tmp_config(content);
    ps_config_t cfg;
    assert_int_equal(ps_config_load(tmp_path, &cfg), PS_ERR_CONFIG);
    unlink(link_path);
    cleanup_tmp();
    cleanup_tls_files();
}

static void test_mtls_nonexistent_path_rejected(void **state) {
    (void)state;
    write_tmp_config(
        "webhook_url = https://example.com/hook\n"
        "webhook_client_cert = /nonexistent/pamsignal-cert-does-not-exist\n"
        "webhook_client_key = /nonexistent/pamsignal-key-does-not-exist\n");
    ps_config_t cfg;
    assert_int_equal(ps_config_load(tmp_path, &cfg), PS_ERR_CONFIG);
    cleanup_tmp();
}

static void test_mtls_without_webhook_url_rejected(void **state) {
    (void)state;
    assert_int_equal(write_tls_file(tls_cert_path, sizeof(tls_cert_path), 0644),
                     0);
    assert_int_equal(write_tls_file(tls_key_path, sizeof(tls_key_path), 0600),
                     0);
    char content[1024];
    snprintf(content, sizeof(content),
             "webhook_client_cert = %s\n"
             "webhook_client_key = %s\n",
             tls_cert_path, tls_key_path);
    write_tmp_config(content);
    ps_config_t cfg;
    assert_int_equal(ps_config_load(tmp_path, &cfg), PS_ERR_CONFIG);
    cleanup_tmp();
    cleanup_tls_files();
}

static void test_mtls_path_with_quote_rejected(void **state) {
    (void)state;
    write_tmp_config("webhook_url = https://example.com/hook\n"
                     "webhook_client_cert = /etc/pamsignal/cert\"name.crt\n"
                     "webhook_client_key = /etc/pamsignal/key.key\n");
    ps_config_t cfg;
    assert_int_equal(ps_config_load(tmp_path, &cfg), PS_ERR_CONFIG);
    cleanup_tmp();
}

static void test_mtls_combined_with_auth_header(void **state) {
    (void)state;
    // Bearer + mTLS together — the common Wazuh / corporate-SIEM pattern.
    assert_int_equal(write_tls_file(tls_cert_path, sizeof(tls_cert_path), 0644),
                     0);
    assert_int_equal(write_tls_file(tls_key_path, sizeof(tls_key_path), 0600),
                     0);
    char content[1536];
    snprintf(content, sizeof(content),
             "webhook_url = https://example.com/hook\n"
             "webhook_auth_header = Authorization: Bearer xyz\n"
             "webhook_client_cert = %s\n"
             "webhook_client_key = %s\n",
             tls_cert_path, tls_key_path);
    write_tmp_config(content);
    ps_config_t cfg;
    int ret = ps_config_load(tmp_path, &cfg);
    assert_int_equal(ret, PS_OK);
    assert_string_equal(cfg.webhook_auth_header, "Authorization: Bearer xyz");
    assert_string_equal(cfg.webhook_client_cert, tls_cert_path);
    cleanup_tmp();
    cleanup_tls_files();
}

// --- webhook_auth_header parse + validation ---

static void test_webhook_auth_header_bearer_loads(void **state) {
    (void)state;
    write_tmp_config(
        "webhook_url = https://example.com/hook\n"
        "webhook_auth_header = Authorization: Bearer s3cr3t-token-abc.123\n");
    ps_config_t cfg;
    int ret = ps_config_load(tmp_path, &cfg);
    assert_int_equal(ret, PS_OK);
    assert_string_equal(cfg.webhook_auth_header,
                        "Authorization: Bearer s3cr3t-token-abc.123");
    cleanup_tmp();
}

static void test_webhook_auth_header_api_key_loads(void **state) {
    (void)state;
    write_tmp_config("webhook_url = https://example.com/hook\n"
                     "webhook_auth_header = X-API-Key: deadbeef\n");
    ps_config_t cfg;
    int ret = ps_config_load(tmp_path, &cfg);
    assert_int_equal(ret, PS_OK);
    assert_string_equal(cfg.webhook_auth_header, "X-API-Key: deadbeef");
    cleanup_tmp();
}

static void test_webhook_auth_header_default_empty(void **state) {
    (void)state;
    write_tmp_config("webhook_url = https://example.com/hook\n");
    ps_config_t cfg;
    int ret = ps_config_load(tmp_path, &cfg);
    assert_int_equal(ret, PS_OK);
    assert_int_equal(cfg.webhook_auth_header[0], '\0');
    cleanup_tmp();
}

static void test_webhook_auth_header_without_url_rejected(void **state) {
    (void)state;
    write_tmp_config("webhook_auth_header = Authorization: Bearer xyz\n");
    ps_config_t cfg;
    assert_int_equal(ps_config_load(tmp_path, &cfg), PS_ERR_CONFIG);
    cleanup_tmp();
}

static void test_webhook_auth_header_no_colon_rejected(void **state) {
    (void)state;
    write_tmp_config("webhook_url = https://example.com/hook\n"
                     "webhook_auth_header = AuthorizationBearer xyz\n");
    ps_config_t cfg;
    assert_int_equal(ps_config_load(tmp_path, &cfg), PS_ERR_CONFIG);
    cleanup_tmp();
}

static void test_webhook_auth_header_empty_name_rejected(void **state) {
    (void)state;
    write_tmp_config("webhook_url = https://example.com/hook\n"
                     "webhook_auth_header = : Bearer xyz\n");
    ps_config_t cfg;
    assert_int_equal(ps_config_load(tmp_path, &cfg), PS_ERR_CONFIG);
    cleanup_tmp();
}

static void test_webhook_auth_header_with_quote_rejected(void **state) {
    (void)state;
    // Embedded `"` would terminate the curl-config quoted value.
    write_tmp_config("webhook_url = https://example.com/hook\n"
                     "webhook_auth_header = Authorization: Bearer ab\"cd\n");
    ps_config_t cfg;
    assert_int_equal(ps_config_load(tmp_path, &cfg), PS_ERR_CONFIG);
    cleanup_tmp();
}

static void test_webhook_auth_header_with_backslash_rejected(void **state) {
    (void)state;
    write_tmp_config("webhook_url = https://example.com/hook\n"
                     "webhook_auth_header = X-Token: abc\\def\n");
    ps_config_t cfg;
    assert_int_equal(ps_config_load(tmp_path, &cfg), PS_ERR_CONFIG);
    cleanup_tmp();
}

static void test_webhook_auth_header_bad_name_char_rejected(void **state) {
    (void)state;
    // Space inside the header name is not a valid token char per RFC 7230.
    write_tmp_config("webhook_url = https://example.com/hook\n"
                     "webhook_auth_header = X Token: abc\n");
    ps_config_t cfg;
    assert_int_equal(ps_config_load(tmp_path, &cfg), PS_ERR_CONFIG);
    cleanup_tmp();
}

// --- Validators: WhatsApp field rejection ---

static void test_validate_whatsapp_phone_id_non_numeric(void **state) {
    (void)state;
    write_tmp_config("whatsapp_access_token = abc123\n"
                     "whatsapp_phone_number_id = NOT_NUMERIC\n"
                     "whatsapp_recipient = 14155551212\n");
    ps_config_t cfg;
    assert_int_equal(ps_config_load(tmp_path, &cfg), PS_ERR_CONFIG);
    cleanup_tmp();
}

static void test_validate_whatsapp_recipient_non_numeric(void **state) {
    (void)state;
    write_tmp_config("whatsapp_access_token = abc123\n"
                     "whatsapp_phone_number_id = 1234567890\n"
                     "whatsapp_recipient = +1-415-555-1212\n");
    ps_config_t cfg;
    assert_int_equal(ps_config_load(tmp_path, &cfg), PS_ERR_CONFIG);
    cleanup_tmp();
}

static void test_validate_whatsapp_token_bad_char(void **state) {
    (void)state;
    write_tmp_config("whatsapp_access_token = abc 123\n"
                     "whatsapp_phone_number_id = 1234567890\n"
                     "whatsapp_recipient = 14155551212\n");
    ps_config_t cfg;
    assert_int_equal(ps_config_load(tmp_path, &cfg), PS_ERR_CONFIG);
    cleanup_tmp();
}

// --- Config file integrity: permission checks ---

static void test_config_rejects_world_writable(void **state) {
    (void)state;
    write_tmp_config("fail_threshold = 5\n");
    // Re-open the path with mode 0666 — group AND world writable.
    chmod(tmp_path, 0666);
    ps_config_t cfg;
    int ret = ps_config_load(tmp_path, &cfg);
    assert_int_equal(ret, PS_ERR_CONFIG);
    cleanup_tmp();
}

static void test_config_rejects_group_writable(void **state) {
    (void)state;
    write_tmp_config("fail_threshold = 5\n");
    chmod(tmp_path, 0660);
    ps_config_t cfg;
    int ret = ps_config_load(tmp_path, &cfg);
    assert_int_equal(ret, PS_ERR_CONFIG);
    cleanup_tmp();
}

static void test_config_rejects_symlink(void **state) {
    (void)state;
    write_tmp_config("fail_threshold = 5\n");
    char link_path[256];
    snprintf(link_path, sizeof(link_path), "/tmp/pamsignal_test_link_%d.conf",
             getpid());
    unlink(link_path);
    if (symlink(tmp_path, link_path) != 0) {
        cleanup_tmp();
        skip();
    }
    ps_config_t cfg;
    int ret = ps_config_load(link_path, &cfg);
    assert_int_equal(ret, PS_ERR_CONFIG);
    unlink(link_path);
    cleanup_tmp();
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_config_defaults),
        cmocka_unit_test(test_config_load_missing_file),
        cmocka_unit_test(test_config_load_empty_file),
        cmocka_unit_test(test_config_load_comments_only),
        cmocka_unit_test(test_config_load_valid),
        cmocka_unit_test(test_config_load_all_channels),
        cmocka_unit_test(test_config_load_whitespace),
        cmocka_unit_test(test_config_load_whitespace_all_kinds),
        cmocka_unit_test(test_config_load_boundary_min),
        cmocka_unit_test(test_config_load_boundary_max),
        cmocka_unit_test(test_config_load_out_of_range_high),
        cmocka_unit_test(test_config_load_out_of_range_low),
        cmocka_unit_test(test_config_load_negative_value),
        cmocka_unit_test(test_config_load_non_numeric),
        cmocka_unit_test(test_config_load_missing_equals),
        cmocka_unit_test(test_config_load_unknown_key),
        cmocka_unit_test(test_config_load_partial),
        cmocka_unit_test(test_notify_type_default_is_all),
        cmocka_unit_test(test_notify_type_single_category),
        cmocka_unit_test(test_notify_type_multiple_categories),
        cmocka_unit_test(test_notify_type_all_sentinel),
        cmocka_unit_test(test_notify_type_whitespace_and_case),
        cmocka_unit_test(test_notify_type_all_six_categories),
        cmocka_unit_test(test_notify_type_login_after_failures_token),
        cmocka_unit_test(test_success_after_fail_threshold_default),
        cmocka_unit_test(test_success_after_fail_threshold_loads),
        cmocka_unit_test(test_success_after_fail_threshold_zero_disables),
        cmocka_unit_test(test_success_after_fail_threshold_out_of_range),
        cmocka_unit_test(test_trusted_sources_default_empty),
        cmocka_unit_test(test_trusted_sources_ipv4_cidr_and_host),
        cmocka_unit_test(test_trusted_sources_non_octet_prefix),
        cmocka_unit_test(test_trusted_sources_host_bits_ignored),
        cmocka_unit_test(test_trusted_sources_ipv6),
        cmocka_unit_test(test_trusted_sources_ipv4_mapped_ipv6),
        cmocka_unit_test(test_trusted_sources_unparseable_ip_not_trusted),
        cmocka_unit_test(test_trusted_sources_empty_value_clears),
        cmocka_unit_test(test_trusted_sources_malformed_rejected),
        cmocka_unit_test(test_trusted_sources_too_many_rejected),
        cmocka_unit_test(test_trusted_sources_max_entries_accepted),
        cmocka_unit_test(test_notify_type_unknown_category_rejected),
        cmocka_unit_test(test_notify_type_empty_value_rejected),
        cmocka_unit_test(test_notify_type_empty_element_rejected),
        cmocka_unit_test(test_notify_type_omitted_keeps_default),
        cmocka_unit_test(test_validate_telegram_token_no_colon),
        cmocka_unit_test(test_validate_telegram_token_short_suffix),
        cmocka_unit_test(test_validate_telegram_token_bad_chars),
        cmocka_unit_test(test_validate_telegram_chat_id_missing),
        cmocka_unit_test(test_validate_telegram_chat_id_bad),
        cmocka_unit_test(test_validate_webhook_http_scheme),
        cmocka_unit_test(test_validate_webhook_file_scheme),
        cmocka_unit_test(test_validate_webhook_no_scheme),
        cmocka_unit_test(test_validate_webhook_with_quote),
        cmocka_unit_test(test_validate_webhook_with_backslash),
        cmocka_unit_test(test_webhook_auth_header_bearer_loads),
        cmocka_unit_test(test_webhook_auth_header_api_key_loads),
        cmocka_unit_test(test_webhook_auth_header_default_empty),
        cmocka_unit_test(test_webhook_auth_header_without_url_rejected),
        cmocka_unit_test(test_webhook_auth_header_no_colon_rejected),
        cmocka_unit_test(test_webhook_auth_header_empty_name_rejected),
        cmocka_unit_test(test_webhook_auth_header_with_quote_rejected),
        cmocka_unit_test(test_webhook_auth_header_with_backslash_rejected),
        cmocka_unit_test(test_webhook_auth_header_bad_name_char_rejected),
        cmocka_unit_test(test_mtls_cert_and_key_load),
        cmocka_unit_test(test_mtls_with_ca_bundle),
        cmocka_unit_test(test_mtls_cert_without_key_rejected),
        cmocka_unit_test(test_mtls_key_without_cert_rejected),
        cmocka_unit_test(test_mtls_world_readable_key_rejected),
        cmocka_unit_test(test_mtls_group_readable_key_rejected),
        cmocka_unit_test(test_mtls_symlink_rejected),
        cmocka_unit_test(test_mtls_nonexistent_path_rejected),
        cmocka_unit_test(test_mtls_without_webhook_url_rejected),
        cmocka_unit_test(test_mtls_path_with_quote_rejected),
        cmocka_unit_test(test_mtls_combined_with_auth_header),
        cmocka_unit_test(test_validate_whatsapp_phone_id_non_numeric),
        cmocka_unit_test(test_validate_whatsapp_recipient_non_numeric),
        cmocka_unit_test(test_validate_whatsapp_token_bad_char),
        cmocka_unit_test(test_config_rejects_world_writable),
        cmocka_unit_test(test_config_rejects_group_writable),
        cmocka_unit_test(test_config_rejects_symlink),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
