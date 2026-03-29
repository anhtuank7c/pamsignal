#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <cmocka.h>

#include "config.h"
#include "init.h"

// Helper: write a temp config file, return path
static char tmp_path[256];

static int write_tmp_config(const char *content) {
    snprintf(tmp_path, sizeof(tmp_path), "/tmp/pamsignal_test_%d.conf",
             getpid());
    FILE *f = fopen(tmp_path, "w");
    if (!f)
        return -1;
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
    write_tmp_config("telegram_bot_token = abc123\n"
                     "telegram_chat_id = 12345\n"
                     "fail_threshold = 10\n"
                     "fail_window_sec = 600\n"
                     "max_tracked_ips = 500\n"
                     "alert_cooldown_sec = 30\n");
    ps_config_t cfg;
    int ret = ps_config_load(tmp_path, &cfg);
    assert_int_equal(ret, PS_OK);
    assert_string_equal(cfg.telegram_bot_token, "abc123");
    assert_string_equal(cfg.telegram_chat_id, "12345");
    assert_int_equal(cfg.fail_threshold, 10);
    assert_int_equal(cfg.fail_window_sec, 600);
    assert_int_equal(cfg.max_tracked_ips, 500);
    assert_int_equal(cfg.alert_cooldown_sec, 30);
    cleanup_tmp();
}

// --- ps_config_load: all alert channels ---

static void test_config_load_all_channels(void **state) {
    (void)state;
    write_tmp_config("telegram_bot_token = tok\n"
                     "telegram_chat_id = cid\n"
                     "slack_webhook_url = https://slack\n"
                     "teams_webhook_url = https://teams\n"
                     "whatsapp_access_token = wat\n"
                     "whatsapp_phone_number_id = wpid\n"
                     "whatsapp_recipient = 123\n"
                     "discord_webhook_url = https://discord\n"
                     "webhook_url = https://custom\n");
    ps_config_t cfg;
    int ret = ps_config_load(tmp_path, &cfg);
    assert_int_equal(ret, PS_OK);
    assert_string_equal(cfg.telegram_bot_token, "tok");
    assert_string_equal(cfg.telegram_chat_id, "cid");
    assert_string_equal(cfg.slack_webhook_url, "https://slack");
    assert_string_equal(cfg.teams_webhook_url, "https://teams");
    assert_string_equal(cfg.whatsapp_access_token, "wat");
    assert_string_equal(cfg.whatsapp_phone_number_id, "wpid");
    assert_string_equal(cfg.whatsapp_recipient, "123");
    assert_string_equal(cfg.discord_webhook_url, "https://discord");
    assert_string_equal(cfg.webhook_url, "https://custom");
    cleanup_tmp();
}

// --- ps_config_load: whitespace trimming ---

static void test_config_load_whitespace(void **state) {
    (void)state;
    write_tmp_config("  telegram_bot_token  =  mytoken  \n"
                     "  fail_threshold  =  20  \n");
    ps_config_t cfg;
    int ret = ps_config_load(tmp_path, &cfg);
    assert_int_equal(ret, PS_OK);
    assert_string_equal(cfg.telegram_bot_token, "mytoken");
    assert_int_equal(cfg.fail_threshold, 20);
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

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_config_defaults),
        cmocka_unit_test(test_config_load_missing_file),
        cmocka_unit_test(test_config_load_empty_file),
        cmocka_unit_test(test_config_load_comments_only),
        cmocka_unit_test(test_config_load_valid),
        cmocka_unit_test(test_config_load_all_channels),
        cmocka_unit_test(test_config_load_whitespace),
        cmocka_unit_test(test_config_load_boundary_min),
        cmocka_unit_test(test_config_load_boundary_max),
        cmocka_unit_test(test_config_load_out_of_range_high),
        cmocka_unit_test(test_config_load_out_of_range_low),
        cmocka_unit_test(test_config_load_negative_value),
        cmocka_unit_test(test_config_load_non_numeric),
        cmocka_unit_test(test_config_load_missing_equals),
        cmocka_unit_test(test_config_load_unknown_key),
        cmocka_unit_test(test_config_load_partial),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
