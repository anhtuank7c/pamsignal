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
        cmocka_unit_test(test_validate_whatsapp_phone_id_non_numeric),
        cmocka_unit_test(test_validate_whatsapp_recipient_non_numeric),
        cmocka_unit_test(test_validate_whatsapp_token_bad_char),
        cmocka_unit_test(test_config_rejects_world_writable),
        cmocka_unit_test(test_config_rejects_group_writable),
        cmocka_unit_test(test_config_rejects_symlink),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
