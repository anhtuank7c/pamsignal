#include "../utils/config_util.h"
#include "../vendor/unity/unity.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

// Helper function to create test config files
static void create_test_file(const char *filename, const char *content)
{
  FILE *fp = fopen(filename, "w");
  if (fp) {
    fputs(content, fp);
    fclose(fp);
  }
}

// Helper function to cleanup test files
static void cleanup_test_file(const char *filename) { unlink(filename); }

// Helper to create empty config
static Config create_empty_config()
{
  Config cfg;
  memset(&cfg, 0, sizeof(Config));
  return cfg;
}

// Unity setUp and tearDown
void setUp(void)
{
  // Set up before each test
}

void tearDown(void)
{
  // Clean up after each test
}

// ============================================================================
// File Loading Tests
// ============================================================================

void test_load_config_fails_when_file_not_found(void)
{
  Config cfg = create_empty_config();
  int result = load_config(&cfg, "/nonexistent/config.conf");
  TEST_ASSERT_EQUAL(0, result);
}

void test_load_config_succeeds_with_valid_config(void)
{
  const char *filename = "/tmp/test_valid_config.conf";
  const char *content = "[general]\n"
                        "log_path=/var/log/auth.log\n"
                        "provider=TestProvider\n"
                        "description=Test Server\n"
                        "\n"
                        "[telegram]\n"
                        "bot_token=test_token\n"
                        "channel_id=test_channel\n";

  create_test_file(filename, content);

  Config cfg = create_empty_config();
  int result = load_config(&cfg, filename);

  cleanup_test_file(filename);

  TEST_ASSERT_EQUAL(1, result);
  TEST_ASSERT_EQUAL_STRING("/var/log/auth.log", cfg.log_path);
  TEST_ASSERT_EQUAL_STRING("TestProvider", cfg.provider);
  TEST_ASSERT_EQUAL_STRING("Test Server", cfg.description);
  TEST_ASSERT_EQUAL_STRING("test_token", cfg.telegram_bot_token);
  TEST_ASSERT_EQUAL_STRING("test_channel", cfg.telegram_channel_id);
}

// ============================================================================
// Required Field Validation Tests
// ============================================================================

void test_load_config_fails_when_log_path_missing(void)
{
  const char *filename = "/tmp/test_missing_log_path.conf";
  const char *content = "[general]\n"
                        "provider=TestProvider\n"
                        "description=Test Server\n"
                        "\n"
                        "[telegram]\n"
                        "bot_token=test_token\n"
                        "channel_id=test_channel\n";

  create_test_file(filename, content);

  Config cfg = create_empty_config();
  int result = load_config(&cfg, filename);

  cleanup_test_file(filename);

  TEST_ASSERT_EQUAL(0, result);
}

void test_load_config_fails_when_provider_missing(void)
{
  const char *filename = "/tmp/test_missing_provider.conf";
  const char *content = "[general]\n"
                        "log_path=/var/log/auth.log\n"
                        "description=Test Server\n"
                        "\n"
                        "[telegram]\n"
                        "bot_token=test_token\n"
                        "channel_id=test_channel\n";

  create_test_file(filename, content);

  Config cfg = create_empty_config();
  int result = load_config(&cfg, filename);

  cleanup_test_file(filename);

  TEST_ASSERT_EQUAL(0, result);
}

void test_load_config_fails_when_description_missing(void)
{
  const char *filename = "/tmp/test_missing_description.conf";
  const char *content = "[general]\n"
                        "log_path=/var/log/auth.log\n"
                        "provider=TestProvider\n"
                        "\n"
                        "[telegram]\n"
                        "bot_token=test_token\n"
                        "channel_id=test_channel\n";

  create_test_file(filename, content);

  Config cfg = create_empty_config();
  int result = load_config(&cfg, filename);

  cleanup_test_file(filename);

  TEST_ASSERT_EQUAL(0, result);
}

// ============================================================================
// Service Configuration Tests
// ============================================================================

void test_load_config_fails_when_no_services_configured(void)
{
  const char *filename = "/tmp/test_no_services.conf";
  const char *content = "[general]\n"
                        "log_path=/var/log/auth.log\n"
                        "provider=TestProvider\n"
                        "description=Test Server\n";

  create_test_file(filename, content);

  Config cfg = create_empty_config();
  int result = load_config(&cfg, filename);

  cleanup_test_file(filename);

  TEST_ASSERT_EQUAL(0, result);
}

void test_load_config_succeeds_with_telegram_only(void)
{
  const char *filename = "/tmp/test_telegram_only.conf";
  const char *content = "[general]\n"
                        "log_path=/var/log/auth.log\n"
                        "provider=TestProvider\n"
                        "description=Test Server\n"
                        "\n"
                        "[telegram]\n"
                        "bot_token=test_token\n"
                        "channel_id=test_channel\n";

  create_test_file(filename, content);

  Config cfg = create_empty_config();
  int result = load_config(&cfg, filename);

  cleanup_test_file(filename);

  TEST_ASSERT_EQUAL(1, result);
}

void test_load_config_succeeds_with_slack_only(void)
{
  const char *filename = "/tmp/test_slack_only.conf";
  const char *content = "[general]\n"
                        "log_path=/var/log/auth.log\n"
                        "provider=TestProvider\n"
                        "description=Test Server\n"
                        "\n"
                        "[slack]\n"
                        "webhook_url=https://hooks.slack.com/test\n";

  create_test_file(filename, content);

  Config cfg = create_empty_config();
  int result = load_config(&cfg, filename);

  cleanup_test_file(filename);

  TEST_ASSERT_EQUAL(1, result);
  TEST_ASSERT_EQUAL_STRING("https://hooks.slack.com/test", cfg.slack_webhook_url);
}

void test_load_config_succeeds_with_webhook_only(void)
{
  const char *filename = "/tmp/test_webhook_only.conf";
  const char *content = "[general]\n"
                        "log_path=/var/log/auth.log\n"
                        "provider=TestProvider\n"
                        "description=Test Server\n"
                        "\n"
                        "[webhook]\n"
                        "url=https://example.com/webhook\n";

  create_test_file(filename, content);

  Config cfg = create_empty_config();
  int result = load_config(&cfg, filename);

  cleanup_test_file(filename);

  TEST_ASSERT_EQUAL(1, result);
  TEST_ASSERT_EQUAL_STRING("https://example.com/webhook", cfg.webhook_url);
}

void test_load_config_fails_when_telegram_incomplete(void)
{
  const char *filename = "/tmp/test_telegram_incomplete.conf";
  const char *content = "[general]\n"
                        "log_path=/var/log/auth.log\n"
                        "provider=TestProvider\n"
                        "description=Test Server\n"
                        "\n"
                        "[telegram]\n"
                        "bot_token=test_token\n";

  create_test_file(filename, content);

  Config cfg = create_empty_config();
  int result = load_config(&cfg, filename);

  cleanup_test_file(filename);

  TEST_ASSERT_EQUAL(0, result);
}

// ============================================================================
// Default Value Tests
// ============================================================================

void test_load_config_sets_default_retry_count(void)
{
  const char *filename = "/tmp/test_default_retry.conf";
  const char *content = "[general]\n"
                        "log_path=/var/log/auth.log\n"
                        "provider=TestProvider\n"
                        "description=Test Server\n"
                        "\n"
                        "[telegram]\n"
                        "bot_token=test_token\n"
                        "channel_id=test_channel\n";

  create_test_file(filename, content);

  Config cfg = create_empty_config();
  int result = load_config(&cfg, filename);

  cleanup_test_file(filename);

  TEST_ASSERT_EQUAL(1, result);
  TEST_ASSERT_EQUAL(3, cfg.retry_count);
  TEST_ASSERT_EQUAL(2, cfg.retry_delay_seconds);
}

void test_load_config_uses_custom_retry_settings(void)
{
  const char *filename = "/tmp/test_custom_retry.conf";
  const char *content = "[general]\n"
                        "log_path=/var/log/auth.log\n"
                        "provider=TestProvider\n"
                        "description=Test Server\n"
                        "retry_count=5\n"
                        "retry_delay_seconds=10\n"
                        "\n"
                        "[telegram]\n"
                        "bot_token=test_token\n"
                        "channel_id=test_channel\n";

  create_test_file(filename, content);

  Config cfg = create_empty_config();
  int result = load_config(&cfg, filename);

  cleanup_test_file(filename);

  TEST_ASSERT_EQUAL(1, result);
  TEST_ASSERT_EQUAL(5, cfg.retry_count);
  TEST_ASSERT_EQUAL(10, cfg.retry_delay_seconds);
}

void test_load_config_sets_default_webhook_method(void)
{
  const char *filename = "/tmp/test_default_webhook_method.conf";
  const char *content = "[general]\n"
                        "log_path=/var/log/auth.log\n"
                        "provider=TestProvider\n"
                        "description=Test Server\n"
                        "\n"
                        "[webhook]\n"
                        "url=https://example.com/webhook\n";

  create_test_file(filename, content);

  Config cfg = create_empty_config();
  int result = load_config(&cfg, filename);

  cleanup_test_file(filename);

  TEST_ASSERT_EQUAL(1, result);
  TEST_ASSERT_EQUAL_STRING("POST", cfg.webhook_method);
}

void test_load_config_uses_custom_webhook_method(void)
{
  const char *filename = "/tmp/test_custom_webhook_method.conf";
  const char *content = "[general]\n"
                        "log_path=/var/log/auth.log\n"
                        "provider=TestProvider\n"
                        "description=Test Server\n"
                        "\n"
                        "[webhook]\n"
                        "url=https://example.com/webhook\n"
                        "method=GET\n";

  create_test_file(filename, content);

  Config cfg = create_empty_config();
  int result = load_config(&cfg, filename);

  cleanup_test_file(filename);

  TEST_ASSERT_EQUAL(1, result);
  TEST_ASSERT_EQUAL_STRING("GET", cfg.webhook_method);
}

void test_load_config_sets_default_log_pulling_interval(void)
{
  const char *filename = "/tmp/test_default_log_pulling_interval.conf";
  const char *content = "[general]\n"
                        "log_path=/var/log/auth.log\n"
                        "provider=TestProvider\n"
                        "description=Test Server\n"
                        "\n"
                        "[telegram]\n"
                        "bot_token=test_token\n"
                        "channel_id=test_channel\n";

  create_test_file(filename, content);

  Config cfg = create_empty_config();
  int result = load_config(&cfg, filename);

  cleanup_test_file(filename);

  TEST_ASSERT_EQUAL(1, result);
  TEST_ASSERT_EQUAL(200000, cfg.log_pulling_interval);
}

void test_load_config_uses_custom_log_pulling_interval(void)
{
  const char *filename = "/tmp/test_custom_log_pulling_interval.conf";
  const char *content = "[general]\n"
                        "log_path=/var/log/auth.log\n"
                        "provider=TestProvider\n"
                        "description=Test Server\n"
                        "log_pulling_interval=500000\n"
                        "\n"
                        "[telegram]\n"
                        "bot_token=test_token\n"
                        "channel_id=test_channel\n";

  create_test_file(filename, content);

  Config cfg = create_empty_config();
  int result = load_config(&cfg, filename);

  cleanup_test_file(filename);

  TEST_ASSERT_EQUAL(1, result);
  TEST_ASSERT_EQUAL(500000, cfg.log_pulling_interval);
}

// ============================================================================
// Parsing Tests
// ============================================================================

void test_load_config_handles_comments(void)
{
  const char *filename = "/tmp/test_comments.conf";
  const char *content = "# This is a comment\n"
                        "[general]\n"
                        "# Another comment\n"
                        "log_path=/var/log/auth.log\n"
                        "provider=TestProvider # inline comment ignored\n"
                        "description=Test Server\n"
                        "\n"
                        "# Telegram section\n"
                        "[telegram]\n"
                        "bot_token=test_token\n"
                        "channel_id=test_channel\n";

  create_test_file(filename, content);

  Config cfg = create_empty_config();
  int result = load_config(&cfg, filename);

  cleanup_test_file(filename);

  TEST_ASSERT_EQUAL(1, result);
}

void test_load_config_handles_empty_lines(void)
{
  const char *filename = "/tmp/test_empty_lines.conf";
  const char *content = "\n"
                        "\n"
                        "[general]\n"
                        "\n"
                        "log_path=/var/log/auth.log\n"
                        "\n"
                        "provider=TestProvider\n"
                        "\n"
                        "description=Test Server\n"
                        "\n"
                        "\n"
                        "[telegram]\n"
                        "\n"
                        "bot_token=test_token\n"
                        "channel_id=test_channel\n"
                        "\n";

  create_test_file(filename, content);

  Config cfg = create_empty_config();
  int result = load_config(&cfg, filename);

  cleanup_test_file(filename);

  TEST_ASSERT_EQUAL(1, result);
}

void test_load_config_handles_whitespace(void)
{
  const char *filename = "/tmp/test_whitespace.conf";
  const char *content = "[general]\n"
                        "  log_path  =  /var/log/auth.log  \n"
                        "provider=  TestProvider\n"
                        "  description=Test Server  \n"
                        "\n"
                        "[telegram]\n"
                        "bot_token = test_token\n"
                        "  channel_id  =  test_channel  \n";

  create_test_file(filename, content);

  Config cfg = create_empty_config();
  int result = load_config(&cfg, filename);

  cleanup_test_file(filename);

  TEST_ASSERT_EQUAL(1, result);
  TEST_ASSERT_EQUAL_STRING("/var/log/auth.log", cfg.log_path);
  TEST_ASSERT_EQUAL_STRING("TestProvider", cfg.provider);
  TEST_ASSERT_EQUAL_STRING("Test Server", cfg.description);
}

void test_load_config_parses_all_telegram_fields(void)
{
  const char *filename = "/tmp/test_all_telegram.conf";
  const char *content = "[general]\n"
                        "log_path=/var/log/auth.log\n"
                        "provider=TestProvider\n"
                        "description=Test Server\n"
                        "\n"
                        "[telegram]\n"
                        "bot_token=123456:ABC-DEF1234567890\n"
                        "channel_id=-1001234567890\n";

  create_test_file(filename, content);

  Config cfg = create_empty_config();
  int result = load_config(&cfg, filename);

  cleanup_test_file(filename);

  TEST_ASSERT_EQUAL(1, result);
  TEST_ASSERT_EQUAL_STRING("123456:ABC-DEF1234567890", cfg.telegram_bot_token);
  TEST_ASSERT_EQUAL_STRING("-1001234567890", cfg.telegram_channel_id);
}

void test_load_config_parses_all_slack_fields(void)
{
  const char *filename = "/tmp/test_all_slack.conf";
  const char *content = "[general]\n"
                        "log_path=/var/log/auth.log\n"
                        "provider=TestProvider\n"
                        "description=Test Server\n"
                        "\n"
                        "[slack]\n"
                        "webhook_url=https://hooks.slack.com/services/T00/B00/XX\n"
                        "channel=#alerts\n";

  create_test_file(filename, content);

  Config cfg = create_empty_config();
  int result = load_config(&cfg, filename);

  cleanup_test_file(filename);

  TEST_ASSERT_EQUAL(1, result);
  TEST_ASSERT_EQUAL_STRING("https://hooks.slack.com/services/T00/B00/XX", cfg.slack_webhook_url);
  TEST_ASSERT_EQUAL_STRING("#alerts", cfg.slack_channel);
}

void test_load_config_parses_all_webhook_fields(void)
{
  const char *filename = "/tmp/test_all_webhook.conf";
  const char *content = "[general]\n"
                        "log_path=/var/log/auth.log\n"
                        "provider=TestProvider\n"
                        "description=Test Server\n"
                        "\n"
                        "[webhook]\n"
                        "url=https://api.example.com/alerts\n"
                        "method=POST\n"
                        "bearer_token=secret-token-123\n";

  create_test_file(filename, content);

  Config cfg = create_empty_config();
  int result = load_config(&cfg, filename);

  cleanup_test_file(filename);

  TEST_ASSERT_EQUAL(1, result);
  TEST_ASSERT_EQUAL_STRING("https://api.example.com/alerts", cfg.webhook_url);
  TEST_ASSERT_EQUAL_STRING("POST", cfg.webhook_method);
  TEST_ASSERT_EQUAL_STRING("secret-token-123", cfg.webhook_bearer_token);
}

void test_load_config_parses_multiple_services(void)
{
  const char *filename = "/tmp/test_multiple_services.conf";
  const char *content = "[general]\n"
                        "log_path=/var/log/auth.log\n"
                        "provider=TestProvider\n"
                        "description=Test Server\n"
                        "\n"
                        "[telegram]\n"
                        "bot_token=telegram_token\n"
                        "channel_id=telegram_channel\n"
                        "\n"
                        "[slack]\n"
                        "webhook_url=https://slack.webhook.url\n"
                        "\n"
                        "[webhook]\n"
                        "url=https://webhook.url\n"
                        "method=GET\n";

  create_test_file(filename, content);

  Config cfg = create_empty_config();
  int result = load_config(&cfg, filename);

  cleanup_test_file(filename);

  TEST_ASSERT_EQUAL(1, result);
  TEST_ASSERT_EQUAL_STRING("telegram_token", cfg.telegram_bot_token);
  TEST_ASSERT_EQUAL_STRING("https://slack.webhook.url", cfg.slack_webhook_url);
  TEST_ASSERT_EQUAL_STRING("https://webhook.url", cfg.webhook_url);
}

// ============================================================================
// Test Runner
// ============================================================================

int main(void)
{
  UNITY_BEGIN();

  // File loading tests
  RUN_TEST(test_load_config_fails_when_file_not_found);
  RUN_TEST(test_load_config_succeeds_with_valid_config);

  // Required field validation tests
  RUN_TEST(test_load_config_fails_when_log_path_missing);
  RUN_TEST(test_load_config_fails_when_provider_missing);
  RUN_TEST(test_load_config_fails_when_description_missing);

  // Service configuration tests
  RUN_TEST(test_load_config_fails_when_no_services_configured);
  RUN_TEST(test_load_config_succeeds_with_telegram_only);
  RUN_TEST(test_load_config_succeeds_with_slack_only);
  RUN_TEST(test_load_config_succeeds_with_webhook_only);
  RUN_TEST(test_load_config_fails_when_telegram_incomplete);

  // Default value tests
  RUN_TEST(test_load_config_sets_default_retry_count);
  RUN_TEST(test_load_config_uses_custom_retry_settings);
  RUN_TEST(test_load_config_sets_default_webhook_method);
  RUN_TEST(test_load_config_uses_custom_webhook_method);
  RUN_TEST(test_load_config_sets_default_log_pulling_interval);
  RUN_TEST(test_load_config_uses_custom_log_pulling_interval);

  // Parsing tests
  RUN_TEST(test_load_config_handles_comments);
  RUN_TEST(test_load_config_handles_empty_lines);
  RUN_TEST(test_load_config_handles_whitespace);
  RUN_TEST(test_load_config_parses_all_telegram_fields);
  RUN_TEST(test_load_config_parses_all_slack_fields);
  RUN_TEST(test_load_config_parses_all_webhook_fields);
  RUN_TEST(test_load_config_parses_multiple_services);

  return UNITY_END();
}
