#include "../utils/communication_util.h"
#include "../utils/config_util.h"
#include "../vendor/unity/unity.h"

#include <stdio.h>
#include <string.h>

// Helper function to create a default empty config
static Config create_empty_config()
{
  Config cfg;
  memset(&cfg, 0, sizeof(Config));
  cfg.retry_count = 3;
  cfg.retry_delay_seconds = 1;
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
// Configuration Check Tests
// ============================================================================

void test_telegram_not_configured_when_empty(void)
{
  Config cfg = create_empty_config();
  TEST_ASSERT_EQUAL(0, is_telegram_configured(&cfg));
}

void test_telegram_not_configured_when_only_token(void)
{
  Config cfg = create_empty_config();
  strcpy(cfg.telegram_bot_token, "test_token");
  TEST_ASSERT_EQUAL(0, is_telegram_configured(&cfg));
}

void test_telegram_not_configured_when_only_channel(void)
{
  Config cfg = create_empty_config();
  strcpy(cfg.telegram_channel_id, "test_channel");
  TEST_ASSERT_EQUAL(0, is_telegram_configured(&cfg));
}

void test_telegram_configured_when_both_set(void)
{
  Config cfg = create_empty_config();
  strcpy(cfg.telegram_bot_token, "test_token");
  strcpy(cfg.telegram_channel_id, "test_channel");
  TEST_ASSERT_EQUAL(1, is_telegram_configured(&cfg));
}

void test_slack_not_configured_when_empty(void)
{
  Config cfg = create_empty_config();
  TEST_ASSERT_EQUAL(0, is_slack_configured(&cfg));
}

void test_slack_configured_when_webhook_url_set(void)
{
  Config cfg = create_empty_config();
  strcpy(cfg.slack_webhook_url, "https://hooks.slack.com/services/test");
  TEST_ASSERT_EQUAL(1, is_slack_configured(&cfg));
}

void test_webhook_not_configured_when_empty(void)
{
  Config cfg = create_empty_config();
  TEST_ASSERT_EQUAL(0, is_webhook_configured(&cfg));
}

void test_webhook_configured_when_url_set(void)
{
  Config cfg = create_empty_config();
  strcpy(cfg.webhook_url, "https://example.com/webhook");
  TEST_ASSERT_EQUAL(1, is_webhook_configured(&cfg));
}

// ============================================================================
// Alert Sending Tests (without network calls)
// ============================================================================

void test_send_telegram_alert_returns_0_when_not_configured(void)
{
  Config cfg = create_empty_config();
  int result = send_telegram_alert(&cfg, "test message");
  TEST_ASSERT_EQUAL(0, result);
}

void test_send_slack_alert_returns_0_when_not_configured(void)
{
  Config cfg = create_empty_config();
  int result = send_slack_alert(&cfg, "test message");
  TEST_ASSERT_EQUAL(0, result);
}

void test_send_webhook_alert_returns_0_when_not_configured(void)
{
  Config cfg = create_empty_config();
  int result = send_webhook_alert(&cfg, "test message");
  TEST_ASSERT_EQUAL(0, result);
}

void test_send_alert_returns_0_when_message_is_null(void)
{
  Config cfg = create_empty_config();
  int result = send_alert(&cfg, NULL);
  TEST_ASSERT_EQUAL(0, result);
}

void test_send_alert_returns_0_when_message_is_empty(void)
{
  Config cfg = create_empty_config();
  int result = send_alert(&cfg, "");
  TEST_ASSERT_EQUAL(0, result);
}

void test_send_alert_returns_0_when_no_services_configured(void)
{
  Config cfg = create_empty_config();
  int result = send_alert(&cfg, "test message");
  TEST_ASSERT_EQUAL(0, result);
}

// ============================================================================
// Integration Tests (Note: These will make actual network calls)
// ============================================================================

// These tests are commented out by default because they require actual API credentials
// and will make real network calls. Uncomment and configure them for integration testing.

/*
void test_send_telegram_alert_integration(void)
{
  Config cfg = create_empty_config();
  strcpy(cfg.telegram_bot_token, "YOUR_BOT_TOKEN");
  strcpy(cfg.telegram_channel_id, "YOUR_CHANNEL_ID");
  cfg.retry_count = 1;

  int result = send_telegram_alert(&cfg, "Test message from unit test");
  TEST_ASSERT_EQUAL(1, result);
}

void test_send_slack_alert_integration(void)
{
  Config cfg = create_empty_config();
  strcpy(cfg.slack_webhook_url, "YOUR_WEBHOOK_URL");
  cfg.retry_count = 1;

  int result = send_slack_alert(&cfg, "Test message from unit test");
  TEST_ASSERT_EQUAL(1, result);
}

void test_send_webhook_alert_integration(void)
{
  Config cfg = create_empty_config();
  strcpy(cfg.webhook_url, "https://webhook.site/YOUR_UNIQUE_URL");
  strcpy(cfg.webhook_method, "POST");
  cfg.retry_count = 1;

  int result = send_webhook_alert(&cfg, "Test message from unit test");
  TEST_ASSERT_EQUAL(1, result);
}

void test_send_alert_all_services_integration(void)
{
  Config cfg = create_empty_config();
  strcpy(cfg.telegram_bot_token, "YOUR_BOT_TOKEN");
  strcpy(cfg.telegram_channel_id, "YOUR_CHANNEL_ID");
  strcpy(cfg.slack_webhook_url, "YOUR_WEBHOOK_URL");
  strcpy(cfg.webhook_url, "https://webhook.site/YOUR_UNIQUE_URL");
  strcpy(cfg.webhook_method, "POST");
  cfg.retry_count = 1;

  int result = send_alert(&cfg, "Test message from unit test - all services");
  TEST_ASSERT_EQUAL(3, result);
}
*/

// ============================================================================
// Test Runner
// ============================================================================

int main(int argc, char *argv[])
{
  (void)argc;  // Unused
  (void)argv;  // Unused

  UNITY_BEGIN();

  // Configuration check tests
  RUN_TEST(test_telegram_not_configured_when_empty);
  RUN_TEST(test_telegram_not_configured_when_only_token);
  RUN_TEST(test_telegram_not_configured_when_only_channel);
  RUN_TEST(test_telegram_configured_when_both_set);
  RUN_TEST(test_slack_not_configured_when_empty);
  RUN_TEST(test_slack_configured_when_webhook_url_set);
  RUN_TEST(test_webhook_not_configured_when_empty);
  RUN_TEST(test_webhook_configured_when_url_set);

  // Alert sending tests
  RUN_TEST(test_send_telegram_alert_returns_0_when_not_configured);
  RUN_TEST(test_send_slack_alert_returns_0_when_not_configured);
  RUN_TEST(test_send_webhook_alert_returns_0_when_not_configured);
  RUN_TEST(test_send_alert_returns_0_when_message_is_null);
  RUN_TEST(test_send_alert_returns_0_when_message_is_empty);
  RUN_TEST(test_send_alert_returns_0_when_no_services_configured);

  // Integration tests (if enabled)
  // Uncomment these when integration tests are enabled:
  // RUN_TEST(test_send_telegram_alert_integration);
  // RUN_TEST(test_send_slack_alert_integration);
  // RUN_TEST(test_send_webhook_alert_integration);
  // RUN_TEST(test_send_alert_all_services_integration);

  return UNITY_END();
}
