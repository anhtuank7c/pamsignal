#include "../utils/log_parser_util.h"
#include "../vendor/unity/unity.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Unity setUp and tearDown
void setUp(void)
{
  // Set up before each test
}

void tearDown(void)
{
  // Clean up after each test
}

// Helper function to create a temporary file with test data
FILE* create_temp_log_file(const char *content)
{
  FILE *fp = tmpfile();
  if (fp && content) {
    fputs(content, fp);
    rewind(fp);
  }
  return fp;
}

// ============================================================================
// Valid SSH Login Tests
// ============================================================================

void test_parse_auth_log_handles_password_authentication(void)
{
  const char *log_content =
    "Dec 22 10:30:45 server sshd[1234]: Accepted password for john from 192.168.1.100 port 54321 ssh2\n";

  FILE *fp = create_temp_log_file(log_content);
  TEST_ASSERT_NOT_NULL(fp);

  int event_count = 0;
  SSHLoginEvent *events = parse_auth_log(fp, &event_count);

  TEST_ASSERT_NOT_NULL(events);
  TEST_ASSERT_EQUAL(1, event_count);
  TEST_ASSERT_EQUAL_STRING("john", events[0].username);
  TEST_ASSERT_EQUAL_STRING("192.168.1.100", events[0].ip_address);
  TEST_ASSERT_EQUAL_STRING("password", events[0].auth_method);
  TEST_ASSERT_EQUAL_STRING("Dec 22 10:30:45", events[0].timestamp);

  free(events);
  fclose(fp);
}

void test_parse_auth_log_handles_publickey_authentication(void)
{
  const char *log_content =
    "Dec 22 10:35:12 server sshd[5678]: Accepted publickey for alice from 10.0.0.50 port 12345 ssh2\n";

  FILE *fp = create_temp_log_file(log_content);
  TEST_ASSERT_NOT_NULL(fp);

  int event_count = 0;
  SSHLoginEvent *events = parse_auth_log(fp, &event_count);

  TEST_ASSERT_NOT_NULL(events);
  TEST_ASSERT_EQUAL(1, event_count);
  TEST_ASSERT_EQUAL_STRING("alice", events[0].username);
  TEST_ASSERT_EQUAL_STRING("10.0.0.50", events[0].ip_address);
  TEST_ASSERT_EQUAL_STRING("publickey", events[0].auth_method);
  TEST_ASSERT_EQUAL_STRING("Dec 22 10:35:12", events[0].timestamp);

  free(events);
  fclose(fp);
}

void test_parse_auth_log_handles_multiple_events(void)
{
  const char *log_content =
    "Dec 22 10:30:45 server sshd[1234]: Accepted password for john from 192.168.1.100 port 54321 ssh2\n"
    "Dec 22 10:31:20 server sshd[1235]: Accepted publickey for alice from 10.0.0.50 port 12345 ssh2\n"
    "Dec 22 10:32:15 server sshd[1236]: Accepted password for bob from 172.16.0.1 port 22222 ssh2\n";

  FILE *fp = create_temp_log_file(log_content);
  TEST_ASSERT_NOT_NULL(fp);

  int event_count = 0;
  SSHLoginEvent *events = parse_auth_log(fp, &event_count);

  TEST_ASSERT_NOT_NULL(events);
  TEST_ASSERT_EQUAL(3, event_count);

  TEST_ASSERT_EQUAL_STRING("john", events[0].username);
  TEST_ASSERT_EQUAL_STRING("192.168.1.100", events[0].ip_address);
  TEST_ASSERT_EQUAL_STRING("password", events[0].auth_method);

  TEST_ASSERT_EQUAL_STRING("alice", events[1].username);
  TEST_ASSERT_EQUAL_STRING("10.0.0.50", events[1].ip_address);
  TEST_ASSERT_EQUAL_STRING("publickey", events[1].auth_method);

  TEST_ASSERT_EQUAL_STRING("bob", events[2].username);
  TEST_ASSERT_EQUAL_STRING("172.16.0.1", events[2].ip_address);
  TEST_ASSERT_EQUAL_STRING("password", events[2].auth_method);

  free(events);
  fclose(fp);
}

void test_parse_auth_log_stores_full_log_line(void)
{
  const char *log_content =
    "Dec 22 10:30:45 server sshd[1234]: Accepted password for john from 192.168.1.100 port 54321 ssh2\n";

  FILE *fp = create_temp_log_file(log_content);
  TEST_ASSERT_NOT_NULL(fp);

  int event_count = 0;
  SSHLoginEvent *events = parse_auth_log(fp, &event_count);

  TEST_ASSERT_NOT_NULL(events);
  TEST_ASSERT_EQUAL(1, event_count);

  // Verify the timestamp is extracted correctly
  TEST_ASSERT_EQUAL_STRING("Dec 22 10:30:45", events[0].timestamp);

  // Verify the full log line is stored (without newline)
  TEST_ASSERT_NOT_NULL(strstr(events[0].log_line, "Dec 22 10:30:45"));
  TEST_ASSERT_NOT_NULL(strstr(events[0].log_line, "Accepted password"));

  free(events);
  fclose(fp);
}

// ============================================================================
// Invalid/Malformed Entry Tests
// ============================================================================

void test_parse_auth_log_ignores_failed_authentication(void)
{
  const char *log_content =
    "Dec 22 10:30:45 server sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2\n";

  FILE *fp = create_temp_log_file(log_content);
  TEST_ASSERT_NOT_NULL(fp);

  int event_count = 0;
  SSHLoginEvent *events = parse_auth_log(fp, &event_count);

  // Should return no events for failed attempts
  TEST_ASSERT_EQUAL(0, event_count);

  free(events);
  fclose(fp);
}

void test_parse_auth_log_ignores_non_ssh_entries(void)
{
  const char *log_content =
    "Dec 22 10:30:45 server kernel: Something else happened\n"
    "Dec 22 10:31:00 server cron[1234]: Job completed\n";

  FILE *fp = create_temp_log_file(log_content);
  TEST_ASSERT_NOT_NULL(fp);

  int event_count = 0;
  SSHLoginEvent *events = parse_auth_log(fp, &event_count);

  TEST_ASSERT_EQUAL(0, event_count);

  free(events);
  fclose(fp);
}

void test_parse_auth_log_handles_mixed_valid_and_invalid_entries(void)
{
  const char *log_content =
    "Dec 22 10:30:45 server kernel: Something else happened\n"
    "Dec 22 10:31:00 server sshd[1234]: Accepted password for john from 192.168.1.100 port 54321 ssh2\n"
    "Dec 22 10:31:30 server sshd[1235]: Failed password for admin from 10.0.0.1 port 22222 ssh2\n"
    "Dec 22 10:32:00 server sshd[1236]: Accepted publickey for alice from 10.0.0.50 port 12345 ssh2\n";

  FILE *fp = create_temp_log_file(log_content);
  TEST_ASSERT_NOT_NULL(fp);

  int event_count = 0;
  SSHLoginEvent *events = parse_auth_log(fp, &event_count);

  // Should only capture the 2 successful authentications
  TEST_ASSERT_EQUAL(2, event_count);
  TEST_ASSERT_EQUAL_STRING("john", events[0].username);
  TEST_ASSERT_EQUAL_STRING("alice", events[1].username);

  free(events);
  fclose(fp);
}

void test_parse_auth_log_ignores_malformed_ssh_lines(void)
{
  const char *log_content =
    "Dec 22 10:30:45 server sshd[1234]: Accepted password\n"  // Missing username and IP
    "Dec 22 10:31:00 server sshd[1235]: Accepted password for john\n";  // Missing IP

  FILE *fp = create_temp_log_file(log_content);
  TEST_ASSERT_NOT_NULL(fp);

  int event_count = 0;
  SSHLoginEvent *events = parse_auth_log(fp, &event_count);

  // Should ignore malformed entries
  TEST_ASSERT_EQUAL(0, event_count);

  free(events);
  fclose(fp);
}

// ============================================================================
// Edge Cases
// ============================================================================

void test_parse_auth_log_handles_empty_log(void)
{
  const char *log_content = "";

  FILE *fp = create_temp_log_file(log_content);
  TEST_ASSERT_NOT_NULL(fp);

  int event_count = 0;
  SSHLoginEvent *events = parse_auth_log(fp, &event_count);

  TEST_ASSERT_EQUAL(0, event_count);

  free(events);
  fclose(fp);
}

void test_parse_auth_log_handles_null_file_pointer(void)
{
  int event_count = 0;
  SSHLoginEvent *events = parse_auth_log(NULL, &event_count);

  // Should handle NULL gracefully
  TEST_ASSERT_EQUAL(0, event_count);
  TEST_ASSERT_NULL(events);
}

void test_parse_auth_log_handles_null_event_count(void)
{
  const char *log_content =
    "Dec 22 10:30:45 server sshd[1234]: Accepted password for john from 192.168.1.100 port 54321 ssh2\n";

  FILE *fp = create_temp_log_file(log_content);
  TEST_ASSERT_NOT_NULL(fp);

  SSHLoginEvent *events = parse_auth_log(fp, NULL);

  // Should handle NULL event_count gracefully
  TEST_ASSERT_NULL(events);

  fclose(fp);
}

void test_parse_auth_log_handles_long_username(void)
{
  const char *log_content =
    "Dec 22 10:30:45 server sshd[1234]: Accepted password for very_long_username_that_might_exceed_normal_limits from 192.168.1.100 port 54321 ssh2\n";

  FILE *fp = create_temp_log_file(log_content);
  TEST_ASSERT_NOT_NULL(fp);

  int event_count = 0;
  SSHLoginEvent *events = parse_auth_log(fp, &event_count);

  TEST_ASSERT_NOT_NULL(events);
  TEST_ASSERT_EQUAL(1, event_count);
  TEST_ASSERT_EQUAL_STRING("very_long_username_that_might_exceed_normal_limits", events[0].username);

  free(events);
  fclose(fp);
}

void test_parse_auth_log_handles_ipv6_addresses(void)
{
  const char *log_content =
    "Dec 22 10:30:45 server sshd[1234]: Accepted password for john from 2001:db8::1 port 54321 ssh2\n";

  FILE *fp = create_temp_log_file(log_content);
  TEST_ASSERT_NOT_NULL(fp);

  int event_count = 0;
  SSHLoginEvent *events = parse_auth_log(fp, &event_count);

  TEST_ASSERT_NOT_NULL(events);
  TEST_ASSERT_EQUAL(1, event_count);
  TEST_ASSERT_EQUAL_STRING("john", events[0].username);
  TEST_ASSERT_EQUAL_STRING("2001:db8::1", events[0].ip_address);

  free(events);
  fclose(fp);
}

// ============================================================================
// Memory Management Tests
// ============================================================================

void test_parse_auth_log_returns_freeable_memory(void)
{
  const char *log_content =
    "Dec 22 10:30:45 server sshd[1234]: Accepted password for john from 192.168.1.100 port 54321 ssh2\n";

  FILE *fp = create_temp_log_file(log_content);
  TEST_ASSERT_NOT_NULL(fp);

  int event_count = 0;
  SSHLoginEvent *events = parse_auth_log(fp, &event_count);

  TEST_ASSERT_NOT_NULL(events);

  // Should be able to free without crashing
  free(events);
  fclose(fp);

  TEST_ASSERT(1); // If we get here, test passed
}

void test_parse_auth_log_handles_many_events(void)
{
  // Create a log with many events to test dynamic array growth
  char log_content[5000];
  strcpy(log_content, "");

  for (int i = 0; i < 50; i++) {
    char line[200];
    snprintf(line, sizeof(line),
             "Dec 22 10:30:%02d server sshd[%d]: Accepted password for user%d from 192.168.1.%d port 54321 ssh2\n",
             i, 1000 + i, i, i % 255);
    strcat(log_content, line);
  }

  FILE *fp = create_temp_log_file(log_content);
  TEST_ASSERT_NOT_NULL(fp);

  int event_count = 0;
  SSHLoginEvent *events = parse_auth_log(fp, &event_count);

  TEST_ASSERT_NOT_NULL(events);
  TEST_ASSERT_EQUAL(50, event_count);

  // Verify first and last events
  TEST_ASSERT_EQUAL_STRING("user0", events[0].username);
  TEST_ASSERT_EQUAL_STRING("user49", events[49].username);

  free(events);
  fclose(fp);
}

// ============================================================================
// Different Log Format Tests (different distros)
// ============================================================================

void test_parse_auth_log_handles_ubuntu_format(void)
{
  const char *log_content =
    "Jan  5 14:23:45 ubuntu-server sshd[12345]: Accepted password for ubuntu from 203.0.113.10 port 52314 ssh2\n";

  FILE *fp = create_temp_log_file(log_content);
  TEST_ASSERT_NOT_NULL(fp);

  int event_count = 0;
  SSHLoginEvent *events = parse_auth_log(fp, &event_count);

  TEST_ASSERT_NOT_NULL(events);
  TEST_ASSERT_EQUAL(1, event_count);
  TEST_ASSERT_EQUAL_STRING("ubuntu", events[0].username);
  TEST_ASSERT_EQUAL_STRING("203.0.113.10", events[0].ip_address);

  free(events);
  fclose(fp);
}

void test_parse_auth_log_handles_centos_format(void)
{
  const char *log_content =
    "Feb 15 09:12:33 centos-server sshd[9876]: Accepted publickey for centos from 198.51.100.5 port 48321 ssh2: RSA SHA256:xyz123\n";

  FILE *fp = create_temp_log_file(log_content);
  TEST_ASSERT_NOT_NULL(fp);

  int event_count = 0;
  SSHLoginEvent *events = parse_auth_log(fp, &event_count);

  TEST_ASSERT_NOT_NULL(events);
  TEST_ASSERT_EQUAL(1, event_count);
  TEST_ASSERT_EQUAL_STRING("centos", events[0].username);
  TEST_ASSERT_EQUAL_STRING("198.51.100.5", events[0].ip_address);
  TEST_ASSERT_EQUAL_STRING("publickey", events[0].auth_method);

  free(events);
  fclose(fp);
}

void test_parse_auth_log_handles_iso8601_timestamp(void)
{
  const char *log_content =
    "2025-12-22T09:23:25.920453+07:00 bd10f sshd[459168]: Accepted publickey for root from 14.177.149.157 port 59284 ssh2: ED25519 SHA256:bzOUbJnY6RwuU+5fKZ+p6ZrIhh6G9IxUfK5WeliFK5Q\n";

  FILE *fp = create_temp_log_file(log_content);
  TEST_ASSERT_NOT_NULL(fp);

  int event_count = 0;
  SSHLoginEvent *events = parse_auth_log(fp, &event_count);

  TEST_ASSERT_NOT_NULL(events);
  TEST_ASSERT_EQUAL(1, event_count);
  TEST_ASSERT_EQUAL_STRING("root", events[0].username);
  TEST_ASSERT_EQUAL_STRING("14.177.149.157", events[0].ip_address);
  TEST_ASSERT_EQUAL_STRING("publickey", events[0].auth_method);
  TEST_ASSERT_EQUAL_STRING("2025-12-22T09:23:25.920453+07:00", events[0].timestamp);

  free(events);
  fclose(fp);
}

void test_parse_auth_log_handles_mixed_timestamp_formats(void)
{
  const char *log_content =
    "2025-12-22T09:23:25.920453+07:00 bd10f sshd[459168]: Accepted publickey for root from 14.177.149.157 port 59284 ssh2\n"
    "Dec 22 14:40:59 cs-turbo sshd[7606]: Accepted publickey for admin from 118.71.140.216 port 53188 ssh2\n"
    "Dec 22 14:57:35 hqplay-2 sshd[30520]: Accepted password for ubuntu from 118.71.140.216 port 54655 ssh2\n";

  FILE *fp = create_temp_log_file(log_content);
  TEST_ASSERT_NOT_NULL(fp);

  int event_count = 0;
  SSHLoginEvent *events = parse_auth_log(fp, &event_count);

  TEST_ASSERT_NOT_NULL(events);
  TEST_ASSERT_EQUAL(3, event_count);

  // ISO 8601 format
  TEST_ASSERT_EQUAL_STRING("root", events[0].username);
  TEST_ASSERT_EQUAL_STRING("14.177.149.157", events[0].ip_address);
  TEST_ASSERT_EQUAL_STRING("2025-12-22T09:23:25.920453+07:00", events[0].timestamp);

  // Traditional syslog format
  TEST_ASSERT_EQUAL_STRING("admin", events[1].username);
  TEST_ASSERT_EQUAL_STRING("118.71.140.216", events[1].ip_address);
  TEST_ASSERT_EQUAL_STRING("Dec 22 14:40:59", events[1].timestamp);

  TEST_ASSERT_EQUAL_STRING("ubuntu", events[2].username);
  TEST_ASSERT_EQUAL_STRING("118.71.140.216", events[2].ip_address);
  TEST_ASSERT_EQUAL_STRING("Dec 22 14:57:35", events[2].timestamp);

  free(events);
  fclose(fp);
}

// ============================================================================
// Test Runner
// ============================================================================

int main(void)
{
  UNITY_BEGIN();

  // Valid SSH login tests
  RUN_TEST(test_parse_auth_log_handles_password_authentication);
  RUN_TEST(test_parse_auth_log_handles_publickey_authentication);
  RUN_TEST(test_parse_auth_log_handles_multiple_events);
  RUN_TEST(test_parse_auth_log_stores_full_log_line);

  // Invalid/malformed entry tests
  RUN_TEST(test_parse_auth_log_ignores_failed_authentication);
  RUN_TEST(test_parse_auth_log_ignores_non_ssh_entries);
  RUN_TEST(test_parse_auth_log_handles_mixed_valid_and_invalid_entries);
  RUN_TEST(test_parse_auth_log_ignores_malformed_ssh_lines);

  // Edge cases
  RUN_TEST(test_parse_auth_log_handles_empty_log);
  RUN_TEST(test_parse_auth_log_handles_null_file_pointer);
  RUN_TEST(test_parse_auth_log_handles_null_event_count);
  RUN_TEST(test_parse_auth_log_handles_long_username);
  RUN_TEST(test_parse_auth_log_handles_ipv6_addresses);

  // Memory management tests
  RUN_TEST(test_parse_auth_log_returns_freeable_memory);
  RUN_TEST(test_parse_auth_log_handles_many_events);

  // Different log format tests
  RUN_TEST(test_parse_auth_log_handles_ubuntu_format);
  RUN_TEST(test_parse_auth_log_handles_centos_format);
  RUN_TEST(test_parse_auth_log_handles_iso8601_timestamp);
  RUN_TEST(test_parse_auth_log_handles_mixed_timestamp_formats);

  return UNITY_END();
}
