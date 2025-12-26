#include "../utils/host_util.h"
#include "../vendor/unity/unity.h"

#include <stdio.h>
#include <string.h>

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
// IPv4 List Tests
// ============================================================================

void test_get_ipv4_list_returns_null_when_count_is_null(void)
{
  char **result = get_ipv4_list(NULL);
  TEST_ASSERT_NULL(result);
}

void test_get_ipv4_list_initializes_count_to_zero_on_start(void)
{
  int count = 999;
  char **result = get_ipv4_list(&count);

  // Count should be set to 0 initially
  if (result == NULL) {
    TEST_ASSERT_EQUAL(0, count);
  }

  free_ip_list(result, count);
}

void test_get_ipv4_list_returns_valid_result(void)
{
  int count = 0;
  char **result = get_ipv4_list(&count);

  // Result should either be NULL (no interfaces) or a valid pointer
  // Count should be >= 0
  TEST_ASSERT_GREATER_OR_EQUAL(0, count);

  // If result is not NULL, count should match the number of IPs
  if (result != NULL) {
    TEST_ASSERT_NOT_NULL(result);

    // Verify each IP string is not NULL
    for (int i = 0; i < count; i++) {
      TEST_ASSERT_NOT_NULL(result[i]);
      // Each IP should have some length
      TEST_ASSERT_GREATER_THAN(0, strlen(result[i]));
    }
  }

  free_ip_list(result, count);
}

void test_get_ipv4_list_excludes_loopback(void)
{
  int count = 0;
  char **result = get_ipv4_list(&count);

  // Verify that 127.0.0.1 is not in the results
  if (result != NULL) {
    for (int i = 0; i < count; i++) {
      TEST_ASSERT_TRUE(strcmp(result[i], "127.0.0.1") != 0);
    }
  }

  free_ip_list(result, count);
}

void test_get_ipv4_list_returns_valid_ip_format(void)
{
  int count = 0;
  char **result = get_ipv4_list(&count);

  if (result != NULL && count > 0) {
    // Check that at least one IP has dots (basic IPv4 format check)
    int has_dots = 0;
    for (int i = 0; i < count; i++) {
      if (strchr(result[i], '.') != NULL) {
        has_dots = 1;
        break;
      }
    }
    TEST_ASSERT_EQUAL(1, has_dots);
  }

  free_ip_list(result, count);
}

// ============================================================================
// IPv6 List Tests
// ============================================================================

void test_get_ipv6_list_returns_null_when_count_is_null(void)
{
  char **result = get_ipv6_list(NULL);
  TEST_ASSERT_NULL(result);
}

void test_get_ipv6_list_initializes_count_to_zero_on_start(void)
{
  int count = 999;
  char **result = get_ipv6_list(&count);

  // Count should be set to 0 initially
  if (result == NULL) {
    TEST_ASSERT_EQUAL(0, count);
  }

  free_ip_list(result, count);
}

void test_get_ipv6_list_returns_valid_result(void)
{
  int count = 0;
  char **result = get_ipv6_list(&count);

  // Result should either be NULL (no interfaces) or a valid pointer
  // Count should be >= 0
  TEST_ASSERT_GREATER_OR_EQUAL(0, count);

  // If result is not NULL, count should match the number of IPs
  if (result != NULL) {
    TEST_ASSERT_NOT_NULL(result);

    // Verify each IP string is not NULL
    for (int i = 0; i < count; i++) {
      TEST_ASSERT_NOT_NULL(result[i]);
      // Each IP should have some length
      TEST_ASSERT_GREATER_THAN(0, strlen(result[i]));
    }
  }

  free_ip_list(result, count);
}

void test_get_ipv6_list_excludes_loopback(void)
{
  int count = 0;
  char **result = get_ipv6_list(&count);

  // Verify that ::1 is not in the results
  if (result != NULL) {
    for (int i = 0; i < count; i++) {
      TEST_ASSERT_TRUE(strcmp(result[i], "::1") != 0);
    }
  }

  free_ip_list(result, count);
}

void test_get_ipv6_list_excludes_link_local(void)
{
  int count = 0;
  char **result = get_ipv6_list(&count);

  // Verify that fe80: addresses are not in the results
  if (result != NULL) {
    for (int i = 0; i < count; i++) {
      TEST_ASSERT_NOT_EQUAL(0, strncmp(result[i], "fe80:", 5));
    }
  }

  free_ip_list(result, count);
}

void test_get_ipv6_list_returns_valid_ip_format(void)
{
  int count = 0;
  char **result = get_ipv6_list(&count);

  if (result != NULL && count > 0) {
    // Check that at least one IP has colons (basic IPv6 format check)
    int has_colons = 0;
    for (int i = 0; i < count; i++) {
      if (strchr(result[i], ':') != NULL) {
        has_colons = 1;
        break;
      }
    }
    TEST_ASSERT_EQUAL(1, has_colons);
  }

  free_ip_list(result, count);
}

// ============================================================================
// Hostname Tests
// ============================================================================

void test_get_hostname_returns_non_null(void)
{
  char *hostname = get_hostname();
  TEST_ASSERT_NOT_NULL(hostname);
}

void test_get_hostname_returns_non_empty_string(void)
{
  char *hostname = get_hostname();
  TEST_ASSERT_NOT_NULL(hostname);
  TEST_ASSERT_GREATER_THAN(0, strlen(hostname));
}

void test_get_hostname_returns_unknown_on_error_or_valid_hostname(void)
{
  char *hostname = get_hostname();
  TEST_ASSERT_NOT_NULL(hostname);

  // Hostname should either be "unknown" (on error) or a valid hostname
  // Valid hostname should not be empty
  if (strcmp(hostname, "unknown") != 0) {
    TEST_ASSERT_GREATER_THAN(0, strlen(hostname));
  }
}

void test_get_hostname_returns_consistent_value(void)
{
  char *hostname1 = get_hostname();
  char *hostname2 = get_hostname();

  // Multiple calls should return the same value
  TEST_ASSERT_EQUAL_STRING(hostname1, hostname2);
}

// ============================================================================
// Memory Management Tests
// ============================================================================

void test_free_ip_list_handles_null_list(void)
{
  // Should not crash when list is NULL
  free_ip_list(NULL, 0);
  free_ip_list(NULL, 10);
  TEST_ASSERT(1); // If we get here, test passed
}

void test_free_ip_list_handles_zero_count(void)
{
  int count = 0;
  char **result = get_ipv4_list(&count);

  // Should handle zero count gracefully
  free_ip_list(result, 0);
  TEST_ASSERT(1); // If we get here, test passed
}

void test_free_ip_list_frees_valid_list(void)
{
  int count = 0;
  char **result = get_ipv4_list(&count);

  // Should free without crashing
  free_ip_list(result, count);
  TEST_ASSERT(1); // If we get here, test passed
}

void test_memory_allocation_and_deallocation_ipv4(void)
{
  // Test multiple allocations and deallocations
  for (int iteration = 0; iteration < 3; iteration++) {
    int count = 0;
    char **result = get_ipv4_list(&count);

    if (result != NULL) {
      // Verify we can read all strings
      for (int i = 0; i < count; i++) {
        TEST_ASSERT_NOT_NULL(result[i]);
        size_t len = strlen(result[i]);
        TEST_ASSERT_GREATER_THAN(0, len);
      }
    }

    free_ip_list(result, count);
  }

  TEST_ASSERT(1); // If we get here, test passed
}

void test_memory_allocation_and_deallocation_ipv6(void)
{
  // Test multiple allocations and deallocations
  for (int iteration = 0; iteration < 3; iteration++) {
    int count = 0;
    char **result = get_ipv6_list(&count);

    if (result != NULL) {
      // Verify we can read all strings
      for (int i = 0; i < count; i++) {
        TEST_ASSERT_NOT_NULL(result[i]);
        size_t len = strlen(result[i]);
        TEST_ASSERT_GREATER_THAN(0, len);
      }
    }

    free_ip_list(result, count);
  }

  TEST_ASSERT(1); // If we get here, test passed
}

// ============================================================================
// Integration Tests
// ============================================================================

void test_can_get_both_ipv4_and_ipv6(void)
{
  int ipv4_count = 0;
  int ipv6_count = 0;

  char **ipv4_list = get_ipv4_list(&ipv4_count);
  char **ipv6_list = get_ipv6_list(&ipv6_count);

  // Both should work independently
  TEST_ASSERT_GREATER_OR_EQUAL(0, ipv4_count);
  TEST_ASSERT_GREATER_OR_EQUAL(0, ipv6_count);

  free_ip_list(ipv4_list, ipv4_count);
  free_ip_list(ipv6_list, ipv6_count);
}

void test_complete_workflow(void)
{
  // Test a complete workflow of getting all host information
  char *hostname = get_hostname();
  TEST_ASSERT_NOT_NULL(hostname);

  int ipv4_count = 0;
  char **ipv4_list = get_ipv4_list(&ipv4_count);

  int ipv6_count = 0;
  char **ipv6_list = get_ipv6_list(&ipv6_count);

  // At least hostname should be available
  TEST_ASSERT_GREATER_THAN(0, strlen(hostname));

  // Clean up
  free_ip_list(ipv4_list, ipv4_count);
  free_ip_list(ipv6_list, ipv6_count);
}

// ============================================================================
// Test Runner
// ============================================================================

int main(void)
{
  UNITY_BEGIN();

  // IPv4 tests
  RUN_TEST(test_get_ipv4_list_returns_null_when_count_is_null);
  RUN_TEST(test_get_ipv4_list_initializes_count_to_zero_on_start);
  RUN_TEST(test_get_ipv4_list_returns_valid_result);
  RUN_TEST(test_get_ipv4_list_excludes_loopback);
  RUN_TEST(test_get_ipv4_list_returns_valid_ip_format);

  // IPv6 tests
  RUN_TEST(test_get_ipv6_list_returns_null_when_count_is_null);
  RUN_TEST(test_get_ipv6_list_initializes_count_to_zero_on_start);
  RUN_TEST(test_get_ipv6_list_returns_valid_result);
  RUN_TEST(test_get_ipv6_list_excludes_loopback);
  RUN_TEST(test_get_ipv6_list_excludes_link_local);
  RUN_TEST(test_get_ipv6_list_returns_valid_ip_format);

  // Hostname tests
  RUN_TEST(test_get_hostname_returns_non_null);
  RUN_TEST(test_get_hostname_returns_non_empty_string);
  RUN_TEST(test_get_hostname_returns_unknown_on_error_or_valid_hostname);
  RUN_TEST(test_get_hostname_returns_consistent_value);

  // Memory management tests
  RUN_TEST(test_free_ip_list_handles_null_list);
  RUN_TEST(test_free_ip_list_handles_zero_count);
  RUN_TEST(test_free_ip_list_frees_valid_list);
  RUN_TEST(test_memory_allocation_and_deallocation_ipv4);
  RUN_TEST(test_memory_allocation_and_deallocation_ipv6);

  // Integration tests
  RUN_TEST(test_can_get_both_ipv4_and_ipv6);
  RUN_TEST(test_complete_workflow);

  return UNITY_END();
}
