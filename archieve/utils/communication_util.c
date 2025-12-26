#include "communication_util.h"

#include <strings.h>
#include <curl/curl.h>
#include <curl/easy.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config_util.h"

// Response buffer structure for curl callbacks
typedef struct {
  char *data;
  size_t size;
} ResponseBuffer;

// Thread argument structure for parallel sending
typedef struct {
  const Config *cfg;
  const char *message;
  int success;
  char service_name[32];
} ThreadArgs;

// Callback function for handling curl response data
static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  ResponseBuffer *mem = (ResponseBuffer *)userp;

  char *ptr = realloc(mem->data, mem->size + realsize + 1);
  if (ptr == NULL) {
    fputs("Not enough memory for response buffer\n", stderr);
    return 0;
  }

  mem->data = ptr;
  memcpy(&(mem->data[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->data[mem->size] = 0;

  return realsize;
}

// Simple JSON string escaping (handles quotes and backslashes)
static void escape_json_string(const char *input, char *output, size_t output_size)
{
  size_t j = 0;
  for (size_t i = 0; input[i] != '\0' && j < output_size - 2; i++) {
    if (input[i] == '"' || input[i] == '\\') {
      output[j++] = '\\';
    }
    if (j < output_size - 1) {
      output[j++] = input[i];
    }
  }
  output[j] = '\0';
}

// Check if Telegram is properly configured
int is_telegram_configured(const Config *cfg)
{
  return (cfg->telegram_bot_token[0] != '\0' && cfg->telegram_channel_id[0] != '\0');
}

// Check if Slack is properly configured
int is_slack_configured(const Config *cfg)
{
  return (cfg->slack_webhook_url[0] != '\0');
}

// Check if generic webhook is properly configured
int is_webhook_configured(const Config *cfg)
{
  return (cfg->webhook_url[0] != '\0');
}

// Send alert to Telegram
int send_telegram_alert(const Config *cfg, const char *message)
{
  if (!is_telegram_configured(cfg)) {
    return 0;
  }

  printf("[Telegram] Sending alert to channel %s\n", cfg->telegram_channel_id);

  int success = 0;
  int retry_count = cfg->retry_count;

  // Build API URL
  char url[1024];
  snprintf(url, sizeof(url), "https://api.telegram.org/bot%s/sendMessage", cfg->telegram_bot_token);

  // Escape message for JSON
  char escaped_message[4096];
  escape_json_string(message, escaped_message, sizeof(escaped_message));

  // Build JSON payload
  char json_payload[8192];
  snprintf(json_payload, sizeof(json_payload), "{\"chat_id\":\"%s\",\"text\":\"%s\"}",
           cfg->telegram_channel_id, escaped_message);

  // Retry loop
  for (int attempt = 1; attempt <= retry_count && !success; attempt++) {
    if (attempt > 1) {
      printf("[Telegram] Retry attempt %d/%d (waiting %d seconds)...\n", attempt, retry_count,
             cfg->retry_delay_seconds);
      sleep(cfg->retry_delay_seconds);
    }

    CURL *curl = curl_easy_init();
    if (!curl) {
      fputs("[Telegram] Failed to initialize curl\n", stderr);
      continue;
    }

    // Set up response buffer
    ResponseBuffer response = {0};
    response.data = malloc(1);
    response.size = 0;

    // Configure curl
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_payload);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

    // Set headers
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    // Perform the request
    CURLcode res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
      char error_msg[256];
      snprintf(error_msg, sizeof(error_msg), "[Telegram] Request failed: %s\n",
               curl_easy_strerror(res));
      fputs(error_msg, stderr);
    } else {
      long response_code = 0;
      curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
      if (response_code == 200) {
        printf("[Telegram] Alert sent successfully\n");
        success = 1;
      } else {
        char error_msg[128];
        snprintf(error_msg, sizeof(error_msg), "[Telegram] API returned error code: %ld\n",
                 response_code);
        fputs(error_msg, stderr);
        if (response.data) {
          fputs("[Telegram] Response: ", stderr);
          fputs(response.data, stderr);
          fputs("\n", stderr);
        }
      }
    }

    // Cleanup
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(response.data);
  }

  if (!success) {
    char error_msg[128];
    snprintf(error_msg, sizeof(error_msg), "[Telegram] Failed after %d attempts\n", retry_count);
    fputs(error_msg, stderr);
  }

  return success;
}

// Send alert to Slack
int send_slack_alert(const Config *cfg, const char *message)
{
  if (!is_slack_configured(cfg)) {
    return 0;
  }

  printf("[Slack] Sending alert to webhook\n");

  int success = 0;
  int retry_count = cfg->retry_count;

  // Escape message for JSON
  char escaped_message[4096];
  escape_json_string(message, escaped_message, sizeof(escaped_message));

  // Build JSON payload
  char json_payload[8192];
  if (cfg->slack_channel[0] != '\0') {
    printf("[Slack] Channel override: %s\n", cfg->slack_channel);
    snprintf(json_payload, sizeof(json_payload), "{\"text\":\"%s\",\"channel\":\"%s\"}",
             escaped_message, cfg->slack_channel);
  } else {
    snprintf(json_payload, sizeof(json_payload), "{\"text\":\"%s\"}", escaped_message);
  }

  // Retry loop
  for (int attempt = 1; attempt <= retry_count && !success; attempt++) {
    if (attempt > 1) {
      printf("[Slack] Retry attempt %d/%d (waiting %d seconds)...\n", attempt, retry_count,
             cfg->retry_delay_seconds);
      sleep(cfg->retry_delay_seconds);
    }

    CURL *curl = curl_easy_init();
    if (!curl) {
      fputs("[Slack] Failed to initialize curl\n", stderr);
      continue;
    }

    // Set up response buffer
    ResponseBuffer response = {0};
    response.data = malloc(1);
    response.size = 0;

    // Configure curl
    curl_easy_setopt(curl, CURLOPT_URL, cfg->slack_webhook_url);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_payload);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

    // Set headers
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    // Perform the request
    CURLcode res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
      char error_msg[256];
      snprintf(error_msg, sizeof(error_msg), "[Slack] Request failed: %s\n",
               curl_easy_strerror(res));
      fputs(error_msg, stderr);
    } else {
      long response_code = 0;
      curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
      if (response_code == 200) {
        printf("[Slack] Alert sent successfully\n");
        success = 1;
      } else {
        char error_msg[128];
        snprintf(error_msg, sizeof(error_msg), "[Slack] Webhook returned error code: %ld\n",
                 response_code);
        fputs(error_msg, stderr);
        if (response.data) {
          fputs("[Slack] Response: ", stderr);
          fputs(response.data, stderr);
          fputs("\n", stderr);
        }
      }
    }

    // Cleanup
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(response.data);
  }

  if (!success) {
    char error_msg[128];
    snprintf(error_msg, sizeof(error_msg), "[Slack] Failed after %d attempts\n", retry_count);
    fputs(error_msg, stderr);
  }

  return success;
}

// Send alert to generic webhook
int send_webhook_alert(const Config *cfg, const char *message)
{
  if (!is_webhook_configured(cfg)) {
    return 0;
  }

  printf("[Webhook] Sending %s request to %s\n", cfg->webhook_method, cfg->webhook_url);

  int success = 0;
  int retry_count = cfg->retry_count;

  // Escape message for JSON
  char escaped_message[4096];
  escape_json_string(message, escaped_message, sizeof(escaped_message));

  // Retry loop
  for (int attempt = 1; attempt <= retry_count && !success; attempt++) {
    if (attempt > 1) {
      printf("[Webhook] Retry attempt %d/%d (waiting %d seconds)...\n", attempt, retry_count,
             cfg->retry_delay_seconds);
      sleep(cfg->retry_delay_seconds);
    }

    CURL *curl = curl_easy_init();
    if (!curl) {
      fputs("[Webhook] Failed to initialize curl\n", stderr);
      continue;
    }

    // Set up response buffer
    ResponseBuffer response = {0};
    response.data = malloc(1);
    response.size = 0;

    char url[2048];
    struct curl_slist *headers = NULL;

    // Handle different HTTP methods
    if (strcasecmp(cfg->webhook_method, "GET") == 0) {
      // For GET, send message as URL-encoded query parameter
      char *encoded_message = curl_easy_escape(curl, message, 0);
      snprintf(url, sizeof(url), "%s?message=%s", cfg->webhook_url, encoded_message);
      curl_free(encoded_message);

      curl_easy_setopt(curl, CURLOPT_URL, url);
      curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    } else {
      // Default to POST with JSON payload
      char json_payload[8192];
      snprintf(json_payload, sizeof(json_payload), "{\"message\":\"%s\"}", escaped_message);

      curl_easy_setopt(curl, CURLOPT_URL, cfg->webhook_url);
      curl_easy_setopt(curl, CURLOPT_POST, 1L);
      curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_payload);

      headers = curl_slist_append(headers, "Content-Type: application/json");
    }

    // Add Bearer token authentication if configured
    if (cfg->webhook_bearer_token[0] != '\0') {
      char auth_header[1024];
      snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s",
               cfg->webhook_bearer_token);
      headers = curl_slist_append(headers, auth_header);
    }

    // Set headers if any were added
    if (headers) {
      curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    }

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

    // Perform the request
    CURLcode res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
      char error_msg[256];
      snprintf(error_msg, sizeof(error_msg), "[Webhook] Request failed: %s\n",
               curl_easy_strerror(res));
      fputs(error_msg, stderr);
    } else {
      long response_code = 0;
      curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
      if (response_code >= 200 && response_code < 300) {
        printf("[Webhook] Alert sent successfully (HTTP %ld)\n", response_code);
        success = 1;
      } else {
        char error_msg[128];
        snprintf(error_msg, sizeof(error_msg), "[Webhook] Server returned error code: %ld\n",
                 response_code);
        fputs(error_msg, stderr);
        if (response.data) {
          fputs("[Webhook] Response: ", stderr);
          fputs(response.data, stderr);
          fputs("\n", stderr);
        }
      }
    }

    // Cleanup
    if (headers) {
      curl_slist_free_all(headers);
    }
    curl_easy_cleanup(curl);
    free(response.data);
  }

  if (!success) {
    char error_msg[128];
    snprintf(error_msg, sizeof(error_msg), "[Webhook] Failed after %d attempts\n", retry_count);
    fputs(error_msg, stderr);
  }

  return success;
}

// Thread wrapper for Telegram
static void *telegram_thread(void *arg)
{
  ThreadArgs *args = (ThreadArgs *)arg;
  args->success = send_telegram_alert(args->cfg, args->message);
  return NULL;
}

// Thread wrapper for Slack
static void *slack_thread(void *arg)
{
  ThreadArgs *args = (ThreadArgs *)arg;
  args->success = send_slack_alert(args->cfg, args->message);
  return NULL;
}

// Thread wrapper for Webhook
static void *webhook_thread(void *arg)
{
  ThreadArgs *args = (ThreadArgs *)arg;
  args->success = send_webhook_alert(args->cfg, args->message);
  return NULL;
}

// Send alert to all configured services in parallel
int send_alert(const Config *cfg, const char *message)
{
  int success_count = 0;

  if (message == NULL || message[0] == '\0') {
    fputs("Error: Cannot send empty message\n", stderr);
    return 0;
  }

  // Initialize curl globally (required for thread-safe operations)
  curl_global_init(CURL_GLOBAL_DEFAULT);

  printf("\n=== Sending alerts in parallel ===\n");

  // Prepare thread data structures
  pthread_t threads[3];
  ThreadArgs thread_args[3];
  int thread_count = 0;

  // Setup Telegram thread
  if (is_telegram_configured(cfg)) {
    thread_args[thread_count].cfg = cfg;
    thread_args[thread_count].message = message;
    thread_args[thread_count].success = 0;
    snprintf(thread_args[thread_count].service_name, sizeof(thread_args[thread_count].service_name),
             "Telegram");

    if (pthread_create(&threads[thread_count], NULL, telegram_thread, &thread_args[thread_count]) !=
        0) {
      fputs("Failed to create Telegram thread\n", stderr);
    } else {
      thread_count++;
    }
  }

  // Setup Slack thread
  if (is_slack_configured(cfg)) {
    thread_args[thread_count].cfg = cfg;
    thread_args[thread_count].message = message;
    thread_args[thread_count].success = 0;
    snprintf(thread_args[thread_count].service_name, sizeof(thread_args[thread_count].service_name),
             "Slack");

    if (pthread_create(&threads[thread_count], NULL, slack_thread, &thread_args[thread_count]) !=
        0) {
      fputs("Failed to create Slack thread\n", stderr);
    } else {
      thread_count++;
    }
  }

  // Setup Webhook thread
  if (is_webhook_configured(cfg)) {
    thread_args[thread_count].cfg = cfg;
    thread_args[thread_count].message = message;
    thread_args[thread_count].success = 0;
    snprintf(thread_args[thread_count].service_name, sizeof(thread_args[thread_count].service_name),
             "Webhook");

    if (pthread_create(&threads[thread_count], NULL, webhook_thread, &thread_args[thread_count]) !=
        0) {
      fputs("Failed to create Webhook thread\n", stderr);
    } else {
      thread_count++;
    }
  }

  // Wait for all threads to complete
  for (int i = 0; i < thread_count; i++) {
    pthread_join(threads[i], NULL);

    if (thread_args[i].success) {
      success_count++;
    } else {
      char error_msg[128];
      snprintf(error_msg, sizeof(error_msg), "Failed to send %s alert\n",
               thread_args[i].service_name);
      fputs(error_msg, stderr);
    }
  }

  printf("=== Alerts sent to %d/%d service(s) ===\n\n", success_count, thread_count);

  // Cleanup curl global state
  curl_global_cleanup();

  return success_count;
}
