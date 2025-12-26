#include "config_util.h"

#include <ctype.h>
#include <stddef.h> // NOLINT(misc-include-cleaner) - provides size_t
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// private helper
static char *trim(char *str)
{
  char *end = NULL;

  // Trim leading whitespace
  while (isspace((unsigned char)*str)) {
    str++;
  }

  if (*str == 0) {
    return str;
  }

  // Trim trailing whitespace
  end = str + strlen(str) - 1;
  while (end > str && isspace((unsigned char)*end)) {
    end--;
  }

  // Write new null terminator
  end[1] = '\0';

  return str;
}

int load_config(Config *cfg, const char *config_path)
{
  FILE *fp = fopen(config_path, "r");
  if (!fp) {
    perror("Error opening config file");
    return 0;
  }

  char line[512];
  char section[64] = "";

  while (fgets(line, sizeof(line), fp)) {
    char *t = trim(line);

    if (t[0] == '\0' || t[0] == '#') {
      continue;
    }

    if (t[0] == '[') {
      // Parse section name from [section] format
      char *start = t + 1;
      char *end = strchr(start, ']');
      if (end) {
        size_t len = end - start;
        if (len >= sizeof(section)) {
          len = sizeof(section) - 1;
        }
        memcpy(section, start, len);
        section[len] = '\0';
      }
      continue;
    }

    char key[128], value[384];

    // Parse key=value format manually
    char *equals = strchr(t, '=');
    if (equals) {
      size_t key_len = equals - t;
      if (key_len >= sizeof(key)) {
        key_len = sizeof(key) - 1;
      }
      memcpy(key, t, key_len);
      key[key_len] = '\0';

      size_t value_len = strlen(equals + 1);
      if (value_len >= sizeof(value)) {
        value_len = sizeof(value) - 1;
      }
      memcpy(value, equals + 1, value_len);
      value[value_len] = '\0';

      char *k = trim(key);
      char *v = trim(value);

      if (strcmp(section, "general") == 0) {
        if (strcmp(k, "log_path") == 0) {
          strncpy(cfg->log_path, v, sizeof(cfg->log_path) - 1);
          cfg->log_path[sizeof(cfg->log_path) - 1] = '\0';
        }
        if (strcmp(k, "description") == 0) {
          strncpy(cfg->description, v, sizeof(cfg->description) - 1);
          cfg->description[sizeof(cfg->description) - 1] = '\0';
        }
        if (strcmp(k, "provider") == 0) {
          strncpy(cfg->provider, v, sizeof(cfg->provider) - 1);
          cfg->provider[sizeof(cfg->provider) - 1] = '\0';
        }
        if (strcmp(k, "retry_count") == 0) {
          cfg->retry_count = atoi(v);
        }
        if (strcmp(k, "retry_delay_seconds") == 0) {
          cfg->retry_delay_seconds = atoi(v);
        }
        if (strcmp(k, "log_pulling_interval") == 0) {
          cfg->log_pulling_interval = atoi(v);
        }
      }
      if (strcmp(section, "telegram") == 0) {
        if (strcmp(k, "bot_token") == 0) {
          strncpy(cfg->telegram_bot_token, v, sizeof(cfg->telegram_bot_token) - 1);
          cfg->telegram_bot_token[sizeof(cfg->telegram_bot_token) - 1] = '\0';
        }
        if (strcmp(k, "channel_id") == 0) {
          strncpy(cfg->telegram_channel_id, v, sizeof(cfg->telegram_channel_id) - 1);
          cfg->telegram_channel_id[sizeof(cfg->telegram_channel_id) - 1] = '\0';
        }
      }
      if (strcmp(section, "slack") == 0) {
        if (strcmp(k, "webhook_url") == 0) {
          strncpy(cfg->slack_webhook_url, v, sizeof(cfg->slack_webhook_url) - 1);
          cfg->slack_webhook_url[sizeof(cfg->slack_webhook_url) - 1] = '\0';
        }
        if (strcmp(k, "channel") == 0) {
          strncpy(cfg->slack_channel, v, sizeof(cfg->slack_channel) - 1);
          cfg->slack_channel[sizeof(cfg->slack_channel) - 1] = '\0';
        }
      }
      if (strcmp(section, "webhook") == 0) {
        if (strcmp(k, "url") == 0) {
          strncpy(cfg->webhook_url, v, sizeof(cfg->webhook_url) - 1);
          cfg->webhook_url[sizeof(cfg->webhook_url) - 1] = '\0';
        }
        if (strcmp(k, "method") == 0) {
          strncpy(cfg->webhook_method, v, sizeof(cfg->webhook_method) - 1);
          cfg->webhook_method[sizeof(cfg->webhook_method) - 1] = '\0';
        }
        if (strcmp(k, "bearer_token") == 0) {
          strncpy(cfg->webhook_bearer_token, v, sizeof(cfg->webhook_bearer_token) - 1);
          cfg->webhook_bearer_token[sizeof(cfg->webhook_bearer_token) - 1] = '\0';
        }
      }
    }
  }

  fclose(fp);

  // Validate required general fields
  if (cfg->log_path[0] == '\0') {
    fputs("Config error: 'log_path' is required in [general] section\n", stderr);
    return 0;
  }
  if (cfg->description[0] == '\0') {
    fputs("Config error: 'description' is required in [general] section\n", stderr);
    return 0;
  }
  if (cfg->provider[0] == '\0') {
    fputs("Config error: 'provider' is required in [general] section\n", stderr);
    return 0;
  }

  // Set default webhook method if webhook URL is configured but method is not
  if (cfg->webhook_url[0] != '\0' && cfg->webhook_method[0] == '\0') {
    strncpy(cfg->webhook_method, "POST", sizeof(cfg->webhook_method) - 1);
    cfg->webhook_method[sizeof(cfg->webhook_method) - 1] = '\0';
  }

  // Set default retry settings if not configured
  if (cfg->retry_count <= 0) {
    cfg->retry_count = 3; // Default: 3 retries
  }
  if (cfg->retry_delay_seconds <= 0) {
    cfg->retry_delay_seconds = 2; // Default: 2 seconds between retries
  }

  // Set default log_pulling_interval if not configured
  if (cfg->log_pulling_interval <= 0) {
    cfg->log_pulling_interval = 200000; // Default: 200ms (200000μs)
  }

  // Check if at least one notification service is properly configured
  int telegram_configured =
      (cfg->telegram_bot_token[0] != '\0' && cfg->telegram_channel_id[0] != '\0');
  int slack_configured = (cfg->slack_webhook_url[0] != '\0');
  int webhook_configured = (cfg->webhook_url[0] != '\0');

  if (!telegram_configured && !slack_configured && !webhook_configured) {
    fputs("Config error: At least one notification service must be configured:\n", stderr);
    fputs("  - [telegram]: bot_token and channel_id\n", stderr);
    fputs("  - [slack]: webhook_url\n", stderr);
    fputs("  - [webhook]: url\n", stderr);
    return 0;
  }

  return 1;
}