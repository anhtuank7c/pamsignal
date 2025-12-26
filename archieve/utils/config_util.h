#ifndef CONFIG_UTIL_H
#define CONFIG_UTIL_H

typedef struct {
  char log_path[512];
  int log_pulling_interval;
  char provider[512];
  char description[512];

  // Telegram settings
  char telegram_bot_token[512];
  char telegram_channel_id[512];

  // Slack settings
  char slack_webhook_url[512];
  char slack_channel[256];

  // Generic webhook settings
  char webhook_url[512];
  char webhook_method[16];
  char webhook_bearer_token[512];

  // Retry settings
  int retry_count;
  int retry_delay_seconds;

  char server_ip[64];
  char system_hostname[256];
} Config;

int load_config(Config *cfg, const char *config_path);

#endif