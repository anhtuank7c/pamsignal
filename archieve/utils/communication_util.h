#ifndef COMMUNICATION_UTIL_H
#define COMMUNICATION_UTIL_H

#include "config_util.h"

// Check if specific notification services are configured
int is_telegram_configured(const Config *cfg);
int is_slack_configured(const Config *cfg);
int is_webhook_configured(const Config *cfg);

// Send alert to a specific service
int send_telegram_alert(const Config *cfg, const char *message);
int send_slack_alert(const Config *cfg, const char *message);
int send_webhook_alert(const Config *cfg, const char *message);

// Send alert to all configured services
// Returns the number of successfully sent alerts
int send_alert(const Config *cfg, const char *message);

#endif