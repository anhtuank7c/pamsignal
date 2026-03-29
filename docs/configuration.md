# Configuration

`/etc/pamsignal/pamsignal.conf` — INI-style, zero dependencies. All values are optional; sane defaults apply if the file is missing or a key is absent.

Since this file may contain alert credentials, it should have restricted permissions:

```bash
sudo chown root:pamsignal /etc/pamsignal/pamsignal.conf
sudo chmod 0640 /etc/pamsignal/pamsignal.conf
```

## Full reference

```ini
# Brute-force detection
fail_threshold = 5
fail_window_sec = 300
max_tracked_ips = 256
alert_cooldown_sec = 60

# Telegram
telegram_bot_token = 123456:ABC-DEF
telegram_chat_id = -100123456

# Slack
slack_webhook_url = https://hooks.slack.com/services/...

# Microsoft Teams
teams_webhook_url = https://outlook.office.com/webhook/...

# WhatsApp (Meta Cloud API)
whatsapp_access_token = EAABs...
whatsapp_phone_number_id = 123456789
whatsapp_recipient = 84901234567

# Discord
discord_webhook_url = https://discord.com/api/webhooks/...

# Custom webhook
webhook_url = https://your-app.com/api/alerts
```

## Brute-force detection

| Key | Default | Range | Description |
|-----|---------|-------|-------------|
| `fail_threshold` | `5` | 1 - 10000 | Failed attempts before triggering alert |
| `fail_window_sec` | `300` | 1 - 86400 | Time window (seconds) for counting failures per IP |
| `max_tracked_ips` | `256` | 1 - 100000 | Maximum IPs tracked simultaneously |
| `alert_cooldown_sec` | `60` | 0 - 86400 | Minimum seconds between alerts for the same IP (0 = no cooldown) |

## Alert channels

Only configure the channels you use. PAMSignal sends alerts to all channels that have credentials set. Alerts are best-effort — if a channel fails, pamsignal logs a warning and continues monitoring.

See [Alerts](./alerts.md) for message formats, setup guides, and payload reference.

| Key | Channel | Description |
|-----|---------|-------------|
| `telegram_bot_token` | Telegram | Bot token from [@BotFather](https://t.me/BotFather) |
| `telegram_chat_id` | Telegram | Chat, group, or channel ID |
| `slack_webhook_url` | Slack | Incoming webhook URL |
| `teams_webhook_url` | Teams | Incoming webhook URL |
| `whatsapp_access_token` | WhatsApp | Meta Cloud API access token |
| `whatsapp_phone_number_id` | WhatsApp | Phone Number ID from dashboard |
| `whatsapp_recipient` | WhatsApp | Recipient phone with country code (e.g. `84901234567`) |
| `discord_webhook_url` | Discord | Webhook URL from channel settings |
| `webhook_url` | Custom | Your endpoint URL (receives JSON POST) |

## CLI flags

| Flag | Short | Description |
|------|-------|-------------|
| `--foreground` | `-f` | Run in foreground (don't daemonize) |
| `--config PATH` | `-c PATH` | Use alternative config file path |

Relative paths are resolved to absolute before daemonization.

## Reload without restart

```bash
sudo systemctl reload pamsignal
```

This sends SIGHUP to the daemon. If the new config is valid, it takes effect immediately and the brute-force tracking table resets. If the config has errors, the daemon keeps the current config and logs a warning.
