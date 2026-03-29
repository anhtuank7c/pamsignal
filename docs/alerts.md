# Alerts

PAMSignal sends best-effort alerts to messaging platforms when login events or brute-force patterns are detected. Alerts are sent via `fork()+exec(curl)` — a short-lived child process that cannot affect the core monitoring.

If an alert fails (network down, API error, timeout), pamsignal logs a warning and continues. The event is always persisted in the journal first.

## Supported channels

| Channel | Config keys needed |
|---------|-------------------|
| Telegram | `telegram_bot_token`, `telegram_chat_id` |
| Slack | `slack_webhook_url` |
| Microsoft Teams | `teams_webhook_url` |
| WhatsApp | `whatsapp_access_token`, `whatsapp_phone_number_id`, `whatsapp_recipient` |
| Discord | `discord_webhook_url` |
| Custom webhook | `webhook_url` |

Only configure the channels you use. PAMSignal sends to all channels that have credentials set. See [Configuration](./configuration.md) for the full config reference.

## Message format

### Telegram

Sent as HTML-formatted text via the [Bot API `sendMessage`](https://core.telegram.org/bots/api#sendmessage).

```
🚨 LOGIN_FAILED

User: root
From: 203.0.113.45
Port: 22
Service: sshd
Auth: password
Host: web-01
Time: 2026-03-29 14:23:01
```

```
🔴 BRUTE_FORCE_DETECTED

IP: 203.0.113.45
Attempts: 5
Window: 300s
Last user: root
Host: web-01
Time: 2026-03-29 14:23:01
```

**Setup:**
1. Create a bot with [@BotFather](https://t.me/BotFather) and copy the token
2. Add the bot to your group/channel
3. Get the chat ID (send a message, then check `https://api.telegram.org/bot<token>/getUpdates`)
4. Set `telegram_bot_token` and `telegram_chat_id` in `pamsignal.conf`

### Slack

Sent as a single-line Markdown message via [incoming webhook](https://api.slack.com/messaging/webhooks).

```
🚨 *LOGIN_FAILED* | User: `root` | From: `203.0.113.45:22` | Service: sshd | Auth: password | Host: web-01 | 2026-03-29 14:23:01
```

**Setup:**
1. Go to [Slack App Directory](https://api.slack.com/apps) and create an app
2. Enable **Incoming Webhooks** and create a webhook for your channel
3. Set `slack_webhook_url` in `pamsignal.conf`

### Microsoft Teams

Sent as a plain text message via [incoming webhook connector](https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook).

**Setup:**
1. In your Teams channel, go to **Channel settings > Connectors > Incoming Webhook**
2. Set `teams_webhook_url` in `pamsignal.conf`

### WhatsApp

Sent as plain text via the [Meta WhatsApp Cloud API](https://developers.facebook.com/docs/whatsapp/cloud-api).

**Setup:**
1. Create a [Meta Business app](https://developers.facebook.com/apps/) and add WhatsApp
2. Get your **Phone Number ID** and generate a **permanent access token**
3. Set `whatsapp_access_token`, `whatsapp_phone_number_id`, and `whatsapp_recipient` in `pamsignal.conf`

> **Note:** WhatsApp Cloud API requires a verified Meta Business account for production use.

### Discord

Sent as a Markdown message via [Discord webhook](https://support.discord.com/hc/en-us/articles/228383668-Intro-to-Webhooks).

**Setup:**
1. In your Discord channel, go to **Settings > Integrations > Webhooks > New Webhook**
2. Set `discord_webhook_url` in `pamsignal.conf`

### Custom webhook

Sent as a `POST` request with `Content-Type: application/json`. The payload is structured raw data — parse it however you need.

**Login event:**

```json
{
  "event": "LOGIN_FAILED",
  "username": "root",
  "source_ip": "203.0.113.45",
  "port": 22,
  "service": "sshd",
  "auth_method": "password",
  "hostname": "web-01",
  "timestamp": "2026-03-29T14:23:01Z",
  "timestamp_usec": 1743260581000000,
  "pid": 12345,
  "uid": 0
}
```

**Brute-force detection:**

```json
{
  "event": "BRUTE_FORCE_DETECTED",
  "source_ip": "203.0.113.45",
  "attempts": 5,
  "window_sec": 300,
  "last_username": "root",
  "hostname": "web-01",
  "timestamp": "2026-03-29T14:23:01Z",
  "timestamp_usec": 1743260581000000
}
```

**HTTP details:**

| Property | Value |
|----------|-------|
| Method | `POST` |
| Content-Type | `application/json` |
| Expected response | `2xx` (non-2xx is logged as a warning) |

### Event types

| Event | When |
|-------|------|
| `SESSION_OPEN` | A PAM session is opened (login via sshd, sudo, su) |
| `SESSION_CLOSE` | A PAM session is closed (logout) |
| `LOGIN_SUCCESS` | Successful SSH authentication (password or public key) |
| `LOGIN_FAILED` | Failed SSH authentication attempt |
| `BRUTE_FORCE_DETECTED` | Failed attempts from one IP exceeded the threshold within the time window |

### Field reference (custom webhook JSON)

| Field | Type | Present in | Description |
|-------|------|------------|-------------|
| `event` | string | All | Event type (see table above) |
| `username` | string | Login/Session | Username from the PAM message |
| `source_ip` | string | Login events | Remote IP address (validated via `inet_pton`) |
| `port` | integer | Login events | Remote port number |
| `service` | string | All | PAM service: `sshd`, `sudo`, `su`, `login`, `other` |
| `auth_method` | string | Login events | `password`, `publickey`, or `unknown` |
| `hostname` | string | All | Server hostname |
| `timestamp` | string | All | ISO 8601 UTC timestamp |
| `timestamp_usec` | integer | All | Microsecond Unix timestamp |
| `pid` | integer | Login/Session | Process ID of the PAM service |
| `uid` | integer | Login/Session | User ID of the PAM service |
| `attempts` | integer | Brute-force | Number of failed attempts that triggered the alert |
| `window_sec` | integer | Brute-force | Configured time window in seconds |
| `last_username` | string | Brute-force | Last username attempted from this IP |

## How alert isolation works

See [Architecture — Alert isolation model](./architecture.md#alert-isolation-model) for the full explanation. In short:

1. Event is **always written to journal first** (core record persisted)
2. Parent `fork()`s a child process
3. Child `exec("curl", ...)` sends the HTTP request
4. Parent continues the event loop immediately — does not wait
5. If child crashes or network is down — parent is unaffected
6. No HTTP library exists in the parent process
