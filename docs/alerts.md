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

Since v0.2.0, alert payloads follow [Elastic Common Schema (ECS)] conventions:

- **Chat channels** (Telegram / Slack / Teams / WhatsApp / Discord) get a single-line, severity-prefixed `key=value` text message.
- **Custom webhook** gets a JSON document with nested ECS objects (`event.*`, `host.*`, `user.*`, `source.*`, `service.*`, `process.*`) plus a `pamsignal.*` namespace for vendor-specific fields.

This means the webhook output drops directly into Elastic SIEM and Wazuh without remapping, and is one Vector / Logstash config away from any other modern SIEM.

[Elastic Common Schema (ECS)]: https://www.elastic.co/guide/en/ecs/current/index.html

### Chat text format

Severity bracket is fixed-width (8 chars) so columns align in monospace renderings. Field order is severity → action → identity → location → metadata → `pid` → `ts`. The `pid=` field is the live process for `session_opened` and `login_success` events (you can `kill <pid>` to disconnect the user) and the failing-auth child for failures (already reaped — useful as forensic context only).

```
[INFO]   auth.session_opened user=root host=web-01 service=sudo pid=12345 ts=2026-03-29T14:23:01+0000 provider=aws service_name=web-api
[INFO]   auth.session_closed user=root host=web-01 service=sshd pid=12346 ts=2026-03-29T14:25:10+0000 provider=aws service_name=web-api
[NOTICE] auth.login_success user=admin src=192.168.1.100:52341 host=web-01 service=sshd auth=password pid=12345 ts=2026-03-29T14:23:01+0000
[WARN]   auth.login_failure user=root src=203.0.113.50:39182 host=web-01 service=sshd auth=password pid=12347 ts=2026-03-29T14:23:01+0000
[ALERT]  auth.brute_force_detected src=203.0.113.50 attempts=12 window=300s user=root host=web-01 pid=12347 ts=2026-03-29T14:23:01+0000
```

*(Note: Custom context tags like `provider=aws service_name=web-api` will be appended automatically if configured in `pamsignal.conf`)*

### Telegram

Sent as plain text via the [Bot API `sendMessage`](https://core.telegram.org/bots/api#sendmessage). The same single-line chat text shown above.

**Setup:**
1. Create a bot with [@BotFather](https://t.me/BotFather) and copy the token
2. Add the bot to your group/channel
3. Get the chat ID (send a message, then check `https://api.telegram.org/bot<token>/getUpdates`)
4. Set `telegram_bot_token` and `telegram_chat_id` in `pamsignal.conf`

### Slack

Sent as a single-line message via [incoming webhook](https://api.slack.com/messaging/webhooks). Same chat text format.

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

Sent as plain text via [Discord webhook](https://support.discord.com/hc/en-us/articles/228383668-Intro-to-Webhooks).

**Setup:**
1. In your Discord channel, go to **Settings > Integrations > Webhooks > New Webhook**
2. Set `discord_webhook_url` in `pamsignal.conf`

### Custom webhook (ECS JSON)

Sent as a `POST` request with `Content-Type: application/json`. Conforms to ECS so it can be ingested into Elastic Stack, Wazuh, or any pipeline that speaks ECS without field remapping.

> 💡 **Want to build your own receiver?** Check out the ready-to-deploy **[Node.js Express Webhook Example](../examples/nodejs-webhook/README.md)**! It demonstrates how to authenticate, parse the ECS JSON payload, and route PAMSignal events.

**Login event:**

```json
{
  "@timestamp": "2026-03-29T14:23:01+0000",
  "event": {
    "action": "login_failure",
    "category": ["authentication"],
    "kind": "event",
    "outcome": "failure",
    "severity": 5,
    "module": "pamsignal",
    "dataset": "pamsignal.events"
  },
  "host": {"hostname": "web-01"},
  "user": {"name": "root"},
  "service": {"name": "sshd"},
  "source": {"ip": "203.0.113.50", "port": 39182},
  "process": {"pid": 12347, "user": {"id": "0"}},
  "pamsignal": {
    "event_type": "LOGIN_FAILED",
    "auth_method": "password"
  },
  "labels": {
    "provider": "aws",
    "service_name": "database"
  }
}
```

*(Note: The `labels` object is only included if you have defined `provider` or `service_name` in your `pamsignal.conf`)*

**Session event** (no `source.*` because it's not a network event):

```json
{
  "@timestamp": "2026-03-29T14:23:01+0000",
  "event": {
    "action": "session_opened",
    "category": ["authentication", "session"],
    "kind": "event",
    "outcome": "success",
    "severity": 3,
    "module": "pamsignal",
    "dataset": "pamsignal.events"
  },
  "host": {"hostname": "web-01"},
  "user": {"name": "root"},
  "service": {"name": "sudo"},
  "process": {"pid": 12345, "user": {"id": "0"}},
  "pamsignal": {"event_type": "SESSION_OPEN"}
}
```

**Brute-force detection** (`event.kind=alert`, severity 8):

```json
{
  "@timestamp": "2026-03-29T14:23:01+0000",
  "event": {
    "action": "brute_force_detected",
    "category": ["authentication", "intrusion_detection"],
    "kind": "alert",
    "outcome": "unknown",
    "severity": 8,
    "module": "pamsignal",
    "dataset": "pamsignal.events"
  },
  "host": {"hostname": "web-01"},
  "user": {"name": "root"},
  "source": {"ip": "203.0.113.50"},
  "process": {"pid": 12347},
  "pamsignal": {
    "event_type": "BRUTE_FORCE_DETECTED",
    "attempts": 12,
    "window_sec": 300
  }
}
```

**HTTP details:**

| Property | Value |
|----------|-------|
| Method | `POST` |
| Content-Type | `application/json` |
| Expected response | `2xx` (non-2xx is logged as a warning) |

### Event types

| `event.action` (ECS) | `pamsignal.event_type` (legacy) | When | Severity |
|---|---|---|---|
| `session_opened` | `SESSION_OPEN` | A PAM session opens (sshd / sudo / su / login) | 3 (info) |
| `session_closed` | `SESSION_CLOSE` | A PAM session closes | 3 (info) |
| `login_success` | `LOGIN_SUCCESS` | Successful SSH auth (password or public key) | 4 (notice) |
| `login_failure` | `LOGIN_FAILED` | Failed SSH auth | 5 (warning) |
| `brute_force_detected` | `BRUTE_FORCE_DETECTED` | Failed attempts from one IP exceeded the threshold within the window | 8 (alert) |

### Field reference (ECS webhook JSON)

| Path | Type | Present in | Description |
|---|---|---|---|
| `@timestamp` | string | All | ISO 8601 with timezone offset |
| `event.action` | string | All | One of the values in the table above |
| `event.category` | array&lt;string&gt; | All | Always includes `"authentication"`; sessions add `"session"`, brute-force adds `"intrusion_detection"` |
| `event.kind` | string | All | `"event"` for observations, `"alert"` for brute-force |
| `event.outcome` | string | All | `"success"`, `"failure"`, or `"unknown"` |
| `event.severity` | integer | All | 3=info, 4=notice, 5=warning, 8=alert |
| `event.module` | string | All | Always `"pamsignal"` |
| `event.dataset` | string | All | Always `"pamsignal.events"` |
| `host.hostname` | string | All | Server hostname |
| `user.name` | string | All | Username from the PAM message |
| `service.name` | string | Login/Session | PAM service: `sshd`, `sudo`, `su`, `login`, `other` |
| `source.ip` | string | Login + Brute | Remote IP (validated via `inet_pton`) |
| `source.port` | integer | Login | Remote port |
| `process.pid` | integer | All | Process ID — the live sshd session for `login_success`/`session_opened`, the (already reaped) auth child for failures and brute-force |
| `process.user.id` | string | Login/Session | UID of the PAM-handled process |
| `pamsignal.event_type` | string | All | Legacy uppercase enum (kept for backward compat through v0.2.x; retired in v0.3.0) |
| `pamsignal.auth_method` | string | Login | `password`, `publickey`, or `unknown` |
| `pamsignal.attempts` | integer | Brute-force | Number of failed attempts that breached the threshold |
| `pamsignal.window_sec` | integer | Brute-force | Configured time window |

### SIEM compatibility

The ECS payload is drop-in for:

- **Elastic SIEM** — schema is native; no remapping
- **Wazuh** — the wazuh-indexer template ingests ECS-shaped events directly
- **Sumo Logic, Datadog, Graylog, Loki** — schema-flexible; index whatever JSON you send

It needs a one-time mapping (Vector / Logstash / Filebeat processor, or the SIEM's own pipeline) for:

- **Splunk** — install the [Add-on for Elastic Common Schema] which maps ECS to Splunk CIM, or POST to HEC and write a CIM-compliant Splunk macro
- **Microsoft Sentinel** — write a [KQL parse function](https://learn.microsoft.com/azure/sentinel/normalization-about-parsers) translating ECS to ASIM
- **AWS Security Hub** — translate to [ASFF] before forwarding

For legacy enterprise SIEMs that prefer CEF (ArcSight) or LEEF (IBM QRadar), use Vector or Logstash to remap the ECS fields. (A native CEF output mode is on the roadmap if there's demand.)

[Add-on for Elastic Common Schema]: https://splunkbase.splunk.com/app/4848
[ASFF]: https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html

### Production architecture

Most production SIEMs don't accept webhooks directly. The conventional flow is:

```
pamsignal --HTTP--> ingest layer (Vector / Fluent Bit / Logstash) --> SIEM
```

Example Vector config receiving from pamsignal and forwarding to Elastic:

```toml
[sources.pamsignal]
type = "http_server"
address = "0.0.0.0:8080"
encoding = "json"

[sinks.elastic]
type = "elasticsearch"
inputs = ["pamsignal"]
endpoints = ["https://es.example.com:9200"]
api_version = "v8"
```

The same pattern works for any non-ECS SIEM — add a `transforms.remap` step between the source and sink to rename fields.

## How alert isolation works

See [Architecture — Alert isolation model](./architecture.md#alert-isolation-model) for the full explanation. In short:

1. Event is **always written to journal first** (core record persisted)
2. Parent `fork()`s a child process
3. Child `exec("curl", ...)` sends the HTTP request
4. Parent continues the event loop immediately — does not wait
5. If child crashes or network is down — parent is unaffected
6. No HTTP library exists in the parent process
