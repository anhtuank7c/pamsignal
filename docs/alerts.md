# Alerts

> 🌐 **English** · [Tiếng Việt](vi/alerts.md)

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
[ALERT]  auth.brute_force_detected actor=alice target=root attempts=5 window=300s service=sudo host=web-01 pid=12348 ts=2026-03-29T14:23:01+0000
[CRIT]   auth.login_after_failures user=root src=203.0.113.50:40112 failures=7 window=300s host=web-01 service=sshd auth=password pid=12360 ts=2026-03-29T14:24:10+0000
```

The last form is emitted when a local user (`alice`) repeatedly fails `sudo`/`su` authentication on the host. There is no `src=` because the attempt has no remote endpoint; ECS `user.name` carries the actor and `user.target.name` the elevation target. Per-event `auth.login_failure` alerts are **not** emitted for sudo/su — only the brute-force aggregate fires, so a mistyped password does not page the operator. The journal entry from `pamsignal` is still written for every individual failure.

The `[CRIT]` line is the login-after-failures alert: a login **succeeded** from an IP that had just failed `failures` times, which is what a guessed password looks like. It is sent in addition to the normal `auth.login_success` line, and fires even for `trusted_sources`; repeats for the same IP are spaced by `alert_cooldown_sec`. See [Configuration → Login-after-failures detection](./configuration.md#login-after-failures-detection).

*(Note: Custom context tags like `provider=aws service_name=web-api` will be appended automatically if configured in `pamsignal.conf`)*

### Pretty format

Set `message_style = pretty` to replace the single line above with a multi-line message: a headline, then one row per field with a bold label and a monospace value. The fields are the same; only the layout changes. What each platform receives:

```text
Telegram (HTML parse mode)
🚨 <b>Brute force detected</b>
<b>Host:</b> <code>web-01</code>
<b>Source:</b> <code>203.0.113.50</code>
<b>User:</b> <code>root</code>
<b>Attempts:</b> <code>12 in 300s</code>
<b>Time:</b> <code>2026-03-29 14:23:01 +0000</code>

Slack / WhatsApp
🚨 *Brute force detected*
*Host:* `web-01`
*Source:* `203.0.113.50`

Discord / Teams
🚨 **Brute force detected**
**Host:** `web-01`
**Source:** `203.0.113.50`
```

| Headline | Event | Rows |
|---|---|---|
| ✅ Login success / ❌ Login failed | `login_success`, `login_failure` | Host, User, Source, Auth, PID, Time |
| 🔓 Session opened / 🔒 Session closed | `session_opened`, `session_closed` | Host, User, Service, PID, Time |
| 🚨 Brute force detected | `brute_force_detected` (remote) | Host, Source, User, Attempts, Time |
| 🚨 Brute force detected (local) | `brute_force_detected` (sudo/su) | Host, Actor, Target, Service, Attempts, Time |
| 🔥 Login after failed attempts | `login_after_failures` | Host, User, Source, Failures, Auth, PID, Time |
| 🔔 PAMSignal test alert | `pamsignal --test-alert` | Host, Time |

`Provider` and `Service name` rows are appended when those tags are configured. Teams separates rows with a blank line, because its markdown folds single line breaks.

### How untrusted text is neutralised

User names and host names come from the journal, and a user name is chosen by whoever is trying to log in. Nothing derived from them is ever sent as ordinary message text, in either style:

- **Pretty:** every value is the content of a code span.
- **Compact:** the whole line is sent as one code span (`<code>…</code>` on Telegram, backticks elsewhere), so it also renders monospace, which is what its fixed-width layout was designed for.

Inside a code span no platform parses markup, resolves mentions, or turns text into links. Before the text goes in:

| Input | Becomes | Why |
|---|---|---|
| A backtick | `'` | It is the only character that can close a code span |
| `&` `<` `>` | `&amp;` `&lt;` `&gt;` on Telegram, Slack, Teams | They are syntax there (HTML tags, `<!channel>`, `<url\|text>`) |
| Control characters, including CR / LF / TAB | `?` | A line break would start a forged row |
| Unicode line and paragraph separators (U+2028, U+2029), C1 controls | `?` | Same, for clients that treat them as line breaks |
| Bidirectional overrides and isolates (U+202A–202E, U+2066–2069), zero-width and other invisible format characters | `?` | They reorder or hide the visible text |
| Bytes that are not well-formed UTF-8 | `?` | The chat APIs reject the whole request otherwise, which would suppress the alert |

So a login attempt as `[reset-password](https://evil.example)`, `https://evil.example`, `@everyone`, `<!channel>` or `/start` arrives as that literal text and nothing more. Discord alerts additionally carry `"allowed_mentions":{"parse":[]}`. A message that would exceed 2000 bytes is sent in the compact form, and if that does not fit either the alert is dropped with a journal warning rather than cut in the middle of its markup.

The same UTF-8 check applies to the custom webhook's JSON: an invalid byte in a field becomes `?` so the body always parses.

### Telegram

Sent via the [Bot API `sendMessage`](https://core.telegram.org/bots/api#sendmessage). Plain text for the compact style; HTML parse mode for the pretty style.

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

**Brute-force detection — remote (sshd, or sudo/su with `rhost=` set)**: keyed by source IP, `event.kind=alert`, severity 8:

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

**Brute-force detection — local (sudo/su without remote endpoint)**: keyed by actor (`ruser=`), no `source.*`. `user.name` is the actor; `user.target.name` is the elevation target:

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
  "user": {"name": "alice", "target": {"name": "root"}},
  "service": {"name": "sudo"},
  "process": {"pid": 12348},
  "pamsignal": {
    "event_type": "BRUTE_FORCE_DETECTED",
    "attempts": 5,
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

**Authentication (optional):**

Set `webhook_auth_header` in `pamsignal.conf` to send an arbitrary HTTP header with each POST:

```ini
webhook_url = https://siem.example.com/ingest/pamsignal
webhook_auth_header = Authorization: Bearer s3cr3t-token-here
```

Common patterns:

| Receiver | Header |
|----------|--------|
| Bearer / OAuth | `Authorization: Bearer <token>` |
| Generic API key | `X-API-Key: <key>` |
| Splunk HEC | `Authorization: Splunk <token>` |
| Datadog Logs | `DD-API-KEY: <key>` |
| Wazuh API | `Authorization: Bearer <jwt>` |

The header value is passed to curl via a memfd-backed `-K` config file, so the secret never appears in `argv`, `/proc/<pid>/cmdline`, or any process listing. Only one header is supported; values containing `\r`, `\n`, `"`, or `\` are rejected at config load.

**Mutual TLS (optional, advanced):**

For environments that already run a PKI (internal CA, cert-manager, SPIFFE, service-mesh issuance), pamsignal can authenticate to the receiver with a client certificate. Stronger than shared-secret auth: the private key never travels over the wire, and credential rotation is delegated to the cert-management pipeline.

```ini
webhook_url = https://siem.internal.example.com/ingest
webhook_client_cert = /etc/pamsignal/webhook-client.crt
webhook_client_key  = /etc/pamsignal/webhook-client.key
# Optional: only if the receiver's CA isn't in the system trust store
webhook_ca_bundle   = /etc/pamsignal/webhook-ca.pem
```

mTLS combines additively with `webhook_auth_header` — operators with receivers like Wazuh API or corporate SIEM gateways often require both (mTLS for transport-layer service identity, Bearer for app-layer rate-limit / multi-tenancy).

**Operational requirements:**

- `webhook_client_cert` and `webhook_client_key` must be set together; setting one without the other is a config-load error.
- `webhook_client_key` must not be group- or world-readable. Recommended layout: `0640 root:pamsignal` (or `0600 pamsignal:pamsignal` if the daemon runs unprivileged), mirroring the protection on `pamsignal.conf` itself.
- All three paths are opened with `O_NOFOLLOW` (symlinks rejected) and must be regular files owned by `root` or the daemon user.
- Path values containing `\r`, `\n`, `"`, or `\` are rejected at config load.
- Encrypted (passphrase-protected) keys are not supported. Use filesystem permissions, `systemd-creds`, or your cert manager's secret-injection model instead.
- The cert/key paths flow through the same memfd-backed curl config as the auth header, so they don't appear in `argv` either — keeps the alert child's process listing minimal.

### Event types

| `event.action` (ECS) | `pamsignal.event_type` (legacy) | When | Severity | `enable_notification_type` token |
|---|---|---|---|---|
| `session_opened` | `SESSION_OPEN` | A PAM session opens (sshd / sudo / su / login) | 3 (info) | `session_open` |
| `session_closed` | `SESSION_CLOSE` | A PAM session closes | 3 (info) | `session_close` |
| `login_success` | `LOGIN_SUCCESS` | Successful SSH auth (password, public key, or keyboard-interactive) | 4 (notice) | `login_success` |
| `login_failure` | `LOGIN_FAILED` | Failed SSH auth | 5 (warning) | `login_failed` |
| `login_failure` (sudo/su) | `LOGIN_FAILED` | Failed sudo/su attempt — **journal-only** (no per-event chat alert; tracked toward the brute-force threshold) | 5 (warning) | `login_failed` (suppression is independent and still applies) |
| `brute_force_detected` | `BRUTE_FORCE_DETECTED` | Failed attempts from one IP **or** from one local actor (sudo/su) exceeded the threshold within the window | 8 (alert) | `brute_force` |
| `login_after_failures` | `LOGIN_AFTER_FAILURES` | A login succeeds from an IP with at least `success_after_fail_threshold` recent failures — a likely guessed password | 9 (critical) | `login_after_failures` |

The last column is the token to list in `enable_notification_type` to receive that category as a chat alert. The default (`all`, or the key omitted) enables every category. The filter only gates chat dispatch — `journalctl -t pamsignal` records every event regardless. See [Configuration → Notification-type filter](./configuration.md#notification-type-filter) for the full reference.

`pamsignal --test-alert` sends one extra payload that is not a detection: `event.action` = `test_alert`, `pamsignal.event_type` = `TEST_ALERT`, severity 3, with only `@timestamp`, `event.*`, `host.hostname` and any `labels`. Receivers can ignore it or use it as a connectivity check.

### Field reference (ECS webhook JSON)

| Path | Type | Present in | Description |
|---|---|---|---|
| `@timestamp` | string | All | ISO 8601 with timezone offset |
| `event.action` | string | All | One of the values in the table above |
| `event.category` | array&lt;string&gt; | All | Always includes `"authentication"`; sessions add `"session"`, brute-force and login-after-failures add `"intrusion_detection"` |
| `event.kind` | string | All | `"event"` for observations, `"alert"` for brute-force and login-after-failures |
| `event.outcome` | string | All | `"success"`, `"failure"`, or `"unknown"` |
| `event.severity` | integer | All | 3=info, 4=notice, 5=warning, 8=alert, 9=critical |
| `event.module` | string | All | Always `"pamsignal"` |
| `event.dataset` | string | All | Always `"pamsignal.events"` |
| `host.hostname` | string | All | Server hostname |
| `user.name` | string | All | Username from the PAM message |
| `service.name` | string | Login/Session | PAM service: `sshd`, `sudo`, `su`, `login`, `other` |
| `source.ip` | string | Login + Brute + Login-after-failures | Remote IP (validated via `inet_pton`) |
| `source.port` | integer | Login + Login-after-failures | Remote port |
| `process.pid` | integer | All | Process ID — the live sshd session for `login_success`/`session_opened`, the (already reaped) auth child for failures and brute-force |
| `process.user.id` | string | Login/Session | UID of the PAM-handled process |
| `pamsignal.event_type` | string | All | Legacy uppercase enum (kept for backward compat through v0.2.x; retired in v0.3.0) |
| `pamsignal.auth_method` | string | Login + Login-after-failures | `password`, `publickey`, `keyboard-interactive`, or `unknown` |
| `pamsignal.attempts` | integer | Brute-force | Number of failed attempts that breached the threshold |
| `pamsignal.failures` | integer | Login-after-failures | Length of the run of failed attempts that preceded the successful login |
| `pamsignal.window_sec` | integer | Brute-force + Login-after-failures | Configured time window |

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
