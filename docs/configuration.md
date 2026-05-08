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
telegram_bot_token = <bot_token>
telegram_chat_id = <chat_id>

# Slack
slack_webhook_url = <webhook_url>

# Microsoft Teams
teams_webhook_url = <webhook_url>

# WhatsApp (Meta Cloud API)
whatsapp_access_token = <access_token>
whatsapp_phone_number_id = <phone_number_id>
whatsapp_recipient = <recipient_number>

# Discord
discord_webhook_url = <webhook_url>

# Custom webhook
webhook_url = <webhook_url>

# Custom webhook authentication (optional)
webhook_auth_header = Authorization: Bearer <token>

# Custom webhook mTLS (optional, advanced)
webhook_client_cert = /etc/pamsignal/webhook-client.crt
webhook_client_key  = /etc/pamsignal/webhook-client.key
webhook_ca_bundle   = /etc/pamsignal/webhook-ca.pem
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

## Custom webhook authentication

The `webhook_url` channel supports two optional, additive authentication mechanisms — neither, either, or both. Telegram, Slack, Teams, WhatsApp, and Discord authenticate through their own URL/token schemes and are unaffected.

| Key | Mode | Description |
|-----|------|-------------|
| `webhook_auth_header` | Header | Single arbitrary HTTP header sent on every POST. Full `Name: value` form so any auth scheme works (Bearer, API key, Splunk HEC, Datadog, HMAC). The value is rendered into a memfd-backed curl `-K` config file, so the secret never appears in `argv` or `/proc/<pid>/cmdline`. |
| `webhook_client_cert` | mTLS | Path to a PEM-encoded client certificate. Must be set together with `webhook_client_key`. |
| `webhook_client_key` | mTLS | Path to the matching PEM-encoded private key. **Must not be group- or world-readable** — pamsignal refuses to start otherwise. Recommended: `0640 root:pamsignal` (or `0600 pamsignal:pamsignal` if you run the daemon as that user). |
| `webhook_ca_bundle` | mTLS | Optional path to a CA bundle PEM. Only needed when the receiver's CA is not in the system trust store (private CA, internal cert-manager). |

**Common patterns:**

```ini
# Bearer-only — most receivers (Wazuh, Splunk HEC, Datadog, custom Express receivers).
webhook_url = https://siem.example.com/ingest/pamsignal
webhook_auth_header = Authorization: Bearer <token>

# mTLS-only — environments with PKI in place; transport-layer service identity.
webhook_url = https://siem.internal.example.com/ingest
webhook_client_cert = /etc/pamsignal/webhook-client.crt
webhook_client_key  = /etc/pamsignal/webhook-client.key

# Combined — corporate SIEM gateways that want both transport auth and per-request authorization.
webhook_url = https://siem.internal.example.com/ingest
webhook_auth_header = Authorization: Bearer <jwt>
webhook_client_cert = /etc/pamsignal/webhook-client.crt
webhook_client_key  = /etc/pamsignal/webhook-client.key
webhook_ca_bundle   = /etc/pamsignal/internal-ca.pem
```

**Validation enforced at config load:**

- Setting any of the three TLS keys without `webhook_url` is a config-load error.
- `webhook_client_cert` and `webhook_client_key` must be set together; one without the other is rejected.
- All cert/key/CA paths are opened with `O_NOFOLLOW` (symlinks rejected) and must be regular files owned by `root` or the daemon user.
- Path strings containing control characters, `"`, or `\` are rejected so the value is unambiguous in the curl `-K` config.
- `webhook_auth_header` must be in `Name: value` form; values containing CR, LF, `"`, or `\` are rejected (CRLF header injection / quote-escape protection).

Encrypted (passphrase-protected) keys are not supported — manage key secrecy via filesystem permissions, `systemd-creds`, or your cert manager's secret-injection model.

See [Alerts → Custom webhook (ECS JSON)](./alerts.md#custom-webhook-ecs-json) for the on-the-wire payload, the receiver-pattern table (Bearer / X-API-Key / Splunk / Datadog / Wazuh), and the operator-side mTLS deployment notes.

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
