# Configuration

> 🌐 **English** · [Tiếng Việt](vi/configuration.md)

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

# Login-after-failures detection (0 = disabled)
success_after_fail_threshold = 3

# Trusted sources (default: empty)
trusted_sources = 10.0.0.0/8, 203.0.113.7

# Chat-dispatch filter (default: all)
enable_notification_type = all

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

## Login-after-failures detection

| Key | Default | Range | Description |
|-----|---------|-------|-------------|
| `success_after_fail_threshold` | `3` | 0 - 10000 | Failed attempts from one IP that make a following successful login suspicious (0 = disabled) |

A successful login from an IP that has just failed several times is the pattern of a guessed password, and it is the one alert you should never ignore. When a login succeeds from a source IP with at least `success_after_fail_threshold` failures, the most recent within `fail_window_sec`, PAMSignal raises a `[CRIT]` `login_after_failures` alert (severity 9), on top of the normal `login_success` event.

- **One alert per incident.** Any successful login from that IP clears its run of failures, so the alert does not repeat on the next login.
- **Not muted by `trusted_sources`.** It fires for trusted networks too. Repeat chat alerts for the same IP are spaced by `alert_cooldown_sec`, like brute-force alerts; the journal records every occurrence. To turn it off, set the threshold to `0` or leave `login_after_failures` out of `enable_notification_type`.
- **Independent of the brute-force counter.** The run survives a brute-force alert, so an attacker who trips `fail_threshold` and then gets in is still flagged.
- **Remote logins only.** It is keyed by source IP; local `sudo`/`su` elevation has no IP and is not covered.

A person who mistypes their own password three times and then gets it right triggers it too. Raise the threshold if that is common on your hosts.

## Trusted sources

| Key | Default | Description |
|-----|---------|-------------|
| `trusted_sources` | *(empty)* | Comma-separated IPv4/IPv6 addresses or CIDR networks (at most 32) whose routine login alerts are not sent to chat |

Use it for the places you log in from every day — an office range, a VPN, a bastion host — so those logins stop pinging the channel.

```ini
trusted_sources = 10.0.0.0/8, 203.0.113.7, 2001:db8::/32
```

- **What is muted.** Only the per-event `login_success` and `login_failed` chat alerts for events whose source IP is inside a listed network.
- **What still fires.** `brute_force` and `login_after_failures` alerts. A compromised machine inside a trusted network cannot attack silently.
- **The journal is unaffected.** `journalctl -t pamsignal` records every event from every source.
- **Session events are not covered.** `session_open` / `session_close` carry no source IP. Mute them with `enable_notification_type` instead.

A bare address means that single host. The prefix length must be at least 1 (`0.0.0.0/0` is rejected), hostnames are not resolved, and a malformed entry is a hard config error. An IPv4-mapped IPv6 peer (`::ffff:10.1.2.3`) matches the IPv4 entries.

## Notification-type filter

`enable_notification_type` selects which event categories trigger chat alerts. It is a comma-separated list. The default — when the key is omitted, or when `all` is given — is every category, preserving prior behaviour. Unknown tokens are a hard config error; empty values and empty list elements are rejected.

| Token | Triggers chat alert when… |
|-------|---------------------------|
| `login_success` | A successful login is detected (sshd, login) |
| `login_failed` | A failed login is detected (sshd, login; sudo/su failures stay subject to the existing per-event suppression — see below) |
| `session_open` | A PAM session opens (incl. systemd background sessions like cron) |
| `session_close` | A PAM session closes |
| `brute_force` | Either remote (IP-based) or local (sudo/su actor-based) brute-force threshold is crossed |
| `login_after_failures` | A login succeeds from an IP with a run of recent failures (see [Login-after-failures detection](#login-after-failures-detection)) |
| `all` | Sentinel for every category above (equivalent to omitting the key) |

> **Upgrading with an explicit list?** `login_after_failures` is a new category. If your config already names specific tokens (for example `login_success,brute_force`), add `login_after_failures` to keep receiving that alert in chat; with `all` or the key omitted you get it automatically.

**Scope.** This filter only gates chat dispatch (Telegram, Slack, Teams, WhatsApp, Discord, custom webhook). The local `journalctl -t pamsignal` trail records every event regardless, so the forensic log stays complete. The existing per-event suppression for sudo/su `LOGIN_FAILED` (only the brute-force alert fires) is independent and layered beneath this filter.

Examples:

```ini
# Only successful logins and brute-force detections
enable_notification_type = login_success,brute_force

# Only brute-force
enable_notification_type = brute_force

# Everything (default)
enable_notification_type = all
```

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

*Any of these patterns can be paired with `enable_notification_type` to narrow which event categories reach the webhook — see [Notification-type filter](#notification-type-filter) above for the full list of tokens (`login_success`, `login_failed`, `session_open`, `session_close`, `brute_force`, `all`).*

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
| `--check-config` | `-t` | Validate the config file, print any errors, and exit |
| `--test-alert` | `-T` | Send a test message to every configured channel and exit |

Relative paths are resolved to absolute before daemonization.

## Check the config and test your alerts

After editing the config, validate it before reloading, then confirm the channels actually deliver:

```bash
sudo -u pamsignal pamsignal --check-config
sudo -u pamsignal pamsignal --test-alert
```

`--check-config` prints every problem with its line number and exits `1`, or a short summary and `0`:

```text
pamsignal: config:2: trusted_sources must be a comma-separated list of at most 32 IPv4/IPv6 addresses or CIDR networks (prefix length 1 or more)
pamsignal: config has 1 error(s)
```

```text
pamsignal: /etc/pamsignal/pamsignal.conf: configuration OK
  alert channels: telegram slack
  trusted sources: 2
```

`--test-alert` sends one test message per configured channel, waits for each to finish, and prints a verdict. A rejected request (wrong token, revoked webhook) is a failure, and curl's own error is shown above the verdict:

```text
telegram  ok
curl: (22) The requested URL returned error: 404
slack     FAILED (curl exit code 22; see the curl message above)
pamsignal: 1 alert channel(s) failed
```

It exits `0` only if every configured channel accepted the message. The test message ignores `enable_notification_type` and `alert_cooldown_sec`.

Both commands must run as the service user, not root: the ownership checks on the config and TLS key files are relative to the user running them, so only then does the result match what the daemon will see. Both also work with `-c PATH`.

## Reload without restart

```bash
sudo systemctl reload pamsignal
```

This sends SIGHUP to the daemon. If the new config is valid, it takes effect immediately and the brute-force tracking table resets. If the config has errors, the daemon keeps the current config and logs a warning.
