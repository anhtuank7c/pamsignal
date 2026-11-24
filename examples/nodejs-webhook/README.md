# PAMSignal Node.js Webhook Receiver

> **English** · [Tiếng Việt](../../docs/vi/examples/nodejs-webhook.md)

This is a ready-to-use example of a Custom Webhook receiver built with **TypeScript**, Node.js, and Express. It receives structured ECS JSON alerts from PAMSignal and processes them.

This example incorporates Express best practices, including:
- **TypeScript** for strict type safety and modern syntax
- **Security Headers** using `helmet`
- **Request Logging** using `morgan`
- **Authentication** using a secret Bearer token

## Getting Started

### 1. Install Dependencies

Ensure you have Node.js 20 or later and [pnpm](https://pnpm.io/installation), then run:

```bash
pnpm install
```

Use pnpm rather than npm: the lockfile is `pnpm-lock.yaml`, and the security overrides for vulnerable transitive dependencies live in `pnpm-workspace.yaml`, which npm ignores.

### 2. Configure Environment

Copy the example environment file and set a strong secret token:

```bash
cp .env.example .env
```

Edit `.env` and set `WEBHOOK_SECRET` to a random string.

### 3. Build & Run the Server

```bash
# Compile TypeScript to JavaScript (outputs to dist/ directory)
pnpm run build

# Run the compiled code for production
pnpm start

# For development (auto-restarts on file changes without building)
pnpm run dev
```

The server will start listening on `http://localhost:3000/webhook/pamsignal`.

## Integrating with PAMSignal

This Express app strictly enforces `Authorization: Bearer <token>` to avoid leaking secrets through URL access logs. PAMSignal supports this directly via the `webhook_auth_header` config key, so no reverse proxy is required.

PAMSignal only sends to HTTPS: `webhook_url` must start with `https://` (the config is rejected otherwise) and curl runs with `--proto =https`. The plain-HTTP mode above is for curl and Bruno tests. For real alerts, run the receiver with TLS (see [Mutual TLS](#mutual-tls-advanced)) or behind a TLS reverse proxy.

### Direct configuration (recommended)

Edit `/etc/pamsignal/pamsignal.conf`:

```ini
webhook_url = https://your-receiver.example.com/webhook/pamsignal
webhook_auth_header = Authorization: Bearer your_super_secret_token_here
```

Reload PAMSignal to apply the changes:

```bash
sudo systemctl reload pamsignal
```

Then check the channel end to end. `--test-alert` sends one `test_alert` payload to every configured channel and reports `ok` or `FAILED` for each; the receiver logs a `[TEST_ALERT]` line:

```bash
sudo -u pamsignal pamsignal --test-alert
```

The header value is passed to curl via a memfd-backed config file, so the token never appears in `/proc/<pid>/cmdline`. Set `0640 root:pamsignal` on `pamsignal.conf` to keep the value off-disk-readable for non-daemon users.

### Reverse proxy (alternative)

If you front the receiver with Nginx/Caddy/Traefik anyway (TLS termination, rate-limit, etc.), you can let the proxy inject the header instead:

- Proxy: `proxy_set_header Authorization "Bearer your_super_secret_token_here";`
- pamsignal.conf: `webhook_url = https://your-secure-proxy.local/webhook/pamsignal` (omit `webhook_auth_header`)

### Mutual TLS (advanced)

If you already run an internal PKI, this example can run as an mTLS-enforcing HTTPS receiver that pairs with pamsignal's `webhook_client_cert` / `webhook_client_key` config. The server picks HTTPS over plain HTTP automatically when the TLS env vars are set.

#### Local end-to-end demo

```bash
# 1. Generate a CA + server cert + client cert in the shared dir.
#    The `./certs/` path here is a symlink to ../shared-certs/, so the
#    Python example and the Bruno collection pick up the same files.
(cd ../shared-certs && ./gen-test-certs.sh)

# 2. Configure this example to listen on HTTPS and require a client cert.
cat >> .env <<'EOF'
TLS_KEY_PATH=./certs/server.key
TLS_CERT_PATH=./certs/server.crt
TLS_CLIENT_CA_PATH=./certs/ca.crt
TLS_REQUIRE_CLIENT_CERT=true
EOF

# 3. Start the receiver.
pnpm run dev   # or: pnpm run build && pnpm start
```

You should see `PAMSignal Webhook Receiver listening on https://localhost:3000/webhook/pamsignal (mTLS, client cert required)`.

#### Configure pamsignal

In `/etc/pamsignal/pamsignal.conf`:

```ini
webhook_url = https://localhost:3000/webhook/pamsignal
webhook_auth_header = Authorization: Bearer your_super_secret_token_here
webhook_client_cert = /etc/pamsignal/webhook-client.crt
webhook_client_key  = /etc/pamsignal/webhook-client.key
# Required because the demo CA isn't in the system trust store.
webhook_ca_bundle   = /etc/pamsignal/webhook-ca.crt
```

PAMSignal will not use the files from `./certs/` directly: it opens each path with `O_NOFOLLOW` (symlinks are rejected), each file must be owned by `root` or the daemon user, the key must not be group- or world-readable, and the unit's `ProtectHome=yes` hides `/home`. Copy them into place, with the key owned by `pamsignal` because curl runs as that user:

```bash
sudo install -m 0644 -o root -g root certs/client.crt /etc/pamsignal/webhook-client.crt
sudo install -m 0644 -o root -g root certs/ca.crt     /etc/pamsignal/webhook-ca.crt
sudo install -m 0600 -o pamsignal -g pamsignal certs/client.key /etc/pamsignal/webhook-client.key
sudo -u pamsignal pamsignal --check-config
```

Reload pamsignal (`sudo systemctl reload pamsignal`) and run `sudo -u pamsignal pamsignal --test-alert`; the receiver should log a `[TEST_ALERT]` line. A request from any client without a valid cert (e.g. `curl https://localhost:3000/webhook/pamsignal`) will be rejected at the TLS handshake before reaching Express.

#### Production layout

For production deployments, replace the demo files with ones managed by your cert pipeline (cert-manager, certbot, `systemd-creds`, internal CA + ACME, etc.). The four env vars and the `webhook_*` config keys are unchanged. `gen-test-certs.sh` is for local/CI testing; do not ship its output to production.

mTLS combines additively with `webhook_auth_header` if the receiver wants both (mTLS for transport-layer service identity, Bearer for per-request authorization). The Express middleware in this example checks the Bearer token regardless of the transport, so an mTLS-only deployment can simply leave `WEBHOOK_SECRET` unset (or set both for defense in depth).

## What PAMSignal sends

PAMSignal posts one ECS JSON object per alert. The receiver checks only that `event` and `pamsignal` are present, then logs one line per `event.action`:

| `event.action` | When | Fields the log line uses |
|---|---|---|
| `login_success` | Successful login | `user.name`, `source.ip`, `host.hostname`, `process.pid` |
| `login_failure` | Failed login (`sudo`/`su` failures are not sent one by one; they only count toward brute force) | `user.name`, `source.ip`, `host.hostname` |
| `session_opened`, `session_closed` | Session start and end | `user.name`, `host.hostname` |
| `brute_force_detected` | `fail_threshold` failures inside `fail_window_sec` | `pamsignal.attempts`, `source.ip`, `pamsignal.window_sec` |
| `login_after_failures` | A login that succeeds right after a run of failures from the same IP | `user.name`, `source.ip`, `pamsignal.failures`, `host.hostname` |
| `test_alert` | `pamsignal --test-alert` | `host.hostname` |

Any other action is logged as `[UNKNOWN_EVENT]`. Two payload shapes matter if you extend the handler:

- Session events have no `source` object. When the session was opened from another account (for example a `sudo` session started by `alice`), `pamsignal.actor` holds that account and `user.name` stays the session's user.
- A local `sudo`/`su` brute force has no `source` object: `user.name` is the account typing the passwords and `user.target.name` the account it tried to become. The demo log line prints `source.ip`, so it shows `undefined` for this case.

Full payload examples and the field reference are in [docs/alerts.md](../../docs/alerts.md#custom-webhook-ecs-json).

## Deploying as a Systemd Daemon

For production, you should run this webhook receiver as a background service so it automatically starts on boot and restarts if it crashes. 

1. Ensure you have compiled the code:
   ```bash
   pnpm run build
   ```

2. Create a systemd service file. Open `/etc/systemd/system/pamsignal-webhook.service`:
   ```bash
   sudo nano /etc/systemd/system/pamsignal-webhook.service
   ```

3. Paste the following configuration. Make sure to update `WorkingDirectory` to the actual path of your project and `User` to your actual non-root user:

   ```ini
   [Unit]
   Description=PAMSignal Node.js Webhook Receiver
   After=network.target

   [Service]
   Type=simple
   # Update this to the user you want to run the Node.js process as
   User=www-data
   # Update this to the absolute path of this example directory
   WorkingDirectory=/opt/pamsignal-nodejs-webhook
   # Path to your Node.js executable (find it with `which node`)
   ExecStart=/usr/bin/node dist/server.js
   Restart=on-failure
   RestartSec=5
   
   # Load the environment variables from the .env file
   EnvironmentFile=/opt/pamsignal-nodejs-webhook/.env

   # Security Hardening
   NoNewPrivileges=yes
   ProtectSystem=strict
   ProtectHome=yes
   PrivateTmp=yes

   [Install]
   WantedBy=multi-user.target
   ```

4. Enable and start the service:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now pamsignal-webhook
   sudo systemctl status pamsignal-webhook
   ```

5. View the logs in real-time:
   ```bash
   journalctl -u pamsignal-webhook -f
   ```

## Testing it manually

### Using Bruno API Client

A shared **Bruno** collection lives at [`../bruno-collection/`](../bruno-collection/) and works against any receiver that implements the PAMSignal webhook contract. This Node.js example and the Python Flask example both qualify. It ships two environments:

- **Local**: plain HTTP, Bearer-token only
- **Local-mTLS**: HTTPS with a client cert (pair with `TLS_REQUIRE_CLIENT_CERT=true` here)

See [`../bruno-collection/README.md`](../bruno-collection/README.md) for cert-symlink setup. Quick start:

1. Download [Bruno](https://www.usebruno.com/).
2. Click **Open Collection** (not *Import Collection*, which expects Postman/OpenAPI JSON) and select the `examples/bruno-collection` folder.
3. Pick the environment from the dropdown (top right): `Local` or `Local-mTLS`.
4. Update the chosen environment's `WEBHOOK_SECRET` to match your `.env` and click **Send**.

### Using Curl

You can also simulate a PAMSignal brute-force alert using `curl` to test the Express server. The receiver only checks that `event` and `pamsignal` exist, so a trimmed payload is enough:

```bash
# Testing with Bearer Token header
curl -X POST http://localhost:3000/webhook/pamsignal \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer your_super_secret_token_here" \
     -d '{
       "event": { "action": "brute_force_detected" },
       "source": { "ip": "203.0.113.50" },
       "pamsignal": { "attempts": 12, "window_sec": 300 }
     }'
```

The receiver logs `[BRUTE_FORCE] 12 failed attempts detected from IP 203.0.113.50 in 300s!` to its console (or `journalctl -u pamsignal-webhook` when run as a service).

## Unit Tests

This project includes a Jest test suite that verifies authentication (Bearer token), payload validation, a real HTTP round trip, and the mTLS handshake path.

To run the tests:

```bash
pnpm test
```
