# PAMSignal Python Webhook Receiver

This is a ready-to-use example of a Custom Webhook receiver built with **Python** and **Flask**. It receives structured ECS JSON alerts from PAMSignal and processes them. It is the Python counterpart to the `examples/nodejs-webhook/` example and exposes the same endpoint contract, env vars, and mTLS behavior.

This example incorporates:
- **Flask** for the HTTP layer
- **Authentication** using a secret Bearer token (no secrets leaked via URLs)
- Optional **HTTPS / mutual TLS** when paired with `pamsignal.conf`'s `webhook_client_cert` / `webhook_client_key`
- **[uv](https://docs.astral.sh/uv/)** for dependency and virtualenv management

## 🚀 Getting Started

### 1. Install uv

If you don't already have it:

```bash
# macOS / Linux
curl -LsSf https://astral.sh/uv/install.sh | sh
```

See the [uv install docs](https://docs.astral.sh/uv/getting-started/installation/) for other methods.

### 2. Install Dependencies

From this directory:

```bash
uv sync
```

`uv sync` creates a `.venv/` and installs everything from `pyproject.toml` (including dev tools like `pytest`).

### 3. Configure Environment

Copy the example environment file and set a strong secret token:

```bash
cp .env.example .env
```

Edit `.env` and set `WEBHOOK_SECRET` to a random string (e.g. `openssl rand -hex 32`).

### 4. Run the Server

```bash
uv run python src/server.py
```

The server will start listening on `http://localhost:3000/webhook/pamsignal`.

## ⚙️ Integrating with PAMSignal

This Flask app strictly enforces `Authorization: Bearer <token>` to avoid leaking secrets through URL access logs. PAMSignal supports this directly via the `webhook_auth_header` config key — no reverse proxy required.

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
#    Node example and the Bruno collection pick up the same files.
(cd ../shared-certs && ./gen-test-certs.sh)

# 2. Configure this example to listen on HTTPS and require a client cert.
cat >> .env <<'EOF'
TLS_KEY_PATH=./certs/server.key
TLS_CERT_PATH=./certs/server.crt
TLS_CLIENT_CA_PATH=./certs/ca.crt
TLS_REQUIRE_CLIENT_CERT=true
EOF

# 3. Start the receiver.
uv run python src/server.py
```

You should see `🔐 PAMSignal Webhook Receiver listening on https://localhost:3000/webhook/pamsignal (mTLS — client cert required)`.

#### Configure pamsignal

In `/etc/pamsignal/pamsignal.conf`:

```ini
webhook_url = https://localhost:3000/webhook/pamsignal
webhook_auth_header = Authorization: Bearer your_super_secret_token_here
webhook_client_cert = /absolute/path/to/certs/client.crt
webhook_client_key  = /absolute/path/to/certs/client.key
# Required because the demo CA isn't in the system trust store.
webhook_ca_bundle   = /absolute/path/to/certs/ca.crt
```

Reload pamsignal (`sudo systemctl reload pamsignal`) and trigger an event — the receiver should log it. A request from any client without a valid cert (e.g. `curl https://localhost:3000/webhook/pamsignal`) will be rejected at the TLS handshake before reaching Flask.

#### Production layout

For production deployments, replace `./certs/*` with paths managed by your cert pipeline (cert-manager, certbot, `systemd-creds`, internal CA + ACME, etc.). The four env vars and the `webhook_*` config keys are unchanged. `gen-test-certs.sh` is for local/CI testing — do not ship its output to production.

mTLS combines additively with `webhook_auth_header` if the receiver wants both (mTLS for transport-layer service identity, Bearer for per-request authorization). The Flask middleware in this example checks the Bearer token regardless of the transport, so an mTLS-only deployment can simply leave `WEBHOOK_SECRET` unset (or set both for defense in depth).

## 🛠️ Deploying as a Systemd Daemon

For production, you should run this webhook receiver as a background service so it automatically starts on boot and restarts if it crashes. Werkzeug's built-in server is fine for low-volume webhooks, but for higher load you may want to put a real WSGI server (gunicorn, uWSGI) in front — adjust `ExecStart` accordingly.

1. Install dependencies into the project's `.venv/`:
   ```bash
   uv sync --no-dev
   ```

2. Create a systemd service file. Open `/etc/systemd/system/pamsignal-webhook.service`:
   ```bash
   sudo nano /etc/systemd/system/pamsignal-webhook.service
   ```

3. Paste the following configuration. Make sure to update `WorkingDirectory` to the actual path of your project and `User` to your actual non-root user:

   ```ini
   [Unit]
   Description=PAMSignal Python Webhook Receiver
   After=network.target

   [Service]
   Type=simple
   # Update this to the user you want to run the Python process as
   User=www-data
   # Update this to the absolute path of this example directory
   WorkingDirectory=/opt/pamsignal-python-webhook
   # Run the server using the venv's Python interpreter
   ExecStart=/opt/pamsignal-python-webhook/.venv/bin/python src/server.py
   Restart=on-failure
   RestartSec=5

   # Load the environment variables from the .env file
   EnvironmentFile=/opt/pamsignal-python-webhook/.env

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

## 🧪 Testing it manually

### Using Curl

You can simulate a PAMSignal brute-force alert using `curl` to test the Flask server:

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

You should see the parsed event beautifully logged in your `journalctl` stream or Python console.

### Using Bruno API Client

A shared **Bruno** collection lives at [`../bruno-collection/`](../bruno-collection/) and works against any receiver that implements the PAMSignal webhook contract — this Python example and the Node.js example both qualify. It ships two environments:

- **Local** — plain HTTP, Bearer-token only
- **Local-mTLS** — HTTPS with a client cert (pair with `TLS_REQUIRE_CLIENT_CERT=true` here)

See [`../bruno-collection/README.md`](../bruno-collection/README.md) for cert-symlink setup. Quick start:

1. Download [Bruno](https://www.usebruno.com/).
2. Click **Open Collection** (not *Import Collection* — that path expects Postman/OpenAPI JSON) and select the `examples/bruno-collection` folder.
3. Pick the environment from the dropdown (top right) — `Local` or `Local-mTLS`.
4. Update the chosen environment's `WEBHOOK_SECRET` to match your `.env` and click **Send**.

## ✅ Unit Tests

This project includes a `pytest` test suite that verifies authentication (Bearer token), payload validation, and the mTLS handshake path.

To run the tests:

```bash
uv run pytest
```

The mTLS tests require `openssl` to be available on `PATH` (used to generate ephemeral certs in a temp dir); they are skipped automatically if it is not.
