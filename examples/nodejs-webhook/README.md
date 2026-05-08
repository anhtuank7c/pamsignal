# PAMSignal Node.js Webhook Receiver

This is a ready-to-use example of a Custom Webhook receiver built with **TypeScript**, Node.js, and Express. It receives structured ECS JSON alerts from PAMSignal and processes them.

This example incorporates Express best practices, including:
- **TypeScript** for strict type safety and modern syntax
- **Security Headers** using `helmet`
- **Request Logging** using `morgan`
- **Authentication** using a secret Bearer token

## 🚀 Getting Started

### 1. Install Dependencies

Ensure you have Node.js installed, then run:

```bash
npm install
```

### 2. Configure Environment

Copy the example environment file and set a strong secret token:

```bash
cp .env.example .env
```

Edit `.env` and set `WEBHOOK_SECRET` to a random string.

### 3. Build & Run the Server

```bash
# Compile TypeScript to JavaScript (outputs to dist/ directory)
npm run build

# Run the compiled code for production
npm start

# For development (auto-restarts on file changes without building)
npm run dev
```

The server will start listening on `http://localhost:3000/webhook/pamsignal`.

## ⚙️ Integrating with PAMSignal

This Express app strictly enforces `Authorization: Bearer <token>` to avoid leaking secrets through URL access logs. PAMSignal supports this directly via the `webhook_auth_header` config key — no reverse proxy required.

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

If you already run an internal PKI, configure the receiver to require client certs and let pamsignal authenticate with one. Replace this example's plain Express server with `https.createServer` and verify the peer cert:

```ts
import https from 'node:https';
import fs from 'node:fs';

const server = https.createServer({
  key: fs.readFileSync('/etc/ssl/private/server.key'),
  cert: fs.readFileSync('/etc/ssl/certs/server.crt'),
  ca: fs.readFileSync('/etc/ssl/certs/internal-ca.crt'),
  requestCert: true,
  rejectUnauthorized: true,
}, app);
server.listen(8443);
```

On the pamsignal side:

```ini
webhook_url = https://your-receiver.internal:8443/webhook/pamsignal
webhook_client_cert = /etc/pamsignal/webhook-client.crt
webhook_client_key  = /etc/pamsignal/webhook-client.key
# Only if your receiver's CA isn't in the system trust store
webhook_ca_bundle   = /etc/pamsignal/internal-ca.crt
```

mTLS combines additively with `webhook_auth_header` if the receiver wants both (mTLS for service identity, Bearer for per-request authorization).

## 🛠️ Deploying as a Systemd Daemon

For production, you should run this webhook receiver as a background service so it automatically starts on boot and restarts if it crashes. 

1. Ensure you have compiled the code:
   ```bash
   npm run build
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
   ExecStart=/usr/bin/node dist/index.js
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

## 🧪 Testing it manually

### Using Bruno API Client

We have provided a ready-to-use **Bruno** collection to easily test the webhook. 
1. Download [Bruno](https://www.usebruno.com/).
2. Click **Open Collection** and select the `examples/nodejs-webhook/bruno-collection` folder.
3. Open any of the requests (e.g., *Login Success*, *Brute Force Detected*).
4. Update the `Auth` tab to match your `WEBHOOK_SECRET` from `.env` and click **Send**!

### Using Curl

You can also simulate a PAMSignal brute-force alert using `curl` to test the Express server:

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

You should see the parsed event beautifully logged in your `journalctl` stream or Node.js console!

## ✅ Unit Tests

This project includes a comprehensive Jest test suite that verifies authentication (Bearer token) and payload validation.

To run the tests:

```bash
npm run test
```
