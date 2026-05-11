# PAMSignal Webhook Bruno Collection

Ready-to-use [Bruno](https://www.usebruno.com/) requests for testing any PAMSignal webhook receiver — the [Node.js example](../nodejs-webhook/), the [Python example](../python-webhook/), or any other implementation of the same `POST /webhook/pamsignal` contract.

Tested with **Bruno ≥ 3.3.0**.

## Contents

- [Quick start](#quick-start) — first 200 OK in five steps
- [Environments](#environments) — HTTP vs mTLS
- [Sending your first request](#sending-your-first-request) — UI walkthrough
- [Testing your receiver's defenses](#testing-your-receivers-defenses) — deliberately trigger 401 / 415 / 413 / 400
- [mTLS setup](#mtls-setup) — client cert + self-signed CA workflow
- [Customizing the collection](#customizing-the-collection) — edit payloads, add requests, override per-request
- [Troubleshooting](#troubleshooting)

## Quick start

1. Install [Bruno](https://www.usebruno.com/).
2. Click **Open Collection** (not *Import Collection* — that path expects Postman/OpenAPI JSON and will fail with *"Unsupported collection format"*). Select the `examples/bruno-collection` folder.
3. Start one of the example receivers in another terminal:
   ```bash
   # Python
   cd ../python-webhook && uv run python src/server.py
   # or Node.js
   cd ../nodejs-webhook && pnpm run dev
   ```
4. In Bruno, pick the **Local** environment from the top-right dropdown and click the **eye icon** to edit it. Set `WEBHOOK_SECRET` to whatever you put in the receiver's `.env`.
5. Open the **Login Success** request and click **Send**. You should see `200 OK` with `{"status":"success","message":"Event received"}`.

If you got that, the collection is wired up. The rest of this README explains how to exercise the receiver more thoroughly.

## Environments

| Environment | URL | Use when |
|---|---|---|
| **Local** | `http://localhost:3000/webhook/pamsignal` | Receiver is running on plain HTTP |
| **Local-mTLS** | `https://localhost:3000/webhook/pamsignal` | Receiver has `TLS_REQUIRE_CLIENT_CERT=true` (see [mTLS setup](#mtls-setup)) |

Both share the same two variables — `WEBHOOK_URL` and `WEBHOOK_SECRET` — which every request references via `{{...}}`. Switching environments is a one-click change in the dropdown; no request edits required.

## Sending your first request

1. Open **Login Success** in the sidebar. You'll see:
   - **URL** panel: `{{WEBHOOK_URL}}` — interpolated at send time from the active environment.
   - **Auth** tab: Bearer scheme, token `{{WEBHOOK_SECRET}}`.
   - **Body** tab: a synthetic ECS-shaped JSON document describing a `login_success` event.
2. Click **Send**.
3. The **Response** pane shows:
   - **Status**: `200 OK`
   - **Body**: `{"status":"success","message":"Event received"}`
   - **Headers**: `Content-Type: application/json`
   - **Timeline**: round-trip time, request/response sizes
4. Switch to the receiver's terminal — you should see the matching log line:
   ```
   ✅ [LOGIN_SUCCESS] User 'admin' logged in via 10.0.0.1 on server-01 (PID: 1234)
   ```

The other two canned requests (`Login Failure`, `Brute Force Detected`) work identically with different payload shapes and produce different log prefixes on the receiver side.

## Testing your receiver's defenses

The receiver implements several defensive checks (authentication, body size, Content-Type, payload shape). You can verify each one by deliberately breaking a request and watching the response code. Each row is a 30-second test:

| Defense | How to break the request | Expected response |
|---|---|---|
| **Bearer auth** | In the env, clear `WEBHOOK_SECRET` (or open the request → **Auth** tab → temporarily change the token). Send. | `401 {"error":"Unauthorized: Invalid or missing token"}` |
| **Bearer auth (wrong scheme)** | Auth tab → switch from *Bearer* to *Basic*. Send. | `401` |
| **Content-Type** | **Body** tab → switch type from *JSON* to *Text*. Leave the body content as-is. Send. | `415 {"error":"Unsupported Media Type: expected application/json"}` |
| **Body size cap (64 KB)** | Body tab → in the JSON, add a long string field, e.g. `"pad": "AAA…"` repeated to ~70 KB. Send. | `413 Payload Too Large` |
| **Payload shape** | Body tab → delete the `"event"` or `"pamsignal"` block from the JSON. Send. | `400 {"error":"Bad Request: Invalid payload format"}` |
| **Auth-before-validation order** | Clear `WEBHOOK_SECRET` *and* switch Body type to Text. Send. | `401` (not `415`) — the receiver authenticates before sniffing the media type, so unauthenticated peers can't learn anything about the endpoint's content negotiation. |
| **mTLS handshake** | (Local-mTLS env) → collection **Settings → Client Certs** → delete the localhost cert entry. Send. | TLS handshake error (Bruno shows *"alert certificate required"* or similar — the request never reaches HTTP). Re-add the cert to recover. |

If any of these returns a different status than the table, you've found either a bug in the receiver or a real divergence between the two example implementations — both worth investigating.

Bruno keeps a **History** tab per request, so you can flip back and forth between the broken and the corrected version to see them side by side.

## mTLS setup

Bruno 3.x stores client-certificate config in its UI, not in version-controlled files, so this is a one-time per-machine setup.

### Step 1 — generate the demo certs

The collection's `certs/` is a committed symlink to [`examples/shared-certs/`](../shared-certs/). Generate the actual files once with the shared script — both webhook receivers pick up the same output via their own `certs/` symlinks, so you never have to switch between Python/Node setups manually:

```bash
# From the repo root:
(cd examples/shared-certs && ./gen-test-certs.sh)
```

After this, `examples/bruno-collection/certs/client.crt` (resolved through the symlink) exists and Bruno can load it.

### Step 2 — register the client cert in Bruno

Click the collection name (left sidebar) → **Settings** → **Client Certs** tab → **Add Client Certificate**:

| Field | Value |
|---|---|
| Domain | `127.0.0.1` |
| Type | `cert` (PEM cert + PEM key) |
| Cert file path | `certs/client.crt` |
| Key file path | `certs/client.key` |
| Passphrase | *(leave empty)* |

Save. Bruno will now present `certs/client.crt` + `certs/client.key` whenever a request's host matches `127.0.0.1`.

> Why `127.0.0.1` and not `localhost`? The Python example binds IPv4-only (`run_simple("0.0.0.0", ...)`), and macOS resolves `localhost` to `::1` (IPv6) first — connections fail with `ECONNREFUSED ::1:3000`. The shipped env files use `127.0.0.1` to dodge this; the demo server cert's SAN includes `IP:127.0.0.1`, so TLS still validates. If you've changed the env to `localhost` and your server binds dual-stack (the Node example does), register the cert against `localhost` instead — or add both entries.

### Step 3 — accept the self-signed demo CA

The CA produced by `gen-test-certs.sh` isn't in your OS trust store, so Bruno will refuse the TLS handshake by default. Disable verification:

- Collection name → **Settings → Proxy** (or **Network**, name varies) → toggle **SSL Verification off**.
- Or, per-request: gear icon next to the URL → uncheck **SSL Verification**.

For production deployments with CA-signed certs, leave verification on.

### How it works (one-paragraph version)

mTLS happens at the TLS layer *before* any HTTP is exchanged. The server (Werkzeug/Express) presents its cert and asks for a client cert; Bruno presents `client.crt` + signs the handshake transcript with `client.key`; the server validates that cert against its CA pool (`certs/ca.crt`); only then does the request reach your handler, where Bearer-token auth runs as a second, independent layer. A missing client cert = TLS handshake failure (no HTTP response). A wrong Bearer token but valid client cert = `401`. The two layers are independent — that's the point of defense-in-depth.

## Customizing the collection

### Edit a request body

Open any request → **Body** tab → edit the JSON inline. Bruno renders it with a JSON editor; syntax errors are highlighted. The body is sent verbatim, so you can experiment with edge cases (very long strings, unicode, embedded control characters) to see how your receiver handles them.

### Add a new request

Right-click the collection in the sidebar → **New Request**. Use the same template:

```
post {
  url: {{WEBHOOK_URL}}
  body: json
  auth: bearer
}

auth:bearer {
  token: {{WEBHOOK_SECRET}}
}

body:json {
  {
    "event": { "action": "your_new_action" },
    "pamsignal": {}
  }
}
```

Bruno will save it as `<Name>.bru` next to the others. `seq:` in the `meta` block controls sort order in the sidebar.

### Override env values per-request

Sometimes you want a single request to use a different URL or secret (e.g. to test a staging endpoint). Open the request → **Vars** tab → add a `Pre-request` variable. Vars defined here shadow the env vars for that one request.

### Switch quickly between Python and Node receivers

Both receivers default to port 3000, so there's nothing to change — start whichever one you want to test, then send. To test both at once, edit the env files to use different ports (e.g. `Local-Node` on `:3000`, `Local-Python` on `:3001`) and run the corresponding receiver on the matching port.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| *"Unsupported collection format"* on opening | You clicked **Import Collection** instead of **Open Collection** | Use **Open Collection** — the folder is already in Bruno's native `.bru` format and doesn't need conversion |
| Variable shows as `{{WEBHOOK_SECRET}}` literally in the response/timeline | No environment selected, or the env is missing that variable | Pick an env from the dropdown (top right); confirm both `WEBHOOK_URL` and `WEBHOOK_SECRET` are defined |
| `ECONNREFUSED ::1:3000` | The env uses `localhost`, but the receiver binds IPv4-only (Python's `run_simple("0.0.0.0", ...)`); macOS resolves `localhost` to `::1` first | Use `127.0.0.1` in the env URL (the shipped envs already do); if you also configured a Client Cert against `localhost`, update its **Domain** to `127.0.0.1` to match |
| `ECONNREFUSED` / "Failed to connect" (any other port/host) | Receiver not running, wrong port, or wrong scheme (HTTP vs HTTPS env) | `curl -v {{WEBHOOK_URL}}` outside Bruno to confirm; check that the env URL's scheme matches what the receiver is listening on |
| `401 Unauthorized` unexpectedly | The env's `WEBHOOK_SECRET` doesn't match the receiver's `.env` | Update one to match the other; restart the receiver if you changed `.env` (it reads on startup) |
| `TLS handshake / alert certificate required` | mTLS env selected but no client cert registered in Bruno, or `gen-test-certs.sh` hasn't been run yet, or the symlink target is broken | Run `(cd ../shared-certs && ./gen-test-certs.sh)`; re-check the **Client Certs** entry; verify `ls -L certs/client.crt` resolves to a real file |
| `SELF_SIGNED_CERT_IN_CHAIN` / unable to verify cert | mTLS works but SSL verification is still on for the demo CA | Toggle **SSL Verification off** for the demo (Step 3 above); for production, install the real CA |
| `Parse Error: Expected HTTP/, RTSP/ or ICE/` | Scheme mismatch: Bruno sent plain HTTP but the receiver replied with TLS bytes (a TLS alert read as garbage by Node's HTTP parser) | Either switch to the **Local-mTLS** env, or comment out the `TLS_*` lines in the receiver's `.env` and restart it. Confirm with `curl -v http://localhost:3000/...` — if you see *"Received HTTP/0.9 when not allowed"*, the server is on HTTPS. |
| Request "hangs" on Send | Receiver process crashed or is blocked | Check the receiver terminal for stack traces; restart |

If something else weird happens, Bruno's **Timeline** tab (next to *Response*) shows the full HTTP exchange including request line, headers, body bytes, and timing. That's usually enough to spot the mismatch.
