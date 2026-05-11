# Shared mTLS Demo Certs

A single, self-contained CA + server cert + client cert used by all three example projects to demonstrate the PAMSignal webhook's mTLS path. **Local/demo only — never use these certs in production.**

## What's here

| File | Committed? | Description |
|---|---|---|
| `gen-test-certs.sh` | ✅ | Generator — produces the six files below |
| `README.md` | ✅ | This file |
| `.gitignore` | ✅ | Ignores generated `*.crt`, `*.key`, `*.csr`, `*.srl` |
| `ca.crt`, `ca.key` | ❌ | Self-signed root CA used by both receivers to validate the client cert |
| `server.crt`, `server.key` | ❌ | Server identity (`CN=localhost`, `SAN=DNS:localhost,IP:127.0.0.1`) used by both receivers |
| `client.crt`, `client.key` | ❌ | Client identity presented by `curl` from PAMSignal, by Bruno, and by the test suite |

## How it's wired up

Each consumer symlinks its `certs/` path here:

```
examples/shared-certs/                       ← real files live here
        ▲
        ├── examples/python-webhook/certs    (symlink)
        ├── examples/nodejs-webhook/certs    (symlink)
        └── examples/bruno-collection/certs  (symlink)
```

The receivers reference `./certs/server.{crt,key}` and `./certs/ca.crt` in their `.env`; Bruno's Client Certs entry points at `certs/client.{crt,key}` relative to the collection root. The symlinks make all three paths resolve here. Running `gen-test-certs.sh` once populates everyone at the same time.

## Usage

```bash
# From this directory:
./gen-test-certs.sh

# Or with a custom output dir (rarely needed):
./gen-test-certs.sh /tmp/some-other-place
```

After generation, restart any receiver currently running — Werkzeug/Express loaded the previous certs into memory at startup and won't reload until restarted:

```bash
# Python:
cd ../python-webhook && uv run python src/server.py
# Node:
cd ../nodejs-webhook && pnpm run dev
```

## Why one shared CA instead of one per receiver?

Each invocation of `gen-test-certs.sh` produces an **independent** self-signed CA. If Python and Node each ran the script separately, the resulting CAs would be different, and a client cert from one wouldn't authenticate against the other. Sharing simplifies cross-testing — generate once, both receivers accept the same Bruno (and curl) cert, no symlink-shuffling when you flip between them.

## Production setup

Replace this directory's contents with paths managed by your cert pipeline (cert-manager, certbot, internal CA + ACME, `systemd-creds`, etc.). The four `TLS_*` env vars and the `webhook_*` config keys in `pamsignal.conf` stay the same; only the file contents change. The symlinks in the consumer projects can stay or be replaced with absolute paths — whichever fits your deployment.
