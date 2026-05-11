"""Entry point for the PAMSignal Flask webhook receiver.

Mirrors src/server.ts from the Node example: picks HTTPS over plain HTTP when
TLS_KEY_PATH/TLS_CERT_PATH are set, and enforces mTLS when
TLS_REQUIRE_CLIENT_CERT=true.
"""

from __future__ import annotations

import os
import ssl
import sys

from dotenv import load_dotenv

# Load .env before importing the app so WEBHOOK_SECRET is available at import.
load_dotenv()

from app import app  # noqa: E402


def build_ssl_context() -> ssl.SSLContext | None:
    """Return an SSLContext if TLS env vars are set, else None."""
    key_path = os.environ.get("TLS_KEY_PATH")
    cert_path = os.environ.get("TLS_CERT_PATH")
    if not (key_path and cert_path):
        return None

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)

    ca_path = os.environ.get("TLS_CLIENT_CA_PATH")
    if ca_path:
        ctx.load_verify_locations(cafile=ca_path)

    if os.environ.get("TLS_REQUIRE_CLIENT_CERT") == "true":
        if not ca_path:
            print(
                "⚠️  TLS_REQUIRE_CLIENT_CERT=true but TLS_CLIENT_CA_PATH is unset — "
                "clients will be validated against the default trust store, which is "
                "almost certainly not what you want for an internal-PKI deployment.",
                file=sys.stderr,
            )
        ctx.verify_mode = ssl.CERT_REQUIRED

    return ctx


def main() -> None:
    from werkzeug.serving import run_simple

    port = int(os.environ.get("PORT", "3000"))
    webhook_secret = os.environ.get("WEBHOOK_SECRET")

    ssl_context = build_ssl_context()
    scheme = "https" if ssl_context else "http"

    if scheme == "https":
        mtls = os.environ.get("TLS_REQUIRE_CLIENT_CERT") == "true"
        suffix = " (mTLS — client cert required)" if mtls else ""
        print(
            f"🔐 PAMSignal Webhook Receiver listening on "
            f"https://localhost:{port}/webhook/pamsignal{suffix}"
        )
    else:
        print(
            f"🚀 PAMSignal Webhook Receiver listening on "
            f"http://localhost:{port}/webhook/pamsignal"
        )

    if not webhook_secret:
        print("⚠️  WARNING: Running without Bearer authentication. Set WEBHOOK_SECRET in .env")

    run_simple("0.0.0.0", port, app, ssl_context=ssl_context, use_reloader=False)


if __name__ == "__main__":
    main()
