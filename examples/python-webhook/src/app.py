"""PAMSignal webhook receiver — Flask application.

Mirrors the behavior of the Node.js example:
  - Bearer-token authentication (Authorization header).
  - Lightweight payload validation for PAMSignal's ECS JSON shape.
  - Per-action logging with the same emoji prefixes.
"""

from __future__ import annotations

import hmac
import logging
import os

from flask import Flask, jsonify, request

logger = logging.getLogger("pamsignal-webhook")

# 64 KB body cap. PAMSignal payloads are well under 4 KB; this keeps an
# unauthenticated attacker from forcing unbounded JSON allocation. Flask raises
# 413 automatically when exceeded.
MAX_BODY_BYTES = 64 * 1024

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_BODY_BYTES


def _is_test() -> bool:
    return os.environ.get("FLASK_ENV") == "test"


def _safe(value: object) -> str:
    """Strip control characters from user-controlled values before logging.

    PAMSignal payloads are JSON, so an attacker can put newlines, ANSI escape
    sequences, or fake-looking log lines in any string field. Replace anything
    below 0x20 (and DEL) with '?' and cap length so a malicious peer cannot
    inject log entries or terminal escapes into the receiver's stdout.
    """
    if value is None:
        return "None"
    s = str(value)
    cleaned = "".join(c if (c >= " " and c != "\x7f") else "?" for c in s)
    return cleaned[:200]


@app.post("/webhook/pamsignal")
def webhook():
    # --- Authentication ------------------------------------------------------
    secret = os.environ.get("WEBHOOK_SECRET")
    if secret:
        auth = request.headers.get("Authorization", "")
        # Constant-time compare: `==` short-circuits at the first differing
        # byte, leaking the secret via response-time differences.
        # hmac.compare_digest handles unequal-length inputs in constant time.
        token = auth[len("Bearer ") :] if auth.startswith("Bearer ") else ""
        if not hmac.compare_digest(token, secret):
            if not _is_test():
                logger.warning(
                    "[AUTH FAILED] Unauthorized access attempt from IP: %s",
                    request.remote_addr,
                )
            return jsonify({"error": "Unauthorized: Invalid or missing token"}), 401
    elif not _is_test():
        logger.warning("WEBHOOK_SECRET is not set. Accepting all requests.")

    # --- Content-Type --------------------------------------------------------
    if not request.is_json:
        return (
            jsonify({"error": "Unsupported Media Type: expected application/json"}),
            415,
        )

    # --- Payload validation --------------------------------------------------
    payload = request.get_json(silent=True)
    if (
        not payload
        or not isinstance(payload, dict)
        or "event" not in payload
        or "pamsignal" not in payload
    ):
        if not _is_test():
            logger.warning("[BAD REQUEST] Invalid payload format received")
        return jsonify({"error": "Bad Request: Invalid payload format"}), 400

    # --- Dispatch ------------------------------------------------------------
    if not _is_test():
        event = payload.get("event") or {}
        user = payload.get("user") or {}
        source = payload.get("source") or {}
        host = payload.get("host") or {}
        proc = payload.get("process") or {}
        ps = payload.get("pamsignal") or {}
        action = event.get("action")

        if action == "login_success":
            print(
                f"✅ [LOGIN_SUCCESS] User '{_safe(user.get('name'))}' logged in via "
                f"{_safe(source.get('ip'))} on {_safe(host.get('hostname'))} "
                f"(PID: {_safe(proc.get('pid'))})",
                flush=True,
            )
        elif action == "login_failure":
            print(
                f"❌ [LOGIN_FAILED] Failed login attempt for user "
                f"'{_safe(user.get('name'))}' from {_safe(source.get('ip'))} on "
                f"{_safe(host.get('hostname'))}",
                flush=True,
            )
        elif action == "brute_force_detected":
            print(
                f"🚨 [BRUTE_FORCE] {_safe(ps.get('attempts'))} failed attempts "
                f"detected from IP {_safe(source.get('ip'))} in "
                f"{_safe(ps.get('window_sec'))}s!",
                flush=True,
            )
        elif action == "session_opened":
            print(
                f"ℹ️ [SESSION_OPEN] Session opened for user "
                f"'{_safe(user.get('name'))}' on {_safe(host.get('hostname'))}",
                flush=True,
            )
        elif action == "session_closed":
            print(
                f"ℹ️ [SESSION_CLOSE] Session closed for user "
                f"'{_safe(user.get('name'))}' on {_safe(host.get('hostname'))}",
                flush=True,
            )
        else:
            print(
                f"[UNKNOWN_EVENT] Received unknown event action: {_safe(action)}",
                flush=True,
            )

    return jsonify({"status": "success", "message": "Event received"}), 200
