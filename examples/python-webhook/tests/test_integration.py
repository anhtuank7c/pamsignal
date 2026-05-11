"""Integration tests over real HTTP transport.

Spins up a Werkzeug WSGI server on a kernel-picked free port and exercises the
webhook with the `requests` client — the same path PAMSignal's curl
fork+exec uses. Proves that the in-process behavior covered by test_webhook.py
survives a real WSGI roundtrip (headers, body framing, error status codes,
content negotiation).

mTLS-specific transport behavior lives in test_mtls.py.
"""

from __future__ import annotations

import os
import socket
import threading
from typing import Iterator

import pytest
import requests
from werkzeug.serving import make_server

SECRET = "integration-secret"

VALID_PAYLOAD = {
    "event": {"action": "brute_force_detected"},
    "source": {"ip": "203.0.113.50"},
    "pamsignal": {"attempts": 12, "window_sec": 300},
}


def _free_port() -> int:
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


@pytest.fixture(scope="module")
def http_server() -> Iterator[int]:
    """Real HTTP server on a kernel-picked free port."""
    # Module-scoped — can't use monkeypatch (function-scoped). Save and restore
    # the env var manually so we don't leak state into other test modules.
    old_secret = os.environ.get("WEBHOOK_SECRET")
    os.environ["WEBHOOK_SECRET"] = SECRET

    from app import app

    port = _free_port()
    server = make_server("127.0.0.1", port, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        server.shutdown()
        thread.join(timeout=5)
        if old_secret is None:
            os.environ.pop("WEBHOOK_SECRET", None)
        else:
            os.environ["WEBHOOK_SECRET"] = old_secret


def _url(port: int) -> str:
    return f"http://127.0.0.1:{port}/webhook/pamsignal"


def _auth() -> dict[str, str]:
    return {"Authorization": f"Bearer {SECRET}"}


# =============================================================================
# Happy path
# =============================================================================


def test_valid_request_returns_200(http_server):
    r = requests.post(_url(http_server), json=VALID_PAYLOAD, headers=_auth(), timeout=5)
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "success"
    assert body["message"] == "Event received"


def test_response_is_json(http_server):
    r = requests.post(_url(http_server), json=VALID_PAYLOAD, headers=_auth(), timeout=5)
    assert r.headers["Content-Type"].startswith("application/json")


# =============================================================================
# Authentication over real transport
# =============================================================================


def test_no_token_returns_401(http_server):
    r = requests.post(_url(http_server), json=VALID_PAYLOAD, timeout=5)
    assert r.status_code == 401
    assert r.json()["error"] == "Unauthorized: Invalid or missing token"


def test_wrong_token_returns_401(http_server):
    r = requests.post(
        _url(http_server),
        json=VALID_PAYLOAD,
        headers={"Authorization": "Bearer not-the-secret"},
        timeout=5,
    )
    assert r.status_code == 401


def test_wrong_scheme_returns_401(http_server):
    r = requests.post(
        _url(http_server),
        json=VALID_PAYLOAD,
        headers={"Authorization": f"Basic {SECRET}"},
        timeout=5,
    )
    assert r.status_code == 401


# =============================================================================
# Defenses over real transport
# =============================================================================


def test_wrong_content_type_returns_415(http_server):
    r = requests.post(
        _url(http_server),
        data="this is not json",
        headers={**_auth(), "Content-Type": "text/plain"},
        timeout=5,
    )
    assert r.status_code == 415


def test_oversize_body_returns_413(http_server):
    # 70 KB body, above the 64 KB MAX_CONTENT_LENGTH.
    payload = {
        "event": {"action": "x"},
        "pamsignal": {},
        "pad": "A" * (70 * 1024),
    }
    r = requests.post(_url(http_server), json=payload, headers=_auth(), timeout=5)
    assert r.status_code == 413


def test_invalid_payload_shape_returns_400(http_server):
    r = requests.post(_url(http_server), json={}, headers=_auth(), timeout=5)
    assert r.status_code == 400
    assert r.json()["error"] == "Bad Request: Invalid payload format"


def test_log_injection_payload_does_not_crash_server(http_server):
    # Control chars in every string field. The server must accept the
    # request and return 200 — the unit-test suite separately verifies that
    # the actual stdout output is sanitized.
    attack = "alice\n\x1b[31mFAKE\x00\x7f"
    payload = {
        "event": {"action": "login_success"},
        "user": {"name": attack},
        "source": {"ip": attack},
        "host": {"hostname": attack},
        "process": {"pid": attack},
        "pamsignal": {},
    }
    r = requests.post(_url(http_server), json=payload, headers=_auth(), timeout=5)
    assert r.status_code == 200


# =============================================================================
# Event dispatch over real transport (every action type returns 200)
# =============================================================================


@pytest.mark.parametrize(
    "action",
    [
        "login_success",
        "login_failure",
        "brute_force_detected",
        "session_opened",
        "session_closed",
        "totally_unknown_xyz",
    ],
)
def test_all_event_actions_accepted(http_server, action):
    payload = {
        "event": {"action": action},
        "user": {"name": "alice"},
        "source": {"ip": "1.2.3.4"},
        "host": {"hostname": "srv"},
        "process": {"pid": 1234},
        "pamsignal": {"attempts": 1, "window_sec": 60},
    }
    r = requests.post(_url(http_server), json=payload, headers=_auth(), timeout=5)
    assert r.status_code == 200
