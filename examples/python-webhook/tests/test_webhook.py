"""Unit tests for the PAMSignal Flask webhook receiver.

Uses Flask's test_client so no transport is involved — these tests pin down
the in-process behavior of the request handler, the security defenses
(timing-safe Bearer compare, body size cap, Content-Type validation, log
injection sanitization), and the per-action dispatch logic.

Real-transport tests live in test_integration.py and test_mtls.py.
"""

from __future__ import annotations

import pytest

from app import _safe, app

SECRET = "test-secret"

VALID_PAYLOAD = {
    "event": {"action": "brute_force_detected"},
    "source": {"ip": "203.0.113.50"},
    "pamsignal": {"attempts": 12, "window_sec": 300},
}


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("WEBHOOK_SECRET", SECRET)
    return app.test_client()


@pytest.fixture
def loud_env(monkeypatch):
    """Undo conftest's FLASK_ENV=test so the dispatch print() block runs."""
    monkeypatch.delenv("FLASK_ENV", raising=False)


def _auth() -> dict[str, str]:
    return {"Authorization": f"Bearer {SECRET}"}


# =============================================================================
# Authentication
# =============================================================================


class TestAuthentication:
    def test_rejects_request_without_token(self, client):
        response = client.post("/webhook/pamsignal", json=VALID_PAYLOAD)
        assert response.status_code == 401
        assert response.get_json() == {"error": "Unauthorized: Invalid or missing token"}

    def test_rejects_invalid_bearer_token(self, client):
        response = client.post(
            "/webhook/pamsignal",
            json=VALID_PAYLOAD,
            headers={"Authorization": "Bearer wrong-token"},
        )
        assert response.status_code == 401

    def test_rejects_empty_bearer_token(self, client):
        response = client.post(
            "/webhook/pamsignal",
            json=VALID_PAYLOAD,
            headers={"Authorization": "Bearer "},
        )
        assert response.status_code == 401

    def test_rejects_authorization_without_bearer_prefix(self, client):
        response = client.post(
            "/webhook/pamsignal",
            json=VALID_PAYLOAD,
            headers={"Authorization": SECRET},
        )
        assert response.status_code == 401

    def test_rejects_authorization_with_wrong_scheme(self, client):
        response = client.post(
            "/webhook/pamsignal",
            json=VALID_PAYLOAD,
            headers={"Authorization": f"Basic {SECRET}"},
        )
        assert response.status_code == 401

    def test_rejects_bearer_token_prefix_of_secret(self, client):
        # Prefix of the real secret must not authenticate — covers the
        # timing-safe compare's handling of unequal-length inputs.
        response = client.post(
            "/webhook/pamsignal",
            json=VALID_PAYLOAD,
            headers={"Authorization": f"Bearer {SECRET[:5]}"},
        )
        assert response.status_code == 401

    def test_accepts_valid_bearer_token(self, client):
        response = client.post("/webhook/pamsignal", json=VALID_PAYLOAD, headers=_auth())
        assert response.status_code == 200
        assert response.get_json()["status"] == "success"

    def test_allows_requests_when_secret_unset(self, monkeypatch):
        monkeypatch.delenv("WEBHOOK_SECRET", raising=False)
        response = app.test_client().post("/webhook/pamsignal", json=VALID_PAYLOAD)
        assert response.status_code == 200


# =============================================================================
# Content-Type validation (defense against parsing non-JSON bodies)
# =============================================================================


class TestContentType:
    def test_rejects_text_plain(self, client):
        response = client.post(
            "/webhook/pamsignal",
            data="not json",
            headers={**_auth(), "Content-Type": "text/plain"},
        )
        assert response.status_code == 415
        assert "Unsupported Media Type" in response.get_json()["error"]

    def test_rejects_form_urlencoded(self, client):
        response = client.post(
            "/webhook/pamsignal",
            data="x=1",
            headers={**_auth(), "Content-Type": "application/x-www-form-urlencoded"},
        )
        assert response.status_code == 415

    def test_rejects_missing_content_type(self, client):
        response = client.post(
            "/webhook/pamsignal",
            data="{}",
            headers=_auth(),
        )
        assert response.status_code == 415

    def test_accepts_application_json(self, client):
        response = client.post("/webhook/pamsignal", json=VALID_PAYLOAD, headers=_auth())
        assert response.status_code == 200

    def test_415_path_runs_after_auth(self, client):
        # An unauthenticated request with the wrong Content-Type must still
        # 401, not 415 — auth happens before media-type validation so we
        # don't tell an unauthenticated peer anything about the endpoint.
        response = client.post(
            "/webhook/pamsignal",
            data="not json",
            headers={"Content-Type": "text/plain"},
        )
        assert response.status_code == 401


# =============================================================================
# Body size limit (DoS defense)
# =============================================================================


class TestBodySizeLimit:
    def test_rejects_body_over_64kb(self, client):
        big = "A" * (65 * 1024)
        payload = {"event": {"action": "x"}, "pamsignal": {}, "pad": big}
        response = client.post("/webhook/pamsignal", json=payload, headers=_auth())
        assert response.status_code == 413

    def test_accepts_body_well_under_limit(self, client):
        # ~10 KB payload — comfortably below the 64 KB cap.
        payload = {
            "event": {"action": "x"},
            "pamsignal": {},
            "pad": "A" * (10 * 1024),
        }
        response = client.post("/webhook/pamsignal", json=payload, headers=_auth())
        assert response.status_code == 200


# =============================================================================
# Payload shape validation
# =============================================================================


class TestPayloadValidation:
    def test_rejects_empty_object(self, client):
        response = client.post("/webhook/pamsignal", json={}, headers=_auth())
        assert response.status_code == 400
        assert response.get_json() == {"error": "Bad Request: Invalid payload format"}

    def test_rejects_missing_event(self, client):
        response = client.post(
            "/webhook/pamsignal",
            json={"pamsignal": {"attempts": 1}},
            headers=_auth(),
        )
        assert response.status_code == 400

    def test_rejects_missing_pamsignal(self, client):
        response = client.post(
            "/webhook/pamsignal",
            json={"event": {"action": "login_success"}},
            headers=_auth(),
        )
        assert response.status_code == 400

    def test_rejects_array_at_top_level(self, client):
        response = client.post("/webhook/pamsignal", json=[1, 2, 3], headers=_auth())
        assert response.status_code == 400

    def test_rejects_string_at_top_level(self, client):
        response = client.post("/webhook/pamsignal", json="not an object", headers=_auth())
        assert response.status_code == 400

    def test_rejects_null_payload(self, client):
        # Literal JSON `null` with the correct Content-Type — should hit the
        # payload validator, not the 415 path.
        response = client.post(
            "/webhook/pamsignal",
            data="null",
            headers={**_auth(), "Content-Type": "application/json"},
        )
        assert response.status_code == 400


# =============================================================================
# Event dispatch (per-action stdout logging)
# =============================================================================


class TestEventDispatch:
    def test_login_success_logs_user_ip_host_pid(self, client, capsys, loud_env):
        response = client.post(
            "/webhook/pamsignal",
            json={
                "event": {"action": "login_success"},
                "user": {"name": "alice"},
                "source": {"ip": "10.0.0.1"},
                "host": {"hostname": "srv01"},
                "process": {"pid": 1234},
                "pamsignal": {},
            },
            headers=_auth(),
        )
        out = capsys.readouterr().out
        assert response.status_code == 200
        assert "[LOGIN_SUCCESS]" in out
        assert "alice" in out
        assert "10.0.0.1" in out
        assert "srv01" in out
        assert "1234" in out

    def test_login_failure(self, client, capsys, loud_env):
        client.post(
            "/webhook/pamsignal",
            json={
                "event": {"action": "login_failure"},
                "user": {"name": "bob"},
                "source": {"ip": "1.2.3.4"},
                "host": {"hostname": "srv"},
                "pamsignal": {},
            },
            headers=_auth(),
        )
        out = capsys.readouterr().out
        assert "[LOGIN_FAILED]" in out
        assert "bob" in out

    def test_brute_force_detected(self, client, capsys, loud_env):
        client.post(
            "/webhook/pamsignal",
            json={
                "event": {"action": "brute_force_detected"},
                "source": {"ip": "203.0.113.50"},
                "pamsignal": {"attempts": 12, "window_sec": 300},
            },
            headers=_auth(),
        )
        out = capsys.readouterr().out
        assert "[BRUTE_FORCE]" in out
        assert "12" in out
        assert "203.0.113.50" in out
        assert "300" in out

    def test_session_opened(self, client, capsys, loud_env):
        client.post(
            "/webhook/pamsignal",
            json={
                "event": {"action": "session_opened"},
                "user": {"name": "alice"},
                "host": {"hostname": "srv"},
                "pamsignal": {},
            },
            headers=_auth(),
        )
        out = capsys.readouterr().out
        assert "[SESSION_OPEN]" in out

    def test_session_closed(self, client, capsys, loud_env):
        client.post(
            "/webhook/pamsignal",
            json={
                "event": {"action": "session_closed"},
                "user": {"name": "alice"},
                "host": {"hostname": "srv"},
                "pamsignal": {},
            },
            headers=_auth(),
        )
        out = capsys.readouterr().out
        assert "[SESSION_CLOSE]" in out

    def test_unknown_action(self, client, capsys, loud_env):
        client.post(
            "/webhook/pamsignal",
            json={"event": {"action": "totally_unknown_xyz"}, "pamsignal": {}},
            headers=_auth(),
        )
        out = capsys.readouterr().out
        assert "[UNKNOWN_EVENT]" in out
        assert "totally_unknown_xyz" in out

    def test_log_injection_attempt_is_neutralized_end_to_end(
        self, client, capsys, loud_env
    ):
        # Newlines, ANSI escapes, NUL, and DEL all in one attack string.
        # The dispatch must emit a single line where every control byte
        # has been replaced with '?'.
        attack = "admin\nFAKE\x1b[31m\x00\x7fend"
        client.post(
            "/webhook/pamsignal",
            json={
                "event": {"action": "login_success"},
                "user": {"name": attack},
                "pamsignal": {},
            },
            headers=_auth(),
        )
        out = capsys.readouterr().out
        # Find the LOGIN_SUCCESS line and verify it's a single physical line
        # with no control chars in the user-supplied region.
        line = next(ln for ln in out.splitlines() if "[LOGIN_SUCCESS]" in ln)
        assert "\x1b" not in line
        assert "\x00" not in line
        assert "\x7f" not in line
        # The original "admin\nFAKE..." must not have produced two log lines.
        assert sum("[LOGIN_SUCCESS]" in ln for ln in out.splitlines()) == 1


# =============================================================================
# _safe helper (the primitive behind log-injection defense)
# =============================================================================


class TestSafeHelper:
    def test_passes_safe_ascii_through(self):
        assert _safe("alice") == "alice"
        assert _safe("192.168.1.1") == "192.168.1.1"
        assert _safe("") == ""

    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("a\nb", "a?b"),
            ("a\rb", "a?b"),
            ("a\tb", "a?b"),
            ("a\x00b", "a?b"),
            ("\x1b[31m", "?[31m"),
            ("\x7f", "?"),
        ],
    )
    def test_replaces_control_chars(self, raw, expected):
        assert _safe(raw) == expected

    def test_replaces_every_control_byte(self):
        for i in range(32):
            assert _safe(chr(i)) == "?", f"byte {i:#x} not replaced"
        assert _safe("\x7f") == "?"

    def test_caps_at_200_chars(self):
        out = _safe("A" * 1000)
        assert len(out) == 200
        assert out == "A" * 200

    def test_handles_none(self):
        assert _safe(None) == "None"

    @pytest.mark.parametrize("value", [0, 12345, True, False, 3.14])
    def test_handles_non_string_scalars(self, value):
        assert _safe(value) == str(value)

    def test_preserves_non_ascii_unicode(self):
        # Non-control non-ASCII chars (accents, CJK, emoji) pass through.
        assert _safe("café") == "café"
        assert _safe("日本語") == "日本語"
        assert _safe("🔥") == "🔥"
