"""Transport-layer test for the mTLS path.

The existing test_webhook.py exercises the Bearer middleware via Flask's test
client (no transport involved); this file proves the construction pattern in
src/server.py — `ssl.SSLContext` with `verify_mode = CERT_REQUIRED` + the same
`app` — actually rejects unauthenticated TLS handshakes and accepts
authenticated ones.

Certs are generated fresh under a temp dir at setup via openssl (same commands
as ../shared-certs/gen-test-certs.sh). No fixtures committed to the repo.
"""

from __future__ import annotations

import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
from pathlib import Path

import pytest
import requests
from werkzeug.serving import make_server

from app import app

pytestmark = pytest.mark.skipif(
    shutil.which("openssl") is None, reason="openssl not installed"
)

SECRET = "test-secret"
VALID_PAYLOAD = {
    "event": {"action": "brute_force_detected"},
    "source": {"ip": "203.0.113.50"},
    "pamsignal": {"attempts": 12, "window_sec": 300},
}


def _openssl(*args: str) -> None:
    subprocess.run(["openssl", *args], check=True, capture_output=True)


def _gen_certs(d: Path) -> None:
    # CA
    _openssl(
        "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3650",
        "-keyout", str(d / "ca.key"), "-out", str(d / "ca.crt"),
        "-subj", "/CN=PAMSignal Test CA",
    )
    # Server cert (CN=localhost, SAN=DNS:localhost,IP:127.0.0.1)
    _openssl(
        "req", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(d / "server.key"), "-out", str(d / "server.csr"),
        "-subj", "/CN=localhost",
    )
    (d / "server.ext").write_text("subjectAltName=DNS:localhost,IP:127.0.0.1\n")
    _openssl(
        "x509", "-req", "-in", str(d / "server.csr"),
        "-CA", str(d / "ca.crt"), "-CAkey", str(d / "ca.key"), "-CAcreateserial",
        "-out", str(d / "server.crt"), "-days", "3650",
        "-extfile", str(d / "server.ext"),
    )
    # Client cert
    _openssl(
        "req", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(d / "client.key"), "-out", str(d / "client.csr"),
        "-subj", "/CN=pamsignal-test-client",
    )
    _openssl(
        "x509", "-req", "-in", str(d / "client.csr"),
        "-CA", str(d / "ca.crt"), "-CAkey", str(d / "ca.key"), "-CAcreateserial",
        "-out", str(d / "client.crt"), "-days", "3650",
    )


@pytest.fixture(scope="module")
def cert_dir():
    with tempfile.TemporaryDirectory(prefix="pamsignal-mtls-test-") as td:
        d = Path(td)
        _gen_certs(d)
        yield d


@pytest.fixture(scope="module")
def mtls_server(cert_dir):
    # Module-scope env override — set, then restore on teardown.
    import os

    old_secret = os.environ.get("WEBHOOK_SECRET")
    os.environ["WEBHOOK_SECRET"] = SECRET

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(
        certfile=str(cert_dir / "server.crt"),
        keyfile=str(cert_dir / "server.key"),
    )
    ctx.load_verify_locations(cafile=str(cert_dir / "ca.crt"))
    ctx.verify_mode = ssl.CERT_REQUIRED

    # Bind to port 0 to let the kernel pick a free port.
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    server = make_server("127.0.0.1", port, app, ssl_context=ctx)
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


def _post(
    port: int,
    cert_dir: Path,
    payload: dict,
    *,
    use_client_cert: bool = True,
    bearer: str = SECRET,
):
    kwargs = {
        "verify": str(cert_dir / "ca.crt"),
        "headers": {"Authorization": f"Bearer {bearer}"},
        "json": payload,
        "timeout": 5,
    }
    if use_client_cert:
        kwargs["cert"] = (str(cert_dir / "client.crt"), str(cert_dir / "client.key"))
    return requests.post(f"https://127.0.0.1:{port}/webhook/pamsignal", **kwargs)


def test_mtls_accepts_valid_client_cert(mtls_server, cert_dir):
    response = _post(mtls_server, cert_dir, VALID_PAYLOAD)
    assert response.status_code == 200
    assert response.json()["status"] == "success"


def test_mtls_rejects_request_without_client_cert(mtls_server, cert_dir):
    # Server with verify_mode=CERT_REQUIRED rejects the TLS handshake before
    # the request reaches Flask. The exact error type varies across OpenSSL
    # versions — what matters is that no HTTP response is produced.
    with pytest.raises((requests.exceptions.SSLError, requests.exceptions.ConnectionError)):
        _post(mtls_server, cert_dir, VALID_PAYLOAD, use_client_cert=False)


def test_mtls_still_validates_bearer_token(mtls_server, cert_dir):
    response = _post(mtls_server, cert_dir, VALID_PAYLOAD, bearer="different-secret")
    # TLS handshake + client cert validation pass, but the Bearer middleware
    # still rejects the request with 401.
    assert response.status_code == 401
