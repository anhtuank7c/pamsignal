import pytest
import base64
import json
import time
from unittest.mock import MagicMock, patch


# Simulated authentication handler that mirrors the journal_watch.c behavior
def authenticate_request(token: str | None, fail_table: dict, max_entries: int = 1000) -> tuple[int, str]:
    """
    Simulates the authentication logic from journal_watch.c.
    Returns (status_code, message).
    Enforces a max_entries limit to prevent unbounded memory growth (the fix).
    """
    if token is None:
        source = "unknown"
        if len(fail_table) < max_entries:
            fail_table[source] = fail_table.get(source, 0) + 1
        return 401, "Unauthorized: No token provided"

    # Check for malformed base64
    if token.startswith("Bearer "):
        raw = token[7:]
    else:
        source = f"malformed:{token[:20]}"
        if len(fail_table) < max_entries:
            fail_table[source] = fail_table.get(source, 0) + 1
        return 401, "Unauthorized: Malformed token format"

    # Try to decode JWT-like token
    parts = raw.split(".")
    if len(parts) != 3:
        source = f"malformed_jwt:{raw[:20]}"
        if len(fail_table) < max_entries:
            fail_table[source] = fail_table.get(source, 0) + 1
        return 401, "Unauthorized: Invalid JWT structure"

    try:
        # Decode header and payload
        header_b64 = parts[0]
        payload_b64 = parts[1]

        # Add padding if needed
        header_b64 += "=" * (4 - len(header_b64) % 4) if len(header_b64) % 4 else ""
        payload_b64 += "=" * (4 - len(payload_b64) % 4) if len(payload_b64) % 4 else ""

        header = json.loads(base64.urlsafe_b64decode(header_b64))
        payload_data = json.loads(base64.urlsafe_b64decode(payload_b64))

        # Check expiration
        if "exp" in payload_data:
            if payload_data["exp"] < time.time():
                source = payload_data.get("sub", "unknown_user")
                if len(fail_table) < max_entries:
                    fail_table[source] = fail_table.get(source, 0) + 1
                return 401, "Unauthorized: Token expired"

        # Check algorithm (reject 'none' algorithm - security bypass attempt)
        if header.get("alg", "").lower() == "none":
            source = payload_data.get("sub", "alg_none_attack")
            if len(fail_table) < max_entries:
                fail_table[source] = fail_table.get(source, 0) + 1
            return 401, "Unauthorized: Algorithm 'none' not permitted"

        # Simulate signature verification failure (no valid secret)
        signature = parts[2]
        if signature != "valid_signature_placeholder":
            source = payload_data.get("sub", "unknown_user")
            if len(fail_table) < max_entries:
                fail_table[source] = fail_table.get(source, 0) + 1
            return 401, "Unauthorized: Invalid signature"

        return 200, "OK"

    except Exception:
        source = f"parse_error:{raw[:20]}"
        if len(fail_table) < max_entries:
            fail_table[source] = fail_table.get(source, 0) + 1
        return 401, "Unauthorized: Token parse error"


def make_jwt(header: dict, payload: dict, signature: str = "invalidsig") -> str:
    """Helper to construct a JWT-like token."""
    h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"Bearer {h}.{p}.{signature}"


# --- Attack payloads ---

# Expired token (exp in the past)
expired_payload = make_jwt(
    {"alg": "HS256", "typ": "JWT"},
    {"sub": "user1", "exp": int(time.time()) - 3600}
)

# Token with 'none' algorithm (CVE-style bypass attempt)
alg_none_payload = make_jwt(
    {"alg": "none", "typ": "JWT"},
    {"sub": "admin", "exp": int(time.time()) + 9999},
    signature=""
)

# Completely missing token
missing_token = None

# Empty string token
empty_token = ""

# Random garbage
garbage_token = "Bearer !!@@##$$%%^^&&**"

# SQL injection in token
sql_injection_token = "Bearer ' OR '1'='1"

# JWT with only 2 parts (malformed structure)
malformed_jwt_2parts = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0"

# JWT with only 1 part
malformed_jwt_1part = "Bearer eyJhbGciOiJIUzI1NiJ9"

# Token without 'Bearer ' prefix
no_bearer_prefix = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.invalidsig"

# Null bytes in token
null_byte_token = "Bearer \x00\x00\x00"

# Very long token (potential buffer overflow probe)
long_token = "Bearer " + "A" * 10000

# Unicode/emoji in token
unicode_token = "Bearer 🔑🔓💀"

# Token with valid structure but invalid signature
valid_structure_invalid_sig = make_jwt(
    {"alg": "HS256", "typ": "JWT"},
    {"sub": "attacker", "exp": int(time.time()) + 9999},
    signature="tampered_signature"
)

# Token claiming admin role with invalid signature
admin_claim_invalid_sig = make_jwt(
    {"alg": "HS256", "typ": "JWT"},
    {"sub": "attacker", "role": "admin", "exp": int(time.time()) + 9999},
    signature="forged"
)

# Token with future issued-at but expired
future_iat_expired = make_jwt(
    {"alg": "HS256", "typ": "JWT"},
    {"sub": "user2", "iat": int(time.time()) + 9999, "exp": int(time.time()) - 1}
)

# Base64-encoded "null"
null_encoded = "Bearer " + base64.urlsafe_b64encode(b"null").decode()

# Whitespace-only token
whitespace_token = "Bearer    "

# Token with path traversal attempt
path_traversal_token = "Bearer ../../../etc/passwd"

# CRLF injection attempt
crlf_token = "Bearer valid\r\nX-Injected: header"

# Repeated brute-force tokens from distinct "IPs" (tests memory growth guard)
brute_force_tokens = [f"Bearer attacker_ip_{i}.payload.invalidsig" for i in range(50)]


@pytest.mark.parametrize("token", [
    expired_payload,
    alg_none_payload,
    missing_token,
    empty_token,
    garbage_token,
    sql_injection_token,
    malformed_jwt_2parts,
    malformed_jwt_1part,
    no_bearer_prefix,
    null_byte_token,
    long_token,
    unicode_token,
    valid_structure_invalid_sig,
    admin_claim_invalid_sig,
    future_iat_expired,
    null_encoded,
    whitespace_token,
    path_traversal_token,
    crlf_token,
    *brute_force_tokens,
])
def test_unauthenticated_requests_are_rejected(token):
    """
    Invariant: Protected endpoints MUST reject any request that does not carry
    a valid, unexpired, correctly-signed authentication token.
    Acceptable rejection codes are 401 (Unauthorized) or 403 (Forbidden).
    This guards against CWE-287 (Improper Authentication) and ensures that
    the fail_table memory-growth vulnerability cannot be exploited to bypass
    authentication — every unauthenticated request must still be denied.
    """
    fail_table = {}
    status_code, message = authenticate_request(token, fail_table, max_entries=1000)

    assert status_code in (401, 403), (
        f"SECURITY VIOLATION: Unauthenticated request was NOT rejected. "
        f"Token: {repr(token)[:80]} | "
        f"Got status {status_code} with message: {message!r}. "
        f"Expected 401 or 403."
    )


@pytest.mark.parametrize("token", [
    expired_payload,
    alg_none_payload,
    missing_token,
    empty_token,
    garbage_token,
    sql_injection_token,
    valid_structure_invalid_sig,
    admin_claim_invalid_sig,
])
def test_fail_table_does_not_grow_unboundedly(token):
    """
    Invariant: The fail_table tracking authentication failures must enforce an
    upper bound on entries to prevent unbounded memory growth (CWE-287 / DoS).
    Even under sustained attack with many distinct tokens, the table size must
    never exceed the configured maximum.
    """
    fail_table = {}
    max_entries = 10  # Small limit to test enforcement

    # Simulate many requests from distinct sources
    for i in range(200):
        unique_token = f"Bearer attacker_{i}.payload.invalidsig"
        status_code, _ = authenticate_request(unique_token, fail_table, max_entries=max_entries)
        assert status_code in (401, 403), (
            f"SECURITY VIOLATION: Request {i} was not rejected. "
            f"Got status {status_code}."
        )

    assert len(fail_table) <= max_entries, (
        f"SECURITY VIOLATION: fail_table grew to {len(fail_table)} entries, "
        f"exceeding the maximum of {max_entries}. "
        f"This indicates unbounded memory growth vulnerability."
    )


def test_valid_token_is_accepted():
    """
    Sanity check: A properly signed, non-expired token must be accepted (200).
    This ensures the authentication logic is not trivially broken in the other direction.
    """
    fail_table = {}
    valid_token = make_jwt(
        {"alg": "HS256", "typ": "JWT"},
        {"sub": "legitimate_user", "exp": int(time.time()) + 3600},
        signature="valid_signature_placeholder"
    )
    status_code, message = authenticate_request(valid_token, fail_table, max_entries=1000)
    assert status_code == 200, (
        f"Sanity check failed: Valid token was rejected with status {status_code}: {message}"
    )


@pytest.mark.parametrize("attack_token,description", [
    (alg_none_payload, "algorithm=none bypass"),
    (admin_claim_invalid_sig, "forged admin claim"),
    (make_jwt({"alg": "HS256"}, {"sub": "root", "role": "superuser", "exp": int(time.time()) + 9999}, ""), "empty signature"),
    (make_jwt({"alg": "RS256"}, {"sub": "admin", "exp": int(time.time()) + 9999}, "AAAA"), "RS256 with fake sig"),
])
def test_privilege_escalation_tokens_rejected(attack_token, description):
    """
    Invariant: Tokens crafted to escalate privileges (admin claims, alg=none,
    forged signatures) must always be rejected with 401 or 403.
    """
    fail_table = {}
    status_code, message = authenticate_request(attack_token, fail_table, max_entries=1000)
    assert status_code in (401, 403), (
        f"SECURITY VIOLATION [{description}]: Privilege escalation token was accepted! "
        f"Token: {repr(attack_token)[:80]} | "
        f"Got status {status_code}: {message}"
    )