# V11 — Cryptography

> Upstream: <https://github.com/OWASP/ASVS/blob/master/5.0/en/0x20-V11-Cryptography.md>

The chapter covers algorithm choice, key management, AEAD, randomness, password hashing, and key lifecycle. PAMSignal's posture is intentionally minimal: **no homemade crypto.** TLS is curl/OpenSSL's responsibility. No hashing of secrets. No symmetric encryption of stored data. The audit here is mostly a guardrail against accidentally growing a crypto surface.

**Levels in scope for PAMSignal:** L1 mandatory (guardrail), L2 informational.

---

## Where this lives in the codebase

| Surface | File | Notes |
|---|---|---|
| TLS | Delegated to `/usr/bin/curl` (`src/notify.c:250`) | `--proto =https --proto-redir =https`; never `-k` |
| Optional client cert / CA bundle | `src/config.c:228+` + `src/notify.c:112+` (memfd) | Operator-supplied; never validated cryptographically by PAMSignal itself |
| Randomness | Not used | No nonces, no session IDs, no keys |
| Hashing | Not used | No password store, no MAC, no integrity field |

If a future feature introduces randomness, hashing, or symmetric encryption, this chapter becomes much more relevant — and the project should explicitly pull in a vetted library (e.g., libsodium) rather than implementing primitives. Document the threat model in `docs/architecture.md` before adding.

---

## V11.1 — Algorithm selection

| V-ID | Requirement | Level | Project evaluation |
|---|---|---|---|
| V11.1.1 | Verify no deprecated / broken algorithms (MD5, SHA-1 for signatures, DES, RC4, ECB-mode block ciphers). | L1 | N/A — PAMSignal calls no crypto algorithm directly. TLS algorithm choice is delegated to curl/OpenSSL system defaults. |
| V11.1.2 | Verify approved AEAD modes (AES-GCM, ChaCha20-Poly1305) for any custom encryption. | L1 | N/A — no custom encryption. Guardrail: any PR that adds `openssl/EVP_*` or `crypto.h` includes triggers re-review. |

## V11.2 — Key management

| V-ID | Requirement | Level | Project evaluation |
|---|---|---|---|
| V11.2.1 | Verify keys are generated using a CSPRNG (e.g., `getrandom`, `/dev/urandom`). | L1 | N/A — PAMSignal generates no keys. |
| V11.2.2 | Verify keys at rest are protected by file permissions or a hardware secure element. | L1 | Operator-supplied TLS private keys are validated by `validate_tls_path()` to be non-world-readable and owned by root or the daemon user. ✓ See `src/config.c:278-285`. |
| V11.2.3 | Verify keys are rotated and that the rotation procedure is documented. | L2 | Operator-controlled (their cert/key). Document in `docs/configuration.md` that re-issuing the cert + SIGHUP suffices. |

## V11.3 — Randomness

| V-ID | Requirement | Level | Project evaluation |
|---|---|---|---|
| V11.3.1 | Verify any security-sensitive randomness comes from a CSPRNG, not `rand()`. | L1 | N/A — PAMSignal has no security-sensitive RNG. Any future code introducing `rand()` or `random()` is an automatic 🔴. |

## V11.4 — Cryptographic library use

| V-ID | Requirement | Level | Project evaluation |
|---|---|---|---|
| V11.4.1 | Verify use of vetted crypto libraries (no hand-rolled primitives). | L1 | ✓ — PAMSignal has no crypto code at all. |
| V11.4.2 | Verify constant-time comparison on secret material (no `memcmp` against secrets). | L1 | N/A — no in-process secret comparison. Webhook tokens are never compared by the daemon. |

## V11.5 — Password hashing

| V-ID | Requirement | Level | Project evaluation |
|---|---|---|---|
| V11.5.* | All password-hashing requirements (argon2id / bcrypt / scrypt). | L1 | N/A — no user passwords managed by PAMSignal. |

---

## Common drift in this codebase

- **A new feature adds a hashing call ("for a cache key", "for dedup of alerts").** Pause. Document the threat model and choose a vetted library; don't introduce `SHA1`/`MD5`/raw `EVP_*` without review.
- **A new dependency on OpenSSL or libsodium.** Architectural change — flag for re-review. Today's only deps are `libsystemd` (build/runtime) and `curl` (runtime).

---

## Scoring rubric

| Score | Meaning |
|---:|---|
| 9–10 | No crypto code in-tree; TLS delegated to curl; operator-supplied private keys validated for permissions. |
| 7–8 | A minor L2 gap (e.g., undocumented rotation procedure for TLS keys). |
| 5–6 | Crypto introduced without a documented threat model. |
| 3–4 | Hand-rolled primitive (HMAC, MAC, hash) or use of a deprecated algorithm. |
| 0–2 | Insecure RNG (rand()) seeding a security decision. |

---

## Report row template

```markdown
| 4 | V11.4.1 | 🟠 | src/notify.c:412 | New dedup_hash() uses MD5 from <openssl/md5.h> [L1] | MD5 is broken; introducing a crypto dep changes the project's attack surface | Replace with a tagged-set or a counter; if hashing is genuinely needed, document the threat model and use a vetted library |
```

---

## Cross-references

- Root `/CLAUDE.md` §Dependencies — current dep list (libsystemd, curl). Adding crypto = new dep = architectural review.
- `docs/architecture.md` — threat model. Update before adding any crypto.
