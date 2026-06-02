# V12 — Secure Communication

> Upstream: <https://github.com/OWASP/ASVS/blob/master/5.0/en/0x21-V12-Secure-Communication.md>

The chapter covers TLS configuration, cipher suites, HSTS, certificate pinning, and internal mTLS. PAMSignal's only network surface is **outbound HTTPS via fork+exec curl** for alert delivery. There is no inbound listener, so most of the chapter (HSTS, server-side TLS termination, cipher suite policy) is N/A. The audit focuses on the curl invocation: protocol restriction, no insecure flags, optional client cert via memfd.

**Levels in scope for PAMSignal:** L1 mandatory, L2 informational.

---

## Where this lives in the codebase

| Surface | File | Notes |
|---|---|---|
| curl invocation | `src/notify.c:232-251` | `execv("/usr/bin/curl", argv)` with explicit `--proto =https --proto-redir =https`, `--max-time 10`, no `-k` |
| Client cert / CA bundle config keys | `include/config.h:26-28` | `webhook_client_cert`, `webhook_client_key`, `webhook_ca_bundle` |
| Path validation for TLS material | `src/config.c:228-288` `validate_tls_path()` | Refuses control chars/quotes/backslash, refuses symlinks, ownership + mode checks |
| Pairing validation | `src/config.c:290+` `validate_webhook_tls()` | Cert without key (or vice-versa) is rejected at load |
| Secret routing through memfd | `src/notify.c:112-176` `build_secrets_memfd()` | Bearer / TLS-config option lines written to memfd, passed as `-K /dev/fd/<N>`; secrets never enter curl argv |

---

## V12.1 — TLS for outbound calls

| V-ID | Requirement | Level | Project evaluation |
|---|---|---|---|
| V12.1.1 | Verify outbound HTTPS uses TLS 1.2+ with strong cipher suites. | L1 | Delegated to curl/OpenSSL system defaults. Modern distributions ship TLS 1.2/1.3 only. Document in `docs/architecture.md`. |
| V12.1.2 | Verify the client refuses to fall back to HTTP. | L1 | `--proto =https --proto-redir =https` at `src/notify.c:237-240`. ✓ Any future code that omits these is 🔴. |
| V12.1.3 | Verify certificate validation is enabled — i.e., no `-k`, `--insecure`, or environment override that disables it. | L1 | Grep `src/notify.c` for `"-k"`, `"--insecure"`, `"SSL_VERIFY"` — none present. ✓ |
| V12.1.4 | Verify the request has a reasonable timeout (DoS / slowloris defence on the client side). | L1 | `--max-time 10` at `src/notify.c:236`. ✓ |

## V12.2 — Server-side TLS

| V-ID | Requirement | Level | Project evaluation |
|---|---|---|---|
| V12.2.* | All server-side TLS requirements (HSTS, cipher policy, ALPN). | L1 | N/A — PAMSignal has no inbound TLS listener. |

## V12.3 — Mutual TLS

| V-ID | Requirement | Level | Project evaluation |
|---|---|---|---|
| V12.3.1 | Verify mTLS client material is protected at rest. | L2 | `validate_tls_path()` enforces non-world-readable + correct ownership on the private key (`src/config.c:278-285`). ✓ |
| V12.3.2 | Verify the cert and key are paired and validated at load. | L2 | `validate_webhook_tls()` rejects cert-without-key and key-without-cert at config load. ✓ |
| V12.3.3 | Verify mTLS material is not exposed in `argv` / `/proc/<pid>/cmdline`. | L1 | Cert / key paths flow through the memfd `-K` config; they reach curl as `--cert <path>\n--key <path>\n` config lines, not argv. ✓ See `src/notify.c:112+`. |

## V12.4 — Cert pinning / public-key pinning

| V-ID | Requirement | Level | Project evaluation |
|---|---|---|---|
| V12.4.1 | Verify pinning is used where appropriate, or that the decision not to pin is documented. | L2 | Not pinned — relies on system CA bundle. Operator can override with `webhook_ca_bundle`. Acceptable for L1; document the rationale (alert destinations like Slack/Telegram rotate certs frequently). |

---

## Common drift in this codebase

- **A new curl invocation forgets `--proto =https`.** If the URL is operator-controlled, a typo (`http://`) silently falls back to plaintext + credential leak. Catch with: `grep -n 'execv\|curl' src/notify.c` and confirm `--proto =https` is in every argv.
- **A "test mode" flag adds `-k` / `--insecure` to curl.** Don't. Test against a real cert (use a self-signed cert + custom CA bundle) instead.
- **A new alert channel constructs a URL by concatenating `cfg->endpoint` with a path** but doesn't re-verify the protocol is HTTPS. The `--proto =https` flag catches this at curl, but a defensive re-check in C is cheap.

---

## Scoring rubric

| Score | Meaning |
|---:|---|
| 9–10 | `--proto =https --proto-redir =https` + `--max-time` + no `-k`; mTLS material routed through memfd. |
| 7–8 | Pinning not documented (L2 informational gap). |
| 5–6 | Missing `--proto =https` on a new curl invocation. |
| 3–4 | `-k` / `--insecure` present in a code path. |
| 0–2 | curl invoked via `system("...")` shell string, allowing scheme injection. |

---

## Report row template

```markdown
| 5 | V12.1.3 | 🔴 | src/notify.c:412 | New retry path adds "--insecure" to argv for self-signed test endpoints [L1] | Disables certificate validation in production code | Remove --insecure; for self-signed test endpoints, set webhook_ca_bundle to a CA file (config.h:28) |
```

---

## Cross-references

- Root `/CLAUDE.md` §Security Requirements — "Alert dispatch stays isolated via fork+exec — no network code in parent process".
- `docs/alerts.md` — operator-facing TLS config documentation (cert / key / CA bundle keys).
