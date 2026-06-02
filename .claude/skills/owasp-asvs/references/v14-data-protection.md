# V14 — Data Protection

> Upstream: <https://github.com/OWASP/ASVS/blob/master/5.0/en/0x23-V14-Data-Protection.md>

The chapter covers classification, encryption at rest, retention, anti-cache for sensitive views, and PII handling. PAMSignal stores **nothing on disk that it generates** — the PID file is non-secret, the config file is operator-managed, brute-force tracking is in-memory only. The audit's main concern is the secret data flowing **through** the process: webhook URLs with embedded tokens, bearer headers, Telegram bot tokens. These must stay out of `argv`, environment, journal, and any incidental persistence.

**Levels in scope for PAMSignal:** L1 mandatory, L2 informational.

---

## Where this lives in the codebase

| Surface | File | Notes |
|---|---|---|
| In-memory secret holding | `include/config.h:14-28` | Bounded char arrays in `ps_config_t`; reload-swap on SIGHUP overwrites in place |
| Secret routing to curl | `src/notify.c:112-176` `build_secrets_memfd()` | `Authorization:` header + `--cert`/`--key`/`--cacert` written to memfd, passed as `-K /dev/fd/<N>` |
| Bearer header injection | `src/notify.c` | `webhook_auth_header` flows through memfd only — never into argv |
| Telegram chat URL assembly | `src/notify.c` | The URL embeds the bot token; this URL goes through memfd, not argv |
| argv contents at exec | `src/notify.c:232-247` | argv carries: `curl`, `-s`, `-S`, `--max-time`, `10`, `--proto`, `=https`, `--proto-redir`, `=https`, `-H`, `Content-Type: application/json`, `-K`, `/dev/fd/<N>`, `-d`, `<body>` — no secret in there |
| Environment scrub | `src/notify.c:226-227` | `clearenv()` + minimal `PATH` |
| journal output redaction | `src/notify.c:115-118`, error paths throughout | sd_journal_print messages refer to channels by label, never by token |

---

## V14.1 — Data classification

| V-ID | Requirement | Level | Project evaluation |
|---|---|---|---|
| V14.1.1 | Verify a data classification scheme exists and is applied. | L1 | PAMSignal has three classes: (a) operator secrets (tokens, keys), (b) audit data (PAM events), (c) public defaults. Document briefly in `docs/architecture.md`. |
| V14.1.2 | Verify secrets are identified explicitly in code and routed through secret-specific channels. | L1 | `build_secrets_memfd()` is the only sink for secret-bearing config. Verify no new code path emits `cfg->*_token` / `cfg->*_url` to argv, journal, or stderr. |

## V14.2 — Encryption at rest

| V-ID | Requirement | Level | Project evaluation |
|---|---|---|---|
| V14.2.1 | Verify sensitive data at rest is protected (encryption or strict ACL). | L1 | PAMSignal does not persist sensitive data. The config file (operator-managed) is expected to be mode 0600 root:pamsignal. Document in `docs/deployment.md`. |
| V14.2.2 | Verify keys for any at-rest encryption are managed per V11. | L1 | N/A — no at-rest encryption performed by the daemon. |

## V14.3 — Secrets in process

| V-ID | Requirement | Level | Project evaluation |
|---|---|---|---|
| V14.3.1 | Verify secrets never appear in `argv` / `/proc/<pid>/cmdline`. | L1 | argv contents enumerated above — only `-d <body>` could possibly carry user-derived data, and body fields go through `json_escape()` after originating from PAM (not secrets). Bearer / URL with token → memfd. ✓ |
| V14.3.2 | Verify secrets never appear in environment variables visible to other users. | L1 | `clearenv()` before `execv` (`src/notify.c:226`); the child curl has no inherited env at all. ✓ |
| V14.3.3 | Verify file descriptors carrying secrets are not leaked to unrelated children. | L1 | The memfd is opened `MFD_CLOEXEC`; the only descriptor passed to curl is the duplicated `target_fd=9`, with `dup2` clearing CLOEXEC for that one fd only. Every other inherited fd is closed via `close_range` (or bounded loop fallback) before exec. ✓ See `src/notify.c:200-217`. |

## V14.4 — Cache & log redaction

| V-ID | Requirement | Level | Project evaluation |
|---|---|---|---|
| V14.4.1 | Verify sensitive responses are not cached. | L1 | N/A — PAMSignal makes outbound requests; it does not serve responses. |
| V14.4.2 | Verify secrets are not written to logs. | L1 | Grep `sd_journal_print\|sd_journal_send` calls in `src/` for `%s` arguments referencing `cfg->*_token` / `cfg->*_url` — none. ✓ Error paths use labels like `"telegram"`, `"slack webhook"`, never the value. |

## V14.5 — Retention

| V-ID | Requirement | Level | Project evaluation |
|---|---|---|---|
| V14.5.1 | Verify a documented retention policy for any persisted data. | L2 | PAMSignal persists no event data. Operator-side journal retention (`journalctl --vacuum-*`) is separate. Document in `docs/deployment.md`. |

---

## Common drift in this codebase

- **A new alert channel hardcodes the URL as `argv` instead of going through memfd.** Pattern to follow: `src/notify.c:112-176`. Catch with: `grep -n 'argv\[' src/notify.c` and confirm no token-bearing string is in there.
- **A retry / debug path logs the full webhook URL** to help the operator diagnose. Don't log the URL with its token; log the channel label and an HTTP status code.
- **A SIGHUP reload leaves the old `ps_config_t` lying on the stack** with a still-readable secret. The current pattern overwrites `g_config` in place, which is fine for L1. For L2, consider `explicit_bzero()` of the old config struct.

---

## Scoring rubric

| Score | Meaning |
|---:|---|
| 9–10 | Every secret routes through memfd; argv carries no token; clearenv before exec; logs name channels by label only. |
| 7–8 | One L2 informational gap (e.g., no explicit_bzero on reload). |
| 5–6 | A new code path logs the URL with token, OR puts the URL in argv. |
| 3–4 | Bearer token ends up in argv on a primary path. |
| 0–2 | Daemon leaks secrets to the journal as part of normal operation. |

---

## Report row template

```markdown
| 7 | V14.3.1 | 🔴 | src/notify.c:418 | New webhook v2 path concatenates webhook_url into argv [L1] | /proc/<pid>/cmdline is world-readable; any local user can read the embedded token | Route the URL through build_secrets_memfd() following the existing pattern at src/notify.c:112 |
```

---

## Cross-references

- Root `/CLAUDE.md` §Security Requirements — "Alert dispatch stays isolated via fork+exec".
- `docs/architecture.md` — data classification + flow diagram.
- `docs/deployment.md` — operator-side retention policy.
