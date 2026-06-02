# V16 — Security Logging & Error Handling

> Upstream: <https://github.com/OWASP/ASVS/blob/master/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md>

The chapter covers audit logging, error redaction, log integrity, time synchronisation, and alerting. For PAMSignal — whose purpose **is** producing security-relevant journal entries — this chapter governs both what the daemon logs about itself (diagnostics, errors) and what it logs about the PAM events it observes (the audit trail). Structured `sd_journal_send()` fields are the primary mechanism; no `printf`, no `syslog()`.

**Levels in scope for PAMSignal:** L1 mandatory, L2 informational.

---

## Where this lives in the codebase

| Surface | File | Notes |
|---|---|---|
| Structured event emission | `src/journal_watch.c:184,206,329,347` | `sd_journal_send("MESSAGE=…", "PRIORITY=…", "PS_EVENT_TYPE=…", "PS_USERNAME=…", …)` — every PAM event gets named fields, not a free-text blob |
| Daemon diagnostics | `sd_journal_print(LOG_INFO/WARNING/ERR, …)` calls throughout | Used for daemon lifecycle, errors, config issues |
| Truncation marker | `src/utils.c:75` `extract_username` | `+` sentinel on overflow so two long inputs cannot silently alias |
| Spoof guard | `src/journal_watch.c:38,394-410` `ps_is_trusted_exe()` | Closes the `logger(1)` injection vector — emitted events come from trusted exes only |
| Log injection defence | `src/utils.c:13` `sanitize_string()` | Strips control bytes so a hostile user/service name cannot inject a forged log line |
| Time | systemd journal | Each entry carries `__REALTIME_TIMESTAMP` and `__MONOTONIC_TIMESTAMP`. Trust the system clock + `systemd-timesyncd` |

---

## V16.1 — Audit logging

| V-ID | Requirement | Level | Project evaluation |
|---|---|---|---|
| V16.1.1 | Verify security-relevant events are logged with sufficient detail to support investigation. | L1 | Each PAM event emits `PS_EVENT_TYPE`, `PS_SERVICE`, `PS_USERNAME`, `PS_SRC_IP` (when applicable), `PS_PID`, `PS_UID`. ✓ Verify any new event type adds the same field set. |
| V16.1.2 | Verify timestamps are accurate and use a monotonic + wall clock pair where possible. | L1 | Inherited from journald (`__REALTIME_TIMESTAMP`, `__MONOTONIC_TIMESTAMP`). ✓ |
| V16.1.3 | Verify the log format is structured (key=value) so it can be queried without parsing free-text. | L1 | `sd_journal_send` emits named fields. ✓ Anti-pattern: building a single MESSAGE string via snprintf for "human readability" — keep structured. |
| V16.1.4 | Verify the daemon logs its own lifecycle events (start, ready, reload, shutdown). | L1 | `src/main.c:198-209` emits start + ready + shutdown. SIGHUP reload should also emit a structured event — verify. |

## V16.2 — Error handling

| V-ID | Requirement | Level | Project evaluation |
|---|---|---|---|
| V16.2.1 | Verify errors are logged with enough context to diagnose, but without leaking secrets or stack contents. | L1 | Error paths name the failing field/operation but never the value (`"pamsignal: config: %s: cannot open %s"` is OK; `"… token=%s"` would not be). Sample 5 error paths in `src/config.c` and `src/notify.c`. |
| V16.2.2 | Verify error paths fail closed (default-deny). | L1 | Config parse failure: live config unchanged (good). curl fork failure: alert dropped (good — better than partial send). Memfd allocation failure: alert dropped. ✓ |
| V16.2.3 | Verify the daemon does not exit on a single bad event — it keeps running. | L1 | Per-event parsing failures return early without exiting (`src/journal_watch.c:384,404`). ✓ |

## V16.3 — Log redaction

| V-ID | Requirement | Level | Project evaluation |
|---|---|---|---|
| V16.3.1 | Verify secrets are never written to logs. | L1 | Grep `sd_journal_print\|sd_journal_send` arguments in `src/` for `cfg->*_token` / `cfg->*_url` / `cfg->*_header` — none should appear. ✓ Cross-cuts V14.4.2. |
| V16.3.2 | Verify user-controlled bytes are sanitized before they enter a log field. | L1 | `sanitize_string` on every PAM-derived field. ✓ Cross-cuts V1.2.2. |
| V16.3.3 | Verify truncation is signalled rather than hidden. | L2 | `extract_username` writes `+` at the last byte on overflow (`src/utils.c:75`) so the log reader can see truncation happened. Extend the pattern to any new bounded extractor. |

## V16.4 — Log integrity

| V-ID | Requirement | Level | Project evaluation |
|---|---|---|---|
| V16.4.1 | Verify the log destination is tamper-resistant for the operator (append-only / FSS). | L2 | The journal supports Forward Secure Sealing (`journalctl --setup-keys`). Operator-side responsibility — document in `docs/deployment.md`. |
| V16.4.2 | Verify the daemon cannot be tricked into emitting fake security events sourced from an untrusted process. | L1 | `ps_is_trusted_exe()` checks `_EXE` on every journal entry before any parser runs (`src/journal_watch.c:394-410`). Entries with no `_EXE` are dropped. ✓ |

## V16.5 — Time

| V-ID | Requirement | Level | Project evaluation |
|---|---|---|---|
| V16.5.1 | Verify the host time source is reliable and monitored. | L2 | Operator-side (NTP / chrony / systemd-timesyncd). Document. PAMSignal does not need its own time discipline. |

## V16.6 — Alerting

| V-ID | Requirement | Level | Project evaluation |
|---|---|---|---|
| V16.6.1 | Verify the daemon raises alerts on high-confidence security events (brute-force, repeated failures). | L1 | Brute-force detection thresholds + alert dispatch — that is PAMSignal's entire purpose. ✓ |
| V16.6.2 | Verify alerts are rate-limited so a flood does not become a DoS vector. | L1 | `alert_cooldown_sec` (default 60s) + `RLIMIT_NPROC=64` curl child cap. ✓ |

---

## Common drift in this codebase

- **A new error path logs the failing config value verbatim, including the token.** Don't. Log the field name and an operation; the operator can re-read the config file.
- **A new event handler emits a single freeform `MESSAGE=` string instead of separate fields.** Use `sd_journal_send` with named fields so the operator can `journalctl PS_EVENT_TYPE=brute_force`.
- **A truncation point inside a new parser silently drops data.** Either widen the buffer (it's a daemon — stack space is cheap) or write a visible truncation marker, mirroring `extract_username`.

---

## Scoring rubric

| Score | Meaning |
|---:|---|
| 9–10 | Structured fields on every event; no secret in any log; spoof guard active; truncation visibly marked. |
| 7–8 | One L2 informational gap (e.g., journal FSS not documented). |
| 5–6 | One event handler emits freeform messages instead of structured fields. |
| 3–4 | An error path leaks a config secret to the journal, OR truncation is silent on a security-relevant field. |
| 0–2 | Spoof guard removed / bypassable, OR daemon exits on a malformed event. |

---

## Report row template

```markdown
| 9 | V16.3.1 | 🔴 | src/config.c:512 | New "config load failure" path logs the failing line verbatim, including the bot_token value [L1] | Secret leaked to systemd journal — anyone with `journalctl -u pamsignal` read access can see the token | Log the key name and line number only: `sd_journal_print(LOG_ERR, "pamsignal: config: line %d: malformed value for key %s", lineno, key)` |
```

---

## Cross-references

- Root `/CLAUDE.md` §Code Conventions — "Logging: `sd_journal_print()` / `sd_journal_send()` — not printf/syslog".
- `docs/architecture.md` — list of structured fields each event type carries.
- `docs/deployment.md` — operator-facing journal hardening (FSS, retention).
