# V2 — Validation & Business Logic

> Upstream: <https://github.com/OWASP/ASVS/blob/master/5.0/en/0x11-V2-Validation-and-Business-Logic.md>

The chapter covers input validation at trust boundaries, business-rule enforcement, anti-automation, and race-condition defence. For PAMSignal the trust boundaries are: (a) the config file → daemon, (b) the journal stream → daemon, (c) the daemon's in-memory state → the outbound JSON body.

**Levels in scope for PAMSignal:** L1 mandatory, L2 informational.

---

## Where this lives in the codebase

| Surface | File | Notes |
|---|---|---|
| Config parser & validator | `src/config.c` | Every key has a typed parser; unknown keys fail closed |
| Numeric parser pattern | `src/init.c:117-124` | `errno = 0` + `strtol` + end-pointer + range check |
| IP validation | `src/utils.c:21` `is_valid_ip()` | `inet_pton(AF_INET)` then `AF_INET6`; rejects anything else |
| Trusted `_EXE` allow-list | `src/journal_watch.c:38` `ps_is_trusted_exe()` | Path prefix + basename filter on journal source |
| Bounded buffers | `include/config.h:14-41` | Every string field has a fixed max (`telegram_bot_token[256]`, `webhook_url[512]`, …) |
| Numeric clamp ranges | `include/config.h:31-40` | `fail_threshold 1..10000`, `fail_window_sec 1..86400`, `max_tracked_ips 1..100000`, `alert_cooldown_sec 0..86400` |
| TLS path validator | `src/config.c:228` `validate_tls_path()` | Refuses control chars, refuses symlinks, ownership + mode checks |
| Brute-force ring buffer | `src/journal_watch.c` (tracking arrays) | Bounded by `max_tracked_ips` to prevent unbounded memory growth |

---

## V2.1 — Input validation

| V-ID | Requirement | Level | Project evaluation |
|---|---|---|---|
| V2.1.1 | Verify validation happens at trust boundaries (server side). | L1 | Config file → `ps_config_load`; journal → `ps_parse_message`; both validate before storing. ✓ |
| V2.1.2 | Verify length, type, range, and format checks on every input. | L1 | Numeric configs: range-checked. String configs: bounded by struct field size + content rules (e.g., `validate_tls_path`). Verify on every new key added. |
| V2.1.3 | Verify validation rejects null bytes, CR/LF and other control characters in fields where they have no meaning. | L1 | `sanitize_string` (V1) handles message-derived fields; config parser rejects control chars in TLS paths at `src/config.c:230`. |
| V2.1.4 | Verify validation uses an allow-list approach where the grammar is constrained. | L1 | Service names map to enum via `parse_service_from_pam`; unknown → `PS_SERVICE_OTHER`. IPs validated via `inet_pton`. ✓ |
| V2.1.5 | Verify integer parsing checks for overflow and trailing garbage. | L1 | `errno = 0; strtol(...)` + `end == buf` check + range check — see `src/init.c:117-124` and `src/journal_watch.c:420-425`. ✓ |

## V2.2 — Strong validation primitives

| V-ID | Requirement | Level | Project evaluation |
|---|---|---|---|
| V2.2.1 | Verify use of well-tested primitives over hand-rolled regex (e.g., `inet_pton` for IPs, `strtol`/`strtoul` for ints). | L1 | `inet_pton` ✓, `strtol` ✓. No regex in the codebase. |
| V2.2.2 | Verify input that crosses a trust boundary is canonicalized before validation. | L1 | Pathnames passed to `validate_tls_path` are validated then opened with `O_NOFOLLOW` — symlink races closed. ✓ |

## V2.3 — Business-logic enforcement

| V-ID | Requirement | Level | Project evaluation |
|---|---|---|---|
| V2.3.1 | Verify business rules (rate limits, thresholds, state transitions) are enforced server-side. | L1 | Brute-force threshold + window + alert cooldown all enforced inside `journal_watch`. ✓ |
| V2.3.2 | Verify anti-automation defends against flood / DoS where applicable. | L2 | `RLIMIT_NPROC=64` (`main.c:171`) prevents fork-bomb of alert children. ✓ Brute-force tracker bounded by `max_tracked_ips`. |

## V2.4 — Race-condition defence

| V-ID | Requirement | Level | Project evaluation |
|---|---|---|---|
| V2.4.1 | Verify operations on shared state are race-free (TOCTOU / write-after-check). | L1 | Pidfile uses `O_NOFOLLOW \| O_EXCL \| O_CREAT` + `flock(F_SETLK)` — no TOCTOU on creation (`src/init.c:153-188`). Stale-pidfile path uses `openat` against held `dirfd` to defeat symlink swaps (`src/init.c:158-168`). ✓ |
| V2.4.2 | Verify signal handlers do not race with main-loop state. | L1 | `running` and `reload_requested` are `atomic_bool` — signal-safe. SIGHUP reload swaps a fully-parsed temp config; on parse failure the live config is unchanged. |

---

## Common drift in this codebase

- **A new numeric config key is parsed with `atoi`** — silent overflow + no error signal. Always use the `errno=0 / strtol / end-pointer / range` quartet.
- **A new string config field is added to `ps_config_t` without a bound** (e.g., a pointer instead of a fixed array). Don't. Bounded buffers are an invariant; allocation lifetime in a reloadable config is a footgun.
- **A new parser is added without a corresponding test in `tests/test_utils.c` or `tests/fuzz_parse_message.c`.** The pre-commit workflow (CLAUDE.md §Pre-Commit Workflow item 1) requires CMocka tests for every new parsing path.

---

## Scoring rubric

| Score | Meaning |
|---:|---|
| 9–10 | Every numeric uses strtol+range; every string is bounded; every IP uses inet_pton; every parser has tests. |
| 7–8 | One config key missing a range check or one parser missing a fuzz case. |
| 5–6 | A config field is unbounded or a numeric uses `atoi`/raw `sscanf`. |
| 3–4 | Multiple unvalidated inputs reach a sink; race window present on shared state. |
| 0–2 | Daemon accepts arbitrary-length input or trusts journal data without any validation. |

---

## Report row template

```markdown
| 2 | V2.1.5 | 🟠 | src/config.c:412 | New keepalive_sec key parsed via atoi() with no range check [L1] | Negative / huge values silently accepted; allows DoS via runaway timer | Replace atoi with the strtol pattern at src/init.c:117 and clamp to 1..3600 |
```

---

## Cross-references

- Root `/CLAUDE.md` §Security Requirements — "bounded buffers, `inet_pton` for IPs".
- `tests/test_config.c` — config-validation tests.
- `tests/fuzz_parse_message.c` + `tests/fuzz/` — fuzz harness for the parsing entrypoint.
