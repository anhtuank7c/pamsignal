# V1 — Encoding & Sanitization

> Upstream: <https://github.com/OWASP/ASVS/blob/master/5.0/en/0x10-V1-Encoding-and-Sanitization.md>

The chapter covers contextual output encoding, sanitization at the sink (vs. blanket input filtering), and injection prevention. For PAMSignal — a daemon that ingests untrusted strings from PAM journal messages and emits them into structured journal entries and outbound JSON — this is one of the most relevant chapters.

**Levels in scope for PAMSignal:** L1 mandatory, L2 informational, L3 not in scope by default.

---

## Where this lives in the codebase

| Surface | File | Notes |
|---|---|---|
| Control-char sanitizer for journal output | `src/utils.c:13` `sanitize_string()` | Replaces every C0 control byte with `?`; called by every parser before fields are exported |
| JSON escaper for alert bodies | `src/notify.c:27` `json_escape()` | RFC 8259 §7: escapes `"`, `\`, and `0x00–0x1F` (the latter is redundant after `sanitize_string` but kept defensive) |
| Username extractor | `src/utils.c:63` `extract_username()` | Truncates with a visible `+` sentinel so two long inputs cannot silently alias to the same prefix |
| PAM service parser | `src/utils.c:38` `parse_service_from_pam()` | Enumerated output (`PS_SERVICE_*`); no free-form text leaks through |
| sshd/sudo/su/login parsers | `src/utils.c:79+` | Each parser calls `sanitize_string()` on every user-controlled field before write |
| Truncation-safe formatter | `src/notify.c:86` `PS_FMT_OK()` | Treats `snprintf` truncation as failure (drops the alert) so partial bodies cannot leak |
| Spoof guard on journal source | `src/journal_watch.c:38,394-410` `ps_is_trusted_exe()` | Rejects entries whose `_EXE` isn't in the trusted set; closes the `logger(1)` injection vector |

---

## V1.1 — Output encoding for the sink

| V-ID | Requirement (paraphrase) | Level | Project evaluation |
|---|---|---|---|
| V1.1.1 | Verify output is encoded for the context it is rendered in (HTML, URL, JS, JSON, shell, SQL, log, …). | L1 | Two sinks: structured journal (sanitize_string) and JSON webhook (sanitize_string + json_escape). Verify both are applied per field. |
| V1.1.2 | Verify the encoder is a well-known library / function rather than ad-hoc concatenation. | L1 | `json_escape()` handles `"`, `\`, `\b\f\n\r\t`, and `\u00XX` for the rest of C0 — covers RFC 8259 §7. ✓ |
| V1.1.3 | Verify the same input is never double-encoded. | L1 | `sanitize_string` is idempotent (no `?` ↔ control round-trip); `json_escape` runs once at body assembly. ✓ |

## V1.2 — Injection prevention at the sink

| V-ID | Requirement | Level | Project evaluation |
|---|---|---|---|
| V1.2.1 | Verify untrusted input cannot break out of its intended grammar (log line, JSON value, shell argv, SQL literal, …). | L1 | Three grammars: journal MESSAGE (control chars → `?`), JSON value (`"` and `\` escaped), curl argv (secrets never enter argv at all — see V14 / `src/notify.c:112+`). |
| V1.2.2 | Verify log injection is prevented by stripping or escaping newlines / CR before write. | L1 | `sanitize_string` strips ALL `iscntrl()` bytes including `\n` and `\r`. ✓ Check every new parser calls it. |
| V1.2.3 | Verify shell command injection is prevented by NOT using a shell to invoke external programs. | L1 | `src/notify.c:250` uses `execv()` with an absolute path and an argv array — no `system()`, no `popen()`, no `/bin/sh -c`. ✓ |
| V1.2.4 | Verify HTML/CSS/JS-injection vectors are encoded for their context. | L1 | N/A — no HTML / CSS / JS sink in PAMSignal. |
| V1.2.5 | Verify SQL injection is prevented via parameterized queries. | L1 | N/A — no SQL surface. |

## V1.3 — Input source classification

| V-ID | Requirement | Level | Project evaluation |
|---|---|---|---|
| V1.3.1 | Verify untrusted input is identified and treated as such throughout its lifecycle (no blind concatenation into a sink). | L1 | Untrusted source = `sd_journal_get_data` payload. It flows through `ps_field_value` → `extract_*` parsers → `sanitize_string` before reaching any sink. ✓ |
| V1.3.2 | Verify a strict allow-list is used for fields with a known small grammar (e.g., PAM service name). | L1 | `parse_service_from_pam` returns an enum — unknown services map to `PS_SERVICE_OTHER`. ✓ |

---

## Common drift in this codebase

- **A new parser added to `src/utils.c` forgets to call `sanitize_string()` on its output field.** Catch with: `grep -n 'extract_' src/utils.c` and confirm each parser calls sanitize_string at exit.
- **A new alert payload field added to `src/notify.c` is concatenated into `body[]` without `json_escape()` first.** Catch with: `grep -n 'snprintf(body' src/notify.c` and confirm every `%s` substring went through json_escape or is a project-controlled literal.
- **`sanitize_string` skips a byte by mistake** — e.g., someone adds `if (c != '\t')` for "readability". Don't. Tabs are control chars, and the journal MESSAGE shape doesn't promise tab tolerance.

---

## Scoring rubric

| Score | Meaning |
|---:|---|
| 9–10 | Every parser calls sanitize_string; every JSON body string went through json_escape; spoof guard active. |
| 7–8 | One parser missing sanitize_string OR one JSON field unescaped — but neither on a primary path. |
| 5–6 | A user-controlled field reaches a sink without sanitization on a primary path; potential log/JSON injection. |
| 3–4 | Multiple sinks unsanitized OR the spoof guard is bypassable / removed. |
| 0–2 | Daemon writes raw PAM message bytes into the journal or alert body with no escaping. |

---

## Report row template

```markdown
| 1 | V1.2.2 | 🔴 | src/utils.c:312 | New extract_session() helper does not call sanitize_string() before writing to event->session [L1] | Control bytes from PAM MESSAGE flow into journal MESSAGE field, enabling log injection | Append `sanitize_string(event->session)` at function exit; pattern mirrors extract_username at src/utils.c:97 |
```

---

## Cross-references

- Root `/CLAUDE.md` §Security Requirements — "Input validation" and "JSON escaping for alert payloads".
- `tests/test_utils.c` — extend with a fuzz case that injects `\n`, `\r`, `\x1b`, `"`, `\` into PAM message fields.
- `tests/fuzz_parse_message.c` — coverage for the parsing entrypoint; add cases here for any new parser.
