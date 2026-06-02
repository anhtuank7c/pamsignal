---
name: review-code
description: Run the 20-rule OWASP ASVS Level 1 pre-merge security gate on the specified PAMSignal code. Use for a QUICK check (input validation, log injection, fork+exec hygiene, file I/O, TLS, hardening flags) before merging — not a full audit. For the full ASVS audit with V-ID-tagged findings, use the `code-reviewer` agent instead. For a learning/reference deep-dive on a single ASVS chapter, load the `owasp-asvs` skill directly.
---

Review the specified PAMSignal code for security issues following OWASP ASVS 5.0 Level 1 standards. PAMSignal is a small C17/gnu17 daemon — no web frontend, no API, no DB, no user accounts. The gate below targets the threats that *do* apply: log injection, memory-safety bugs, fork+exec hygiene, file I/O races, TLS configuration, and build-time hardening.

Check the 20 rules below. For each one, return **PASS / FAIL / N/A** with `file:line` evidence on FAILs and a one-line fix shape that cites an existing project helper.

## V1 — Encoding & Sanitization

1. **Every field copied out of a journal/PAM message passes through `sanitize_string()` before it lands in any output buffer.** `src/utils.c:13`. Common drift: a new `extract_*` parser in `src/utils.c` forgets to call it.
2. **Every string field rendered into a JSON alert body passes through `json_escape()` first.** `src/notify.c:27`. The escaper handles `"`, `\`, and the C0 control range; missing it = injection into the webhook payload.
3. **No raw `printf`/`fprintf`/`syslog` calls in production code paths.** All logging goes through `sd_journal_print()` / `sd_journal_send()`. Grep `src/` for `printf(` and `fprintf(` — only `fprintf(stderr, …)` in early startup before journald is wired is acceptable.

## V2 — Validation & Business Logic

4. **Every numeric config value uses `strtol`/`strtoul` with an explicit `errno = 0` reset, end-pointer check, AND range check.** See `src/init.c:117-124` for the pattern. Drift: forgetting the range check after `strtol`.
5. **Every IP/host-style config or message field is validated via `is_valid_ip()` (`inet_pton`).** `src/utils.c:21`. Loosely-validated IPs flow into JSON bodies and downstream consumers.
6. **Every `snprintf` into a fixed-size buffer checks for truncation via `PS_FMT_OK()` or an equivalent `n >= 0 && (size_t)n < sizeof(buf)` guard.** `src/notify.c:86`. Silent truncation = malformed JSON, partial URLs, sometimes a security boundary slip.
7. **No `strcpy`, `strcat`, `sprintf`, `gets`, or `scanf("%s", …)` anywhere.** Use `strncpy`+manual NUL, `snprintf`, or the project's `PS_FMT_OK` macro.

## V5 — File Handling

8. **Every file open touching a sensitive path uses `O_NOFOLLOW | O_CLOEXEC` at minimum.** PID file and pidfile creation also need `O_EXCL` and explicit mode `0600`. See `src/init.c:155`. Drift: a new helper `open()`s without `O_NOFOLLOW`, opening a TOCTOU window.
9. **PID-file path is opened relative to a `dirfd` (`openat`), so the symlink-swap race is closed.** `src/init.c:146-155`. New file creations under `/run` or `/var/lib/pamsignal` must follow the same pattern.
10. **Config/TLS path validation goes through `validate_tls_path()` (or its equivalent for the config file).** `src/config.c:228`. Checks: refuses control chars / quotes / backslash, refuses symlinks, requires regular file, requires root or daemon ownership, requires non-world-readable for private material.

## V11 / V12 — Cryptography & Secure Communication

11. **No hand-rolled crypto.** TLS is curl's responsibility via `--proto =https --proto-redir =https`. Any new primitive (HMAC, AES, etc.) must justify itself by V11.x rules — flag for re-review.
12. **`curl` is invoked with an absolute path (`/usr/bin/curl`) and never with `-k` / `--insecure`.** `src/notify.c:232-250`. If `-k` ever appears in argv, that's a 🔴 V12 fail.
13. **Optional client cert / CA bundle flows through the memfd config (`-K /dev/fd/<n>`), not argv.** Same memfd that carries the bearer/token. `src/notify.c:112-176`.

## V13 / V14 — Configuration & Data Protection

14. **Secrets (webhook URLs with embedded tokens, bearer headers, Telegram bot tokens) never appear in `argv`.** They are written to the curl `-K` config in a memfd. Grep new code in `src/notify.c` for argv-appended URLs — that's a 🔴 V14 fail because `/proc/<pid>/cmdline` is world-readable.
15. **Secrets are never journaled.** `sd_journal_print` calls in error paths show only field labels and lengths, never the secret value. Grep for `%s` calls that take `cfg->*_token` or `cfg->*_url` as arguments.
16. **Config file is opened `O_RDONLY | O_NOFOLLOW | O_CLOEXEC` and the file's perms / ownership are validated before parse.** `src/config.c:239`.

## V15 — Secure Coding & Architecture

17. **The hardening flags in `meson.build` are intact: `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=3` (with `=2` fallback), `-Wl,-z,relro`, `-Wl,-z,now`, `b_pie=true`, `-fstack-clash-protection`.** Any diff that touches `meson.build` and removes one is a 🔴.
18. **Fork+exec curl path stays isolated**: child must `clearenv()` + reset signal handlers + close fds via `close_range` (or bounded loop fallback) before `execv()`. `src/notify.c:187-251`. `PR_SET_NO_NEW_PRIVS` is set in `main.c:162`; `RLIMIT_NPROC` is capped at 64 in `main.c:171`.
19. **Spoof protection on journal entries**: every `read_pam_event` path verifies `_EXE` via `ps_is_trusted_exe()` and rejects entries without `_EXE` — `src/journal_watch.c:394-410`. New event-handler code must keep this check before trusting any field.

## V16 — Logging & Error Handling

20. **Error paths use `sd_journal_print(LOG_ERR/LOG_WARNING, …)` with a label that says *what* failed and *which* field**, never a raw `errno` dump without context, and never a secret value. Truncation of user-controlled fields is visibly marked (`+` sentinel from `extract_username`, `src/utils.c:75`).

---

## Output format

```markdown
## Pre-merge review — <scope> — <YYYY-MM-DD>

| # | Rule | Status | Evidence | Fix shape |
|---:|---|---|---|---|
| 1 | V1: sanitize_string on all PAM-sourced fields | ✅ PASS | src/utils.c:97,128,140,203,220 — every parser calls it | — |
| 2 | V1: json_escape on all alert body fields | ❌ FAIL | src/notify.c:412 — new `payload_servicename` not escaped | Wrap with json_escape() before snprintf into body |
| … | … | … | … | … |
```

**Summary line at the end**: e.g., `18 PASS / 1 FAIL / 1 N/A — blockers: #2`.

Reference: Root `CLAUDE.md` §Security Requirements and §Pre-Commit Workflow for the canonical rules. For a deeper V-ID-tagged audit, hand the same scope to the `code-reviewer` agent.
