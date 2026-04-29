# Changelog

## Unreleased

### Security (Phase 6 — libFuzzer harness for ps_parse_message)
- [x] `tests/fuzz_parse_message.c` — `LLVMFuzzerTestOneInput` harness gated behind `-Dfuzz=enabled`. Builds with clang + `-fsanitize=fuzzer,address,undefined`. Default gcc workflow is unaffected because the option defaults to `disabled` (TST-03)
- [x] `tests/fuzz/parse_message_corpus/` — 10 seed inputs covering login success/fail, session open/close, IPv4/IPv6, sudo, uid suffix, and an empty-input case
- [x] Smoke run completed: 22M executions in 31 seconds (~710k exec/sec) with ASan + UBSan, no crashes; corpus grew by 346 entries from coverage-guided exploration

### Security (Phase 5 — brute-force tracker tests + cooldown bugfix)
- [x] `tests/test_journal_watch.c` — 13 tests covering `ps_fail_table_init` validation, single/multi-IP counter behavior, window expiration, threshold breach, per-IP cooldown suppression, cooldown release after the window passes, eviction-by-oldest when capacity is full, and empty-IP skip (TST-02)
- [x] **Bug fix surfaced by the new tests**: per-IP cooldown gate treated `last_brute_alert_usec == 0` (never alerted) as "alert fired at epoch", so the very first brute-force alert for any IP could be suppressed if its event timestamp was within `cooldown_sec` of epoch. Added an explicit zero-check so first-time breaches always notify.

### Security (Phase 4 — low-severity cleanup)
- [x] Truncated usernames carry a `+` marker in their last byte — two distinct overlong usernames can no longer silently alias to the same prefix in alerts (SEC-12)
- [x] Login-event parsing routed through `extract_username` instead of `sscanf("%63s")` so the truncation marker applies to login events as well as session events
- [x] ISO-8601 timestamps with timezone offset (`%Y-%m-%dT%H:%M:%S%z`) — forensic alerts no longer require guessing which TZ produced them (INF-03)
- [x] `strtol` for journal `_PID` / `_UID` now checks `errno == ERANGE` and bounds-checks against `INT_MAX` so a malicious `_PID=99999999999999999999` doesn't get cast to `LONG_MAX` (MEM-13)
- [x] `realpath()` failures in `--config` now fail closed unless `errno == ENOENT` (which is the expected "use defaults" case) — refuses to start on `EACCES`, `ELOOP`, etc. rather than continuing with an unresolvable path (DSG-06)
- [x] Test fixtures use `mkstemps()` instead of a `pid`-suffixed predictable path — concurrent test runs can't collide and another local user can't pre-place a fixture file (INF-04). mkstemps creates the file with mode 0600 directly, removing the post-write `chmod`.
- [x] `pamsignal.service` adds `Environment=PATH=/usr/bin:/bin` — closes the gap if the binary is launched outside the unit (defense-in-depth alongside the absolute-path execv from Phase 1)

### Security (Phase 3 — defense in depth)
- [x] `json_escape` is now RFC 8259 compliant — emits `\u00XX` for the full 0x00–0x1F control range plus the short forms `\b \f \n \r \t`; sanitization regressions can no longer inject raw control bytes into alert payloads (MEM-05 latent half)
- [x] Replace the `for (fd=3; fd<1024; fd++) close(fd)` loop in the curl child with `close_range(3, ~0U, 0)` (Linux ≥5.9), with a fallback to the bounded loop on `ENOSYS` — eliminates the fd-leak hazard when `RLIMIT_NOFILE > 1024` (MEM-07)
- [x] Daemon calls `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)` early so any descendant (curl alert child) cannot escalate via setuid (DSG-01)
- [x] `setrlimit(RLIMIT_NPROC, 64)` cap — a flood of journal events triggering alerts now fails closed with `EAGAIN` instead of fork-bombing the system (DSG-03 partial)
- [x] Config file opened with `O_RDONLY|O_NOFOLLOW|O_CLOEXEC`, then `fstat` checks: refuse if not a regular file, group/world-writable, or owned by anyone other than root or the daemon's effective uid; symlinks are refused (DSG-05)
- [x] Per-source-IP brute-force cooldown — the journal entry still fires on every threshold breach, but outbound notifications are rate-limited per IP using `last_brute_alert_usec` in `ps_fail_entry_t` (MEM-09)
- [x] Split the single global cooldown timer into `last_event_alert` (login events) and per-IP brute-force cooldown — a flood of login events can no longer mute brute-force alerts, and vice versa (MEM-09)
- [x] Compiler hardening: `-fstack-clash-protection`, `-fcf-protection=full`, `-Wnull-dereference`, `-Wstrict-overflow=3`; `_FORTIFY_SOURCE=3` (with `-U_FORTIFY_SOURCE` to override distro-injected `=2`); detected via `cc.get_supported_arguments` so the build degrades gracefully on older toolchains (BLD-01, BLD-04)
- [x] Linker hardening: `-Wl,-z,noexecstack` made explicit; `-Wl,-z,separate-code` (disjoint RX/RW segments) added when supported (BLD-01)

### Security (Phase 2 — signals, PID file, config reload)
- [x] Switch `running` / `reload_requested` from `atomic_bool` to `volatile sig_atomic_t` — C11-compliant signal-handler primitives (SEC-06)
- [x] Add `SA_RESTART` to SIGINT/SIGTERM/SIGHUP so syscalls resume cleanly after handlers (SEC-07)
- [x] Install `SIGPIPE = SIG_IGN` — prevents daemon termination when a curl child exits while we still hold a write side (SEC-07)
- [x] PID-file: hold a directory fd to `/run/pamsignal` opened with `O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC`, then `openat` the pidfile — closes the symlink-race window between `unlink` and `open` (SEC-05)
- [x] Stale-pidfile detection: only `unlinkat` when `kill(pid, 0)` returns `ESRCH`; refuse to start (and log the offending PID) if another instance is alive
- [x] Add `O_CLOEXEC` to pidfile fd so it isn't inherited by curl children
- [x] SIGHUP reload: block SIGHUP/SIGINT/SIGTERM via `sigprocmask` around the swap so a second signal cannot land mid-copy (SEC-08)
- [x] `ps_fail_table_init`: allocate-then-swap — calloc failure now leaves the prior table intact instead of dropping to `NULL`, and capacity ≤ 0 is rejected (MEM-01, MEM-02)

### Security (Phase 1 — alert dispatch hardening)
- [x] Webhook URL allowlist — reject non-`https://` schemes (no more `http://`, `file://`, `gopher://`); reject whitespace, control chars, and shell/curl-config metacharacters at config load
- [x] Telegram bot token format check — `^[0-9]+:[A-Za-z0-9_-]{20+}$`
- [x] WhatsApp `phone_number_id` and `recipient` must be digits only; `access_token` restricted to `[A-Za-z0-9_\-.=]`
- [x] Telegram `chat_id` must be `<signed-int>` or `@channelname`
- [x] Replace `execvp("curl")` with `execv("/usr/bin/curl")` — kills `$PATH` injection (SEC-04)
- [x] `clearenv()` + minimal `PATH=/usr/bin:/bin` in curl child — defeats `LD_PRELOAD` and ambient-env attacks
- [x] Move webhook URLs and bearer tokens into a `memfd_create()`-backed curl config file passed via `-K /dev/fd/N` — secrets no longer appear in `/proc/<pid>/cmdline` (SEC-03)
- [x] Force `--proto =https --proto-redir =https` on every curl invocation — defense-in-depth against scheme smuggling (SEC-02)
- [x] Detect `snprintf` truncation on every URL/header/body builder — drop the alert with a journal warning rather than send a malformed payload (MEM-05)
- [x] Drop `parse_mode=HTML` from Telegram payload — eliminates injected-hyperlink risk from attacker-controlled usernames (SEC-09)
- [x] Don't log raw config-line content on parse error — secrets in malformed lines no longer leak to journald (SEC-10)

### Refactoring
- [x] Replace `sscanf` with `strtol` for port parsing — proper error detection, CERT-compliant (`cert-err34-c`)
- [x] Table-driven config parser — replace 15+ `strcmp`/`snprintf` branches with `cfg_entry_t` mapping table
- [x] Consolidate notify channel senders — extract `post_json`/`send_simple_webhook` helpers, ~80 lines removed

### Core Observer
- [x] Journal subscription via `libsystemd` — filter PAM events from sshd, sudo, su, login
- [x] PAM message parsing — extract username, source IP, port, service, auth method
- [x] Structured journal output — `sd_journal_send()` with custom `PAMSIGNAL_*` fields
- [x] Brute-force detection — configurable threshold and time window per IP
- [x] Signal handling — SIGTERM/SIGINT for clean shutdown, SIGHUP for config reload
- [x] Daemonization — double-fork, PID file in `/run/pamsignal/`, foreground mode

### Configuration
- [x] INI-style config parser — zero dependencies, strict validation
- [x] SIGHUP live reload — parse into temp, swap on success, keep current on failure
- [x] `--config` / `-c` CLI flag with `realpath()` resolution
- [x] Dynamic fail table — heap-allocated, resized on config reload

### Alert Dispatch
- [x] Fork+exec `curl` — fire-and-forget, child crash cannot affect parent
- [x] Telegram — Bot API `sendMessage` with HTML formatting
- [x] Slack — incoming webhook
- [x] Microsoft Teams — incoming webhook
- [x] WhatsApp — Meta Cloud API
- [x] Discord — webhook
- [x] Custom webhook — structured JSON POST
- [x] Alert cooldown — configurable rate limiting per event
- [x] SIGCHLD auto-reap — `SA_NOCLDWAIT` prevents zombie processes

### Security
- [x] Non-root enforcement with helpful error messages
- [x] OWASP ASVS 5.0 audit — PID file hardening, `O_NOFOLLOW|O_EXCL`, `getenv` caching
- [x] Compiler hardening — `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`, `-Wformat=2`, `-Werror=format-security`
- [x] Linker hardening — full RELRO (`-Wl,-z,relro,-z,now`), PIE
- [x] Systemd sandboxing — 15+ directives (`NoNewPrivileges`, `ProtectSystem=strict`, `MemoryDenyWriteExecute`, `SystemCallFilter`, etc.)
- [x] Input validation — bounded buffers, `inet_pton` IP validation, log injection sanitization
- [x] No network code in parent process — alerts isolated via fork+exec

### Testing
- [x] CMocka unit test framework — integrated with Meson via `meson test`
- [x] `test_utils` — 30 tests: PAM message parsing (session open/close, login success/fail, IPv4/IPv6), field extraction, edge cases (empty message, invalid IP, long username truncation with `+` marker, exact-fit username without marker, control char sanitization, struct zeroing), enum-to-string, ISO-8601 timestamp formatting
- [x] `test_config` — 32 tests: defaults, file handling (missing/empty/comments), valid config, all alert channels, whitespace trimming, boundary values (min/max), error cases (out of range, negative, non-numeric, missing `=`), unknown keys, partial config, validator rejection (telegram token shape, chat_id shape, http/file/no scheme, embedded quote/backslash, non-numeric WhatsApp ids), file-permission rejection (group-writable, world-writable, symlink)
- [x] `test_notify` — smoke tests for the public dispatch API: no-op behavior with all channels disabled, cooldown handling under repeat invocations

### Tooling
- [x] CLAUDE.md — project conventions, pre-commit workflow, commit message standard
- [x] `.clang-format` — LLVM-based, 4-space indent, 80-column, right-aligned pointers
- [x] `.clang-tidy` — clang-analyzer, bugprone, cert, security checks with project naming rules

### Documentation
- [x] Architecture — C4 model (context, container, component), alert isolation diagram
- [x] Configuration reference — all config keys, CLI flags, reload behavior
- [x] Alert guide — channel setup, message formats, webhook JSON payload reference
- [x] Development guide — build, test environment, e2e testing
- [x] Deployment guide — systemd service, production setup, security hardening table

## To Do

### Next Up
- [ ] End-to-end test with real alert channels (Telegram, Slack, etc.)
- [ ] Per-IP alert cooldown (current cooldown is global, not per-IP)
- [ ] Curl availability check at startup (log warning if `curl` not found)

### Ideas (no promises)
- [ ] GeoIP/ASN lookup for source IPs
- [ ] Forwarding events to external logging systems
- [ ] Package distribution (.deb, .rpm)
- [ ] IPv6 network context from `/proc/net/tcp6`
- [ ] Configurable event filter (choose which events trigger alerts)
- [ ] Message templates (customizable alert format)
