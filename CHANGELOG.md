# Changelog

## Unreleased

### Packaging
- [x] **meson installs the systemd unit to the vendor path natively**: `pamsignal.service.in` is now a template; `configure_file` substitutes `@sbindir@` at configure time and installs to the dir reported by `pkg-config --variable=systemdsystemunitdir systemd` (with a `<prefix>/lib/systemd/system` fallback). Both `debian/rules` and `pamsignal.spec` drop the post-install `mv` (out of `/etc/systemd/system`) and `sed` (`/usr/local/bin` → `/usr/bin`) workarounds — the artifact is correct straight out of `meson install`.
- [x] **RPM `%pre` creates the group explicitly before the user**: `groupadd -r pamsignal` runs before `useradd -r -g pamsignal …` so `Provides: group(pamsignal)` is honored even on hosts where `USERGROUPS_ENAB` is unset and `useradd` would otherwise skip auto-creating the matching group.
- [x] **`PS_DEFAULT_CONFIG_PATH` is now derived from `sysconfdir` at configure time**: a new `include/paths.h.in` template is generated into the build dir via `configure_file`, substituting `@sysconfdir@` from `get_option('prefix') / get_option('sysconfdir')`. Packaged builds (`--sysconfdir=/etc`) still embed `/etc/pamsignal/pamsignal.conf`; a dev `meson install` with the default `--prefix=/usr/local` now correctly embeds `/usr/local/etc/pamsignal/pamsignal.conf` so the daemon finds its conf without an explicit `--config` flag.
- [x] **Daemon binary moved from `bindir` to `sbindir`** (FHS §4.10: system administration daemons belong in `sbin`, not `bin`). Packaged builds now install to `/usr/sbin/pamsignal` (was `/usr/bin/pamsignal`); dev installs land at `/usr/local/sbin/pamsignal` (was `/usr/local/bin/pamsignal`). The systemd unit's `ExecStart` is updated automatically by the `configure_file` substitution. The `pamsignal` command name is unchanged — `/usr/sbin` is in root's `PATH` on every supported distro, and ordinary users invoke the daemon only via `systemctl`. RPM `%files` switches to `%{_sbindir}/pamsignal`. Upgrade behavior: on the deb/rpm transition, the package manager removes the old `/usr/bin/pamsignal` file and installs the new one at `/usr/sbin/pamsignal`; `systemctl daemon-reload` is auto-fired and the unit's new ExecStart points at the new path. Anyone scripting against the absolute `/usr/bin/pamsignal` path needs to update to `/usr/sbin/pamsignal`.

### Documentation
- [x] **`pamsignal(8)` man page added.** New `pamsignal.8.in` template covers SYNOPSIS, OPTIONS (`-f`/`--foreground`, `-c`/`--config PATH`), SIGNALS (`SIGHUP`/`SIGTERM`/`SIGINT` semantics), FILES (`/etc/pamsignal/pamsignal.conf`, `/run/pamsignal/pamsignal.pid`, vendor unit path), structured-journal output (ECS field reference + sample `journalctl` queries), EXIT STATUS, SECURITY (system user, memfd-backed curl `--config`, `--proto =https`, `_EXE` allowlist, per-IP cooldown), SEE ALSO, BUGS, AUTHOR. The `.TH` version is filled by `configure_file` from `meson.project_version()` so it tracks the release. Installed to `<prefix>/share/man/man8/`; debhelper auto-compresses on deb, brp-compress on rpm. The RPM `%files` glob `%{_mandir}/man8/pamsignal.8*` accepts either compressed or uncompressed.

### Security
- [x] **Closed the two clang-analyzer taint-source warnings the lint pass had been carrying.** `src/config.c` `trim()` no longer calls `isspace()` — a locale-independent `is_ws()` classifier replaces it, eliminating the `clang-analyzer-security.ArrayBound` finding (tainted index reaching `__ctype_b_loc()`'s table) and making config parsing deterministic across `LC_CTYPE`. `src/main.c` `has_journal_access()` no longer does `malloc(getgroups(0, NULL) * sizeof(gid_t))` — it uses a 256-entry stack buffer with `getgroups(256, buf)`, dropping `clang-analyzer-optin.taint.TaintedAlloc` and removing a heap allocation. A user with >256 supplementary groups (NGROUPS_MAX is 65536 in theory but real users have <32) gets `EINVAL` and the daemon fails closed with the existing "add user to systemd-journal" error path. `src/journal_watch.c` `ps_fail_table_init()` adds an explicit `if (copy_count < 0) copy_count = 0;` floor — the runtime invariant already held, but the floor lets the analyzer prove `fail_table_count ∈ [0, capacity]` across reinit cycles, closing a transitive `ArrayBound` finding surfaced by `tests/test_journal_watch.c`. New `tests/test_config.c::test_config_load_whitespace_all_kinds` covers `\t`/`\r`/`\v`/`\f` to lock in `is_ws()`'s coverage of the C-locale `isspace` set.

## 0.2.4 — 2026-05-03

Feature release adding server context configurations.

### Features
- [x] **Server Context Tags**: Added `provider` and `service_name` configuration fields to `pamsignal.conf`. When configured, these tags are automatically included in alert payloads to help administrators identify the environment generating the alert.
- [x] **Text Alerts**: Context tags are appended to the end of text-based alerts (e.g. Telegram, Slack, WhatsApp).
- [x] **JSON Webhooks**: Context tags are injected natively into the root of the ECS JSON payload under the `labels` dictionary.

## 0.2.3 — 2026-05-02

Security and bugfix release.

### Security
- [x] **Log Spoofing Prevention**: Added strict `_EXE` journal field verification. Unprivileged users can no longer inject fake PAM events via `logger` to trigger false alerts or brute-force lockouts. Only trusted system binaries (`sshd`, `sudo`, `su`, `login`, `systemd-logind`) are processed.

### Fixes
- [x] **Brute-force cooldown bug**: Fixed an issue where evicting an old IP from a full tracking table failed to zero the `last_brute_alert_usec` timestamp, causing the new IP to incorrectly inherit the evicted IP's alert cooldown.
- [x] **State loss on reload**: Sending `SIGHUP` to reload the configuration no longer destroys the active brute-force tracking table. Existing IP tracking state is now preserved seamlessly across reloads.

## 0.2.0 — 2026-04-30

**Breaking change**: alert payload format moves to [Elastic Common Schema (ECS)] for both chat text and webhook JSON. Anyone parsing the previous pipe-delimited text or the flat `{"event":..., "username":...}` JSON needs to update their consumers — see `docs/alerts.md` for the new schema and a Vector example for non-ECS SIEMs.

[Elastic Common Schema (ECS)]: https://www.elastic.co/guide/en/ecs/current/index.html

### Logging format
- [x] **Chat text** (Telegram / Slack / Teams / WhatsApp / Discord) is now severity-prefixed key=value: `[NOTICE] auth.login_success user=admin src=192.168.1.100:52341 host=ubuntu service=sshd auth=password pid=12345 ts=2026-04-30T10:00:00+0700`. Severity bracket is fixed-width (8 chars) so columns align in monospace; field order is severity → action → identity → location → metadata → `pid` → `ts`.
- [x] **`pid=` field added** to every chat alert. For `session_opened` / `login_success` events the PID is the live sshd session — copy/paste into `kill <pid>` to disconnect a user immediately. For failures and brute-force the PID is the failing-auth child (already reaped, kept for forensic context).
- [x] **JSON webhook payload** is now ECS-conformant: `@timestamp` at top level; nested `event.{action,category,kind,outcome,severity,module,dataset}`, `host.hostname`, `user.name`, `service.name`, `source.{ip,port}`, `process.{pid,user.id}`. Vendor-specific fields (`event_type`, `auth_method`, `attempts`, `window_sec`) live under the `pamsignal.*` namespace per ECS guidance.
- [x] **systemd-journal structured fields** add ECS-aligned `EVENT_ACTION`, `EVENT_CATEGORY`, `EVENT_KIND`, `EVENT_OUTCOME`, `EVENT_SEVERITY`, `EVENT_MODULE`, `USER_NAME`, `SOURCE_IP`, `SOURCE_PORT`, `HOST_HOSTNAME`, `SERVICE_NAME`, `PROCESS_PID` alongside the existing `PAMSIGNAL_*` fields. The legacy `PAMSIGNAL_*` fields stay through v0.2.x for backward-compat with any existing `journalctl` queries; they retire in v0.3.0.

### Event taxonomy
- [x] `event.action` values are past-tense lowercase per ECS: `session_opened`, `session_closed`, `login_success`, `login_failure`, `brute_force_detected`. Legacy uppercase enum (`SESSION_OPEN`, `LOGIN_FAILED`, etc.) survives as `pamsignal.event_type` for one minor release.
- [x] `event.severity` mapped to a syslog-aligned numeric scale: 3=info (sessions), 4=notice (login_success), 5=warning (login_failure), 8=alert (brute_force_detected).
- [x] `event.kind=alert` only for brute-force detections (per ECS recommendation that "alert" indicates security findings, not generic events). Everything else is `event.kind=event`.

### API
- [x] `ps_notify_brute_force` signature gains a `pid_t last_pid` parameter. Updated call site in `journal_watch.c` to pass `event->pid` from the threshold-breaching attempt.
- [x] New ECS helper functions in `utils.h`: `ps_event_action_str`, `ps_event_category_str`, `ps_event_kind_str`, `ps_event_outcome_str`, `ps_event_severity_num`, `ps_event_severity_label`. All total functions, all covered by `test_utils`.

### Tests
- [x] `test_utils` grows to 36 tests (added 6 ECS-helper assertions).
- [x] `test_notify` updated for the new `ps_notify_brute_force` signature.

### Documentation
- [x] `docs/alerts.md` rewritten end-to-end: new chat text examples, full ECS JSON examples for login / session / brute-force events, an updated field-reference table mapping ECS paths to their meanings, a SIEM compatibility table (Elastic / Wazuh / Splunk / Sentinel / Datadog / Sumo / Graylog / ArcSight / QRadar), and a Vector config showing pamsignal → ingest → SIEM as the conventional production architecture.

## 0.1.0 — 2026-04-29

First tagged release. Headlined by a six-phase OWASP 2025 / data-integrity /
memory-safety audit that closed every Critical, High, Medium, Low, and Info
finding the audit identified, plus continuous-fuzzing infrastructure for the
PAM message parser.

Highlights:

- **Alert dispatch** — secrets (Telegram bot token, WhatsApp Bearer, webhook
  URLs) no longer appear in `/proc/<pid>/cmdline`; they're written to a
  `memfd_create()`-backed curl config passed via `-K /dev/fd/N`. `execv` on
  an absolute path with `clearenv()` and a minimal `PATH` defeats `$PATH`
  injection. `--proto =https` is forced on every invocation.
- **Config validation** — per-field allowlists for tokens and webhook URLs;
  config files opened with `O_NOFOLLOW|O_CLOEXEC` and `fstat`-checked for
  ownership / mode (rejects group-writable, world-writable, and symlinks).
- **PID file & signals** — `openat`-based pidfile under an `O_DIRECTORY|
  O_NOFOLLOW` directory fd; stale pidfile only removed after `kill(pid, 0)`
  confirms `ESRCH`. `volatile sig_atomic_t` flags, `SA_RESTART`,
  `SIGPIPE = SIG_IGN`, and `sigprocmask`-blocked SIGHUP reload.
- **Privilege defenses** — `prctl(PR_SET_NO_NEW_PRIVS)` and
  `setrlimit(RLIMIT_NPROC, 64)` cap the daemon's blast radius even outside
  the systemd sandbox.
- **Brute-force tracking** — per-source-IP cooldown (was global), so a
  flood of login events can no longer mute brute-force alerts.
- **Build hardening** — `_FORTIFY_SOURCE=3`, `-fstack-clash-protection`,
  `-fcf-protection=full`, `-Wl,-z,separate-code`; gated through
  `cc.get_supported_arguments` so older toolchains still build.
- **Tests** — 78 CMocka tests across four suites covering parser, config
  validators, dispatch path, and brute-force tracker; opt-in libFuzzer
  harness for `ps_parse_message` (clang only, sanitizer-instrumented).

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

### Packaging
- [x] `debian/` — full Debian/Ubuntu packaging (control, changelog, copyright, rules, source/format, postinst/prerm/postrm). Build with `dpkg-buildpackage -us -uc -b`. Maintainer scripts create the `pamsignal` system user, add it to `systemd-journal`, and chmod the config to `root:pamsignal 0640`.
- [x] `pamsignal.spec` — Fedora/CentOS/AlmaLinux/Rocky Linux RPM spec. Build with `rpmbuild -ba pamsignal.spec`. `%pre` creates the system user via `useradd -r`; `%post` enforces config-file permissions; `%config(noreplace)` preserves admin edits across upgrades.
- Both formats fix the two known `meson.build` issues in the install step: relocate the systemd unit from `/etc/systemd/system/` to the vendor path (`/usr/lib/systemd/system/` for deb, `%{_unitdir}` for rpm), and patch `ExecStart=/usr/local/bin/pamsignal` → `/usr/bin/pamsignal` (or `%{_bindir}` for rpm).

### CI
- [x] `.github/workflows/release-packages.yml` — builds `.deb` (Ubuntu 24.04) and `.rpm` (Fedora container) automatically when a GitHub release is published. apt and dnf caches reuse downloaded packages across runs, keyed on the build-deps hash. Both jobs upload workflow artifacts (90-day retention) and attach the binaries to the triggering release. Manual runs via `workflow_dispatch` accept a `ref` input plus an `attach_to_release` flag for backfilling existing releases.

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
- [x] `test_e2e.sh` — pre-flight checks the `pamsignal` user exists, creates `/run/pamsignal/` (replicates systemd's `RuntimeDirectory=` for non-systemd runs), and points failures at `journalctl -t pamsignal` for diagnosis

### Documentation
- [x] Architecture — C4 model (context, container, component), alert isolation diagram
- [x] Configuration reference — all config keys, CLI flags, reload behavior
- [x] Alert guide — channel setup, message formats, webhook JSON payload reference
- [x] Development guide — build, test environment, e2e testing
- [x] Deployment guide — systemd service, production setup, security hardening table

## 0.2.2 — 2026-05-02

Republish-only release. No source code or packaging logic changes; the `.deb` and `.rpm` binaries are bit-for-bit equivalent to v0.2.1 modulo their version stamp.

### Distribution
- [x] Custom domain removed from the `gh-pages` site. The package repository is now served exclusively at the canonical GitHub Pages URL: `https://anhtuank7c.github.io/pamsignal/`. The README, the `release-packages.yml` `BASE` derivation (`https://${OWNER}.github.io/${REPO}`), and the generated `index.html` / `pamsignal.repo` files were already pointed at the github.io origin, so no in-tree change was required — this release exists to retrigger `publish-repo`, which regenerates `dists/stable/InRelease`, `repomd.xml.asc`, and the per-variant `pamsignal.repo` files on the github.io origin and overwrites any cached references to the prior custom domain.
- [x] Signing key fingerprint unchanged: `2D2C 828F A6F4 D019 E446 8FBB B106 2235 2862 2F69`. Existing users do not need to re-import the key — only the repository URL changes (and only for users who had configured the custom domain manually; users following the README's `apt`/`dnf` instructions were already on the github.io URL).

## 0.2.1 — 2026-04-30

Packaging-only release. Binary is identical to v0.2.0; this release adds signed apt + dnf repositories on GitHub Pages and the small spec fix that lets dnf 5 (Fedora 44) install the `.rpm` cleanly.

### Distribution
- [x] Signed apt + dnf repositories published to GitHub Pages on every release. Users install with the standard one-liner via `apt install` (Debian/Ubuntu) or `dnf install` (Fedora / RHEL 9 / Alma 9 / Rocky 9). The repository's `Release` / `InRelease` (apt) and `repomd.xml.asc` (dnf) are signed by the project release key, so transport-layer integrity is enforced even if a mirror is compromised.
- [x] Each `.deb`, `.ddeb`, `.rpm` artifact gets a detached armored `.asc` signature attached to the GitHub release, for users who download directly from the release page rather than via the apt/dnf repos. RPM packages also carry an embedded signature (`rpm --addsign`) so `dnf install` validates the package contents before running scriptlets.
- [x] Public signing key committed at `docs/signing-key.asc` and served at `https://anhtuank7c.github.io/pamsignal/key.asc`. Fingerprint: `2D2C 828F A6F4 D019 E446 8FBB B106 2235 2862 2F69`.
- [x] One-time `bootstrap-signing-key.yml` workflow generates the GPG key inside CI without it ever touching the maintainer's machine. The bootstrap workflow auto-deletes its output artifact after 24h.

### Spec
- [x] `pamsignal.spec` declares `Provides: user(pamsignal)` and `Provides: group(pamsignal)` so dnf 5's transaction resolver accepts the auto-generated `Requires: group(pamsignal)` (which RPM derives from the `%attr(...,pamsignal)` entries in `%files`) before the `%pre` scriptlet that creates the user/group runs.

## Unreleased

(no changes yet)

### CI
- [x] `build-rpm` workflow job converted to a matrix: builds for **Fedora** (`fedora:latest` container, produces `*.fc<N>.rpm`) AND **EL9** (`almalinux:9` container with EPEL + CRB enabled, produces `*.el9.rpm`). The EL9 RPM installs cleanly on AlmaLinux 9, Rocky Linux 9, and RHEL 9 — all three are bit-compatible at the `.el9` dist tag, so a single build covers them.
- [x] `test-deb` workflow job runs after `build-deb` and exercises the full daemon end-to-end on `ubuntu-24.04`: installs the `.deb`, generates a self-signed cert and adds it to the system trust store (so pamsignal's `--proto =https` curl child can validate without `--insecure`), starts a Python HTTPS mock webhook, configures pamsignal to point at it, injects synthetic sshd events via `logger -t sshd "Failed password for ..."`, then asserts the received ECS payloads have the expected `event.action`, `event.severity`, `event.kind`, `source.ip`, `source.port`, `user.name`, etc. Triggers brute-force detection (threshold=3), verifies SIGHUP reload, then `apt purge` and confirms cleanup.
- [x] `test-rpm` workflow job runs after `build-rpm` per matrix entry: installs the matching `.fc44.rpm` / `.el9.rpm` in the corresponding container, verifies the file layout (`/usr/bin/pamsignal`, `/usr/lib/systemd/system/pamsignal.service` with patched `ExecStart`, `/etc/pamsignal/pamsignal.conf` with correct ownership and `0640` perms), confirms the system user was created by `%pre`, smoke-launches the binary, then `dnf remove` and verifies cleanup.

### Notes
- Alpine Linux is **not supported** and won't be added without significant restructuring: pamsignal's only input source is `sd-journal` (libsystemd), and Alpine ships OpenRC instead of systemd. There's no `journald` to read from. A future major version could add a `/var/log/auth.log` tail-mode for non-systemd hosts; until then Alpine deployments would need to run pamsignal in a sidecar container with systemd, monitoring the host's auth events via a shared journal.

## To Do

### Next Up
- [ ] Curl availability check at startup (log warning if `curl` not found)
- [ ] Sign and publish .deb / .rpm to a hosted repository (Launchpad PPA, COPR)

### Ideas (no promises)
- [ ] GeoIP/ASN lookup for source IPs
- [ ] Forwarding events to external logging systems
- [ ] IPv6 network context from `/proc/net/tcp6`
- [ ] Configurable event filter (choose which events trigger alerts)
- [ ] Message templates (customizable alert format)
