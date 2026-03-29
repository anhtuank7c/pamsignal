# Changelog

## Unreleased

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
