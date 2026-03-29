# CLAUDE.md

## Project Overview

PAMSignal is a lightweight C daemon that monitors PAM authentication events via the systemd journal. It detects login attempts, logouts, and brute-force patterns from sshd, sudo, su, and login services, optionally sending alerts to Telegram, Slack, Teams, WhatsApp, Discord, or custom webhooks.

Target: Linux servers with systemd. Single binary, single config file, single dependency (libsystemd).

## Build

```bash
meson setup build
meson compile -C build
```

Clean rebuild: `rm -rf build && meson setup build && meson compile -C build`

## Test

No unit test framework. Testing is manual via the e2e script and journal inspection:

```bash
# Run in foreground for testing
sudo -u pamsignal ./build/pamsignal --foreground

# Watch journal output
journalctl -t pamsignal -f

# See structured fields
journalctl -t pamsignal -o json-pretty -n 5
```

## Project Structure

- `src/` — 6 C modules: main, config, init, journal_watch, notify, utils
- `include/` — corresponding headers
- `docs/` — architecture, configuration, alerts, development, deployment guides
- `meson.build` — build configuration
- `pamsignal.service` — systemd unit file
- `pamsignal.conf.example` — config template

## Code Conventions

- **Language:** C (gnu17 standard)
- **Indentation:** 4 spaces
- **Functions:** snake_case with `ps_` prefix (e.g., `ps_journal_watch_init()`)
- **Globals:** `g_` prefix (e.g., `g_config`)
- **Constants/Macros:** UPPER_SNAKE_CASE with `PS_` prefix (e.g., `PS_DEFAULT_FAIL_THRESHOLD`)
- **Types:** `_t` suffix for structs and enums (e.g., `ps_pam_event_t`, `ps_event_type_t`)
- **Error handling:** Return code enums (`PS_OK`, `PS_ERR_*`), early returns
- **Logging:** `sd_journal_print()` / `sd_journal_send()` — not printf/syslog

## Security Requirements

This is a security monitoring tool. All code changes must maintain:

- Input validation: bounded buffers, `inet_pton` for IPs, `sanitize_string()` for log injection
- No fixed-size string assumptions without explicit length checks
- JSON escaping for alert payloads
- File operations: `O_NOFOLLOW | O_EXCL` for PID file, explicit umask
- Compiler hardening flags must remain in meson.build (`-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`, full RELRO, PIE)
- Alert dispatch stays isolated via fork+exec — no network code in parent process

## Pre-Commit Workflow

Before every commit, complete these checks in order:

1. **Format code** — run `clang-format -i src/*.c include/*.h` (config in `.clang-format`)
2. **Lint** — run `clang-tidy src/*.c -- $(pkg-config --cflags libsystemd) -I include` (config in `.clang-tidy`). Fix all warnings.
3. **Build** — run `meson compile -C build` and confirm zero errors and zero warnings
4. **OWASP security review** — use the `/owasp-review` skill to audit changed files for vulnerabilities, memory leaks, buffer overflows, use-after-free, and other C-specific issues. Fix all findings before committing.

Install tools if missing: `sudo apt-get install clang-format clang-tidy`

## Commit Message Convention

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>: <short summary in imperative mood>
```

Types:
- `feat:` — new feature or capability
- `fix:` — bug fix
- `security:` — security hardening or vulnerability fix
- `refactor:` — code restructuring with no behavior change
- `docs:` — documentation only
- `chore:` — build system, CI, tooling, dependencies
- `test:` — adding or updating tests
- `perf:` — performance improvement

Rules:
- Subject line under 72 characters
- Imperative mood ("add", "fix", "update" — not "added", "fixes", "updated")
- No period at the end of the subject line
- Body (optional) explains **why**, not what

## Dependencies

- `libsystemd-dev` (only C library dependency)
- `curl` (runtime, for alert dispatch via fork+exec)
- `meson` + `ninja-build` (build time)

## Key Design Decisions

- Alerts are fire-and-forget via fork+exec curl — child process failures cannot crash the daemon
- SIGHUP reloads config into a temp struct first, swaps on success, keeps current on failure
- Signal-safe flags use `atomic_bool` (`running`, `reload_requested`)
- Runs as unprivileged `pamsignal` user, not root
