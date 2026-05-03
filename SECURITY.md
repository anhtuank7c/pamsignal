# Security Policy

PAMSignal is a security-monitoring daemon. A vulnerability in the daemon itself — bypass of the brute-force tracker, alert spoofing, log injection, privilege escalation, memory corruption — is treated as a high-priority defect. This document describes how to report one privately and what to expect once you do.

## Reporting a Vulnerability

**Please do not file a public GitHub issue for security reports.** Public reports give an adversary a head start before a fix ships.

Use one of the private channels below:

1. **Preferred — GitHub Security Advisories.** Open a private advisory on the repository:
   <https://github.com/anhtuank7c/pamsignal/security/advisories/new>
   This thread stays private until both reporter and maintainer agree to publish, and CVE assignment can be requested through the same UI.

2. **Email fallback** if the GitHub UI is not available to you:
   `anhtuank7c@hotmail.com` with subject prefix `[pamsignal-security]`.
   PGP encryption is not currently required, but if you have it the maintainer's signing key fingerprint is `2D2C 828F A6F4 D019 E446  8FBB B106 2235 2862 2F69` (the same key the apt + dnf release packages are signed with).

When reporting, please include:

- The pamsignal version (`pamsignal --version` once available, otherwise the package version from `apt show pamsignal` / `dnf info pamsignal`).
- Whether you reproduced from a published `.deb`/`.rpm` or a `meson install` source build.
- The minimal sequence of journal events / configuration that triggers the issue, ideally as a unit-test reproducer or a `journalctl --output=export` excerpt.
- Your assessment of severity and any exploitation prerequisites (local user, particular configuration, specific distribution, etc.).

## Disclosure Timeline

- **Acknowledgment**: within 5 business days of receipt.
- **Triage and severity assessment**: within 14 days. The maintainer will share the assessment and proposed remediation timeline back to the reporter.
- **Coordinated disclosure**: standard window is **90 days** from acknowledgment to public disclosure. The maintainer will request an extension (with justification) for issues that require an upstream coordinated fix or a non-trivial migration; reporters are welcome to refuse and proceed with their own disclosure timeline.
- **Public advisory**: published as a GitHub Security Advisory + entry in `CHANGELOG.md` under the relevant release. Reporters are credited unless they request anonymity.

## Supported Versions

Only the most recent **minor** release line receives security fixes. Patch releases for older minors are case-by-case and only when the fix is one-line obvious — anyone running the project should expect to upgrade to the latest minor for security work.

| Version | Supported |
|---------|-----------|
| `0.3.x` | ✅ |
| `0.2.x` | ❌ (use `0.3.x`) |
| `0.1.x` | ❌ |

The recommended install path is the signed apt or dnf repository documented in [`README.md`](./README.md#1-install); `apt upgrade` / `dnf upgrade` keeps you on the supported line automatically.

## Scope

**In scope** (please report):

- Memory-safety bugs in `src/` (buffer overflows, use-after-free, double-free, integer overflow, format-string flaws).
- Logic bugs in `src/utils.c` `ps_parse_message` that allow a low-priv local user to spoof a PAM event under another user's identity (e.g. by crafting a `logger` invocation that bypasses the `_EXE` allowlist).
- Brute-force tracker bypasses — any sequence of failed-auth events that does not increment the per-key counter, does not trigger the threshold alert, or causes the cooldown to be skipped.
- Alert-payload injection — any input that escapes JSON quoting in the webhook body, leaks credentials into argv (`/proc/<pid>/cmdline`), or rewrites the URL passed to `curl`.
- Privilege-escalation paths — anything that lets the `pamsignal` system user obtain capabilities beyond its journal-read membership.
- Bypasses of the systemd unit hardening (e.g. `MemoryDenyWriteExecute=`, `SystemCallFilter=`, `CapabilityBoundingSet=`).

**Out of scope** (these belong elsewhere):

- Vulnerabilities in `curl(1)`, `libsystemd`, `systemd-journald`, or any other dependency. Report those upstream.
- Vulnerabilities in alert delivery channels (Telegram Bot API, Slack webhooks, Microsoft Teams connectors, WhatsApp Cloud API, Discord webhooks, your own custom webhook receiver). These are operated by their respective providers; pamsignal only emits HTTPS POSTs.
- Issues that require an attacker who is already root on the monitored host. pamsignal does not defend against an adversary who can already issue arbitrary system calls.
- Configuration mistakes by the operator (e.g. world-readable `pamsignal.conf` containing alert credentials). Improving defaults to make these mistakes harder is welcome as a regular feature request, not a security report.
- Denial of service via a flood of legitimate auth events. The brute-force tracker's per-key cooldown bounds alert volume; tuning it for an unusual workload is a configuration concern.

## Hardening Already Shipped

Reviewing the existing defenses before reporting saves time on both sides:

- `_EXE` allowlist on every journal entry (`src/journal_watch.c`): only entries whose recorded executable path resolves to `sshd`, `sudo`, `su`, `login`, or `systemd-logind` under a system prefix are processed. Spoofed events from `logger(1)` are silently dropped.
- Compiler hardening (`meson.build`): `-fstack-protector-strong`, `_FORTIFY_SOURCE=3`, `-fcf-protection=full`, `-fstack-clash-protection`, full RELRO, PIE, separate-code, no-exec-stack.
- Alert dispatch isolation: `fork()` + `execv()` of an absolute-path `/usr/bin/curl` with `clearenv()`'d environment. Webhook URLs and bearer tokens are written to a `memfd_create()`-backed `--config` file passed via `/dev/fd/9`; they never appear in argv.
- systemd unit hardening: `NoNewPrivileges`, `ProtectSystem=strict`, `MemoryDenyWriteExecute`, `RestrictNamespaces`, `SystemCallFilter=@system-service ~@privileged @resources`, `CapabilityBoundingSet=` (empty). Verifiable with `systemd-analyze security pamsignal.service`.
- Continuous fuzzing: `tests/fuzz_parse_message.c` is an opt-in libFuzzer harness for `ps_parse_message`. Run with `meson setup -Dfuzz=enabled build-fuzz` (requires clang).

If your finding is a refinement on top of one of these — e.g. a parser case the fuzz corpus didn't cover, or a syscall-filter gap — please call that out in the report so the fix can land alongside a regression test.
