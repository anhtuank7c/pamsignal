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

Two axes:

**Release line.** Only the most recent **minor** release line receives security fixes. Patch releases for older minors are case-by-case and only when the fix is one-line obvious — anyone running the project should expect to upgrade to the latest minor for security work.

| Version | Supported |
|---------|-----------|
| `0.3.x` | ✅ |
| `0.2.x` | ❌ (use `0.3.x`) |
| `0.1.x` | ❌ |

The recommended install path is the signed apt or dnf repository documented in [`README.md`](./README.md#1-install); `apt upgrade` / `dnf upgrade` keeps you on the supported line automatically.

**Operating system / distribution.** Pamsignal supports modern systemd-native Linux only. The full distribution matrix — CI-tested distributions, expected-to-work distributions with their per-row caveats, and explicit unsupported releases with the technical reason for each cutoff — lives in [`docs/distros.md`](./docs/distros.md). A vulnerability report against a Tier 3 distribution will be closed with a pointer to that document; vulnerabilities affecting Tier 1 or Tier 2 distributions are in scope for security review per this policy.

## Scope

The full in-scope / out-of-scope breakdown — including adversary capabilities the daemon assumes, the trust boundaries inside the codebase, and the design choices that produce the current security posture — lives in [`docs/threat-model.md`](./docs/threat-model.md). Read that before reporting; in particular, the "Out of scope" section there is comprehensive about the non-goals (compromised journald / libsystemd / curl, root-already-on-host, alert-provider compromise, multi-host correlation, durable alert delivery, admin misconfiguration).

The summary, sufficient for most reports:

**In scope.** Memory-safety bugs in `src/`; logic bugs in `ps_parse_message` that bypass the `_EXE` allowlist; brute-force tracker bypasses; alert-payload injection (JSON-escape escapes, credential leakage into argv, URL hijack of the `curl` child); privilege-escalation paths from the `pamsignal` user; bypasses of the systemd unit hardening directives.

**Out of scope.** Vulnerabilities in `curl`, `libsystemd`, journald, or any alert-channel provider; threat models requiring root on the monitored host; admin misconfiguration; alert-channel rate limits / DoS via legitimate event floods.

## Hardening Already Shipped

Reviewing the existing defenses before reporting saves time on both sides:

- `_EXE` allowlist on every journal entry (`src/journal_watch.c`): only entries whose recorded executable path resolves to `sshd`, `sudo`, `su`, `login`, or `systemd-logind` under a system prefix are processed. Spoofed events from `logger(1)` are silently dropped.
- Compiler hardening (`meson.build`): `-fstack-protector-strong`, `_FORTIFY_SOURCE=3`, `-fcf-protection=full`, `-fstack-clash-protection`, full RELRO, PIE, separate-code, no-exec-stack.
- Alert dispatch isolation: `fork()` + `execv()` of an absolute-path `/usr/bin/curl` with `clearenv()`'d environment. Webhook URLs and bearer tokens are written to a `memfd_create()`-backed `--config` file passed via `/dev/fd/9`; they never appear in argv.
- systemd unit hardening: `NoNewPrivileges`, `ProtectSystem=strict`, `MemoryDenyWriteExecute`, `RestrictNamespaces`, `SystemCallFilter=@system-service ~@privileged @resources`, `CapabilityBoundingSet=` (empty). Verifiable with `systemd-analyze security pamsignal.service`.
- Continuous fuzzing: `tests/fuzz_parse_message.c` is an opt-in libFuzzer harness for `ps_parse_message`. Run with `meson setup -Dfuzz=enabled build-fuzz` (requires clang).

If your finding is a refinement on top of one of these — e.g. a parser case the fuzz corpus didn't cover, or a syscall-filter gap — please call that out in the report so the fix can land alongside a regression test.
