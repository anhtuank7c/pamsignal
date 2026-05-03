# Threat Model

This document describes what PAMSignal defends against, what it deliberately does not, and the design choices that produce that posture. It is the reference for evaluating future contributions: a change that strengthens an in-scope mitigation is welcome; a change that pulls work into the daemon from an out-of-scope area is not, even if it would be technically possible.

For private vulnerability reporting, see [`SECURITY.md`](../SECURITY.md). The two documents are complementary — `SECURITY.md` is operator-facing (how to report, what versions are supported); this document is contributor-facing (what the daemon's responsibilities are and what they aren't).

## Purpose

PAMSignal observes PAM authentication events on a single host via the systemd journal and, when configured patterns occur (failed logins, brute-force thresholds), dispatches alerts over HTTPS to operator-chosen channels. The daemon's job is to be a **trustworthy detection signal** for the operator. Every defense in this document exists to preserve that property — that the alert the operator receives accurately reflects what happened on the host.

## Assets

In priority order:

1. **The integrity and timeliness of alerts.** If an attacker can suppress, delay, spoof, or flood alerts, PAMSignal's value to the operator collapses. This is the single most important asset.
2. **Alert credentials.** Telegram bot tokens, Slack/Teams/Discord/custom-webhook URLs and bearer tokens, stored in `/etc/pamsignal/pamsignal.conf` with mode `0640 root:pamsignal`. Disclosure lets an attacker spoof alerts (impersonating PAMSignal to the operator) and exhaust per-channel rate limits.
3. **The `pamsignal` system user's privilege envelope.** Read-only journal access; no capabilities, no namespace creation, no kernel-module load, no SUID transitions, no writable executable memory. A compromise that escapes this envelope is a host compromise.
4. **The structured journal entries PAMSignal writes** (`SYSLOG_IDENTIFIER=pamsignal`). These feed downstream SIEM ingestion. Entries must reflect actual observed state, not attacker-controlled content.

The host's *own* journal, `/etc/passwd`, kernel state, and so on are explicitly **not** PAMSignal's assets to defend — they belong to journald, the kernel, and the operator's broader hardening posture.

## Adversaries

The threat model assumes the following adversary capabilities. A change is in-scope if it strengthens our defenses against the named adversaries; out-of-scope if it relies on assumptions outside this list.

### A. External remote attacker (no host access)

Capabilities: send arbitrary network traffic, observe responses, run automated scanners against the host's exposed services. Cannot run code on the host. The most common attacker class — SSH brute-force scanners, automated credential-stuffing.

What they can do that PAMSignal cares about:
- Generate authentic-looking sshd journal entries (real failed-password events) at high rate.
- Try to overwhelm the brute-force tracker (table eviction, cooldown bypass, time-window manipulation by sending events with crafted timing).
- DoS the alert path indirectly by generating enough alert-worthy events to exhaust the operator's chat channel rate limit.

### B. Local unprivileged user (shell on the host, non-root, not in `pamsignal` group)

Capabilities: any syscall a non-root user can make on a sandbox-free Linux host. Specifically: `logger(1)`, write to `/dev/log`, read `/proc/<any>/cmdline`, read journal entries that the `systemd-journal` group can read (often just their own user's), connect to local sockets they're allowed to.

What they can do that PAMSignal cares about:
- Inject fake auth-related lines via `logger(1)` — `logger -t sshd "Failed password for root from ..."` — hoping PAMSignal will treat them as real sshd events.
- Trigger their own real auth failures (`sudo` with wrong password) to generate alerts.
- Read `/proc/<pamsignal-pid>/cmdline` looking for credentials in startup args.
- Read `/proc/<pamsignal-pid>/environ` looking for environment-leaked credentials.

### C. Local user *in* the `pamsignal` group (deliberate operator choice)

Capabilities: B + read `/etc/pamsignal/pamsignal.conf` (mode `0640 root:pamsignal`). This is by design — the daemon needs read access too. An operator who adds a non-system user to the `pamsignal` group is making a deliberate trust decision and PAMSignal does not pretend to defend against that user.

### D. Compromised `pamsignal` daemon (e.g. parser RCE)

Capabilities: arbitrary code execution at the daemon's privilege envelope — `pamsignal` user, no caps, the systemd unit's `SystemCallFilter` allowlist, `MemoryDenyWriteExecute=yes`, `ProtectSystem=strict`. From here, full host compromise requires another local privilege escalation (a separate kernel CVE, a sudo misconfiguration, a writable-by-pamsignal binary somewhere in PATH).

What they can do that PAMSignal cares about:
- Read alert credentials from `/etc/pamsignal/pamsignal.conf`.
- Spoof outbound alerts to the configured channels.
- Suppress real alerts by returning early from the alert dispatch path.
- Attempt sandbox escape via residual syscalls left allowed by `SystemCallFilter`.

### E. Network attacker on the alert path

Capabilities: drop, delay, replay, or attempt to MITM the HTTPS request from the daemon to the configured alert provider.

What they can do that PAMSignal cares about:
- Drop the alert (operator never sees the event).
- MITM if TLS is broken/downgraded/unverified.
- Cannot decrypt or forge a TLS-protected request to a properly configured webhook.

## In-scope: attacks the daemon defends against

Each item names the attack, the adversary class from above, the mitigation, and the source location. A regression in any of these is a security defect and falls under [`SECURITY.md`](../SECURITY.md).

### 1. Log injection via `logger(1)` (B)

**Attack.** A local unprivileged user runs `logger -t sshd "Failed password for root from 1.2.3.4 port 22 ssh2"` to forge a journal entry that looks like a real sshd auth failure. Without filtering, PAMSignal would alert on it and the brute-force tracker would count it.

**Mitigation.** The `_EXE` allowlist in `src/journal_watch.c:345-381`. Every journal entry's recorded `_EXE` field (set by journald itself based on the actually-execve'd binary) must resolve to `sshd`, `sudo`, `su`, `login`, or `systemd-logind` under a system prefix (`/usr/`, `/bin/`, `/sbin/`, `/lib/`, `/lib64/`, `/opt/`). Entries with no `_EXE` (synthetic injections from `/dev/log`) are dropped. `logger`'s `_EXE` is `/usr/bin/logger` — not on the allowlist, so the entry is silently dropped.

### 2. Brute-force tracker bypass (A, B)

**Attack.** Send carefully timed failed-auth events that increment the per-key counter without ever crossing the threshold; or generate enough distinct attacker keys to evict the legitimate target's entry from the table.

**Mitigation.**
- `fail_window_sec` (`src/config.c:95`, default 300s, range 1–86400) bounds the time window over which attempts are aggregated. Sliding-window logic in `src/journal_watch.c` resets the count once `event->timestamp_usec - first_attempt_usec > window_usec`, so an attacker cannot spread failures across an arbitrarily long window to stay under threshold.
- Eviction picks the **oldest by `last_attempt_usec`**, not by `first_attempt_usec` — an attacker who keeps refreshing `last_attempt_usec` with new failures cannot evict their own entry; they evict another, lower-priority entry.
- Per-key cooldown (`alert_cooldown_sec`, `src/journal_watch.c:223-232`) prevents alert flooding from a single key without losing the underlying counter.

### 3. Alert credentials exposure via process metadata (B, D)

**Attack.** Read `/proc/<pamsignal-pid>/cmdline` or `/proc/<pamsignal-curl-child-pid>/cmdline` to harvest Telegram bot tokens / webhook URLs.

**Mitigation.** Secrets are written to a `memfd_create()`-backed file (`src/notify.c:101`) and passed to curl as `-K /dev/fd/9`; they never appear in the curl child's argv. The parent daemon's argv is `pamsignal --foreground` plus an optional `--config <path>` — no credentials.

### 4. Alert dispatch hijack via `PATH` / `LD_PRELOAD` (D)

**Attack.** A compromised pamsignal daemon manipulates the environment of the curl child to redirect it through an attacker-controlled binary or library.

**Mitigation.** The curl child does `clearenv()` (`src/notify.c:184`), then `setenv("PATH", "/usr/bin:/bin", 1)`, then `execv("/usr/bin/curl", …)` with the absolute path so `PATH` is not consulted at all. `LD_PRELOAD` is dropped by `clearenv()`. The systemd unit also sets `Environment=PATH=/usr/bin:/bin` (`pamsignal.service.in:30`) for defense-in-depth when the daemon is launched outside the unit.

### 5. TLS downgrade / cleartext webhook (E)

**Attack.** A misconfigured `webhook_url = http://...` or a redirect to `http://` would expose alert contents and credentials to a passive network observer.

**Mitigation.** PAMSignal's URL validator rejects non-`https://` URLs at config-load time (`src/config.c`); curl's invocation passes `--proto =https --proto-redir =https` (`src/notify.c`) so even an attacker who manages to inject a `Location: http://...` redirect cannot make curl follow it.

### 6. Alert payload injection (A → D)

**Attack.** A username, hostname, or PAM-message field contains JSON-meaningful characters or control bytes, leading to malformed payloads or escape from JSON quoting.

**Mitigation.**
- `sanitize_string()` (`src/utils.c:13`) replaces all control characters (0x00–0x1F + 0x7F) with `?` on every extracted username and target_username, immediately after parsing.
- `is_valid_ip()` (`src/utils.c:21`) requires `inet_pton` to accept the source IP; failures clear the field.
- `json_escape()` (`src/notify.c:27`) RFC 8259 escapes `"`, `\`, all 0x00–0x1F bytes, plus the standard short escapes for `\b\f\n\r\t`. Even if `sanitize_string` ever regressed, JSON quoting holds.
- All extraction is bounded: usernames into 64-byte buffers with the `+` truncation marker (`src/utils.c:63-77`), hostnames bounded by `event.hostname[256]`, `sscanf` uses width specifiers everywhere.

### 7. Sandbox escape from a compromised daemon (D)

**Attack.** Parser-level RCE in the C code achieves arbitrary execution at the `pamsignal` user level, then attempts to escalate to root.

**Mitigation (depth, not perfect):**
- `User=pamsignal Group=pamsignal` (no privileges to start with).
- `CapabilityBoundingSet=` empty (`pamsignal.service.in:53`).
- `NoNewPrivileges=yes` (`pamsignal.service.in:38`) — `setuid` SUID binaries become no-ops.
- `MemoryDenyWriteExecute=yes` (`pamsignal.service.in:46`) — shellcode injection requires a separate kernel bug.
- `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `PrivateDevices=yes`, `ProtectKernelTunables=yes`, `ProtectKernelModules=yes`, `ProtectKernelLogs=yes`, `ProtectControlGroups=yes`.
- `RestrictNamespaces=yes`, `RestrictRealtime=yes`, `RestrictSUIDSGID=yes`, `LockPersonality=yes`.
- `SystemCallFilter=@system-service ~@privileged @resources` — bpf, mount, kexec, finit_module, etc. all denied.
- `RLIMIT_NPROC` capped at 64 in `src/main.c` so a fork-bomb in the alert path cannot exhaust process slots.
- `prctl(PR_SET_NO_NEW_PRIVS, 1)` set early in `src/main.c` even outside the unit.

The systemd-analyze security score (CI-gated to ≤30 on the 0–100 internal scale; current 22) is the regression guard for these directives.

### 8. Memory-safety bugs in the C parser (A → D)

**Attack.** Crafted journal-entry contents trigger a buffer overflow / use-after-free / integer overflow in `ps_parse_message` or downstream string handling.

**Mitigation.**
- Compiler hardening: `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=3`, `-fcf-protection=full` (Intel CET), `-fstack-clash-protection`, full RELRO, PIE, `-z noexecstack`, `-z separate-code` (`meson.build`).
- libFuzzer harness in `tests/fuzz_parse_message.c` covering the parser's primary entry point. Run with `CC=clang meson setup -Dfuzz=enabled build-fuzz && build-fuzz/fuzz_parse_message tests/fuzz/parse_message_corpus -max_total_time=60`.
- 98 CMocka tests across four suites, including parser edge cases (truncated usernames, control characters, IP-validation failures, multi-`user=` PAM messages, IPv6 literals).
- clang-tidy + clang-analyzer in CI with `WarningsAsErrors` on the `clang-analyzer-security.*` checker family.

### 9. Alert-volume DoS from a single source IP (A)

**Attack.** A scanner runs forever against one IP, generating thousands of brute-force alerts that drown the operator's chat channel.

**Mitigation.** Per-source-IP cooldown in `src/journal_watch.c:223-232`. After a threshold-breach alert fires, the same IP cannot trigger another alert for `alert_cooldown_sec` seconds (default 60s), but the underlying counter and journal entries continue. This compresses sustained-attack alerts into one chat ping per cooldown period without losing observability.

## Out of scope: attacks PAMSignal does not defend against

These are deliberate non-goals. A change that tries to extend the daemon to defend against any of them will be rejected unless the entire threat model is being expanded.

### NS1. An attacker who is already root on the monitored host

Once an adversary has root, they can `systemctl stop pamsignal`, replace `/usr/bin/pamsignal` with a no-op, edit `/etc/pamsignal/pamsignal.conf` to point alerts at their own webhook, or `kill -STOP` the daemon to freeze it. No usermode daemon defends against root, and pamsignal does not pretend to.

### NS2. An attacker in the `pamsignal` group

This group is the deliberate read-access boundary for the configuration file. An operator who adds a non-system user to it is voluntarily extending trust to that user. PAMSignal does not defend against members of its own credential-bearing group.

### NS3. A compromised journald

PAMSignal trusts journald's `_EXE`, `_PID`, `_UID`, and `_HOSTNAME` fields. journald sets these from kernel-supplied process metadata at write time; PAMSignal cannot independently verify them. If journald itself is compromised (or, more realistically, if the kernel's `/proc/<pid>/exe` lookup is broken by a kernel CVE), the `_EXE` allowlist is moot.

### NS4. A compromised `libsystemd` or `curl`

PAMSignal links against `libsystemd` and exec's `/usr/bin/curl`. A trojan in either is a host-compromise problem the package manager and signed-package supply chain should catch upstream of PAMSignal.

### NS5. A compromised alert provider

By configuring `telegram_bot_token` / `slack_webhook_url` / etc., the operator extends trust to those services. If Telegram is compromised, the operator's alerts are visible to the attacker. The mitigation is operator choice — using the custom-webhook channel pointed at infrastructure the operator controls.

### NS6. Alert delivery durability under network failure

PAMSignal alerts are fire-and-forget: a curl child is fork+exec'd, the parent does not wait for completion or retry on failure. If the network is down or the alert provider is unreachable, the alert is **lost**. This is a deliberate trade-off — durable delivery requires queueing, which requires on-disk state, which expands the attack surface (state-corruption attacks, disk-full DoS, etc.). Operators who need durable alert delivery should send to a custom webhook receiver they control, with their own queueing and retry logic.

### NS7. Multi-host correlation

Each PAMSignal instance is independent. There is no central aggregation, no shared brute-force table across hosts. An attacker hitting 50 hosts with 4 attempts each will not trigger any threshold, even if the cumulative pattern is obviously an attack. Operators who need cross-host correlation pipe the JSON-webhook output to a SIEM that does correlation properly.

### NS8. Authenticated alert delivery

PAMSignal does not HMAC-sign or otherwise cryptographically authenticate alert payloads. A webhook receiver cannot prove that a request came from a *specific* PAMSignal instance vs. an attacker who has obtained the webhook URL. Operators who need authenticated delivery put a reverse proxy in front of their webhook that validates a shared secret (or use mTLS).

### NS9. Defense against admin misconfiguration

If an operator sets `pamsignal.conf` to mode `0644` (world-readable) and stores credentials in it, PAMSignal will start (after warning at config-load) but the credentials are exposed. Improving defaults is welcome as a feature request; treating this as a security defect is not appropriate.

### NS10. Network-side DoS targeting the daemon's own resources

An attacker who can generate millions of legitimate journal events per second can saturate PAMSignal's CPU. The daemon does no rate-limiting of its own input — it processes whatever journald hands it. Per the systemd-analyze score, the daemon cannot fork-bomb the system (`RLIMIT_NPROC=64`) or exhaust memory beyond its bounded data structures (`max_tracked_ips`), but it can be slowed down. The standard answer for input-side DoS on a single host is firewalling, fail2ban-style auto-banning, or the journald-side rate limits (`RateLimitIntervalSec=`, `RateLimitBurst=`).

## Trust boundaries

A trust boundary is a place in the system where untrusted-or-attacker-influenced data crosses into a region where it is treated as well-formed. Each boundary has a designated validator; bugs in validators are the highest-priority class of defect.

| Boundary | Untrusted side | Validator | Source |
|---|---|---|---|
| Journal entry → parser | journald-recorded `MESSAGE` field | `ps_parse_message` + `_EXE` allowlist | `src/utils.c`, `src/journal_watch.c:345-381` |
| Conf file → daemon config | file contents (root-controlled but on-disk) | `ps_config_load` + permission/ownership checks | `src/config.c:249-300` |
| Event → JSON webhook payload | `event->username`, `event->source_ip`, `event->hostname` | `sanitize_string` + `json_escape` | `src/utils.c:13`, `src/notify.c:27` |
| Daemon → curl child | webhook URL, bearer token, body | memfd-backed `--config`, fixed argv, `--proto =https`, absolute-path `execv` | `src/notify.c:101-209` |

## Design limitations (deliberate trade-offs)

These are choices the project has made *for* simplicity and a smaller attack surface, with full awareness of the cost:

- **In-memory brute-force tracker**, wiped on restart (preserved across SIGHUP). Cost: a daemon restart resets per-IP counters, briefly opening the door for an attacker to retry. Mitigated by short `fail_window_sec` (default 300s — matches typical restart times).
- **No PAM module loaded.** PAMSignal does not run inside the PAM stack; it observes its outputs. Cost: it cannot intervene to *block* an auth attempt, only to alert on it. Benefit: zero privileged code in the PAM authentication path.
- **No persistent state on disk.** The daemon writes nothing to `/var/lib/`. Cost: no historical brute-force memory across restarts, no offline-analysis state. Benefit: nothing to corrupt, nothing to disk-fill, nothing to leak.
- **Single-host scope.** No clustering, no shared state, no central server. Cost: aggregation is an out-of-band SIEM concern. Benefit: single-process daemon, no network listening port, no auth between instances.
- **Fire-and-forget alerts.** Discussed in NS6 above.

These are the lines where someone proposing a feature should stop and ask whether the feature is worth the cost — and the answer is usually "no, send the operator to the custom-webhook escape hatch."

## Operator guidance

A PAMSignal install is only as secure as its surrounding configuration. The threat model assumes the operator follows these:

1. **Do not add untrusted users to the `pamsignal` group.** Doing so extends configuration-file read access (and therefore alert-credentials access) to those users. The package's `postinst` does not add anyone; the only member by default is the daemon.
2. **Keep `/etc/pamsignal/pamsignal.conf` at `0640 root:pamsignal`.** The package sets this on first install. PAMSignal warns at startup if the mode is looser; it does not refuse to start, in case an operator is intentionally running with stricter perms.
3. **For high-assurance deployments, send alerts to a custom webhook you control.** Third-party chat providers (Telegram, Slack, Teams, Discord, WhatsApp) see your alert metadata. A webhook on infrastructure you control gives you durable storage, HMAC validation, multi-host aggregation, and full control over retention.
4. **Rotate alert credentials periodically.** PAMSignal does not rotate credentials itself; rotation is operator responsibility. Update `pamsignal.conf` and `systemctl reload pamsignal`.
5. **Don't run PAMSignal as `root`.** It refuses anyway, but the underlying expectation is that the daemon stays at the package-created `pamsignal` user. Custom unit overrides that change `User=` invalidate the threat model.
6. **For defense-in-depth on the alert path, pair PAMSignal with a fail2ban (or equivalent) instance** that consumes the same journal entries to add firewall rules. PAMSignal observes; fail2ban acts. The two are complementary, not redundant; see `examples/fail2ban/` in this repo for a sample integration.

## Reporting issues

Vulnerabilities should be reported privately following the channel and timeline in [`SECURITY.md`](../SECURITY.md). The in-scope/out-of-scope split in `SECURITY.md` matches this document; this document provides the technical reasoning behind that split.
