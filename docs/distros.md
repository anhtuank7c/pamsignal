# Supported Linux Distributions

PAMSignal is designed for modern systemd-native Linux. Older releases either don't have the libc functions the daemon calls (`memfd_create`, used for credential isolation in the alert dispatch path), don't have the systemd unit directives the project's hardening relies on (`ProcSubset=pid`, `ProtectProc=invisible`, `ProtectClock=`, `ProtectHostname=`, `RestrictNamespaces=`, the `@system-service` syscall set), or don't have a recent enough debhelper to build the package. This document is the canonical reference for "will pamsignal run on my host?" and is referenced from [`SECURITY.md`](../SECURITY.md) and the [README](../README.md) docs index.

The support tiers below have different meanings and different commitments:

- **Tier 1 — CI-tested**. Every release is built and end-to-end tested on these. The published `.deb` / `.rpm` on the gh-pages apt+dnf repos are the artifacts that pass these tests. A Tier 1 regression fails the release workflow and is treated as a release blocker.
- **Tier 2 — Expected to work**. The codebase + dependencies should support these, but no automated test continuously verifies them. May have specific caveats (older systemd missing some hardening directives, slightly higher live `systemd-analyze security` score). Bug reports on Tier 2 distributions are welcome and triaged with normal priority.
- **Tier 3 — Not supported**. Pamsignal won't compile, won't install, or won't apply enough of its hardening posture for the security claims in [`docs/threat-model.md`](./threat-model.md) to hold. Bug reports on Tier 3 distributions will be closed with a pointer to this document.

A single fact you should keep in mind throughout: **the published `.deb` is built once per release on the Tier 1 CI runner**, which currently means the package's `libsystemd0` runtime dependency is pinned to the runner's libsystemd version (Ubuntu 24.04 ships libsystemd0 255). On older Ubuntus and Debians, `apt install pamsignal` from the gh-pages repo will refuse with "unmet dependencies" even when the codebase itself would compile fine. Tier 2 install methods are documented per row.

## Tier 1 — CI-tested

The release workflow's `test-deb` and `test-rpm` jobs build the package, install it under systemd in a clean container/VM, configure the daemon against a mock HTTPS webhook, drive real sshd auth events, verify the ECS payload structure, exercise SIGHUP reload, and then `apt purge` / `dnf remove` to confirm cleanup. Pass = ship.

| Distribution | Version | systemd | glibc | OpenSSH | sshd binary | Live security score | Install method |
|---|---|---|---|---|---|---|---|
| **Ubuntu** | 24.04 LTS (Noble) | 255 | 2.39 | 9.6 | `sshd` | 1.3 (OK) | `apt install pamsignal` from the gh-pages repo |
| **Fedora** | 44+ (`fedora:latest`) | 256+ | 2.40+ | 9.9+ | `sshd-session` | 1.3 (OK) | `dnf install pamsignal` from the gh-pages repo |
| **AlmaLinux** / **Rocky Linux** | 9 | 252 | 2.34 | 8.7 | `sshd` | 1.3 (OK) | `dnf install pamsignal` from the gh-pages repo |

The `test-deb` job exercises the full E2E flow (`Type=notify` activation, sshd brute-force, SIGHUP reload, ECS payload). The `test-rpm` jobs exercise install + uninstall + file-layout verification but not the daemon-under-systemd flow because the rpm test runs in a Docker container without a systemd PID 1.

## Tier 2 — Expected to work, not actively tested

| Distribution | Version | systemd | OpenSSH | Verdict | Caveats |
|---|---|---|---|---|---|
| **Ubuntu** | 22.04 LTS (Jammy) | 249 | 8.9 | ✅ Compiles + runs | No `apt install pamsignal` from the gh-pages repo (libsystemd dependency pins to 24.04's version). Build from source via `dpkg-buildpackage` on a 22.04 host, or wait for per-distroseries pockets. |
| **Ubuntu** | 26.04 (Resolute) | 259 | 9.10p2 | ✅ Compiles + runs (validated by `tests/scenario.sh` on 2026-05-03; not yet in CI matrix) | Same package-availability caveat as 22.04 until the gh-pages repo gains a `resolute` pocket. |
| **Debian** | 12 (Bookworm) | 252 | 9.2p1 | ✅ Compiles + runs | Same package-availability caveat. Build from source. |
| **Debian** | 13 (Trixie, expected GA mid-2026) | 257+ | 9.7+ | ✅ Compiles + runs | Same package-availability caveat. Likely Tier 1 once Trixie LTS lands. |
| **RHEL** | 9 | 252 | 8.7 | ✅ Same binaries as AlmaLinux 9 | The Tier 1 AlmaLinux 9 rpm should install on RHEL 9 since they're ABI-compatible at the libc + libsystemd level. |
| **Fedora** | N-1 (43 at time of writing) | 254 | 9.6 | ✅ Compiles + runs | The Tier 1 Fedora rpm targets `fedora:latest`; older Fedora may or may not satisfy its dependency strings. |

For all Tier 2 rows, the pamsignal daemon's parser, brute-force tracker, and alert dispatch behave identically to Tier 1 — the differences are upgrade-path friction (per-distroseries package pockets), not runtime behavior. The live `systemd-analyze security` score on Ubuntu 22.04 / Debian 12 may be 1–2 points higher than the CI baseline because newer systemd versions weight directives slightly differently, but every directive in the unit is honored.

## Tier 3 — Not supported

| Distribution | Version | systemd | glibc | What blocks support |
|---|---|---|---|---|
| **Ubuntu** | 20.04 LTS (Focal) | 245 | 2.31 | `debhelper-compat (= 13)` unavailable; several hardening directives ignored; live security score would land near 25 (Tier 3-equivalent posture) |
| **Ubuntu** | 18.04 LTS (Bionic) | 237 | 2.27 | Many sandbox directives missing (`ProtectProc=`, `ProcSubset=`, `ProtectClock=`, `ProtectHostname=`); live security score ~30+ |
| **Ubuntu** | 16.04 LTS (Xenial) | 229 | 2.23 | **Won't compile** — `memfd_create()` missing from glibc 2.23; alert credentials would have to fall back to argv exposure, which directly contradicts a documented threat-model mitigation (attack #3 in `docs/threat-model.md`) |
| **Debian** | 11 (Bullseye) | 247 | 2.31 | `debhelper-compat (= 13)` borderline; some hardening directives missing; effectively the same posture as Ubuntu 20.04 |
| **Debian** | ≤10 | ≤241 | ≤2.28 | Same blockers as older Ubuntu releases |
| **CentOS / RHEL** | 7 (EOL'd 2024-06-30) | 219 | 2.17 | **Won't compile** — `memfd_create()` missing from glibc 2.17 and the stock kernel 3.10 lacks the underlying syscall (Linux 3.17+ required). Alert credentials would have to fall back to argv exposure, which contradicts a documented threat-model mitigation (attack #3 in `docs/threat-model.md`). systemd 219 also ignores roughly half the hardening directives the unit relies on. See [Why CentOS / RHEL 7 isn't supportable](#why-centos--rhel-7-isnt-supportable) below for the migration path. |
| **CentOS / RHEL** | 8 (EOL'd 2021/2024) | 239 | 2.28 | Equivalent to Ubuntu 18.04 — sandbox posture too far from the threat model's claims |
| **Anything older** | — | — | — | The combination of glibc + systemd + OpenSSH that pamsignal's hardening relies on doesn't exist. |

The cutoffs are explicit because the threat model makes specific claims (compiler hardening, sandbox directives, the `_EXE` allowlist matching against the actual on-disk binary path) that depend on these versions. A pamsignal install on Tier 3 would *run* in many cases, but it would be running with a substantially weaker isolation posture than the security policy advertises — operators who deploy it would be making decisions based on guarantees the host doesn't actually provide.

## Why CentOS / RHEL 7 isn't supportable

Operators with a CentOS 7 fleet sometimes ask whether the cutoff can be relaxed. The answer is no, for three independent reasons:

1. **No `memfd_create()` syscall in the kernel.** The Linux kernel added `memfd_create` in 3.17 (October 2014). Stock RHEL 7 / CentOS 7 ships kernel 3.10 with vendor backports — `memfd_create` is *not* among the backported syscalls. Confirm on your host with `grep memfd_create /proc/kallsyms` (no match means absent). pamsignal calls it at [`src/notify.c:113`](../src/notify.c) to build the curl child's config file in an anonymous in-memory descriptor; the descriptor name `pamsignal-curl` carries the webhook URL, auth header, and TLS-path config so the curl child's `argv` reveals none of them in `/proc/<pid>/cmdline` (verifiable with `ps auxf` during an active alert). Without that syscall, the only remaining places to put credentials are argv (visible to every local user) or a tempfile (visible to anyone with `/tmp` read access at the right moment) — both are call-out targets in [`docs/threat-model.md`](./threat-model.md) attack #3. The threat model would have to be revised downward to claim support for CentOS 7, which we won't do.

2. **No `memfd_create()` glibc wrapper.** Even if a backported kernel had the syscall, RHEL 7's glibc is 2.17 — the wrapper landed in glibc 2.27 (2018). The daemon calls `memfd_create("pamsignal-curl", MFD_CLOEXEC)` as a libc function, not `syscall(SYS_memfd_create, ...)`. Switching to the raw syscall form is doable, but it doesn't unlock CentOS 7 — see point 1.

3. **EOL on 2024-06-30.** CentOS 7 reached end-of-life on June 30, 2024 — no further upstream security updates. Running a *security-monitoring* daemon on a host that no longer receives security updates is an inversion of priorities: the host's exposure is now larger than what the daemon detects, and any unpatched CVE in the kernel, openssh, sudo, or systemd would be exploited well before pamsignal could observe a failed-auth event from the attack.

### Migration paths for CentOS 7 hosts

Three realistic options, in increasing order of disruption:

| Option | What it looks like | When to use it |
|---|---|---|
| **In-place migration to AlmaLinux 9 / Rocky Linux 9 / RHEL 9** | Run the vendor migration script (`almalinux-deploy.sh` from AlmaLinux, `migrate2rocky.sh` from Rocky, `convert2rhel` from Red Hat). All three are Tier 1 / Tier 2 for pamsignal, glibc 2.34, systemd 252, kernel 5.14 with a 10-year support window. Existing `/etc/sudoers`, sshd config, and most app stacks carry forward unchanged. | The host is a long-lived production server you want to keep running. This is the recommended path. |
| **Container deployment on the existing CentOS 7 host** | Run pamsignal inside a `podman run` (or docker) container based on `almalinux:9` or `ubuntu:24.04`. The container ships its own newer glibc, so the libc-level constraint is satisfied. **Hard prerequisite**: the host kernel must be ≥ 3.17 — `uname -r` must report a backport newer than stock 3.10 (some CentOS 7 hosts run elrepo's `kernel-lt` 5.4 or `kernel-ml` 6.x, which work; the original `3.10.0-1160.x.x.el7` does not). The container also needs read-only access to `/var/log/journal` from the host (the journal is what pamsignal observes), which is operationally awkward when the host's journald is the source of truth. | The host can't be migrated (vendor application support contract, regulatory pin, etc.) and its kernel has been updated to a recent backport. |
| **Different tooling** | `auditd` is already on every RHEL host; pair it with `rsyslog`/`journald` forwarding to a SIEM (e.g. Wazuh, Splunk, Loki) and write the brute-force-detection correlation rules SIEM-side. This is what most enterprise CentOS 7 deployments already do. | The host is going to be decommissioned within the next 12 months and isn't worth the migration effort, but you still want the detection coverage in the meantime. |

If the choice is option 1, the migration is operationally lightweight: the AlmaLinux/Rocky scripts swap packages in-place without a reboot for most of the transition (a final reboot loads the new kernel). pamsignal's Tier 1 `dnf install pamsignal` works immediately on the migrated host.

## Architecture

CI tests **x86_64** only. The codebase is architecture-neutral (no inline asm, no architecture-specific intrinsics), the compiler hardening flags include `-fcf-protection=full` only when supported, and the systemd directive `SystemCallArchitectures=native` adapts automatically. **arm64 / aarch64** is therefore Tier 2 by default — expected to work, not actively tested. Bug reports on aarch64 are welcome.

## Adding a distribution to Tier 1

A row moves from Tier 2 to Tier 1 when:

1. The release workflow's `test-deb` (or `test-rpm`) matrix gains a strategy entry for the target distribution.
2. The end-to-end test passes on a fresh CI run for that target.
3. The published gh-pages apt/dnf repo grows a per-distroseries pocket so users can `apt install pamsignal` / `dnf install pamsignal` against a package built on the matching base.
4. A regression on that target fails the release workflow.

The current Tier 1 set was chosen by what already runs in CI. Expansion to Ubuntu 22.04 + Ubuntu 26.04 + Debian 12 is on the roadmap; see the `# TODO: Tier 1 matrix expansion` comment near the `test-deb` job in [`.github/workflows/release-packages.yml`](../.github/workflows/release-packages.yml).

## What this document doesn't cover

- **Container runtimes** (Docker, Podman, Kubernetes pods). PAMSignal is a daemon that reads journald and depends on a real systemd. Running inside a container that doesn't share the host's journal is unsupported by design — the threat model assumes the daemon and the events it reads are on the same kernel boundary.
- **musl-based distros** (Alpine Linux, Void). PAMSignal links against glibc-specific functions (`memfd_create()` wrapper, `clearenv()`, `close_range()` syscall fallback). Alpine's musl libc may or may not provide compatible signatures; not currently tested.
- **The BSDs.** PAMSignal calls `sd_journal_*` directly. There is no journald on FreeBSD/OpenBSD/NetBSD; the project would need a fundamentally different event source. Out of scope.

For a clean security posture, run pamsignal on a Tier 1 distribution.
