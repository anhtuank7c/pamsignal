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
| **CentOS / RHEL** | 7 | 219 | 2.17 | Won't compile; many hardening directives ignored even if patched to compile |
| **CentOS / RHEL** | 8 (EOL'd 2021/2024) | 239 | 2.28 | Equivalent to Ubuntu 18.04 — sandbox posture too far from the threat model's claims |
| **Anything older** | — | — | — | The combination of glibc + systemd + OpenSSH that pamsignal's hardening relies on doesn't exist. |

The cutoffs are explicit because the threat model makes specific claims (compiler hardening, sandbox directives, the `_EXE` allowlist matching against the actual on-disk binary path) that depend on these versions. A pamsignal install on Tier 3 would *run* in many cases, but it would be running with a substantially weaker isolation posture than the security policy advertises — operators who deploy it would be making decisions based on guarantees the host doesn't actually provide.

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
