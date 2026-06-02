# V13 — Configuration

> Upstream: <https://github.com/OWASP/ASVS/blob/master/5.0/en/0x22-V13-Configuration.md>

The chapter covers hardened defaults, secret management, environment separation, dependency hygiene, and the disabling of debug surfaces in production. For PAMSignal, the audit hits compiler hardening flags, the systemd unit's sandboxing, default config values, the `-d` / `--foreground` operator flags, and the config file shipped in `pamsignal.conf.example`.

**Levels in scope for PAMSignal:** L1 mandatory, L2 informational.

---

## Where this lives in the codebase

| Surface | File | Notes |
|---|---|---|
| Compiler hardening flags | `meson.build:19-51` | `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=3` (with `=2` fallback), `-fstack-clash-protection`, `-Wl,-z,relro`, `-Wl,-z,now`, `b_pie=true` |
| systemd unit sandboxing | `pamsignal.service` | `User=pamsignal`, `NoNewPrivileges=`, `ProtectSystem=`, `ProtectHome=`, `PrivateTmp=`, etc. |
| Default config values | `include/config.h:9-12` and `src/config.c ps_config_defaults()` | `fail_threshold=5`, `fail_window_sec=300`, `max_tracked_ips=256`, `alert_cooldown_sec=60` |
| Operator flags | `src/main.c` | `--foreground`, `-c <path>`, `--help`, `--version` |
| Config file template | `pamsignal.conf.example` | Distributed as documentation; **must not contain real secrets** |
| Privilege drop | systemd `User=pamsignal` (preferred) + manual `setuid` not needed | Daemon never runs as root in supported deployments |
| `NoNewPrivileges` belt-and-braces | `src/main.c:162` `prctl(PR_SET_NO_NEW_PRIVS)` | Covers non-systemd launches |
| `RLIMIT_NPROC` cap | `src/main.c:171` | 64 child processes max |

---

## V13.1 — Hardened defaults

| V-ID | Requirement | Level | Project evaluation |
|---|---|---|---|
| V13.1.1 | Verify the application ships with hardened defaults — defaults should be safe even if the operator configures nothing. | L1 | Default config has alerts disabled (every channel token empty); brute-force detection enabled with sensible thresholds. ✓ |
| V13.1.2 | Verify debug / verbose / trace surfaces are off by default in production. | L1 | No `--debug` flag exposing internal state. `--foreground` runs in foreground but logs at the same level as the daemon. ✓ |
| V13.1.3 | Verify any "demo" / "test" credentials are not present in the shipped config. | L1 | `pamsignal.conf.example` uses placeholder values clearly marked as such. ✓ Confirm before each release. |

## V13.2 — Secret management

| V-ID | Requirement | Level | Project evaluation |
|---|---|---|---|
| V13.2.1 | Verify secrets are not stored in source control. | L1 | `.gitignore` excludes real `pamsignal.conf`. ✓ The `.example` file uses placeholders. |
| V13.2.2 | Verify secrets at rest have restrictive file permissions (≤ 0600, owned by daemon user). | L1 | Operator-managed (the config file). The systemd unit's `ProtectHome=` and `ReadOnlyPaths=` plus operator-supplied 0600 perms cover this. Document in `docs/deployment.md`. |
| V13.2.3 | Verify secrets are not exposed via process inspection (argv, environment variables visible to other users). | L1 | argv: secrets routed through memfd (V14). Environment: `clearenv()` before exec (`src/notify.c:226`). ✓ |
| V13.2.4 | Verify secrets are not logged. | L1 | Grep `src/` for `sd_journal_print` arguments that include `cfg->*_token` or `cfg->*_url` — none. ✓ See V16 for the wider audit. |

## V13.3 — Build hardening

| V-ID | Requirement | Level | Project evaluation |
|---|---|---|---|
| V13.3.1 | Verify the binary is built with compiler hardening (stack canary, FORTIFY_SOURCE, PIE, full RELRO, stack-clash protection). | L1 | `meson.build`: `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=3` (gcc≥12/glibc≥2.34, fallback `=2`), `-fstack-clash-protection`, `-Wl,-z,relro`, `-Wl,-z,now`, `b_pie=true`. ✓ Verify on every meson.build diff. |
| V13.3.2 | Verify warnings are enabled and treated seriously (`-Wall -Wextra -Wformat-security`). | L1 | Check `meson.build` for the warning set. The CLAUDE.md pre-commit workflow requires zero warnings from clang-tidy and the build. |

## V13.4 — Runtime sandboxing

| V-ID | Requirement | Level | Project evaluation |
|---|---|---|---|
| V13.4.1 | Verify the process runs as a non-root user. | L1 | `pamsignal.service`: `User=pamsignal`. ✓ |
| V13.4.2 | Verify `NoNewPrivileges=yes` (or equivalent) is set. | L1 | systemd unit + `prctl(PR_SET_NO_NEW_PRIVS)` in `main.c:162`. ✓ |
| V13.4.3 | Verify the filesystem is restricted: `ProtectSystem=`, `ProtectHome=`, `PrivateTmp=`. | L2 | Verify in `pamsignal.service`. Inspect the current unit; flag any that's missing. |
| V13.4.4 | Verify resource caps prevent runaway behaviour (`RLIMIT_NPROC`, `RLIMIT_CPU`). | L2 | `RLIMIT_NPROC=64` in `main.c:171`. Add `MemoryMax=` in the systemd unit for L2 strength. |

## V13.5 — Dependency hygiene

| V-ID | Requirement | Level | Project evaluation |
|---|---|---|---|
| V13.5.1 | Verify the dependency surface is minimal and pinned. | L1 | Runtime deps: `libsystemd`, `curl`. Build deps: `meson`, `ninja`, `pkg-config`, `libcmocka-dev`. Documented in `/CLAUDE.md` §Dependencies. ✓ |
| V13.5.2 | Verify there is a process to track CVEs against runtime dependencies. | L2 | Operator-side; distro security trackers cover `libsystemd` + `curl`. Document in `docs/deployment.md`. |

---

## Common drift in this codebase

- **`meson.build` loses a hardening flag** during a "cleanup" PR. Catch with: `grep -E 'stack-protector|FORTIFY|relro|stack-clash|b_pie' meson.build`. All five families must remain.
- **A new `--debug` / `--verbose` flag dumps the parsed config (with secrets) to stderr.** Don't.
- **A new test fixture in `pamsignal.conf.example` uses a real-looking webhook URL.** Use clearly-placeholder strings (`https://hooks.slack.com/services/T000.../B000.../...`).
- **The systemd unit drops a `Protect*` directive** during a refactor. Each removal needs a stated reason in the commit message.

---

## Scoring rubric

| Score | Meaning |
|---:|---|
| 9–10 | Hardening flags intact; runs as non-root; NoNewPrivileges + RLIMIT_NPROC + ProtectSystem all set; default config is safe. |
| 7–8 | One L2 sandbox directive missing in the systemd unit (e.g., no MemoryMax). |
| 5–6 | A hardening flag was removed from meson.build, or a debug flag exposes config. |
| 3–4 | Daemon ships configured to run as root; sandbox directives missing. |
| 0–2 | Real secrets in the shipped `.example` config; world-readable config file accepted. |

---

## Report row template

```markdown
| 6 | V13.3.1 | 🔴 | meson.build:32 | -fstack-clash-protection removed during cleanup PR [L1] | Build hardening regression; large stack frames can now jump the guard page | Restore the flag; if causing test failure, add the failing config to the CI matrix |
```

---

## Cross-references

- Root `/CLAUDE.md` §Security Requirements — "Compiler hardening flags must remain in meson.build".
- Root `/CLAUDE.md` §Dependencies — runtime + build + test dependency list.
- `pamsignal.service` — sandboxing directives.
- `docs/deployment.md` — operator-facing hardening guidance.
