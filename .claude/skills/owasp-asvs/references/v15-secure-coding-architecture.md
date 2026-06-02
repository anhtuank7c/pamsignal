# V15 — Secure Coding & Architecture

> Upstream: <https://github.com/OWASP/ASVS/blob/master/5.0/en/0x24-V15-Secure-Coding-and-Architecture.md>

The chapter covers trust boundaries, layer separation, threat modelling, dependency hygiene, supply-chain integrity, signal safety, and safe coding patterns. For PAMSignal — a C daemon that ingests untrusted journal data, holds in-memory state, and spawns curl children — this is the most consequential chapter. Most of the actual security work in the codebase (privilege drop, fork+exec isolation, hardening flags, atomic signal flags, memory safety patterns) maps here.

**Levels in scope for PAMSignal:** L1 mandatory, L2 informational, selected L3 architectural items where appropriate.

---

## Where this lives in the codebase

| Surface | File | Notes |
|---|---|---|
| Trust boundaries documented | `docs/architecture.md` | Inputs (journal, config) and outputs (HTTPS) — verify this is current |
| Privilege drop | `pamsignal.service` `User=pamsignal` | Daemon never runs as root in supported deployments |
| `NoNewPrivileges` | `src/main.c:162` `prctl(PR_SET_NO_NEW_PRIVS)` | Covers manual launches outside systemd |
| Resource cap | `src/main.c:171` `setrlimit(RLIMIT_NPROC, 64)` | Alert flood cannot fork-bomb the system |
| Fork+exec isolation | `src/notify.c:179-257` `fire_curl()` | child does `clearenv` + reset signal handlers + `close_range` + `execv` (absolute path) |
| Signal handling | `src/init.c:30-55` `ps_signal_init` | `atomic_bool running` + `atomic_bool reload_requested`; `SIGCHLD: SIG_IGN \| SA_NOCLDWAIT` so the kernel reaps curl children; `SIGPIPE` ignored |
| Config reload safety | `src/config.c` SIGHUP path | Parses into temp struct; only swaps on success — bad config leaves the live config unchanged |
| Hardening flags | `meson.build:19-51` | Stack canary, FORTIFY_SOURCE=3 (with =2 fallback), full RELRO, PIE, stack-clash protection |
| Bounded buffers | `include/config.h:14-41`, every parser in `src/utils.c` | No dynamic allocation in the data path |
| Spoof guard on journal source | `src/journal_watch.c:38,394-410` `ps_is_trusted_exe()` | Cross-cuts V1 — closes the `logger(1)` injection vector |

---

## V15.1 — Architecture & trust boundaries

| V-ID | Requirement | Level | Project evaluation |
|---|---|---|---|
| V15.1.1 | Verify a current threat model and trust-boundary diagram exists. | L1 | `docs/architecture.md`. Verify it lists: journal → daemon, config file → daemon, daemon → curl → HTTPS, and the spoof guard. |
| V15.1.2 | Verify the architecture separates concerns (parsing, policy, dispatch). | L1 | Six modules: `main`, `init`, `config`, `journal_watch`, `notify`, `utils`. Parsing in `utils.c`, dispatch isolated in `notify.c`. ✓ |
| V15.1.3 | Verify alert dispatch is isolated from the parent process. | L1 | fork+exec curl: child failures cannot crash the daemon. ✓ See `/CLAUDE.md` §Key Design Decisions. |

## V15.2 — Memory safety (C-specific)

| V-ID | Requirement | Level | Project evaluation |
|---|---|---|---|
| V15.2.1 | Verify no `strcpy`, `strcat`, `sprintf`, `gets`, `scanf("%s",…)` in the codebase. | L1 | Grep `src/` and `include/`. Must come back empty. ✓ Pattern: use `snprintf` + truncation check via `PS_FMT_OK`. |
| V15.2.2 | Verify every `snprintf` into a fixed-size buffer treats truncation as failure. | L1 | `PS_FMT_OK()` macro at `src/notify.c:86`. Truncated alerts are dropped. ✓ |
| V15.2.3 | Verify bounded buffers are used for all message-derived strings; no dynamic allocation in the hot path. | L1 | `ps_pam_event_t` (`include/pam_event.h`) and `ps_config_t` (`include/config.h`) use fixed arrays. ✓ |
| V15.2.4 | Verify off-by-one defence on every length-bounded copy. | L1 | `extract_username` uses `i < len - 1` and writes the `+` sentinel at `len - 1` on overflow. ✓ See `src/utils.c:73-77`. |
| V15.2.5 | Verify integer overflow defence on size calculations (`size_t` arithmetic, multiplications). | L1 | Sizes are compile-time-known (`sizeof(buf)`), not user-controlled. ✓ |

## V15.3 — Process / privilege architecture

| V-ID | Requirement | Level | Project evaluation |
|---|---|---|---|
| V15.3.1 | Verify the daemon does not run as root. | L1 | `pamsignal.service` `User=pamsignal`. ✓ |
| V15.3.2 | Verify `NoNewPrivileges` (or `prctl(PR_SET_NO_NEW_PRIVS)`) is set. | L1 | Both: systemd unit + belt-and-braces `prctl` at `src/main.c:162`. ✓ |
| V15.3.3 | Verify child processes inherit minimal state — closed fds, scrubbed env, default signal handlers. | L1 | `src/notify.c:187-227`: dup memfd to fd 9, `close_range` everything else, reset SIGTERM/SIGHUP/SIGINT, `clearenv`, set minimal PATH. ✓ |
| V15.3.4 | Verify resource limits cap denial-of-service potential. | L2 | `RLIMIT_NPROC=64`. ✓ Add `RLIMIT_CPU` / `MemoryMax=` in the unit for L2 strength. |

## V15.4 — Signal safety

| V-ID | Requirement | Level | Project evaluation |
|---|---|---|---|
| V15.4.1 | Verify state mutated by signal handlers uses async-signal-safe primitives. | L1 | `running` and `reload_requested` are `atomic_bool`. Handlers only set these flags; no malloc, no journal calls from inside a handler. ✓ |
| V15.4.2 | Verify SIGCHLD is handled (no zombies) and SIGPIPE is ignored. | L1 | `SA_NOCLDWAIT` and `signal(SIGPIPE, SIG_IGN)` in `src/init.c:40-52`. ✓ |
| V15.4.3 | Verify SIGHUP-driven config reload cannot corrupt the live config. | L1 | Parses into temp struct; swaps only on success. Live config is unchanged on parse failure. ✓ |

## V15.5 — Supply chain

| V-ID | Requirement | Level | Project evaluation |
|---|---|---|---|
| V15.5.1 | Verify dependency surface is minimal and documented. | L1 | `libsystemd` + `curl` (runtime); `meson`/`ninja`/`pkg-config`/`libcmocka` (build/test). Documented in `/CLAUDE.md` §Dependencies. ✓ |
| V15.5.2 | Verify the build is reproducible and signed releases are published. | L2 | Meson build is deterministic given a pinned compiler. Release signing — operator-side process; document. |
| V15.5.3 | Verify dependency CVE feed is monitored. | L2 | Distro security trackers cover `libsystemd` + `curl`. Document operator-side responsibility in `docs/deployment.md`. |

## V15.6 — Hardening flags

| V-ID | Requirement | Level | Project evaluation |
|---|---|---|---|
| V15.6.1 | Verify compiler hardening flags are intact. | L1 | `meson.build`: `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=3` (with `=2` fallback), `-fstack-clash-protection`, `-Wl,-z,relro`, `-Wl,-z,now`, `b_pie=true`. ✓ |
| V15.6.2 | Verify warnings are treated as errors in CI. | L2 | Pre-commit workflow requires zero clang-tidy warnings (`/CLAUDE.md` §Pre-Commit step 3) and zero build warnings (step 4). |
| V15.6.3 | Verify fuzz / sanitizer builds are exercised periodically. | L2 | `tests/fuzz_parse_message.c` + `tests/fuzz/` corpus. Add an ASan / UBSan build to CI for L2. |

---

## Common drift in this codebase

- **A hardening flag is dropped from `meson.build` during a "build cleanup".** Catch with: `grep -E 'stack-protector|FORTIFY|relro|stack-clash|b_pie' meson.build`. All five families must remain.
- **A new signal handler does work beyond setting an `atomic_bool` flag.** Don't — no malloc, no journal calls. Use the flag and let the main loop do the work.
- **`fire_curl()` is "simplified" to skip `clearenv` / `close_range` / signal reset.** Each removal is a 🔴 because curl then inherits dangerous state.
- **A new alert path mallocs in the data hot path.** Don't — use a bounded stack buffer + `PS_FMT_OK`.

---

## Scoring rubric

| Score | Meaning |
|---:|---|
| 9–10 | Hardening flags intact; privilege drop + NNP + RLIMIT_NPROC; fork+exec isolation full; signal-safe flags only; no unsafe stdlib functions. |
| 7–8 | One L2 item missing (e.g., no ASan CI build). |
| 5–6 | A hardening flag dropped, or a signal handler doing non-async-signal-safe work. |
| 3–4 | Fork+exec isolation missing one element (env scrub, fd close, signal reset). |
| 0–2 | strcpy/sprintf in code, OR daemon runs as root, OR no privilege drop. |

---

## Report row template

```markdown
| 8 | V15.3.3 | 🔴 | src/notify.c:412 | New retry helper invokes execv() without calling clearenv() first [L1] | curl child inherits a controllable environment from the parent (PATH, LD_*, etc.) | Mirror src/notify.c:226 — clearenv() + setenv("PATH", "/usr/bin:/bin", 1) before execv |
```

---

## Cross-references

- Root `/CLAUDE.md` §Security Requirements and §Key Design Decisions.
- Root `/CLAUDE.md` §Pre-Commit Workflow — enforces this chapter's requirements at commit time.
- `docs/architecture.md` — trust-boundary diagram.
- `.claude/skills/senior-linux-developer/` — Linux systems persona (CERT C, CWE prevention, FHS).
- `.claude/skills/c-pro/` — craft layer (memory safety patterns, error-handling discipline).
