# Contributing to PAMSignal

Thanks for your interest. PAMSignal is a small C daemon with a tight focus on detecting PAM auth events and dispatching alerts; the deliberately narrow scope is part of the project's threat model. Please read [`docs/threat-model.md`](./docs/threat-model.md) before proposing a feature — it's the reference for whether a change strengthens an in-scope mitigation or pulls work into the daemon from an out-of-scope area.

This document covers how to make code, doc, and packaging contributions. For:

- **Reporting a security vulnerability** → [`SECURITY.md`](./SECURITY.md). Do not file a public GitHub issue for security reports.
- **Reporting a non-security bug** → [open a bug-report issue](https://github.com/anhtuank7c/pamsignal/issues/new?template=bug_report.yml).
- **Proposing a feature** → [open a feature-request issue](https://github.com/anhtuank7c/pamsignal/issues/new?template=feature_request.yml) **first**, before writing code, so we can talk about scope vs. the threat model.
- **Asking a question / discussing usage** → check [`README.md`](./README.md), [`docs/`](./docs/), and the existing GitHub Issues. If your question isn't answered, open a feature-request-style issue and label it `question`.

## Quick start

```bash
git clone https://github.com/anhtuank7c/pamsignal.git
cd pamsignal

# Install build deps (Debian/Ubuntu)
sudo apt-get install -y --no-install-recommends \
  meson ninja-build pkg-config gcc \
  libsystemd-dev libcmocka-dev clang-format clang-tidy

# Build + test
meson setup build
meson compile -C build
meson test -C build
```

For deeper build / debugging guidance — fuzzing, ASAN runs locally, the journalctl introspection patterns, packaging into `.deb` / `.rpm` — see [`docs/development.md`](./docs/development.md). For systemd unit + sandbox details, [`docs/deployment.md`](./docs/deployment.md).

## Branch + commit workflow

1. Fork and branch from `main`. One branch per logical change.
2. Make your change. Keep commits small and focused — reviewers should be able to understand each commit on its own.
3. Run the [pre-commit checklist](#pre-commit-checklist) below. **Every item is required for a PR to merge.**
4. Push your branch and open a PR against `main`. Fill in the PR template.
5. CI runs ASAN+UBSAN sanitizers on every push to a PR; both must pass.

### Commit messages

The project uses [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>: <imperative subject under 72 chars>

<optional body explaining *why*, not *what*>
```

Types in use here:

| Type | When |
|---|---|
| `feat:` | New capability or behavior |
| `fix:` | Bug fix |
| `security:` | Security hardening or vulnerability fix |
| `refactor:` | Restructuring with no behavior change |
| `refactor!:` | Restructuring with a breaking behavior change |
| `docs:` | Documentation only |
| `chore:` | Build, CI, packaging, tooling, dependencies |
| `test:` | Adding or updating tests |
| `perf:` | Performance improvement |

Rules:

- Subject is **imperative mood** ("add", "fix", "update" — not "added", "fixes", "updated").
- No period at the end of the subject.
- The body explains *why* the change is needed; the diff already shows *what*.
- Reference issues with `#NNN` in the body, not the subject.
- Sign-off (`Signed-off-by:`) is optional but encouraged for substantial changes.

Example:

```
fix: stop dropping brute-force counter on SIGHUP reload

Reloading the config previously zeroed the in-memory fail_table,
which let an attacker SIGHUP-spam the daemon to reset their per-IP
counter just before crossing the threshold. Preserve the table
across reloads — config changes shouldn't invalidate observed
attack state.

Refs #42
```

## Coding standards

C source code follows the conventions encoded in `.clang-format` and `.clang-tidy` at the repo root. The pre-commit check (below) runs both. Specifically:

- **Language**: `gnu17` (set in `meson.build`).
- **Indentation**: 4 spaces, no tabs.
- **Functions**: `snake_case` with `ps_` prefix (e.g. `ps_journal_watch_init`).
- **Globals**: `g_` prefix (e.g. `g_config`).
- **Macros / `#define`**: `UPPER_SNAKE_CASE` with `PS_` prefix.
- **Types** (structs and enums): `_t` suffix (e.g. `ps_pam_event_t`, `ps_event_type_t`).
- **Enum constants**: `UPPER_SNAKE_CASE` with `PS_` prefix (clang-tidy enforces this — adding an enum without the prefix will fail lint).
- **Error handling**: return code enums (`PS_OK`, `PS_ERR_*`), early returns over deeply nested success paths.
- **Logging**: `sd_journal_print()` / `sd_journal_send()`. **Do not** call `printf`, `syslog`, or write to stdout/stderr from production code paths.

Comment policy:

- Default to writing **no comments**. Well-named identifiers and small functions should make the *what* obvious.
- Add a comment when the *why* is non-obvious: a hidden constraint, a subtle invariant, a workaround for a specific bug, behavior that would surprise a reader. Include enough context that the comment ages well — reference the relevant CVE, kernel man-page section, or PAM message format if applicable.

## Test requirements

**Every new function or changed behavior must have a corresponding test in `tests/`.** Adding a parser pattern? Add tests for the new pattern, the existing patterns it shouldn't match, and the truncation/edge-case behavior. Adding a config key? Add tests for valid values, out-of-range values, and missing-key fallback. Changing the brute-force tracker? Add tests for the new tuple of `(event-shape, expected counter state)`.

The test suites are CMocka-based and live alongside the source modules they cover:

| Suite | Covers |
|---|---|
| `tests/test_utils.c` | parser, helpers (`sanitize_string`, `is_valid_ip`, ECS helpers) |
| `tests/test_config.c` | config-file parsing, validation, permission checks |
| `tests/test_notify.c` | notify dispatch path (smoke tests for the no-channel paths and cooldown) |
| `tests/test_journal_watch.c` | brute-force tracker (#includes the source file directly to drive file-static state) |

If a change affects parser behavior, also extend `tests/fuzz/parse_message_corpus/` with a representative input.

## Pre-commit checklist

Run these in order before opening a PR. The CI workflow runs ASAN+UBSAN, but everything else is a local check that's faster to run on your machine than to discover via failed CI:

```bash
# 1. Format
clang-format -i src/*.c include/*.h tests/*.c

# 2. Lint (must show zero warnings)
clang-tidy -p build src/*.c tests/*.c

# 3. Build (must show zero warnings)
meson compile -C build

# 4. Test (all suites must pass)
meson test -C build

# 5. Optional but recommended: sanitizer build locally
meson setup build-asan -Db_sanitize=address,undefined -Db_lundef=false --buildtype=debugoptimized
meson compile -C build-asan
meson test -C build-asan
```

Then update [`CHANGELOG.md`](./CHANGELOG.md) under `## Unreleased`. Use `[x]` for items completed in your branch and `[ ]` for follow-ups you're explicitly leaving for later. Group entries under the existing subsection that fits (`Features`, `Fixes`, `Security`, `Packaging`, `Documentation`, `CI`).

## Code review

A maintainer will review your PR. Expect feedback within a few days for non-trivial changes. We aim to keep reviews focused on:

1. **Threat model alignment** — does the change strengthen an in-scope defense or extend the daemon into a non-goal? See [`docs/threat-model.md`](./docs/threat-model.md).
2. **Test adequacy** — does the test suite encode the change so a future regression fails CI?
3. **API stability** — is this change introducing a config key, journal field, or webhook payload field that we'll need to support across versions? Public surfaces are versioned via SemVer; deprecations need an overlap period (the `PAMSIGNAL_*` retirement in v0.3.0 is the precedent).
4. **Coding style** — covered by clang-format / clang-tidy; we won't bikeshed style if your pre-commit run is clean.

Reviewers may request changes; please respond on the PR rather than force-pushing without explanation. Force-pushes during review are fine when explicitly addressing a comment, but please leave a short note on the PR thread saying what changed.

## Distribution and packaging changes

Packaging touches `meson.build`, `pamsignal.service.in`, `debian/`, and `pamsignal.spec`. If your change affects any of these:

- The systemd unit's `systemd-analyze security` score is **CI-gated at 20** in `.github/workflows/release-packages.yml` (see the `test-deb` job). Don't strip a hardening directive without explicit threat-model justification.
- Both `debian/` and `pamsignal.spec` need parallel updates if the change affects what's installed; the `Verify version consistency` CI job catches version drift between `meson.build`, `debian/changelog`, and `pamsignal.spec`.
- `pamsignal.spec`'s `%changelog` block is parsed by the older `rpm` on EL9; **don't** put literal `%xxx` or `%{...}` macros in changelog text or it will fail the build. Phrase as prose ("the install section drops..." rather than "%install drops...").

## Code of conduct

Contributors are expected to behave constructively and respect each other. The maintainer reserves the right to remove contributions or block accounts that consistently fail to do so. If you experience or observe behavior that conflicts with this expectation, please email the maintainer at the same address listed in [`SECURITY.md`](./SECURITY.md).
