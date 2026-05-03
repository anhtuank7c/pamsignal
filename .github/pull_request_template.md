<!--
Thanks for sending a PR. Fill in the sections below — anything left
blank usually means a longer review cycle.

For SECURITY fixes, please use the private-disclosure path in
SECURITY.md before opening a public PR.
-->

## Summary

<!-- One paragraph: what changes, and why. The diff already shows
*what*; tell us *why*. -->

## Linked issue

<!-- "Closes #NNN" or "Refs #NNN". If there's no issue yet for a
non-trivial change, please open one first per CONTRIBUTING.md so we
can discuss scope vs. the threat model. -->

## Test plan

<!-- How did you verify this change works and doesn't regress?
- Which test cases did you add to `tests/`?
- For unit-file / packaging changes: did you build a .deb / .rpm
  locally and exercise the install path?
- For systemd-unit changes: did `systemd-analyze security
  pamsignal.service` produce a score change you expected? -->

## Threat-model alignment

<!-- For non-trivial changes only. Cite the in-scope attack number
or non-goal from `docs/threat-model.md` that this change relates to.
For example:

  - Strengthens attack #2 (brute-force tracker bypass) by …
  - Adds a new in-scope defense for adversary class B (local
    unprivileged user) …
  - Argues for moving NS7 (multi-host correlation) into scope …
-->

## Pre-commit checklist

<!-- All required for merge. Tick what you've done. -->

- [ ] `clang-format -i src/*.c include/*.h tests/*.c` produced no diff (style is convergent).
- [ ] `clang-tidy -p build src/*.c tests/*.c` reports zero warnings/errors.
- [ ] `meson compile -C build` produces zero warnings.
- [ ] `meson test -C build` — every existing test still passes; new tests cover the change.
- [ ] [`CHANGELOG.md`](../CHANGELOG.md) updated under `## Unreleased` with an entry in the appropriate subsection.
- [ ] Commit subject follows [Conventional Commits](https://www.conventionalcommits.org/) (`feat:` / `fix:` / `security:` / `refactor:` / `docs:` / `chore:` / `test:` / `perf:`), imperative mood, ≤72 chars.
- [ ] For `refactor!:` / breaking changes: a `BREAKING CHANGE:` footer in the commit body, plus a CHANGELOG note explaining the migration path.
- [ ] For systemd-unit / `.deb` / `.rpm` packaging changes: read [`CONTRIBUTING.md`](../CONTRIBUTING.md#distribution-and-packaging-changes) and verify the version-consistency + systemd-analyze CI gates still pass.

## Notes for the reviewer

<!-- Anything else worth highlighting: tricky design choices, deferred
follow-ups, areas where you'd like a second opinion. -->
