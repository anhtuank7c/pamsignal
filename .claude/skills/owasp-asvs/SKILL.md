---
name: owasp-asvs
description: Project-aware OWASP ASVS 5.0 audit skill for PAMSignal — a C17/gnu17 daemon that monitors PAM events via systemd journal and dispatches alerts via fork+exec curl. Use when reviewing code against the Application Security Verification Standard — full audit (with N/A chapters explicitly marked), single-chapter deep dive, or level-targeted compliance check (L1 baseline, L2 standard, L3 high-assurance). Triggers on English requests like "ASVS audit", "OWASP ASVS review", "L1 compliance", "verify V1 encoding", "ASVS V15 secure coding review", "security verification", "is this ASVS-compliant". Also triggers on Vietnamese requests like "rà soát ASVS", "đánh giá OWASP ASVS", "kiểm tra ASVS V15", "compliance bảo mật". Each chapter has a dedicated reference file under `references/` with the V-ID list, project-specific evaluation guide pointing at the actual PAMSignal code surfaces (sanitize_string, is_valid_ip, json_escape, validate_tls_path, ps_is_trusted_exe, build_secrets_memfd, fork+exec curl, O_NOFOLLOW|O_EXCL, meson.build hardening flags, pamsignal.service unit), common pitfalls, and a per-chapter scoring rubric. Output is a structured markdown report with findings tagged by V-ID, severity, and applicable level.
---

# OWASP ASVS 5.0 Audit — PAMSignal

A skill that walks the **OWASP Application Security Verification Standard 5.0** (released May 2025) against this codebase. ASVS gives you ~280 testable requirements organised into 17 chapters; this skill maps each applicable chapter to the real surfaces in PAMSignal so the audit produces concrete file:line findings instead of generic checklists.

## What PAMSignal is — and isn't

PAMSignal is a small C daemon (`src/{main,init,config,journal_watch,notify,utils}.c`, ~1.5k LOC) that:

- Reads PAM authentication events from the systemd journal (via `libsystemd`)
- Parses them, tracks brute-force patterns in-memory
- Forks `/usr/bin/curl` to POST alerts to Telegram, Slack, Teams, WhatsApp, Discord, or a custom webhook
- Runs as the unprivileged `pamsignal` user under a hardened systemd unit

There is **no inbound network surface, no API, no web UI, no user accounts, no DB, no session layer, no JavaScript**. That makes 8 of the 17 ASVS chapters **N/A by design** (see §1 below); the remaining 9 are where the audit work happens.

## When to invoke

Trigger on any of:

- **"ASVS audit / review"** — full or scoped run against verification chapters.
- **"L1 compliance check"** — gate-style: does this module meet ASVS Level 1?
- **"V1 encoding review"** (or V5, V13, V15, etc.) — single-chapter deep dive.
- **"OWASP ASVS"** in any combination — defaults to L1 with L2 informational.
- Vietnamese equivalents: "rà soát ASVS", "đánh giá ASVS V15", "compliance bảo mật".

If the user's request is ambiguous, ask which **level** they want (L1 / L2 / L3) and which **chapters** are in scope.

## 1. The 17 chapters

Each chapter has a reference file under `references/`. Load only the ones in scope — do not try to hold all 17 in context.

| # | Chapter | Reference | Applies to PAMSignal? |
|---:|---|---|---|
| V1 | Encoding & Sanitization | `references/v1-encoding-sanitization.md` | ✅ **Yes** — log injection from PAM messages, JSON payload escaping |
| V2 | Validation & Business Logic | `references/v2-validation-business-logic.md` | ✅ **Yes** — config parsing, IP validation, message parsing, bounded buffers |
| V3 | Web Frontend Security | `references/v3-web-frontend-security.md` | ⚪ **N/A** — no browser-rendered surface |
| V4 | API & Web Service | `references/v4-api-web-service.md` | ⚪ **N/A** — no inbound API; outgoing HTTPS only |
| V5 | File Handling | `references/v5-file-handling.md` | ✅ **Yes** — PID file, config file, TLS cert paths |
| V6 | Authentication | `references/v6-authentication.md` | ⚪ **N/A** — observes PAM, doesn't authenticate users itself |
| V7 | Session Management | `references/v7-session-management.md` | ⚪ **N/A** — no sessions |
| V8 | Authorization | `references/v8-authorization.md` | ⚪ **N/A (mostly)** — single trust boundary, covered under V15 |
| V9 | Self-contained Tokens | `references/v9-self-contained-tokens.md` | ⚪ **N/A** — stores opaque webhook tokens, doesn't mint or verify JWTs |
| V10 | OAuth & OIDC | `references/v10-oauth-oidc.md` | ⚪ **N/A** — no OAuth flows |
| V11 | Cryptography | `references/v11-cryptography.md` | ✅ **Yes (narrow)** — no homemade crypto; rely on curl/OpenSSL for TLS |
| V12 | Secure Communication | `references/v12-secure-communication.md` | ✅ **Yes** — curl `--proto =https`, no `-k`, optional client cert / CA bundle |
| V13 | Configuration | `references/v13-configuration.md` | ✅ **Yes** — hardened defaults, secret handling via memfd, systemd unit, debug surfaces |
| V14 | Data Protection | `references/v14-data-protection.md` | ✅ **Yes** — webhook tokens stay out of argv; never logged |
| V15 | Secure Coding & Architecture | `references/v15-secure-coding-architecture.md` | ✅ **Yes** — privilege drop, fork+exec isolation, signal safety, hardening flags |
| V16 | Security Logging & Error Handling | `references/v16-logging-error-handling.md` | ✅ **Yes** — `sd_journal_send()` structured fields, truncation marker, no raw secrets |
| V17 | WebRTC | `references/v17-webrtc.md` | ⚪ **N/A** — no realtime A/V |

## 2. ASVS levels

Pick one when scoping the audit:

| Level | Use case | What it expects |
|---|---|---|
| **L1** (default) | Released system daemon, opportunistic attacker threat model | Smoke-test verifications — every requirement should be at least automatable / verifiable through routine review |
| **L2** | Hardened deployments holding sensitive logs / running on regulated hosts | All L1 + additional defence-in-depth, monitoring discipline, key & secret management |
| **L3** | High-assurance (regulated infrastructure, critical hosts) | All L2 + formal threat model, code review evidence, third-party penetration test evidence |

**PAMSignal default**: **L1 with select L2 controls flagged as ⚠️ informational** — matches the posture documented in `/CLAUDE.md` §Security Requirements. Override on explicit user request.

## 3. Severity ↔ ASVS mapping

Each finding gets a severity. Map to ASVS levels for context:

| Severity | ASVS level affected | When to use |
|---|---|---|
| 🔴 **Critical** | L1 control missing or broken in a primary path | Buffer overflow, unsanitized journal output, plaintext secret in argv, missing privilege drop, `O_NOFOLLOW` removed |
| 🟠 **High** | L1 partial, OR L2 control absent on a sensitive surface | Missing bounds check on a non-primary path, weak TLS configuration, fork+exec without env scrub |
| 🟡 **Medium** | L2/L3 control missing where the audit scope includes it | No CI-side fuzzing, no AddressSanitizer build, no SBOM, hardcoded magic numbers without rationale |
| ⚪ **Low / Informational** | L3 control absent, or improvement opportunity | Missing threat model doc, no upstream-dependency CVE feed wired in |

Each finding row carries the **V-ID** (e.g., `V15.6.1`) for traceability back to the official ASVS doc.

## 4. Workflow

### Step 1 — Confirm scope

State to the user:

- Which chapters (one, several, or "all applicable, with N/A explicitly marked"?)
- Which level (L1 / L2 / L3?)
- Which paths/modules (whole `src/`, a single module, or a single diff?)

If ambiguous, default to **L1 audit over all applicable chapters** scoped to `src/` + `include/` + `meson.build` + `pamsignal.service`. Confirm before running.

### Step 2 — Load only the reference files in scope

For each chapter in scope, read `references/v<n>-*.md`. Each file contains:

- The verification IDs for that chapter (V<n>.x.y), grouped by category
- Project-specific places to inspect (file paths, function names, helpers)
- Common drift patterns this codebase has historically had
- Scoring rubric

Do **not** preload all 17 — the skill is structured to keep your context lean. The 8 N/A chapters have very short reference files (one-line rationale + the trigger that would make them applicable).

### Step 3 — Inspect the code

For each verification requirement in scope:

1. Find the relevant code surface (file:line) via Grep / Read.
2. Check whether the requirement is met, partial, missing, or N/A.
3. Capture a finding row if it isn't a clear pass.

### Step 4 — Produce the report

Single markdown report. Structure:

```markdown
## OWASP ASVS 5.0 Audit — <scope>

**Level audited:** L1 (with L2 informational)
**Date:** YYYY-MM-DD
**Chapters in scope:** V1, V5, V15 (or "all 17 applicable: V1, V2, V5, V11, V12, V13, V14, V15, V16; N/A: V3, V4, V6, V7, V8, V9, V10, V17")
**Methodology:** <sampling note if relevant>

### Per-chapter summary

| Chapter | Status | Notes |
|---|---|---|
| V1 Encoding & Sanitization | ✅ Pass | sanitize_string + json_escape cover all PAM-sourced fields |
| V5 File Handling | ⚠️ Partial | 1 L1 gap on TLS path validation |
| V17 WebRTC | N/A | No realtime A/V surface |

### Findings

| # | V-ID | Severity | Location | Requirement | Gap | Fix |
|---:|---|---|---|---|---|---|
| 1 | V1.2.4 | 🟠 | src/utils.c:13 | "Output to log must escape or strip control characters before write" [L1] | sanitize_string only replaces, doesn't track that replacement happened; downstream cannot tell if a field was tampered | Optional: add a sanitize_string variant that returns the replaced-byte count, surface in audit log fields |

### Top 5 prioritized fixes

…

### Cross-references

- Official ASVS 5.0 chapter: https://github.com/OWASP/ASVS/blob/master/5.0/en/0x10-V1-Encoding-and-Sanitization.md
- Project canonical rule: /CLAUDE.md §Security Requirements
- Pre-merge gate: `/review-code` slash command
```

### Step 5 — Save or hand back

If the report is < 200 lines, return inline. Larger reports → offer to save under `docs/handoff/asvs-audit-<area>-<YYYY-MM-DD>.md` and wait for confirmation.

## 5. Output style guarantees

- **Every finding must reference a V-ID.** No bare "missing bounds check" — anchor to the ASVS clause that requires it.
- **Every finding must show file:line.** A grep result counts; "somewhere in `src/notify.c`" does not.
- **Show levels as `[L1]`, `[L2]`, `[L3]`** so the reader knows the relevance to their selected scope.
- **Mark `N/A` explicitly** when a chapter or requirement doesn't apply (e.g., V6 Authentication: PAMSignal does not authenticate users; it observes PAM events → N/A with one-line rationale).
- **Cite the project's own helpers when proposing a fix** — `sanitize_string`, `is_valid_ip`, `json_escape`, `validate_tls_path`, `ps_is_trusted_exe`, `build_secrets_memfd`, `PS_FMT_OK` — instead of pointing to generic patterns.
- **Severity emoji set is fixed**: 🔴 🟠 🟡 ⚪. Never invent new ones.

## 6. Anti-patterns when auditing

- **Don't run all 17 chapters silently on a one-file change.** Confirm scope.
- **Don't paraphrase ASVS requirements freely** — quote the requirement text (short) and cite the V-ID, so the reader can verify against the official standard.
- **Don't conflate severity with level.** A missing L1 control is critical/high. A missing L3 control on an L1-scoped audit is *informational*, not high.
- **Don't ✅ a requirement just because you "didn't find a violation".** Either show concrete evidence the control exists (file:line + snippet ≤ 5 lines) or downgrade to ⚠️ "could not verify".
- **Don't widen severity to look thorough.** A 🟡 with V-ID + file:line is more useful than a 🔴 with hand-waving.
- **Don't import web-app threat models.** PAMSignal has no HTTP server, no users, no JavaScript. Flagging "missing CSRF" or "no Content-Security-Policy" is a category error.

## 7. Interaction with other project resources

This skill **does not replace**:

- Root `/CLAUDE.md` §Security Requirements — canonical project posture.
- `/review-code` slash command — 20-rule pre-merge gate for any PR touching parsing, fork+exec, file I/O, or the systemd unit.
- `.claude/skills/c-pro/` — craft-layer reviews (idiomatic C, memory safety, error-handling discipline).
- `.claude/skills/senior-linux-developer/` — Linux systems persona (CERT C, CWE prevention, FHS, systemd, PAM).

This skill goes **deeper** than the 20-rule subset by mapping every applicable ASVS V-ID to a verification step against this codebase. Use it before a release tag, when adding a new alert channel, when adding a new parsing path, or when the user asks for ASVS-by-V-ID evidence.

When generating fix code, switch back to:

- Root `/CLAUDE.md` §Security Requirements for the canonical patterns (`sanitize_string`, `inet_pton`, `O_NOFOLLOW|O_EXCL`, JSON escaping, fork+exec isolation, hardening flags).
- `.claude/skills/c-pro/` for the craft layer.
- `.claude/skills/distro-packaging/` if the fix touches packaging.

## 8. Official ASVS 5.0 references

When you need to verify a requirement's exact text or look up additional context, cite the canonical chapter files in the OWASP repository:

- https://github.com/OWASP/ASVS/blob/master/5.0/en/0x10-V1-Encoding-and-Sanitization.md
- https://github.com/OWASP/ASVS/blob/master/5.0/en/0x11-V2-Validation-and-Business-Logic.md
- https://github.com/OWASP/ASVS/blob/master/5.0/en/0x12-V3-Web-Frontend-Security.md
- https://github.com/OWASP/ASVS/blob/master/5.0/en/0x13-V4-API-and-Web-Service.md
- https://github.com/OWASP/ASVS/blob/master/5.0/en/0x14-V5-File-Handling.md
- https://github.com/OWASP/ASVS/blob/master/5.0/en/0x15-V6-Authentication.md
- https://github.com/OWASP/ASVS/blob/master/5.0/en/0x16-V7-Session-Management.md
- https://github.com/OWASP/ASVS/blob/master/5.0/en/0x17-V8-Authorization.md
- https://github.com/OWASP/ASVS/blob/master/5.0/en/0x18-V9-Self-contained-Tokens.md
- https://github.com/OWASP/ASVS/blob/master/5.0/en/0x19-V10-OAuth-and-OIDC.md
- https://github.com/OWASP/ASVS/blob/master/5.0/en/0x20-V11-Cryptography.md
- https://github.com/OWASP/ASVS/blob/master/5.0/en/0x21-V12-Secure-Communication.md
- https://github.com/OWASP/ASVS/blob/master/5.0/en/0x22-V13-Configuration.md
- https://github.com/OWASP/ASVS/blob/master/5.0/en/0x23-V14-Data-Protection.md
- https://github.com/OWASP/ASVS/blob/master/5.0/en/0x24-V15-Secure-Coding-and-Architecture.md
- https://github.com/OWASP/ASVS/blob/master/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md
- https://github.com/OWASP/ASVS/blob/master/5.0/en/0x26-V17-WebRTC.md

Each reference file in this skill includes a link back to its corresponding upstream chapter for the exact requirement text.

---

*Living document. When you find a new project-specific surface that affects a verification requirement, add it to the relevant `references/v<n>-*.md` file rather than restating it here.*
