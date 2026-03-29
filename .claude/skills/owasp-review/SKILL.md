---
name: owasp-review
description: Security audit against OWASP ASVS 5.0. Reviews C code for vulnerabilities, memory safety, input validation, privilege handling, cryptography, and logic flaws. Use when reviewing code for security compliance.
disable-model-invocation: true
user-invocable: true
argument-hint: [file-or-directory]
allowed-tools: Read, Grep, Glob, Bash(objdump *), Bash(readelf *), Bash(checksec *), Bash(file *), Bash(nm *), Bash(meson *), Bash(ninja *)
effort: high
---

# OWASP ASVS 5.0 Security Review

You are performing a security audit of a C systems-level project against OWASP ASVS 5.0 (Application Security Verification Standard). This project is a Linux daemon that monitors PAM authentication events via the systemd journal.

## Scope

If `$ARGUMENTS` is provided, focus the review on those specific files or directories. Otherwise, review the entire `src/` and `include/` tree.

## Review Process

### Step 1: Gather Context

1. Read all source files in scope (both `.c` and `.h`)
2. Read `meson.build` for compiler/linker hardening flags
3. Read any systemd service files (`*.service`) for runtime sandboxing
4. Check binary hardening if a compiled binary exists:
   - `checksec --file=<binary>` (if available)
   - Otherwise: `readelf -l <binary> | grep -E 'GNU_RELRO|GNU_STACK'`
   - `readelf -d <binary> | grep BIND_NOW`
5. Check for any config files, scripts, or supporting files that handle untrusted input

### Step 2: Audit Against OWASP ASVS 5.0 Categories

Evaluate each applicable category below. For each finding, report:
- **Severity**: Critical / High / Medium / Low / Informational
- **ASVS Category**: Which verification chapter it falls under
- **Location**: `file_path:line_number`
- **Issue**: What the vulnerability or weakness is
- **Impact**: What an attacker could achieve
- **Recommendation**: Concrete fix with code example if applicable

---

### V1 — Architecture, Design & Threat Modeling

- [ ] Principle of least privilege enforced (non-root execution, minimal capabilities)
- [ ] Attack surface minimized (minimal dependencies, no unnecessary features)
- [ ] Defense in depth (multiple layers of security controls)
- [ ] Secure defaults (fail-closed, deny by default)
- [ ] No hardcoded secrets, credentials, or keys in source
- [ ] Clear trust boundaries between privileged and unprivileged components

### V2 — Authentication Verification

- [ ] Authentication events properly identified and classified
- [ ] Credential data never logged or stored in plaintext
- [ ] Authentication bypass not possible through parsing flaws
- [ ] Log messages do not leak password content or partial credentials

### V4 — Access Control

- [ ] Privilege checks before sensitive operations
- [ ] File permissions restrictive (umask, open flags)
- [ ] PID file and runtime files safe from symlink attacks (`O_NOFOLLOW`, `O_EXCL`, not in `/tmp`)
- [ ] Group membership properly validated
- [ ] No TOCTOU (time-of-check-time-of-use) race conditions
- [ ] File operations in world-writable directories use safe patterns

### V5 — Validation, Sanitization & Encoding

- [ ] All external input validated before use (journal messages, CLI args, environment variables)
- [ ] Buffer sizes enforced — no unbounded `sprintf`, `strcpy`, `strcat`, `gets`
- [ ] Format string vulnerabilities — no user-controlled format strings in `printf` family
- [ ] Integer overflow/underflow checked in arithmetic used for buffer sizes or indices
- [ ] Null pointer dereference guarded after every allocation and function return
- [ ] Command injection impossible (no `system()`, `popen()` with user input)
- [ ] Log injection prevented (control characters stripped from untrusted data)
- [ ] IP address parsing validated against `inet_pton` or equivalent
- [ ] String termination guaranteed after `strncpy`, `snprintf`, `memcpy`
- [ ] Environment variable reads (`getenv`) cached into local variables — never called twice in same expression (TOCTOU)
- [ ] `snprintf` return value checked for truncation before use
- [ ] `strtol`/`strtoul` results validated: check `errno == ERANGE`, check `end != start`, validate range fits target type before cast

### V6 — Stored Cryptography

- [ ] If cryptographic operations exist: algorithms are current (no MD5, SHA1 for security)
- [ ] Random number generation uses `/dev/urandom`, `getrandom()`, or equivalent CSPRNG
- [ ] Key material zeroed from memory after use (`explicit_bzero` or `memset_s`)
- [ ] No custom cryptographic implementations

### V7 — Error Handling & Logging

- [ ] Errors handled without information disclosure (no stack traces, internal paths to users)
- [ ] All system call return values checked (`fork`, `open`, `read`, `write`, `malloc`, `sd_journal_*`, etc.)
- [ ] Signal handlers are async-signal-safe (no `printf`, `malloc`, `free` in handlers)
- [ ] Logging does not include sensitive data (passwords, keys, tokens)
- [ ] Error paths do not leak resources (file descriptors, memory, locks)
- [ ] Signed/unsigned type mismatches in return value comparisons (e.g., `write()` returns `ssize_t`, not `int`)

### V8 — Data Protection

- [ ] Sensitive data (passwords, IPs of internal systems) handled with care
- [ ] Memory containing sensitive data cleared before free
- [ ] No sensitive data written to world-readable locations
- [ ] Proper file permissions on all created files (consistent with `umask`)
- [ ] Numeric parsing (`strtol`) includes `ERANGE` checking to prevent silent truncation of attacker-controlled values

### V9 — Communications Security

- [ ] If network communication exists: TLS/mTLS used with certificate validation
- [ ] No plaintext transmission of sensitive data
- [ ] IPC mechanisms secured (Unix sockets with proper permissions)
- [ ] Webhook/notification endpoints use HTTPS (when Phase 2 alerting is added)

### V10 — Malicious Code & Supply Chain

- [ ] Third-party dependencies audited and minimal
- [ ] Build system integrity (no downloads during build, pinned dependency versions)
- [ ] No dead code that could hide backdoors
- [ ] Compiler warnings maximized: `-Wformat=2` (stricter than `-Wformat-security`), `-Wshadow`, `-Wconversion`
- [ ] Format string warnings made fatal: `-Werror=format-security` at minimum

### V11 — Business Logic

- [ ] Rate limiting / throttling on alerting to prevent notification flooding
- [ ] Brute-force detection logic correct (time window math, counter resets, eviction policy)
- [ ] Alert cooldown per IP after threshold is triggered (prevent repeated alerts under sustained attack)
- [ ] Resource exhaustion prevented (bounded data structures, memory limits)
- [ ] Graceful handling of journal unavailability or corruption

### V14 — Configuration & Hardening

- [ ] Compiler hardening: `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`, `-fPIE`
- [ ] Linker hardening: `-Wl,-z,relro`, `-Wl,-z,now` (full RELRO)
- [ ] Runtime hardening: ASLR compatible (PIE), NX bit, stack canaries
- [ ] Systemd hardening completeness check:
  - `NoNewPrivileges=yes`
  - `ProtectSystem=strict`
  - `ProtectHome=yes`
  - `PrivateTmp=yes`
  - `ProtectKernelTunables=yes`
  - `ProtectControlGroups=yes`
  - `MemoryDenyWriteExecute=yes`
  - `RuntimeDirectory=` (for PID/socket files instead of `/tmp`)
  - `ProtectKernelModules=yes`
  - `ProtectKernelLogs=yes`
  - `RestrictNamespaces=yes`
  - `RestrictRealtime=yes`
  - `RestrictSUIDSGID=yes`
  - `SystemCallFilter=` (restrict allowed syscalls)
  - `CapabilityBoundingSet=` (drop all capabilities)
  - `LockPersonality=yes`
  - `PrivateDevices=yes`
- [ ] No development/debug code in production builds
- [ ] Restrictive default umask

---

### Step 3: Check for C-Specific Vulnerability Patterns

Beyond ASVS, scan for these common C vulnerability classes:

- **Use-after-free**: Pointer used after `free()`
- **Double-free**: `free()` called twice on same pointer
- **Dangling pointers**: Pointers to stack variables returned from functions
- **Off-by-one**: Fence-post errors in loops and buffer access
- **Signed/unsigned comparison**: Implicit conversions causing logic errors (especially `write()` vs `int`, `size_t` vs `ssize_t`)
- **Uninitialized variables**: Stack variables used before assignment
- **Race conditions**: Shared state without synchronization in signal handlers or threads
- **File descriptor leaks**: `open()` / `socket()` without corresponding `close()` on error paths
- **Symlink attacks**: Operations on files in world-writable directories (`/tmp`)
- **Environment variable safety**: `getenv()` returns mutable shared pointer — cache before multi-use
- **Numeric conversion safety**: `strtol`/`strtoul` without `errno` + range checks before narrowing cast to `pid_t`, `uid_t`, `int`, etc.
- **`snprintf` truncation**: Return value >= buffer size means output was truncated — check before relying on result

### Step 4: Generate Report

Output a structured report with:

1. **Executive Summary**: Overall security posture (1-2 sentences)
2. **Findings**: Sorted by severity (Critical > High > Medium > Low > Info), using the format below
3. **ASVS Compliance Matrix**: For each V-category, mark as Compliant / Partial / Non-compliant / N/A with a short note
4. **Prioritized Recommendations**: Numbered list ordered by risk, with effort estimate (trivial / easy / moderate)
5. **Positive Findings**: Security measures already in place that should be maintained — cite specific file:line

Use this format for each finding:

```
### [SEVERITY] ASVS-Vxx.yy — Title

**File:** `path/to/file.c:line`
**Category:** Vxx — Category Name
**CWE:** CWE-xxx (if applicable)

**Description:**
What the issue is and why it matters.

**Proof / Code:**
The relevant code snippet.

**Impact:**
What an attacker could achieve.

**Recommendation:**
How to fix it, with a code example if applicable.
```
