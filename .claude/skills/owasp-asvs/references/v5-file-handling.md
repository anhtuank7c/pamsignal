# V5 — File Handling

> Upstream: <https://github.com/OWASP/ASVS/blob/master/5.0/en/0x14-V5-File-Handling.md>

The chapter covers upload/download, MIME validation, path traversal, malware scanning, and server-side file processing. PAMSignal has **no upload surface** (web file uploads N/A) but does open three sensitive files on the local filesystem: the config file, the PID file, and optional TLS material (client cert / key / CA bundle). The L1 expectations focus on race-free open, symlink refusal, ownership and mode validation.

**Levels in scope for PAMSignal:** L1 mandatory, L2 informational.

---

## Where this lives in the codebase

| Surface | File | Notes |
|---|---|---|
| PID file create | `src/init.c:144-208` `ps_pidfile_acquire()` | `openat(dirfd, …, O_WRONLY\|O_CREAT\|O_NOFOLLOW\|O_EXCL\|O_CLOEXEC, 0600)` + `flock` + stale-PID recovery via `unlinkat` |
| Runtime directory | `src/init.c:146` | Opened `O_DIRECTORY\|O_RDONLY\|O_NOFOLLOW\|O_CLOEXEC`; held as dirfd to defeat symlink swaps |
| Config file read | `src/config.c:239` `read_config_into_buffer()` | `open(path, O_RDONLY \| O_NOFOLLOW \| O_CLOEXEC)` |
| Config file ownership/mode check | `src/config.c:404+` | Verifies regular file, ownership, permissions before parse |
| TLS path validation | `src/config.c:228-288` `validate_tls_path()` | Refuses control chars/quotes/backslashes in path; refuses symlinks; refuses non-regular files; requires root or daemon ownership; refuses world/group readable for private keys |
| Daemonization umask | `src/init.c:73` | `umask(0077)` so any future file created defaults to 0600 |

---

## V5.1 — File upload

| V-ID | Requirement | Level | Project evaluation |
|---|---|---|---|
| V5.1.* | All file-upload requirements | L1 | N/A — PAMSignal has no upload surface. |

## V5.2 — File download / serve

| V-ID | Requirement | Level | Project evaluation |
|---|---|---|---|
| V5.2.* | All file-download requirements | L1 | N/A — PAMSignal does not serve files. |

## V5.3 — Local file operations on sensitive files

| V-ID | Requirement | Level | Project evaluation |
|---|---|---|---|
| V5.3.1 | Verify all filesystem operations on sensitive files refuse symbolic links. | L1 | `O_NOFOLLOW` on every open: PID file, config file, TLS material. ✓ |
| V5.3.2 | Verify operations close TOCTOU windows (open then validate via `fstat` on the held fd, not `stat` on the path). | L1 | `validate_tls_path` opens then `fstat`s the held fd at `src/config.c:254-261`. ✓ Pidfile uses `openat` against held dirfd at `src/init.c:158`. ✓ |
| V5.3.3 | Verify file creation uses `O_EXCL` to prevent overwriting an existing file. | L1 | `ps_pidfile_acquire` uses `O_CREAT \| O_EXCL`. ✓ Stale-pidfile recovery `unlinkat`s before retry. ✓ |
| V5.3.4 | Verify ownership and mode are validated before trust is extended to the file's contents. | L1 | `validate_tls_path` rejects non-regular, non-root/non-daemon ownership, and world/group-readable private keys. ✓ Verify the config file has an equivalent check (`src/config.c:404+`). |
| V5.3.5 | Verify file creation uses an explicit umask and mode that excludes group/other access for sensitive files. | L1 | `umask(0077)` after daemonization + explicit `0600` on `openat`. ✓ |

## V5.4 — Path traversal

| V-ID | Requirement | Level | Project evaluation |
|---|---|---|---|
| V5.4.1 | Verify user-controlled paths cannot escape an allow-listed root. | L1 | The only user-controlled path is the config file path (passed via `-c` / default `/etc/pamsignal.conf`). It's not concatenated with anything; the daemon opens exactly that path with `O_NOFOLLOW`. ✓ |
| V5.4.2 | Verify path normalization happens before validation (`..` segments, NUL bytes). | L1 | `validate_tls_path` rejects control chars including NUL (loop terminates on `\0`, so embedded NULs are detected); does not normalize `..` because the path is operator-supplied and any traversal would be the operator's own choice. Document this if questioned. |

## V5.5 — Server-side file processing

| V-ID | Requirement | Level | Project evaluation |
|---|---|---|---|
| V5.5.* | All file-processing requirements | L1 | N/A — PAMSignal does not transform, render, or convert files. Reads config text and TLS material; that's it. |

---

## Common drift in this codebase

- **A new file open uses plain `open(path, O_RDONLY)`** without `O_NOFOLLOW` or `O_CLOEXEC`. Catch with: `grep -n 'open(' src/*.c | grep -v O_NOFOLLOW`.
- **A new file create skips `O_EXCL` or sets mode `0644` "for debugging".** Both are 🔴.
- **A new operator-supplied path bypasses `validate_tls_path`-style checks** (e.g., a future "audit log file" feature). New sensitive paths need the same five-check pattern: control-char filter, `O_NOFOLLOW`, `fstat` on fd, ownership, mode.

---

## Scoring rubric

| Score | Meaning |
|---:|---|
| 9–10 | All file opens use O_NOFOLLOW + O_CLOEXEC; creates use O_EXCL + explicit mode; ownership/mode validated on every sensitive file. |
| 7–8 | One sensitive open missing `O_CLOEXEC` (leaks fd to curl child) or one validation gap. |
| 5–6 | An open misses `O_NOFOLLOW` on a primary path. |
| 3–4 | A file create overwrites without `O_EXCL`, or mode/ownership is not validated on TLS material. |
| 0–2 | Daemon opens user-supplied paths without symlink defence. |

---

## Report row template

```markdown
| 3 | V5.3.1 | 🔴 | src/<new>.c:42 | New audit_log_open() uses open(path, O_WRONLY\|O_CREAT) without O_NOFOLLOW [L1] | Symlink swap can redirect the write to an attacker-chosen path | Mirror src/init.c:155 — add O_NOFOLLOW \| O_EXCL \| O_CLOEXEC and an explicit 0600 mode |
```

---

## Cross-references

- Root `/CLAUDE.md` §Security Requirements — "File operations: `O_NOFOLLOW | O_EXCL` for PID file, explicit umask".
- `tests/test_config.c` — extend with negative tests: symlink to `/etc/shadow`, world-readable private key, non-regular file (FIFO).
