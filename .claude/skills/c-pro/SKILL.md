---
name: c-pro
description: Professional C programming craft for the PAMSignal project — clean code, idiomatic modern C (C17/gnu17), memory safety patterns, defensive programming, error-handling discipline, and refactoring guidance. Use this skill whenever writing, editing, reviewing, or refactoring any `.c` or `.h` file in this project, even for small changes or one-line fixes. Triggers on adding new functions, modifying existing C code, extracting helpers, fixing bugs in C, introducing new modules, or any work that produces or modifies C source. Also triggers on phrases like "clean up this C", "make this safer", "refactor this function", "review this C code", "is this idiomatic". Complements `senior-linux-developer` (Linux systems persona) and `owasp-asvs` (security verification) by owning the craft layer — how the code is written, not just what it does.
user-invocable: true
allowed-tools: Read, Grep, Glob, Edit, Write, Bash(meson *), Bash(ninja *), Bash(clang-format *), Bash(clang-tidy *), Bash(pkg-config *)
effort: medium
argument-hint: optional task description
---

# Professional C — Craft, Cleanliness, Safety

You are writing C in a project that values discipline. Memory leaks, latent undefined behavior, or sloppy error handling in a long-running daemon are not just style problems — they are production bugs that surface at 3 AM. This skill is the craft layer: clean code, idiomatic modern C, memory safety, and the patterns that make C code worth maintaining for years.

The project conventions (gnu17, `ps_` prefix, snake_case, `_t` suffix on types, error code enums, `sd_journal_*` for logging) come from `CLAUDE.md` — honor them. This skill adds craft on top.

## Decision Flow — Before Writing Any C

Ask yourself, in order:

1. **Does this function need to exist?** Three similar lines is better than a premature abstraction. Do not add helpers for hypothetical reuse.
2. **Who owns each resource?** Every `malloc`, `open`, `fopen`, `fork`, `pthread_create` needs one clear owner and one clear destruction site. If you cannot draw that line on paper, the design is wrong.
3. **What is the error contract?** Functions return either `void`, a bounded status enum, or a pointer (possibly `NULL`). Pick one — never mix sentinels in a single return value.
4. **What may the caller assume?** Encode preconditions as `assert()`. Document non-obvious postconditions next to the declaration in the header.

If a change feels uncomfortable, stop and figure out why. The discomfort is usually a real signal.

---

## 1. Clean Code in C

C is unforgiving but expressive. Cleanliness here means structure, naming, and restraint.

### Functions

- **One job per function.** If the body has two distinct paragraphs separated by a blank line and a header comment, it is two functions.
- **Length budget:** ~40 lines is comfortable. Past ~60 lines, decompose. Long C functions usually signal a missing abstract data type.
- **Parameter count:** four or fewer. More means you are passing a struct's worth of state — extract a struct.
- **Pure where possible.** Helpers that take inputs and return outputs without touching globals or I/O are testable, reentrant, and obviously correct.

### Naming

- `ps_<module>_<verb>()` for public functions: `ps_journal_watch_start()`, `ps_config_load()`.
- Static helpers drop the prefix and live in the `.c` file: `static int parse_priority(const char *s)`.
- Variables are nouns. Avoid `tmp1`, `tmp2`, `val_var`. Tight-scope loop counters can stay `i`, `j`, `k`.
- Booleans read as predicates: `is_running`, `has_threshold`, `should_reload`. Never `flag`, `mode`, `status` (too vague).
- No Hungarian notation, no type prefixes on variables, no `m_`-style member prefixes.

### Comments

- Default: write no comment. The function name says **why**; the code says **what**.
- Write a comment only when the code cannot: an invariant that holds because of a property elsewhere, a workaround for a kernel quirk, the reason a particular value was chosen.
- No commit-history comments (`// added 2024-03-01 to fix #123`). That belongs in `git blame`.
- No section banners (`/*========== HELPERS ==========*/`). Use functions and files.
- No restating the obvious: `// increment counter` above `counter++` is noise.

### Files and Headers

- One module per `.c` + `.h` pair. The `.h` declares the public surface; everything else is `static` in the `.c`.
- Each header must compile standalone — include what you use.
- Order inside the `.c`: system headers, then local headers, then static prototypes, then static helpers, then public functions.
- Header guards use `PS_<MODULE>_H` (matches project convention).
- Do not declare globals in headers without `extern`. Define them in exactly one `.c`.

---

## 2. Memory Safety Patterns

Most C bugs are lifetime bugs. Make lifetime explicit at the source level.

### Prefer the cleanup attribute

GCC and clang support `__attribute__((cleanup(fn)))`, which runs `fn` when the variable goes out of scope. This eliminates the goto-cleanup ladder for ordinary cases:

```c
static inline void free_strp(char **p)  { free(*p); }
static inline void fclosep(FILE **fp)   { if (*fp) fclose(*fp); }
static inline void closep(int *fd)      { if (*fd >= 0) close(*fd); }

#define _cleanup_str_    __attribute__((cleanup(free_strp)))
#define _cleanup_fclose_ __attribute__((cleanup(fclosep)))
#define _cleanup_close_  __attribute__((cleanup(closep)))

int ps_parse_config(const char *path) {
    _cleanup_fclose_ FILE *fp = fopen(path, "re");   // "e" → O_CLOEXEC
    if (!fp) return PS_ERR_OPEN;

    _cleanup_str_ char *line = NULL;
    size_t cap = 0;
    while (getline(&line, &cap, fp) >= 0) {
        if (parse_line(line) != PS_OK) return PS_ERR_PARSE;
    }
    return PS_OK;
}
```

Place the helpers and macros in one shared header (e.g. `include/ps_cleanup.h`). Reach for cleanup attributes by default in new code.

### When goto-cleanup is still right

Sometimes you genuinely want one cleanup site (e.g., partial rollback on failure). Use it with discipline:

```c
int rc = PS_OK;
char *buf = NULL;
int fd = -1;

buf = calloc(1, SIZE);
if (!buf) { rc = PS_ERR_NOMEM; goto out; }

fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
if (fd < 0)    { rc = PS_ERR_OPEN; goto out_free; }

// ...work...

close(fd);
out_free:
    free(buf);
out:
    return rc;
```

Rules:
- Single exit point at the end.
- Labels appear in reverse-allocation order.
- Each label is idempotent — running it twice would not corrupt state.
- Never `goto` forward, never `goto` into a different scope.

### Allocation hygiene

- Use `calloc()` when you need zeroed memory — one call, one allocation check, no `memset` afterthought.
- Always check the return. `malloc(0)` is implementation-defined; do not write code that relies on it.
- After `free(p)`, set `p = NULL` unless `p` goes out of scope on the next line. Stops use-after-free at the source.
- Pair every allocator with the matching deallocator: `fdopen`/`fclose`, `strdup`/`free`, `open`/`close`, `getline`/`free` (yes — the buffer `getline` returns must be `free`d, even on error).
- Do not cast `malloc`'s return value in C. It is an implicit `void *` conversion; an explicit cast hides a missing `<stdlib.h>` include.

### Strings

- `snprintf()` everywhere. Never `strcpy`, `strcat`, `sprintf`, `gets`.
- Check `snprintf`'s return: if `>= bufsize`, you truncated — that is usually a bug, not a warning.
- `strncpy` is a footgun (no guaranteed NUL terminator). Prefer `snprintf(dst, sizeof dst, "%s", src)` or write a `safe_copy()` helper.
- Compute buffer sizes from `sizeof` on the buffer, never magic numbers: `snprintf(buf, sizeof buf, ...)`.
- For untrusted strings entering logs, sanitize first. See `sanitize_string()` in `src/utils.c`.

### Integers

- Match types to ranges: `size_t` for sizes, `ssize_t` for read/write returns, `time_t` for time, `uint32_t` / `int64_t` for fixed-width.
- Do not compare signed and unsigned. Implicit promotion rules will surprise you. Cast or change the type.
- Check for overflow **before** arithmetic on sizes: `if (a > SIZE_MAX - b) return PS_ERR_OVERFLOW;`
- For `strtol` / `strtoul`: set `errno = 0` first, check `errno == ERANGE`, validate `endptr`.

### Pointers

- Initialize on declaration: `char *p = NULL;`, `FILE *fp = NULL;`. Uninitialized pointers are landmines, especially under `goto out`.
- Do not return addresses of stack locals.
- `const` everything you do not mutate — for the reader, for the optimizer, for the type system.

For deeper patterns (ownership transfer, opaque handles, arena allocators, refcounting), read `references/memory-safety.md`.

---

## 3. Error Handling Discipline

Errors in C are conveyed by return values. The discipline is making the contract obvious and unswallowable.

### One contract per function

- **Status-returning** functions return a bounded enum (`PS_OK`, `PS_ERR_*`). Out-parameters carry data.
- **Pointer-returning** functions return `NULL` on failure; the caller checks `NULL`.
- **Predicate** functions return `bool`.

Never overload: do not return a count where `-1` also means error and `0` also means "empty". Split the API.

### Propagate, do not paper over

- If a callee returns `PS_ERR_*`, return it — or map it to a more specific error the caller can act on. Do not silently translate to `PS_OK`.
- `errno` is per-thread but trampled by every libc call. Capture it immediately: `int saved = errno;` **before** any other libc call.
- Log at the point you decide to give up, not at every layer. Otherwise the journal becomes unreadable noise.

### Do not ignore returns

- `(void)foo();` is acceptable **only** when paired with a one-line comment explaining why the failure is harmless.
- Annotate functions that must be checked: `__attribute__((warn_unused_result))` on allocators, parsers, and anything with side effects on failure. Compile with `-Wunused-result`.

### Assertions vs. runtime checks

- `assert()` is for invariants the programmer guarantees. A `NULL` pointer from a public-API caller is a programmer error — `assert`.
- `if (...) return PS_ERR_*` is for conditions that can occur at runtime (user input, syscall failures, OOM). A `NULL` from `getenv()` is runtime — check it.
- For this project, keep assertions on in release builds. Cheap, catches real bugs.

For error code design and structured logging patterns, see `references/refactoring-patterns.md` (section: error contracts).

---

## 4. Defensive Programming

C has no safety net. You are the safety net.

- **Validate at boundaries, trust internally.** Public functions check inputs; `static` helpers may assume callers are honest.
- **Bound every loop.** A `while (1)` needs either a guaranteed exit condition or a sanity counter.
- **No fixed-size buffers without explicit length checks.** Even for "obviously bounded" inputs — kernel versions change, log formats evolve.
- **Use `O_NOFOLLOW`, `O_EXCL`, `O_CLOEXEC` on file opens.** Defaults are unsafe in daemon contexts.
- **Set `umask` explicitly** before creating files. Never trust the inherited mask.
- **Fork+exec for external commands.** Never `system()` or `popen()` on untrusted input. The PAMSignal alert dispatcher already does this — follow the pattern.
- **Drop privileges early.** This project runs as `pamsignal` user. Code that runs as root should not exist outside `init.c`.

---

## 5. Modern C — Used Sparingly

`gnu17` is the project standard. Use modern features when they make code clearer, not as virtuosity:

- **Designated initializers**, always: `ps_config_t cfg = {.threshold = 5, .window = 60};`
- **Compound literals** for short-lived structs: `process_event(&(ps_event_t){.type = LOGIN, .src_ip = ip});`
- **`_Static_assert`** at file scope for size and layout invariants: `_Static_assert(sizeof(ps_event_t) <= 256, "event size budget exceeded");`
- **`stdbool.h`** — `bool`, `true`, `false`. Not `int 0/1`.
- **`_Generic`** sparingly — only when type dispatch genuinely simplifies the call site.
- **C23 attributes** (`[[nodiscard]]`, `[[maybe_unused]]`) — fine under `__has_c_attribute` guards if the standard ever bumps.
- **Avoid VLAs** (`int arr[n];`). Stack-overflow risk; banned by many style guides.

---

## 6. Refactoring Smells (C-specific)

When you see these in existing code, surface them — do not silently bundle the refactor into an unrelated change.

| Smell | Likely fix |
|-------|------------|
| Function > 60 lines with nested loops | Extract the inner loop into a helper |
| 5+ output parameters | Return a struct |
| Boolean flag parameters: `do_x(thing, true, false, true)` | Split into multiple named functions |
| `if/else` ladder on type tags | Function-pointer table or `switch` over enum |
| Repeated `if (!ptr) return PS_ERR_NULL;` at the top of every function | Document precondition + `assert`, or centralize input validation |
| Manual cleanup ladders in many functions | Introduce `_cleanup_*_` macros |
| `#define` for constants that have a type | Replace with `static const` or `enum` |
| Magic numbers in code (`if (n > 5)`) | Named constants in header or `static const` |
| Cast of `void *` to typed pointer in C | Almost always unnecessary; remove |
| `(int)` cast on a pointer comparison | Almost certainly a bug |
| `strncpy` | Replace with bounded `snprintf` or a `safe_copy()` helper |
| `printf`-family format strings built from user input | `FIO30-C` violation — fix immediately |

For full before/after examples, see `references/refactoring-patterns.md`.

---

## 7. Pre-Edit Checklist

Before writing or editing C in this project, confirm:

- [ ] Read the relevant `.h` and know the existing public surface.
- [ ] Function name follows `ps_<module>_<verb>` (or is `static` if internal).
- [ ] You can point to who owns each allocation in your code.
- [ ] Return type matches one of the three contracts (status / pointer / predicate).
- [ ] No fixed-size buffer without an explicit length check.
- [ ] Every libc/syscall return is either checked or `(void)`-ignored with a comment.

After editing, run the pre-commit workflow from `CLAUDE.md`:
`clang-format` → `clang-tidy` → `meson compile` → `meson test` → `/owasp-asvs` → update `CHANGELOG.md`.

---

## References

- `references/memory-safety.md` — Lifetime patterns, ownership transfer, opaque handles, arena allocators, refcount discipline.
- `references/refactoring-patterns.md` — Concrete before/after refactors for the smells in section 6.

---

You are a craftsman, not a code generator. Slow is smooth, smooth is fast — measured in production hours, not keystrokes.
