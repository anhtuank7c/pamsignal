# Refactoring Patterns — Concrete Before/After

The SKILL.md lists C-specific smells in a table. This file shows how to actually fix them, with paired examples drawn from the kinds of code you find in long-running daemons.

## Index

1. [Long function with mixed concerns](#1-long-function-with-mixed-concerns)
2. [Too many output parameters](#2-too-many-output-parameters)
3. [Boolean flag parameters](#3-boolean-flag-parameters)
4. [If/else ladder on type tags](#4-ifelse-ladder-on-type-tags)
5. [Repeated NULL-guards at the top of every function](#5-repeated-null-guards-at-the-top-of-every-function)
6. [Manual cleanup ladders everywhere](#6-manual-cleanup-ladders-everywhere)
7. [Magic numbers](#7-magic-numbers)
8. [`#define` used where `enum` or `static const` would fit](#8-define-used-where-enum-or-static-const-would-fit)
9. [Error contracts that mix sentinels](#9-error-contracts-that-mix-sentinels)
10. [Unsafe string copies](#10-unsafe-string-copies)

---

## 1. Long function with mixed concerns

**Before** — 80 lines doing three things at once:

```c
int ps_journal_process(sd_journal *j) {
    int rc = sd_journal_get_data(j, "MESSAGE", ...);
    if (rc < 0) return PS_ERR_JOURNAL;

    // ...parse message into struct ps_event_t ev...
    // ...30 lines of strtok and sscanf...

    // ...evaluate against thresholds...
    // ...20 lines of counter bookkeeping...

    // ...dispatch alert...
    // ...20 lines of fork+exec+curl...

    return PS_OK;
}
```

**After** — three named verbs:

```c
int ps_journal_process(sd_journal *j) {
    ps_event_t ev;
    int rc = ps_journal_read_event(j, &ev);
    if (rc != PS_OK) return rc;

    if (!ps_threshold_should_alert(&ev)) return PS_OK;

    return ps_notify_dispatch(&ev);
}
```

Each helper is independently testable. The top-level function reads as the policy it implements.

---

## 2. Too many output parameters

**Before:**

```c
int ps_parse_line(const char *line,
                  char *user, size_t user_sz,
                  char *src_ip, size_t ip_sz,
                  time_t *when,
                  int *pid,
                  bool *is_failure);
```

Five outputs, error-prone at every call site.

**After** — return a struct:

```c
typedef struct {
    char    user[PS_USER_MAX];
    char    src_ip[INET6_ADDRSTRLEN];
    time_t  when;
    pid_t   pid;
    bool    is_failure;
} ps_parsed_line_t;

int ps_parse_line(const char *line, ps_parsed_line_t *out);
```

Caller code becomes:

```c
ps_parsed_line_t p;
if (ps_parse_line(line, &p) != PS_OK) return PS_ERR_PARSE;
log_event(&p);
```

If the struct grows to dozens of fields, that is a separate problem (too many concerns) — but for 4–8 related outputs, the struct is the right answer.

---

## 3. Boolean flag parameters

**Before:**

```c
void ps_notify_send(const char *msg, bool urgent, bool include_ip, bool to_telegram);

ps_notify_send("ssh failure", true, false, true);   // unreadable at the call site
```

**After** — name the variants:

```c
void ps_notify_send_alert(const char *msg);
void ps_notify_send_routine(const char *msg);

// Or, if the variants share enough body:
typedef struct {
    bool urgent;
    bool include_ip;
    ps_channel_t channel;
} ps_notify_opts_t;

void ps_notify_send(const char *msg, const ps_notify_opts_t *opts);
ps_notify_send("ssh failure",
               &(ps_notify_opts_t){.urgent = true, .channel = PS_CH_TELEGRAM});
```

The compound-literal form keeps the call site readable without permanently exploding the parameter list.

---

## 4. If/else ladder on type tags

**Before:**

```c
if (ev->type == PS_EVENT_LOGIN)       format_login(ev, buf);
else if (ev->type == PS_EVENT_LOGOUT) format_logout(ev, buf);
else if (ev->type == PS_EVENT_FAIL)   format_fail(ev, buf);
else if (ev->type == PS_EVENT_SUDO)   format_sudo(ev, buf);
else                                  format_unknown(ev, buf);
```

Every new event type means another `else if`.

**After** — table dispatch:

```c
typedef void (*ps_format_fn)(const ps_event_t *, char *buf, size_t cap);

static const ps_format_fn formatters[PS_EVENT_COUNT] = {
    [PS_EVENT_LOGIN]  = format_login,
    [PS_EVENT_LOGOUT] = format_logout,
    [PS_EVENT_FAIL]   = format_fail,
    [PS_EVENT_SUDO]   = format_sudo,
};

void ps_event_format(const ps_event_t *ev, char *buf, size_t cap) {
    ps_format_fn fn = (ev->type < PS_EVENT_COUNT) ? formatters[ev->type] : NULL;
    if (fn) fn(ev, buf, cap);
    else    format_unknown(ev, buf, cap);
}
```

Adding a new event type is now a one-line change in one place.

A `switch` over the enum is equivalent and sometimes clearer when each case has a unique shape; pick whichever reads better for the specific case.

---

## 5. Repeated NULL-guards at the top of every function

**Before** — five functions, each starting with:

```c
int ps_foo(ps_ctx_t *ctx, const char *s) {
    if (!ctx) return PS_ERR_INVAL;
    if (!s)   return PS_ERR_INVAL;
    // ...
}
```

This is defensive theater if the callers are all internal — and harmful if it masks real bugs by turning programmer errors into runtime errors.

**After** — document the precondition, assert it:

```c
/**
 * Preconditions: ctx != NULL, s != NULL.
 */
int ps_foo(ps_ctx_t *ctx, const char *s) {
    assert(ctx != NULL);
    assert(s != NULL);
    // ...
}
```

If the function is genuinely a public API where untrusted callers might pass `NULL`, keep the runtime check at the one entry point — not at every internal helper.

---

## 6. Manual cleanup ladders everywhere

**Before** — every function ends in 15 lines of goto-cleanup, each subtly different and a source of leaks.

**After** — introduce `_cleanup_*_` macros once, use everywhere:

```c
// include/ps_cleanup.h
static inline void ps_freep(void *p)     { free(*(void **)p); }
static inline void ps_fclosep(FILE **fp) { if (*fp) fclose(*fp); }
static inline void ps_closep(int *fd)    { if (*fd >= 0) close(*fd); }

#define _cleanup_free_   __attribute__((cleanup(ps_freep)))
#define _cleanup_fclose_ __attribute__((cleanup(ps_fclosep)))
#define _cleanup_close_  __attribute__((cleanup(ps_closep)))
```

```c
int ps_config_load(const char *path, ps_config_t *out) {
    _cleanup_fclose_ FILE *fp = fopen(path, "re");
    if (!fp) return PS_ERR_OPEN;

    _cleanup_free_ char *line = NULL;
    size_t cap = 0;
    while (getline(&line, &cap, fp) >= 0) {
        if (parse_line(line, out) != PS_OK) return PS_ERR_PARSE;
    }
    return PS_OK;
}
```

No labels, no leaks, no asymmetric cleanup between success and error paths. Existing modules can migrate one function at a time.

---

## 7. Magic numbers

**Before:**

```c
if (event_count > 5) trigger_alert();
if (now - last_seen > 60) reset_counter();
char buf[256];
```

What is `5`? Why `60`? Why `256`?

**After:**

```c
#define PS_DEFAULT_FAIL_THRESHOLD 5      // already in your headers
#define PS_DEFAULT_FAIL_WINDOW_S  60
#define PS_LOG_BUF_MAX            256

if (event_count > PS_DEFAULT_FAIL_THRESHOLD) trigger_alert();
if (now - last_seen > PS_DEFAULT_FAIL_WINDOW_S) reset_counter();
char buf[PS_LOG_BUF_MAX];
```

For values used in one translation unit only, prefer `static const`:

```c
static const size_t MAX_USERNAME = 32;
```

Macros for things that need a type are a trap — they have no scope and no type-checking.

---

## 8. `#define` used where `enum` or `static const` would fit

**Before:**

```c
#define EVENT_LOGIN  0
#define EVENT_LOGOUT 1
#define EVENT_FAIL   2
#define EVENT_COUNT  3
```

**After:**

```c
typedef enum {
    PS_EVENT_LOGIN  = 0,
    PS_EVENT_LOGOUT,
    PS_EVENT_FAIL,
    PS_EVENT_COUNT      // sentinel for array sizing
} ps_event_type_t;
```

Now the compiler can warn when a `switch (ps_event_type_t)` is missing a case, and the type appears in debugger output as the enum name, not as a bare `int`.

---

## 9. Error contracts that mix sentinels

**Before:**

```c
// Returns count of parsed events, or -1 on error, or 0 if nothing was there.
int ps_parse_batch(const char *blob);
```

Caller has to distinguish three meanings from one `int`. Common bugs: treating `0` as success, treating `-1` as count.

**After** — separate the channels:

```c
int ps_parse_batch(const char *blob, size_t *out_count);

// Caller:
size_t n = 0;
int rc = ps_parse_batch(blob, &n);
if (rc != PS_OK)  return rc;
if (n == 0)       /* empty input — handle distinctly */;
```

The return code carries success/failure. The count is a separate channel that is only meaningful when `rc == PS_OK`.

---

## 10. Unsafe string copies

**Before:**

```c
strcpy(dest, src);                    // unbounded
strncpy(dest, src, sizeof dest);      // no guaranteed NUL
sprintf(buf, "%s:%d", host, port);    // unbounded
```

**After:**

```c
// Single field copy:
if (snprintf(dest, sizeof dest, "%s", src) >= (int)sizeof dest)
    return PS_ERR_TRUNC;

// Formatted assembly:
int n = snprintf(buf, sizeof buf, "%s:%d", host, port);
if (n < 0 || n >= (int)sizeof buf)
    return PS_ERR_TRUNC;
```

For copies you do in many places, factor into a helper:

```c
// Returns PS_OK or PS_ERR_TRUNC. Always NUL-terminates dest if cap > 0.
static inline int ps_safe_copy(char *dest, size_t cap, const char *src) {
    int n = snprintf(dest, cap, "%s", src);
    return (n < 0 || (size_t)n >= cap) ? PS_ERR_TRUNC : PS_OK;
}
```

Truncation is usually a bug — surface it as an error, do not silently drop characters.

---

## How to introduce these refactors

- **Do not bundle refactors into unrelated PRs.** A refactor PR should change behavior in zero ways; a feature PR should change behavior in exactly one way. Reviewers cannot evaluate the two together.
- **Migrate one module at a time.** The cleanup-macro refactor is most valuable applied uniformly, but it can land in `config.c`, then `journal_watch.c`, then `notify.c` across separate commits.
- **Add the test first.** If a function has no test, write a characterization test against current behavior, then refactor, then confirm the test still passes.
- **Update `CHANGELOG.md`** under `## Unreleased` with a `refactor:` entry so the next release notes pick it up.
