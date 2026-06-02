# Memory Safety — Deeper Patterns

The SKILL.md covers the basics (cleanup attribute, goto-cleanup, allocation hygiene). This file is for the patterns you reach for when a module grows beyond a few hundred lines or when ownership is genuinely non-trivial.

## 1. Ownership Transfer at API Boundaries

C has no `unique_ptr`. Ownership is encoded in convention and documented in the header. Pick one of these patterns per function and document it.

### Borrow (no transfer)

The caller owns the memory; the callee reads or writes through the pointer without taking responsibility. Default for `const T *` inputs.

```c
// In the header — make it explicit.
/**
 * Read-only borrow. Pointer must remain valid for the duration of the call.
 */
int ps_event_print(const ps_event_t *ev);
```

### Take ownership (sink)

The callee takes responsibility for freeing. Caller must not free or use the pointer after the call returns.

```c
/**
 * Takes ownership of `ev`. Frees on success and on failure.
 * Caller must not use `ev` after this call.
 */
int ps_event_queue_push(ps_queue_t *q, ps_event_t *ev /* taken */);
```

The trailing `/* taken */` (or `/* owned */`) at the call site is a useful convention — it documents intent at the point of use.

### Return ownership (factory)

The caller becomes responsible for freeing whatever is returned. Pair every factory with an explicit destructor.

```c
ps_event_t *ps_event_new(ps_event_type_t type);   // caller frees with ps_event_free
void        ps_event_free(ps_event_t *ev);        // safe on NULL
```

`ps_event_free(NULL)` should be a no-op. That single rule eliminates dozens of `if (ev) ps_event_free(ev);` checks across the codebase.

### Lend (callback)

The callee passes a pointer to a callback for the duration of the callback's execution. The callback must not retain the pointer.

```c
typedef void (*ps_event_cb)(const ps_event_t *ev, void *user);
int ps_journal_watch_run(ps_event_cb cb, void *user);
```

If the callback **must** retain, return ownership explicitly or document the lifetime in plain language.

---

## 2. Opaque Handles

Use opaque handles to prevent callers from poking at internal state. The header exposes only a forward declaration; the struct definition lives in the `.c`.

```c
// include/ps_queue.h
typedef struct ps_queue ps_queue_t;        // forward only

ps_queue_t *ps_queue_new(size_t capacity);
void        ps_queue_free(ps_queue_t *q);
int         ps_queue_push(ps_queue_t *q, ps_event_t *ev);
int         ps_queue_pop(ps_queue_t *q, ps_event_t **out);
```

```c
// src/queue.c
struct ps_queue {
    ps_event_t **items;
    size_t       capacity;
    size_t       head;
    size_t       tail;
    pthread_mutex_t lock;
};
```

Benefits:
- Callers cannot accidentally rely on layout (e.g., `q->items[0]`).
- You can change the implementation without breaking ABI for callers in the same binary.
- Tests against the public interface remain valid after refactors.

Cost:
- Cannot stack-allocate (`ps_queue_t q;` is a compile error). Always heap.
- One extra indirection on each access.

For data types that are small and frequently allocated (e.g., `ps_event_t`), transparent structs are usually fine. Reserve opaque handles for collections, contexts, and long-lived state.

---

## 3. Arena (Bump) Allocators

When a function does dozens of small allocations whose lifetimes all match the function's scope, an arena collapses the bookkeeping to a single `free`.

```c
typedef struct {
    char  *base;
    size_t cap;
    size_t used;
} ps_arena_t;

static inline int ps_arena_init(ps_arena_t *a, size_t cap) {
    a->base = malloc(cap);
    if (!a->base) return PS_ERR_NOMEM;
    a->cap  = cap;
    a->used = 0;
    return PS_OK;
}

static inline void *ps_arena_alloc(ps_arena_t *a, size_t n) {
    n = (n + 7) & ~(size_t)7;                   // 8-byte align
    if (a->used + n > a->cap) return NULL;
    void *p = a->base + a->used;
    a->used += n;
    return p;
}

static inline void ps_arena_destroy(ps_arena_t *a) {
    free(a->base);
    a->base = NULL;
    a->used = a->cap = 0;
}
```

Use cases:
- Parsing one config file: every string and node lives until the parser returns.
- Building a single alert payload before fork+exec.

Do **not** use for objects whose lifetime crosses the arena's owner — those still need explicit ownership.

---

## 4. Refcounting

Refcounts are for shared-ownership cases where neither caller knows when to free. Keep them rare — explicit single-ownership is almost always clearer.

```c
typedef struct {
    _Atomic uint32_t refs;
    // ...payload...
} ps_shared_t;

static inline ps_shared_t *ps_shared_ref(ps_shared_t *s) {
    atomic_fetch_add(&s->refs, 1);
    return s;
}

static inline void ps_shared_unref(ps_shared_t *s) {
    if (!s) return;
    if (atomic_fetch_sub(&s->refs, 1) == 1) {
        // last reference
        free(s);
    }
}
```

Rules:
- Use `_Atomic` if any unref can happen from a different thread.
- `ps_shared_unref(NULL)` must be safe.
- Every `ref` must be paired with exactly one `unref` on every code path. Use the cleanup attribute to enforce.
- Cycles leak. If you have parent→child→parent references, you need weak references or a different design.

---

## 5. Reading Lifetime in Existing Code

When auditing or refactoring, trace each allocation through to its `free`. If you cannot:

- **No matching free?** Leak. Add the free or transfer ownership.
- **Multiple frees?** Double-free. Set the pointer to `NULL` after the first free, or restructure so only one owner exists.
- **Free in error path but not success?** Asymmetric — usually a bug. Cleanup attribute fixes both paths uniformly.
- **Free of a borrowed pointer?** Crash waiting to happen. The function had no right to free it.

A useful exercise: pick a random allocation in `src/`, then close your eyes (figuratively) and predict where it gets freed. Open the code and check. If you were wrong, that allocation's lifetime is unclear — file a refactor.

---

## 6. Tools That Catch Lifetime Bugs

- **AddressSanitizer (`-fsanitize=address`)** — adds it to dev builds via meson. Catches heap overflow, use-after-free, double-free.
- **UndefinedBehaviorSanitizer (`-fsanitize=undefined`)** — catches signed overflow, alignment violations, OOB shifts.
- **LeakSanitizer (`-fsanitize=leak`)** — bundled with ASan on Linux. Reports leaks at exit.
- **Valgrind (`memcheck`)** — slower, more thorough, no recompile needed.
- **clang-tidy with `bugprone-*` and `cert-*` checks** — already wired into the pre-commit workflow.

Run the test suite with sanitizers periodically:

```bash
meson setup build-asan -Db_sanitize=address,undefined
meson test -C build-asan -v
```

A clean ASan run is not proof of correctness — it is proof against the specific bugs ASan can see on the paths your tests exercised. Keep writing tests.
