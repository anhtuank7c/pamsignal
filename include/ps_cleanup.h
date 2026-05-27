#ifndef PS_CLEANUP_H
#define PS_CLEANUP_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/*
 * RAII-style cleanup helpers using GCC/Clang __attribute__((cleanup)).
 * Used in the functions that have multiple early-return close/free sites
 * (build_secrets_memfd, open_config_secure, validate_tls_path) so error
 * paths and the success path share one teardown.
 */

static inline void ps_freep(void *p) {
    free(*(void **)p);
}

static inline void ps_fclosep(FILE **fp) {
    if (*fp)
        fclose(*fp);
}

static inline void ps_closep(int *fd) {
    if (*fd >= 0)
        close(*fd);
}

#define _cleanup_free_   __attribute__((cleanup(ps_freep)))
#define _cleanup_fclose_ __attribute__((cleanup(ps_fclosep)))
#define _cleanup_close_  __attribute__((cleanup(ps_closep)))

#endif /* PS_CLEANUP_H */