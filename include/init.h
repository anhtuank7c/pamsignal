#ifndef INIT_H
#define INIT_H

#include <signal.h>

// Return codes
enum {
    PS_OK = 0,
    PS_ERR_INIT = -1,
    PS_ERR_SIGNAL = -2,
    PS_ERR_JOURNAL = -3,
    PS_ERR_CONFIG = -4
};

// Global flags (set by signal handlers, read by event loop). C11 requires
// signal handlers to use volatile sig_atomic_t (or a lock-free atomic with
// memory_order_relaxed) — atomic_bool's default seq_cst stores are not
// guaranteed signal-safe by the standard.
extern volatile sig_atomic_t running;
extern volatile sig_atomic_t reload_requested;

// Initialize PAMSignal core
int ps_init();
int ps_daemonize();
int ps_signal_init();

// PID file for single-instance enforcement
#define PS_RUNTIME_DIR   "/run/pamsignal"
#define PS_PID_FILE_NAME "pamsignal.pid"
#define PS_PID_FILE      PS_RUNTIME_DIR "/" PS_PID_FILE_NAME
int ps_pidfile_acquire(void);
void ps_pidfile_release(void);

#endif /* INIT_H */