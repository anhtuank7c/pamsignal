#ifndef INIT_H
#define INIT_H

#include <stdatomic.h>

// Return codes
enum {
    PS_OK = 0,
    PS_ERR_INIT = -1,
    PS_ERR_SIGNAL = -2
};

// Global running flag
extern atomic_bool running;

// Initialize PAMSignal core
int ps_init();
int ps_daemonize();
int ps_signal_init();

#endif /* INIT_H */