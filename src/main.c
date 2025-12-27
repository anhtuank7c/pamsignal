#include <stdio.h>
#include <systemd/sd-journal.h>
#include <unistd.h>

#include "init.h"

int main() {
    int ret;

    ret = ps_daemonize();
    switch (ret) {
        case PS_OK:
            break;
        default:
            fprintf(stderr, "Daemonization failed with code %d\n", ret);
            return ret;
    }

    ret = ps_signal_init();
    switch (ret) {
        case PS_OK:
            break;
        default:
            fprintf(stderr, "Signal init failed with code %d\n", ret);
            return ret;
    }

    ret = ps_init();
    switch (ret) {
        case PS_OK:
            break;
        default:
            fprintf(stderr, "Init failed with code %d\n", ret);
            return ret;
    }

    // NOTE: A venue for initiating future PAMSignal events
    while (running) pause();

    return PS_OK;
}
