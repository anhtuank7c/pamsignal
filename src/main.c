#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <systemd/sd-journal.h>
#include <unistd.h>

#include "init.h"

int main() {
    if(geteuid() != 0) {
        fprintf(stderr, "This program must be run in sudo\n");
        exit(1);
    }
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
    // while (running) pause();

    sd_journal *j = NULL;
    int r = sd_journal_open(&j, SD_JOURNAL_LOCAL_ONLY);
    if(r < 0) {
        fprintf(stderr, "Failed to open journal: %s\n", strerror(-r));
        exit(1);
    }

    return PS_OK;
}
