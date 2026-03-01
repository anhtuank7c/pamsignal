#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <systemd/sd-journal.h>
#include <unistd.h>

#include "init.h"

int main()
{
    if (geteuid() != 0)
    {
        fprintf(stderr, "This program must be run in sudo\n");
        exit(1);
    }
    int ret;

    ret = ps_daemonize();
    switch (ret)
    {
    case PS_OK:
        break;
    default:
        fprintf(stderr, "Daemonization failed with code %d\n", ret);
        return ret;
    }

    ret = ps_signal_init();
    switch (ret)
    {
    case PS_OK:
        break;
    default:
        fprintf(stderr, "Signal init failed with code %d\n", ret);
        return ret;
    }

    ret = ps_init();
    switch (ret)
    {
    case PS_OK:
        break;
    default:
        fprintf(stderr, "Init failed with code %d\n", ret);
        return ret;
    }

    // NOTE: A venue for initiating future PAMSignal events
    // while (running) pause();

    sd_journal *j = NULL;
    /* Hiep's review:
        Did you forget to close the sd_journal after use? Always ensure to call sd_journal_close(j) when done to free resources and avoid memory leaks.
        And point j is not used in the current code, so you can remove it if it's not needed.
    */

    int r = sd_journal_open(&j, SD_JOURNAL_LOCAL_ONLY);
    if (r < 0)
    {
        fprintf(stderr, "Failed to open journal: %s\n", strerror(-r));
        exit(1);
    }

    return PS_OK;
}

/* Here are Hiep's reviews:
    1)
        Please use systemd logging journal instead of printf for better integration with system logs.
        You can use sd_journal_print() for this purpose.
    2)
        Please create your systemd service file for PAMSignal because linux uses systemd to manage daemons,
        and ensure it is properly installed and enabled on the system.
        For example: pamsignal.service
            [Unit]
            Description=PAMSignal Daemon
            After=network.target

            [Service]
            Type=simple
            ExecStart=/usr/local/bin/pamsignal
            Restart=on-failure
            RestartSec=2
            KillSignal=SIGTERM

            # Security hardening (optional but recommended)
            NoNewPrivileges=true
            PrivateTmp=true
            ProtectSystem=full
            ProtectHome=true

            [Install]
            WantedBy=multi-user.target

        And your current code is quite good but it uses systemV. Please learn more about systemd.
        Otherwise, you code firstly and i will fix your code later.
    3)
        If i were you. The code snippet below will be refactored:
        [======= FROM =======]
        ret = ps_daemonize();
        switch (ret)
        {
        case PS_OK:
            break;
        default:
            fprintf(stderr, "Daemonization failed with code %d\n", ret);
            return ret;
        }

        ret = ps_signal_init();
        switch (ret)
        {
        case PS_OK:
            break;
        default:
            fprintf(stderr, "Signal init failed with code %d\n", ret);
            return ret;
        }

        ret = ps_init();
        switch (ret)
        {
        case PS_OK:
            break;
        default:
            fprintf(stderr, "Init failed with code %d\n", ret);
            return ret;
        }

        [======= TO =======]
        if ((ret = ps_daemonize()) != PS_OK) return EXIT_FAILURE;
        if ((ret = ps_signal_init()) != PS_OK) return EXIT_FAILURE;
        if ((ret = ps_init()) != PS_OK) return EXIT_FAILURE;

        TRY to avoid the switch-case statement for error handling in this context, as it adds unnecessary verbosity and reduces readability.
*/