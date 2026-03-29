#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <systemd/sd-journal.h>
#include <unistd.h>

#include "init.h"
#include "journal_watch.h"

static int parse_foreground(int argc, char *argv[]) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--foreground") == 0 ||
            strcmp(argv[i], "-f") == 0)
            return 1;
    }
    return 0;
}

// Check if the current user belongs to the systemd-journal group
static int has_journal_access(void) {
    struct group *grp = getgrnam("systemd-journal");
    if (!grp)
        return 0;

    gid_t target_gid = grp->gr_gid;

    // Check primary group
    if (getegid() == target_gid)
        return 1;

    // Check supplementary groups
    int ngroups = getgroups(0, NULL);
    if (ngroups <= 0)
        return 0;

    gid_t *groups = malloc((size_t)ngroups * sizeof(gid_t));
    if (!groups)
        return 0;

    if (getgroups(ngroups, groups) < 0) {
        free(groups);
        return 0;
    }

    for (int i = 0; i < ngroups; i++) {
        if (groups[i] == target_gid) {
            free(groups);
            return 1;
        }
    }

    free(groups);
    return 0;
}

int main(int argc, char *argv[]) {
    int foreground = parse_foreground(argc, argv);

    if (geteuid() == 0) {
        fprintf(stderr,
                "pamsignal should not run as root.\n"
                "Create a dedicated user and add it to the "
                "systemd-journal group:\n"
                "  sudo useradd -r -s /usr/sbin/nologin pamsignal\n"
                "  sudo usermod -aG systemd-journal pamsignal\n"
                "Then run as:\n"
                "  sudo -u pamsignal ./build/pamsignal\n");
        return 1;
    }

    if (!has_journal_access()) {
        const char *user = getenv("USER");
        fprintf(stderr,
                "pamsignal: current user is not in the systemd-journal "
                "group.\n"
                "Fix with:\n"
                "  sudo usermod -aG systemd-journal %s\n"
                "Then log out and back in, or run:\n"
                "  newgrp systemd-journal\n",
                user ? user : "(unknown)");
        return 1;
    }

    int ret;

    if (!foreground) {
        ret = ps_daemonize();
        if (ret != PS_OK) {
            fprintf(stderr, "Daemonization failed with code %d\n", ret);
            return ret;
        }

        // After daemonization, stderr goes to /dev/null.

        ret = ps_pidfile_acquire();
        if (ret != PS_OK) {
            sd_journal_print(LOG_ERR,
                             "pamsignal: another instance is already running "
                             "or cannot create PID file");
            return ret;
        }
    }

    ret = ps_signal_init();
    if (ret != PS_OK) {
        sd_journal_print(LOG_ERR, "pamsignal: signal init failed with code %d",
                         ret);
        return ret;
    }

    ret = ps_init();
    if (ret != PS_OK) {
        sd_journal_print(LOG_ERR, "pamsignal: init failed with code %d", ret);
        return ret;
    }

    sd_journal *j = NULL;
    ret = ps_journal_watch_init(&j);
    if (ret != PS_OK) {
        sd_journal_print(LOG_ERR,
                         "pamsignal: journal init failed with code %d", ret);
        return ret;
    }

    sd_journal_print(LOG_INFO,
                     "pamsignal: daemon started, monitoring PAM events");

    ret = ps_journal_watch_run(j);

    sd_journal_print(LOG_INFO, "pamsignal: shutting down");
    ps_journal_watch_cleanup(j);

    if (!foreground)
        ps_pidfile_release();

    return ret;
}
