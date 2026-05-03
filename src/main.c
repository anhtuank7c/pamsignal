#include <errno.h>
#include <grp.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <syslog.h>
#include <systemd/sd-daemon.h>
#include <systemd/sd-journal.h>
#include <unistd.h>

#include "config.h"
#include "init.h"
#include "journal_watch.h"

static void parse_args(int argc, char *argv[], int *foreground,
                       const char **config_path) {
    *foreground = 0;
    *config_path = PS_DEFAULT_CONFIG_PATH;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--foreground") == 0 ||
            strcmp(argv[i], "-f") == 0) {
            *foreground = 1;
        } else if ((strcmp(argv[i], "--config") == 0 ||
                    strcmp(argv[i], "-c") == 0) &&
                   i + 1 < argc) {
            *config_path = argv[++i];
        }
    }
}

// Check if the current user belongs to the systemd-journal group.
//
// Uses a fixed-size stack buffer rather than malloc(getgroups(0, NULL))
// for two reasons:
//   1. Eliminates a tainted-syscall-into-malloc path that
//      clang-analyzer-optin.taint.TaintedAlloc otherwise flags.
//   2. NGROUPS_MAX on Linux is 65536, but real users have fewer than 32
//      supplementary groups; 256 is a generous upper bound. If a user
//      somehow exceeds the buffer, getgroups returns -1/EINVAL and the
//      daemon fails closed with the same "add user to systemd-journal"
//      error path as if they truly weren't a member.
static int has_journal_access(void) {
    struct group *grp = getgrnam("systemd-journal");
    if (!grp)
        return 0;

    gid_t target_gid = grp->gr_gid;

    // Primary group
    if (getegid() == target_gid)
        return 1;

    // Supplementary groups
    enum { PS_GROUPS_BUF_LEN = 256 };
    gid_t groups[PS_GROUPS_BUF_LEN];
    int ngroups = getgroups(PS_GROUPS_BUF_LEN, groups);
    if (ngroups < 0)
        return 0;

    for (int i = 0; i < ngroups; i++) {
        if (groups[i] == target_gid)
            return 1;
    }

    return 0;
}

int main(int argc, char *argv[]) {
    int foreground;
    const char *config_path;
    parse_args(argc, argv, &foreground, &config_path);

    if (geteuid() == 0) {
        fprintf(stderr, "pamsignal should not run as root.\n"
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

    // Resolve config path to absolute before daemonize calls chdir("/").
    // Failure modes:
    //   ENOENT — file doesn't exist; ps_config_load will fall back to
    //            defaults. Keep the original (likely default) path.
    //   anything else (EACCES, ELOOP, ENAMETOOLONG, ...) — refuse to start.
    //   Continuing with an unresolvable user-supplied path could surface a
    //   symlink swap or permission misconfiguration.
    static char resolved_path[PATH_MAX];
    if (realpath(config_path, resolved_path)) {
        g_config_path = resolved_path;
    } else if (errno == ENOENT) {
        g_config_path = config_path;
    } else {
        fprintf(stderr, "pamsignal: cannot resolve config path %s: %s\n",
                config_path, strerror(errno));
        return 1;
    }

    int ret = ps_config_load(g_config_path, &g_config);
    if (ret != PS_OK) {
        fprintf(stderr, "pamsignal: failed to load config: %s\n",
                g_config_path);
        return 1;
    }

    ret = ps_fail_table_init(g_config.max_tracked_ips);
    if (ret != PS_OK) {
        fprintf(stderr, "pamsignal: failed to allocate fail table\n");
        return 1;
    }

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

    // Refuse setuid escalation in any descendant (curl alert children).
    // A no-op under the systemd unit (NoNewPrivileges=yes already sets it),
    // but covers manual / non-systemd launches.
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        sd_journal_print(LOG_WARNING,
                         "pamsignal: PR_SET_NO_NEW_PRIVS failed: %m");
    }

    // Cap concurrent processes for this UID. A flood of journal events that
    // trigger alerts cannot fork-bomb the system: extra fork() calls return
    // EAGAIN and the alert is dropped. 64 leaves headroom for the daemon
    // plus a burst of fire-and-forget curl children.
    struct rlimit rl_nproc = {.rlim_cur = 64, .rlim_max = 64};
    if (setrlimit(RLIMIT_NPROC, &rl_nproc) < 0) {
        sd_journal_print(LOG_WARNING,
                         "pamsignal: setrlimit(RLIMIT_NPROC) failed: %m");
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
        sd_journal_print(LOG_ERR, "pamsignal: journal init failed with code %d",
                         ret);
        return ret;
    }

    sd_journal_print(LOG_INFO,
                     "pamsignal: daemon started, monitoring PAM events");

    // Tell systemd we're ready to process events. With Type=notify in the
    // unit, systemd holds the unit in "activating" until this fires. On
    // platforms without a notification socket (manual launch outside
    // systemd, test runs) sd_notify is a no-op and returns 0.
    sd_notify(0, "READY=1");

    ret = ps_journal_watch_run(j);

    sd_journal_print(LOG_INFO, "pamsignal: shutting down");
    ps_journal_watch_cleanup(j);

    if (!foreground)
        ps_pidfile_release();

    return ret;
}
