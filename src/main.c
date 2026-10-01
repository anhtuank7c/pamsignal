#include <errno.h>
#include <grp.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <syslog.h>
#include <systemd/sd-daemon.h>
#include <systemd/sd-journal.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "init.h"
#include "journal_watch.h"
#include "notify.h"

static void print_version(void) {
    printf("pamsignal %s\n", PAMSIGNAL_VERSION);
}

static void print_help(void) {
    printf(
        "Usage: pamsignal [OPTION]...\n"
        "Real-time PAM authentication monitor with multi-channel alerts.\n"
        "\n"
        "Watches the systemd journal for sshd, sudo, su, and login events,\n"
        "detects brute-force patterns, and dispatches alerts to Telegram,\n"
        "Slack, Microsoft Teams, WhatsApp, Discord, or a custom HTTPS webhook.\n"
        "\n"
        "Options:\n"
        "  -f, --foreground       Stay in the foreground (do not daemonize).\n"
        "                         Required under systemd Type=simple; the\n"
        "                         shipped pamsignal.service uses this mode.\n"
        "  -c, --config PATH      Read configuration from PATH instead of\n"
        "                         the compiled-in default (%s).\n"
        "  -t, --check-config     Validate the configuration file, report any\n"
        "                         errors on stderr, and exit (0 = valid).\n"
        "  -T, --test-alert       Send a test message to every configured\n"
        "                         alert channel, print a result per channel,\n"
        "                         and exit (0 = all delivered).\n"
        "  -V, --version          Print version and exit.\n"
        "  -h, --help             Print this help message and exit.\n"
        "\n"
        "Files:\n"
        "  %s\n"
        "      Configuration file (alert credentials, brute-force thresholds,\n"
        "      mTLS paths). See pamsignal.conf(5).\n"
        "  /run/pamsignal/pamsignal.pid\n"
        "      PID file (foreground mode skips this).\n"
        "\n"
        "See pamsignal(8) and pamsignal.conf(5) for the complete reference.\n"
        "Report bugs at https://github.com/anhtuank7c/pamsignal/issues\n",
        PS_DEFAULT_CONFIG_PATH, PS_DEFAULT_CONFIG_PATH);
}

// One-shot modes run a single check from a terminal and exit instead of
// starting the monitor.
typedef enum {
    PS_MODE_DAEMON,
    PS_MODE_CHECK_CONFIG,
    PS_MODE_TEST_ALERT
} ps_run_mode_t;

static void parse_args(int argc, char *argv[], int *foreground,
                       const char **config_path, ps_run_mode_t *mode) {
    *foreground = 0;
    *config_path = PS_DEFAULT_CONFIG_PATH;
    *mode = PS_MODE_DAEMON;

    for (int i = 1; i < argc; i++) {
        // --version / --help exit immediately, before any privilege or
        // journal-access checks. This lets package post-install scripts
        // and smoke tests run from any context (root, dpkg, rpm, plain
        // user) without tripping the non-root invariant enforced later
        // in main(). Both go to stdout, exit 0, per GNU conventions.
        if (strcmp(argv[i], "--version") == 0 || strcmp(argv[i], "-V") == 0) {
            print_version();
            exit(0);
        }
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_help();
            exit(0);
        }
        if (strcmp(argv[i], "--foreground") == 0 ||
            strcmp(argv[i], "-f") == 0) {
            *foreground = 1;
        } else if (strcmp(argv[i], "--check-config") == 0 ||
                   strcmp(argv[i], "-t") == 0) {
            *mode = PS_MODE_CHECK_CONFIG;
        } else if (strcmp(argv[i], "--test-alert") == 0 ||
                   strcmp(argv[i], "-T") == 0) {
            *mode = PS_MODE_TEST_ALERT;
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

// --check-config: the file has already loaded cleanly; summarise what the
// daemon would do with it.
static int run_check_config(void) {
    static const struct {
        const char *name;
        size_t offset;
    } channels[] = {
        {"telegram", offsetof(ps_config_t, telegram_bot_token)},
        {"slack", offsetof(ps_config_t, slack_webhook_url)},
        {"teams", offsetof(ps_config_t, teams_webhook_url)},
        {"whatsapp", offsetof(ps_config_t, whatsapp_access_token)},
        {"discord", offsetof(ps_config_t, discord_webhook_url)},
        {"webhook", offsetof(ps_config_t, webhook_url)},
    };

    printf("pamsignal: %s: configuration OK\n", g_config_path);
    printf("  alert channels:");
    int enabled = 0;
    for (size_t i = 0; i < sizeof(channels) / sizeof(channels[0]); i++) {
        if (((const char *)&g_config)[channels[i].offset]) {
            printf(" %s", channels[i].name);
            enabled++;
        }
    }
    if (!enabled)
        printf(" none (events are only written to the journal)");
    printf("\n  trusted sources: %d\n", g_config.trusted_sources_count);
    return 0;
}

// --test-alert: push one message through every configured channel and wait
// for the verdicts.
static int run_test_alert(void) {
    char hostname[256] = "unknown";
    if (gethostname(hostname, sizeof(hostname)) == 0)
        hostname[sizeof(hostname) - 1] = '\0';

    struct timespec now = {0};
    clock_gettime(CLOCK_REALTIME, &now);
    uint64_t now_usec =
        (uint64_t)now.tv_sec * 1000000ULL + (uint64_t)now.tv_nsec / 1000ULL;

    int failed = ps_notify_test(&g_config, hostname, now_usec);
    if (failed < 0) {
        fprintf(stderr,
                "pamsignal: no alert channel is configured in %s; nothing "
                "to test\n",
                g_config_path);
        return 1;
    }
    if (failed > 0) {
        fprintf(stderr, "pamsignal: %d alert channel(s) failed\n", failed);
        return 1;
    }
    printf("pamsignal: test alert delivered to every configured channel\n");
    return 0;
}

int main(int argc, char *argv[]) {
    int foreground;
    const char *config_path;
    ps_run_mode_t mode;
    parse_args(argc, argv, &foreground, &config_path, &mode);

    if (geteuid() == 0 && mode != PS_MODE_DAEMON) {
        // Same non-root invariant as the daemon: the ownership checks on the
        // config and TLS key files are relative to the effective uid, so the
        // result is only meaningful when run as the service user.
        fprintf(stderr,
                "pamsignal: do not run this check as root. Run it as "
                "the service user so the\n"
                "result matches what the daemon will see:\n"
                "  sudo -u pamsignal pamsignal %s\n",
                mode == PS_MODE_CHECK_CONFIG ? "--check-config"
                                             : "--test-alert");
        return 1;
    }

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

    // The one-shot modes never read the journal, so they do not need the
    // systemd-journal group.
    if (mode == PS_MODE_DAEMON && !has_journal_access()) {
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
        if (mode != PS_MODE_DAEMON) {
            // The daemon tolerates a missing file (compiled defaults), but
            // an operator asking to check or test one almost certainly
            // mistyped the path.
            fprintf(stderr, "pamsignal: config file not found: %s\n",
                    config_path);
            return 1;
        }
    } else {
        fprintf(stderr, "pamsignal: cannot resolve config path %s: %s\n",
                config_path, strerror(errno));
        return 1;
    }

    if (mode != PS_MODE_DAEMON)
        ps_config_log_to_stderr(1);

    int ret = ps_config_load(g_config_path, &g_config);
    if (ret != PS_OK) {
        fprintf(stderr, "pamsignal: failed to load config: %s\n",
                g_config_path);
        return 1;
    }

    if (mode == PS_MODE_CHECK_CONFIG)
        return run_check_config();

    if (mode == PS_MODE_TEST_ALERT) {
        // Same setuid-escalation guard the daemon applies to its curl
        // children.
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
            fprintf(stderr, "pamsignal: PR_SET_NO_NEW_PRIVS failed: %s\n",
                    strerror(errno));
        return run_test_alert();
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
