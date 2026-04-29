#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <systemd/sd-journal.h>
#include <unistd.h>

#include "init.h"

volatile sig_atomic_t running = 1;
volatile sig_atomic_t reload_requested = 0;

static void handle_signal(int sig) {
    if (sig == SIGHUP)
        reload_requested = 1;
    else
        running = 0;
}

int ps_signal_init() {
    struct sigaction sa = {0};
    sa.sa_handler = handle_signal;
    // SA_RESTART so syscalls (e.g. sd_journal_wait) restart cleanly after the
    // handler returns rather than failing with EINTR.
    sa.sa_flags = SA_RESTART;

    if (sigaction(SIGINT, &sa, NULL) < 0)
        return PS_ERR_SIGNAL;
    if (sigaction(SIGTERM, &sa, NULL) < 0)
        return PS_ERR_SIGNAL;
    if (sigaction(SIGHUP, &sa, NULL) < 0)
        return PS_ERR_SIGNAL;

    // Auto-reap child processes (fork+exec curl for alerts).
    struct sigaction sa_chld = {0};
    sa_chld.sa_handler = SIG_IGN;
    sa_chld.sa_flags = SA_NOCLDWAIT;
    if (sigaction(SIGCHLD, &sa_chld, NULL) < 0)
        return PS_ERR_SIGNAL;

    // Ignore SIGPIPE: a curl child exiting while we still hold a pipe to it
    // would otherwise terminate the daemon.
    struct sigaction sa_pipe = {0};
    sa_pipe.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &sa_pipe, NULL) < 0)
        return PS_ERR_SIGNAL;

    return PS_OK;
}

int ps_daemonize() {
    pid_t pid = fork();
    if (pid < 0)
        return PS_ERR_INIT;
    if (pid > 0)
        _exit(0);

    if (setsid() < 0)
        return PS_ERR_INIT;

    pid = fork();
    if (pid < 0)
        return PS_ERR_INIT;
    if (pid > 0)
        _exit(0);

    umask(0077);
    if (chdir("/") < 0)
        return PS_ERR_INIT;

    int fd = open("/dev/null", O_RDWR);
    if (fd < 0)
        return PS_ERR_INIT;

    int fds[3] = {STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO};
    for (int i = 0; i < 3; i++) {
        if (dup2(fd, fds[i]) < 0) {
            close(fd);
            return PS_ERR_INIT;
        }
    }
    if (fd > 2)
        close(fd);

    return PS_OK;
}

int ps_init() {
    sd_journal_print(LOG_INFO, "pamsignal: initialized successfully");
    return PS_OK;
}

// --- PID file ---

static int pidfile_fd = -1;

// Read the existing pidfile and parse the PID. Returns 0 on success, -1 if
// the file is missing/unreadable/unparseable.
static int read_pidfile_pid(int dirfd, pid_t *pid_out) {
    int fd = openat(dirfd, PS_PID_FILE_NAME, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return -1;

    char buf[32];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0)
        return -1;
    buf[n] = '\0';

    char *end;
    errno = 0;
    long v = strtol(buf, &end, 10);
    if (end == buf || v <= 0 || v > INT_MAX || errno == ERANGE)
        return -1;

    *pid_out = (pid_t)v;
    return 0;
}

// True if the pidfile points at a process that is no longer running, or if
// its content cannot be parsed at all.
static int pidfile_is_stale(int dirfd, pid_t *stale_pid_out) {
    pid_t pid;
    if (read_pidfile_pid(dirfd, &pid) < 0) {
        // Unparseable / unreadable — treat as stale and remove on retry.
        *stale_pid_out = 0;
        return 1;
    }
    *stale_pid_out = pid;
    if (kill(pid, 0) == 0)
        return 0; // alive
    if (errno == EPERM)
        return 0; // exists but owned by another user — assume alive
    return 1;     // ESRCH or anything else: gone
}

int ps_pidfile_acquire(void) {
    int dirfd =
        open(PS_RUNTIME_DIR, O_DIRECTORY | O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (dirfd < 0) {
        sd_journal_print(LOG_ERR, "pamsignal: cannot open runtime dir %s: %m",
                         PS_RUNTIME_DIR);
        return PS_ERR_INIT;
    }

    pidfile_fd =
        openat(dirfd, PS_PID_FILE_NAME,
               O_WRONLY | O_CREAT | O_NOFOLLOW | O_EXCL | O_CLOEXEC, 0600);
    if (pidfile_fd < 0 && errno == EEXIST) {
        pid_t stale_pid = 0;
        if (pidfile_is_stale(dirfd, &stale_pid)) {
            // unlinkat clears the stale entry; the kernel's directory lookup
            // is atomic against an attacker swapping the inode for a symlink
            // because we hold dirfd.
            if (unlinkat(dirfd, PS_PID_FILE_NAME, 0) == 0) {
                sd_journal_print(LOG_INFO,
                                 "pamsignal: removed stale PID file (pid=%d)",
                                 (int)stale_pid);
                pidfile_fd = openat(
                    dirfd, PS_PID_FILE_NAME,
                    O_WRONLY | O_CREAT | O_NOFOLLOW | O_EXCL | O_CLOEXEC, 0600);
            }
        } else {
            sd_journal_print(LOG_ERR,
                             "pamsignal: another instance is running (pid=%d)",
                             (int)stale_pid);
        }
    }
    close(dirfd);

    if (pidfile_fd < 0)
        return PS_ERR_INIT;

    struct flock fl = {
        .l_type = F_WRLCK,
        .l_whence = SEEK_SET,
        .l_start = 0,
        .l_len = 0,
    };

    if (fcntl(pidfile_fd, F_SETLK, &fl) < 0) {
        close(pidfile_fd);
        pidfile_fd = -1;
        return PS_ERR_INIT;
    }

    char buf[32];
    int n = snprintf(buf, sizeof(buf), "%d\n", getpid());
    if (n < 0 || (size_t)n >= sizeof(buf)) {
        close(pidfile_fd);
        pidfile_fd = -1;
        return PS_ERR_INIT;
    }
    if (write(pidfile_fd, buf, (size_t)n) != (ssize_t)n) {
        close(pidfile_fd);
        pidfile_fd = -1;
        return PS_ERR_INIT;
    }

    return PS_OK;
}

void ps_pidfile_release(void) {
    if (pidfile_fd >= 0) {
        unlink(PS_PID_FILE);
        close(pidfile_fd);
        pidfile_fd = -1;
    }
}
