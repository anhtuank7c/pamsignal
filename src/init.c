#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <systemd/sd-journal.h>
#include <unistd.h>

#include "init.h"

atomic_bool running = 1;
atomic_bool reload_requested = 0;

static void handle_signal(int sig) {
  if (sig == SIGHUP)
    reload_requested = 1;
  else
    running = 0;
}

int ps_signal_init() {
  struct sigaction sa = {0};
  sa.sa_handler = handle_signal;

  if (sigaction(SIGINT, &sa, NULL) < 0)
    return PS_ERR_SIGNAL;
  if (sigaction(SIGTERM, &sa, NULL) < 0)
    return PS_ERR_SIGNAL;
  if (sigaction(SIGHUP, &sa, NULL) < 0)
    return PS_ERR_SIGNAL;

  // Auto-reap child processes (fork+exec curl for alerts)
  struct sigaction sa_chld = {0};
  sa_chld.sa_handler = SIG_IGN;
  sa_chld.sa_flags = SA_NOCLDWAIT;
  if (sigaction(SIGCHLD, &sa_chld, NULL) < 0)
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

static int pidfile_fd = -1;

int ps_pidfile_acquire(void) {
  pidfile_fd = open(PS_PID_FILE, O_WRONLY | O_CREAT | O_NOFOLLOW | O_EXCL, 0600);
  if (pidfile_fd < 0) {
    // If file exists from a previous unclean shutdown, unlink and retry once
    if (errno == EEXIST) {
      unlink(PS_PID_FILE);
      pidfile_fd = open(PS_PID_FILE, O_WRONLY | O_CREAT | O_NOFOLLOW | O_EXCL, 0600);
    }
    if (pidfile_fd < 0)
      return PS_ERR_INIT;
  }

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
