#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "init.h"

atomic_bool running = 1;

static void handle_signal(int sig) {
    (void)sig;
    running = 0;
}

int ps_signal_init() {
    struct sigaction sa = {0};
    sa.sa_handler = handle_signal;

    if (sigaction(SIGINT, &sa, NULL) < 0)
        return PS_ERR_SIGNAL;
    if (sigaction(SIGTERM, &sa, NULL) < 0)
        return PS_ERR_SIGNAL;

    return PS_OK;
}

int ps_daemonize() {
    pid_t pid = fork();
    if (pid < 0) return PS_ERR_INIT;
    if (pid > 0) _exit(0);

    if (setsid() < 0) return PS_ERR_INIT;

    pid = fork();
    if (pid < 0) return PS_ERR_INIT;
    if (pid > 0) _exit(0);

    umask(0);
    chdir("/");

    int fd = open("/dev/null", O_RDWR);
    if (fd >= 0) {
        int fds[3] = {STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO};
        for (int i=0; i<3; i++) {
            if (dup2(fd, fds[i]) < 0) {
                perror("dup2 failed");
                return PS_ERR_INIT;
            }
        }
        if (fd > 2) close(fd);
    }
    return PS_OK;
}

int ps_init() {
    printf("PAMSignal: Initialize successful on Linux!\n");
    return PS_OK;
}
