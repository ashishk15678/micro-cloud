// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Aman Deep (amdeep.dev@gmail.com)
// SPDX-FileCopyrightText: 2026 Ashish Kumar <15678ashishk@gmail.com>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

#include "../include/log/log.h"
#define PID_FILE "/var/run/daemon.pid"

volatile sig_atomic_t daemon_running = 1;

void handle_signal(int sig) {
    if (sig == SIGTERM || sig == SIGINT) {
        INFO("Received termination signal (%d). Initiating graceful shutdown...", sig);
        daemon_running = 0;
    }
}

void ensure_single_instance() {
    // SECURITY:
    // O_CLOEXEC prevents child VMs/containers from inheriting this lock.
    // O_NOFOLLOW prevents symlink attacks (overwriting arbitrary files).
    int fd = open(PID_FILE, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0640);
    if (fd < 0) {
        LOG_FATAL("Could not open PID file %s: %m", PID_FILE); // %m expands to strerror(errno)
    }

    struct flock fl = {
        .l_type = F_WRLCK,
        .l_whence = SEEK_SET,
        .l_start = 0,
        .l_len = 0
    };

    if (fcntl(fd, F_SETLK, &fl) == -1) {
        if (errno == EACCES || errno == EAGAIN) {
            LOG_FATAL("Daemon is already running. Check %s", PID_FILE);
        } else {
            LOG_FATAL("Failed to lock PID file: %m");
        }
    }

    if (ftruncate(fd, 0) == -1) {
        LOG_FATAL("Failed to truncate PID file: %m");
    }

    char pid_str[32];
    int len = snprintf(pid_str, sizeof(pid_str), "%d\n", getpid());
    if (write(fd, pid_str, len) != len) {
        LOG_FATAL("Failed to write to PID file: %m");
    }
}

// \brief : Create a daemon process and setup in background
// using fork
void daemonize() {
    pid_t pid;
    int fd;

    pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS);

    if (setsid() < 0) exit(EXIT_FAILURE);

    signal(SIGHUP, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);

    pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS);

    // SECURITY: Set umask to 027 (Group can read, Others have no access).
    umask(027);

    if (chdir("/") < 0) {
        exit(EXIT_FAILURE);
    }

    // SECURITY: Cleanly redirect standard I/O to /dev/null
    fd = open("/dev/null", O_RDWR);
    if (fd >= 0) {
        dup2(fd, STDIN_FILENO);
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        if (fd > 2) {
            close(fd);
        }
    }
}

int main() {
    daemonize();

    log_init("iaasd");

    struct sigaction sa;
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGTERM, &sa, NULL) == -1 || sigaction(SIGINT, &sa, NULL) == -1) {
        LOG_FATAL("Failed to register signal handlers: %m");
    }
    ensure_single_instance();

    INFO("Micro-IaaS Daemon (iaasd) started successfully.");

    while (daemon_running) {
        sleep(1);
    }

    INFO("Micro-IaaS Daemon shutting down.");
    unlink(PID_FILE);
    log_close();

    return EXIT_SUCCESS;
}
