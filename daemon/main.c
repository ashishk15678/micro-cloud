// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Aman Deep <amdeep.dev@gmail.com>
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
#include <sys/socket.h>
#include <sys/un.h>
#include <poll.h>
#include <time.h>

#include "../include/log/log.h"
#include "../include/daemon/ipc.h"
#include "utils/state.h"
#include "utils/instance.h"

static volatile sig_atomic_t daemon_running = 1;
static iaasd_state_t g_state;

/** \brief Ensure the daemon is running as root for privileged operations. */
static void ensure_root(void) {
    if (geteuid() != 0) {
        fprintf(stderr, "iaasd must be run as root (requires /dev/loop and /var/lib/iaasd).\n");
        exit(EXIT_FAILURE);
    }
}

/** \brief Create a directory or abort on failure. */
static void ensure_dir_or_die(const char *path, mode_t mode) {
    if (mkdir(path, mode) != 0 && errno != EEXIST) {
        LOG_FATAL("Failed to create %s: %m", path);
    }
}

/** \brief Ensure required runtime directories exist with safe permissions. */
static void ensure_runtime_dirs(void) {
    ensure_dir_or_die("/run/iaasd", 0700);
    ensure_dir_or_die("/var/log/iaasd", 0700);
    ensure_dir_or_die("/var/lib/iaasd", 0700);
    ensure_dir_or_die(IAASD_INSTANCE_DIR, 0700);
}

/** \brief Handle termination signals for graceful shutdown. */
static void handle_signal(int sig) {
    if (sig == SIGTERM || sig == SIGINT) {
        INFO("Received termination signal (%d). Initiating graceful shutdown...", sig);
        daemon_running = 0;
    }
}

/** \brief Acquire a PID lock to prevent multiple daemon instances. */
static void ensure_single_instance(void) {
    // SECURITY:
    // O_CLOEXEC prevents child VMs/containers from inheriting this lock.
    // O_NOFOLLOW prevents symlink attacks (overwriting arbitrary files).
    int fd = open(IAASD_PID_PATH, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0640);
    if (fd < 0) {
        LOG_FATAL("Could not open PID file %s: %m", IAASD_PID_PATH); // %m expands to strerror(errno)
    }

    struct flock fl = {
        .l_type = F_WRLCK,
        .l_whence = SEEK_SET,
        .l_start = 0,
        .l_len = 0
    };

    if (fcntl(fd, F_SETLK, &fl) == -1) {
        if (errno == EACCES || errno == EAGAIN) {
            LOG_FATAL("Daemon is already running. Check %s", IAASD_PID_PATH);
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
/** \brief Detach the process and run as a background daemon. */
static void daemonize(void) {
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

/** \brief Create and bind the IPC UNIX domain socket. */
static int setup_ipc_socket(void) {
    int server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd < 0) {
        LOG_FATAL("Failed to create IPC socket: %m");
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, IAASD_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    unlink(IAASD_SOCKET_PATH);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        close(server_fd);
        LOG_FATAL("Failed to bind IPC socket %s: %m", IAASD_SOCKET_PATH);
    }

    if (listen(server_fd, IAASD_SOCKET_BACKLOG) == -1) {
        close(server_fd);
        LOG_FATAL("Failed to listen on IPC socket: %m");
    }

    if (chmod(IAASD_SOCKET_PATH, 0600) == -1) {
        WARN("Failed to chmod IPC socket %s: %m", IAASD_SOCKET_PATH);
    }

    return server_fd;
}

/** \brief Send a plaintext response to the IPC client. */
static void send_reply(int client_fd, const char *msg) {
    if (!msg) {
        return;
    }
    send(client_fd, msg, strlen(msg), 0);
}

/** \brief Send a formatted error response to the IPC client. */
static void send_error(int client_fd, const char *msg) {
    char buf[256];
    snprintf(buf, sizeof(buf), "%s %s\n", IAASD_ERROR_REPLY, msg ? msg : "unknown");
    send_reply(client_fd, buf);
}

/** \brief Parse an unsigned 64-bit integer from a string. */
static bool parse_u64(const char *s, uint64_t *out) {
    if (!s || *s == '\0') {
        return false;
    }
    errno = 0;
    char *end = NULL;
    unsigned long long val = strtoull(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0') {
        return false;
    }
    *out = (uint64_t)val;
    return true;
}

/** \brief Parse instance arguments from IPC tokens. */
static bool parse_instance_req(char *save, const iaasd_state_t *limits,
                               iaasd_instance_req_t *req, char *err, size_t err_len) {
    if (!req || !limits) {
        snprintf(err, err_len, "invalid instance request");
        return false;
    }

    memset(req, 0, sizeof(*req));
    snprintf(req->ssh_user, sizeof(req->ssh_user), "ubuntu");
    req->ram_mib = limits->quota_ram_mib;
    req->disk_gib = limits->quota_disk_gib;
    req->vcpus = 2;
    req->ssh_port = 2222;

    char *arg = NULL;
    while ((arg = strtok_r(NULL, " \t\r\n", &save)) != NULL) {
        if (strncmp(arg, "NAME=", 5) == 0) {
            snprintf(req->name, sizeof(req->name), "%s", arg + 5);
        } else if (strncmp(arg, "IMAGE=", 6) == 0) {
            snprintf(req->image_path, sizeof(req->image_path), "%s", arg + 6);
        } else if (strncmp(arg, "SSH_KEY=", 8) == 0) {
            snprintf(req->ssh_key_path, sizeof(req->ssh_key_path), "%s", arg + 8);
        } else if (strncmp(arg, "USER=", 5) == 0) {
            snprintf(req->ssh_user, sizeof(req->ssh_user), "%s", arg + 5);
        } else if (strncmp(arg, "RAM=", 4) == 0) {
            uint64_t val = 0;
            if (!parse_u64(arg + 4, &val)) {
                snprintf(err, err_len, "invalid RAM value");
                return false;
            }
            req->ram_mib = val;
        } else if (strncmp(arg, "DISK=", 5) == 0) {
            uint64_t val = 0;
            if (!parse_u64(arg + 5, &val)) {
                snprintf(err, err_len, "invalid DISK value");
                return false;
            }
            req->disk_gib = val;
        } else if (strncmp(arg, "VCPU=", 5) == 0) {
            req->vcpus = atoi(arg + 5);
        } else if (strncmp(arg, "SSH_PORT=", 9) == 0) {
            req->ssh_port = atoi(arg + 9);
        }
    }

    if (req->name[0] == '\0' || req->image_path[0] == '\0' || req->ssh_key_path[0] == '\0') {
        snprintf(err, err_len, "NAME, IMAGE, and SSH_KEY are required");
        return false;
    }

    if (req->vcpus <= 0) {
        snprintf(err, err_len, "VCPU must be positive");
        return false;
    }

    if (req->ssh_port <= 0 || req->ssh_port > 65535) {
        snprintf(err, err_len, "invalid SSH_PORT");
        return false;
    }

    return true;
}

/** \brief Parse and execute a single IPC command. */
static void handle_client(int client_fd) {
    char buffer[IAASD_MAX_CMD_LEN];
    ssize_t bytes_read = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
    if (bytes_read <= 0) {
        return;
    }

    buffer[bytes_read] = '\0';

    char *save = NULL;
    char *cmd = strtok_r(buffer, " \t\r\n", &save);
    if (!cmd) {
        send_error(client_fd, "empty command");
        return;
    }

    if (strcmp(cmd, "PING") == 0) {
        send_reply(client_fd, IAASD_PONG_REPLY "\n");
        return;
    }

    if (strcmp(cmd, "STATUS") == 0) {
        send_reply(client_fd, IAASD_RUNNING_REPLY "\n");
        return;
    }

    if (strcmp(cmd, IAASD_AUTH_CMD) == 0) {
        char *user = strtok_r(NULL, " \t\r\n", &save);
        char *pass = strtok_r(NULL, " \t\r\n", &save);
        if (!user || !pass) {
            send_error(client_fd, "auth requires user and password");
            return;
        }

        char token[128];
        int64_t expires = 0;
        char err[128] = "";
        if (state_authenticate(&g_state, user, pass, token, sizeof(token), &expires, err, sizeof(err)) != 0) {
            send_error(client_fd, err[0] ? err : "auth failed");
            return;
        }

        char reply[256];
        snprintf(reply, sizeof(reply), "TOKEN %s %lld\n", token, (long long)expires);
        send_reply(client_fd, reply);
        INFO("Admin authenticated");
        return;
    }

    if (strcmp(cmd, IAASD_GET_QUOTA_CMD) == 0) {
        char *token = strtok_r(NULL, " \t\r\n", &save);
        if (!token) {
            send_error(client_fd, "token required");
            return;
        }
        int64_t now = (int64_t)time(NULL);
        if (!state_token_valid(&g_state, token, now)) {
            send_error(client_fd, "invalid or expired token");
            return;
        }

        char reply[256];
        snprintf(reply, sizeof(reply), "QUOTA RAM=%llu DISK=%llu NET=%llu\n",
                 (unsigned long long)g_state.quota_ram_mib,
                 (unsigned long long)g_state.quota_disk_gib,
                 (unsigned long long)g_state.quota_net_mbps);
        send_reply(client_fd, reply);
        return;
    }

    if (strcmp(cmd, IAASD_SET_QUOTA_CMD) == 0) {
        char *token = strtok_r(NULL, " \t\r\n", &save);
        if (!token) {
            send_error(client_fd, "token required");
            return;
        }
        int64_t now = (int64_t)time(NULL);
        if (!state_token_valid(&g_state, token, now)) {
            send_error(client_fd, "invalid or expired token");
            return;
        }

        uint64_t ram = 0, disk = 0, net = 0;
        bool have_ram = false, have_disk = false, have_net = false;

        char *arg = NULL;
        while ((arg = strtok_r(NULL, " \t\r\n", &save)) != NULL) {
            if (strncmp(arg, "RAM=", 4) == 0) {
                have_ram = parse_u64(arg + 4, &ram);
            } else if (strncmp(arg, "DISK=", 5) == 0) {
                have_disk = parse_u64(arg + 5, &disk);
            } else if (strncmp(arg, "NET=", 4) == 0) {
                have_net = parse_u64(arg + 4, &net);
            }
        }

        if (!have_ram || !have_disk || !have_net) {
            send_error(client_fd, "quota values required (RAM/DISK/NET)");
            return;
        }

        g_state.quota_ram_mib = ram;
        g_state.quota_disk_gib = disk;
        g_state.quota_net_mbps = net;

        char err[128] = "";
        if (state_save(IAASD_STATE_PATH, &g_state, err, sizeof(err)) != 0) {
            send_error(client_fd, err[0] ? err : "failed to persist state");
            return;
        }

        send_reply(client_fd, IAASD_OK_REPLY "\n");
        INFO("Quotas updated: RAM=%llu MiB DISK=%llu GiB NET=%llu Mbps",
             (unsigned long long)ram, (unsigned long long)disk, (unsigned long long)net);
        return;
    }

    if (strcmp(cmd, IAASD_CREATE_INSTANCE_CMD) == 0) {
        char *token = strtok_r(NULL, " \t\r\n", &save);
        if (!token) {
            send_error(client_fd, "token required");
            return;
        }
        int64_t now = (int64_t)time(NULL);
        if (!state_token_valid(&g_state, token, now)) {
            send_error(client_fd, "invalid or expired token");
            return;
        }

        iaasd_instance_req_t req;
        char req_err[128] = "";
        if (!parse_instance_req(save, &g_state, &req, req_err, sizeof(req_err))) {
            send_error(client_fd, req_err[0] ? req_err : "invalid instance request");
            return;
        }

        iaasd_instance_t inst;
        char inst_err[256] = "";
        if (instance_create(&req, &g_state, &inst, inst_err, sizeof(inst_err)) != 0) {
            send_error(client_fd, inst_err[0] ? inst_err : "instance create failed");
            return;
        }

        char reply[256];
        snprintf(reply, sizeof(reply), "OK NAME=%s USER=%s SSH_PORT=%d\n",
                 inst.name, inst.ssh_user, inst.ssh_port);
        send_reply(client_fd, reply);
        INFO("Instance created: %s (ssh %s@127.0.0.1 -p %d)", inst.name, inst.ssh_user, inst.ssh_port);
        return;
    }

    if (strcmp(cmd, IAASD_START_INSTANCE_CMD) == 0) {
        char *token = strtok_r(NULL, " \t\r\n", &save);
        char *name = strtok_r(NULL, " \t\r\n", &save);
        if (!token || !name) {
            send_error(client_fd, "token and name required");
            return;
        }
        int64_t now = (int64_t)time(NULL);
        if (!state_token_valid(&g_state, token, now)) {
            send_error(client_fd, "invalid or expired token");
            return;
        }
        char start_err[256] = "";
        if (instance_start(name, start_err, sizeof(start_err)) != 0) {
            send_error(client_fd, start_err[0] ? start_err : "instance start failed");
            return;
        }
        send_reply(client_fd, IAASD_OK_REPLY "\n");
        INFO("Instance started: %s", name);
        return;
    }

    if (strcmp(cmd, IAASD_STOP_INSTANCE_CMD) == 0) {
        char *token = strtok_r(NULL, " \t\r\n", &save);
        char *name = strtok_r(NULL, " \t\r\n", &save);
        if (!token || !name) {
            send_error(client_fd, "token and name required");
            return;
        }
        int64_t now = (int64_t)time(NULL);
        if (!state_token_valid(&g_state, token, now)) {
            send_error(client_fd, "invalid or expired token");
            return;
        }
        char stop_err[256] = "";
        if (instance_stop(name, stop_err, sizeof(stop_err)) != 0) {
            send_error(client_fd, stop_err[0] ? stop_err : "instance stop failed");
            return;
        }
        send_reply(client_fd, IAASD_OK_REPLY "\n");
        INFO("Instance stopped: %s", name);
        return;
    }

    if (strcmp(cmd, IAASD_STATUS_INSTANCE_CMD) == 0) {
        char *token = strtok_r(NULL, " \t\r\n", &save);
        char *name = strtok_r(NULL, " \t\r\n", &save);
        if (!token || !name) {
            send_error(client_fd, "token and name required");
            return;
        }
        int64_t now = (int64_t)time(NULL);
        if (!state_token_valid(&g_state, token, now)) {
            send_error(client_fd, "invalid or expired token");
            return;
        }

        iaasd_instance_t inst;
        bool running = false;
        char status_err[256] = "";
        if (instance_status(name, &inst, &running, status_err, sizeof(status_err)) != 0) {
            send_error(client_fd, status_err[0] ? status_err : "instance status failed");
            return;
        }

        char reply[256];
        snprintf(reply, sizeof(reply), "STATUS %s %s PID=%d SSH_PORT=%d USER=%s\n",
                 inst.name,
                 running ? "RUNNING" : "STOPPED",
                 (int)inst.pid,
                 inst.ssh_port,
                 inst.ssh_user);
        send_reply(client_fd, reply);
        return;
    }

    if (strcmp(cmd, IAASD_STOP_CMD) == 0) {
        char *token = strtok_r(NULL, " \t\r\n", &save);
        if (!token) {
            send_error(client_fd, "token required");
            return;
        }
        int64_t now = (int64_t)time(NULL);
        if (!state_token_valid(&g_state, token, now)) {
            send_error(client_fd, "invalid or expired token");
            return;
        }
        send_reply(client_fd, IAASD_OK_REPLY "\n");
        daemon_running = 0;
        return;
    }

    send_error(client_fd, "unknown command");
}

/** \brief Entry point that starts the daemon and IPC loop. */
int main(void) {
    ensure_root();

    daemonize();

    ensure_runtime_dirs();

    log_init(IAASD_DEFAULT_IDENT, IAASD_LOG_PATH, true);

    struct sigaction sa;
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGTERM, &sa, NULL) == -1 || sigaction(SIGINT, &sa, NULL) == -1) {
        LOG_FATAL("Failed to register signal handlers: %m");
    }

    signal(SIGPIPE, SIG_IGN);

    ensure_single_instance();

    char state_err[128] = "";
    if (state_load_or_init(IAASD_STATE_PATH, &g_state, state_err, sizeof(state_err)) != 0) {
        LOG_FATAL("Failed to initialize state: %s", state_err[0] ? state_err : "unknown");
    }

    int server_fd = setup_ipc_socket();

    INFO("Micro-IaaS Daemon (iaasd) started successfully. Socket: %s", IAASD_SOCKET_PATH);
    INFO("Admin user loaded: %s", g_state.admin_user);
    INFO("Quota defaults: RAM=%llu MiB DISK=%llu GiB NET=%llu Mbps",
         (unsigned long long)g_state.quota_ram_mib,
         (unsigned long long)g_state.quota_disk_gib,
         (unsigned long long)g_state.quota_net_mbps);

    struct pollfd pfd = {
        .fd = server_fd,
        .events = POLLIN
    };

    while (daemon_running) {
        int poll_rc = poll(&pfd, 1, 1000);
        if (poll_rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            LOG_FATAL("poll() failed: %m");
        }

        if (poll_rc > 0 && (pfd.revents & POLLIN)) {
            int client_fd = accept(server_fd, NULL, NULL);
            if (client_fd >= 0) {
                handle_client(client_fd);
                close(client_fd);
            } else if (errno != EINTR) {
                WARN("Failed to accept IPC client: %m");
            }
        }
    }

    INFO("Micro-IaaS Daemon shutting down.");

    if (server_fd >= 0) {
        close(server_fd);
    }
    unlink(IAASD_SOCKET_PATH);
    unlink(IAASD_PID_PATH);
    log_close();

    return EXIT_SUCCESS;
}
