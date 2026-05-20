// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Aman Deep (amdeep.dev@gmail.com)
// SPDX-FileCopyrightText: 2026 Ashish Kumar <15678ashishk@gmail.com>

#include "instance.h"

#include "../../include/daemon/ipc.h"
#include "../../include/log/log.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <linux/loop.h>
#include <time.h>
#include <stdarg.h>
#include <signal.h>

#define IAASD_PIDFILE_NAME "qemu.pid"
#define IAASD_STATEFILE_NAME "instance.state"
#define IAASD_ROOT_DISK_NAME "root.qcow2"
#define IAASD_DATA_DISK_NAME "data.raw"
#define IAASD_SEED_ISO_NAME "seed.iso"

/** \brief Write a formatted error message into the caller buffer. */
static void set_err(char *err, size_t err_len, const char *fmt, ...) {
    if (!err || err_len == 0 || !fmt) {
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, err_len, fmt, ap);
    va_end(ap);
}

/** \brief Create a directory if it does not already exist. */
static int ensure_dir(const char *path, mode_t mode, char *err, size_t err_len) {
    if (!path || path[0] == '\0') {
        set_err(err, err_len, "invalid directory path");
        return -1;
    }
    if (mkdir(path, mode) == 0) {
        return 0;
    }
    if (errno == EEXIST) {
        return 0;
    }
    set_err(err, err_len, "mkdir %s failed: %s", path, strerror(errno));
    return -1;
}

/** \brief Validate an instance name to avoid unsafe filesystem paths. */
static bool validate_name(const char *name) {
    if (!name || name[0] == '\0') {
        return false;
    }
    for (const char *p = name; *p; p++) {
        if (!isalnum((unsigned char)*p) && *p != '-' && *p != '_') {
            return false;
        }
    }
    return true;
}

/** \brief Join two path segments into a buffer. */
static int join_path(const char *a, const char *b, char *out, size_t out_len) {
    if (!a || !b || !out || out_len == 0) {
        return -1;
    }
    int n = snprintf(out, out_len, "%s/%s", a, b);
    return (n < 0 || (size_t)n >= out_len) ? -1 : 0;
}

/** \brief Read the first non-empty line from a file. */
static int read_first_line(const char *path, char *out, size_t out_len, char *err, size_t err_len) {
    if (!path || !out || out_len == 0) {
        set_err(err, err_len, "invalid file path");
        return -1;
    }
    FILE *fp = fopen(path, "re");
    if (!fp) {
        set_err(err, err_len, "open %s failed: %s", path, strerror(errno));
        return -1;
    }
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        char *s = line;
        while (*s && isspace((unsigned char)*s)) s++;
        if (*s == '\0' || *s == '\n') {
            continue;
        }
        size_t len = strcspn(s, "\r\n");
        if (len >= out_len) {
            fclose(fp);
            set_err(err, err_len, "line too long in %s", path);
            return -1;
        }
        memcpy(out, s, len);
        out[len] = '\0';
        fclose(fp);
        return 0;
    }
    fclose(fp);
    set_err(err, err_len, "no usable line in %s", path);
    return -1;
}

/** \brief Write a string payload into a file with 0600 permissions. */
static int write_file(const char *path, const char *content, char *err, size_t err_len) {
    if (!path || !content) {
        set_err(err, err_len, "invalid write arguments");
        return -1;
    }
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) {
        set_err(err, err_len, "open %s failed: %s", path, strerror(errno));
        return -1;
    }
    size_t len = strlen(content);
    ssize_t wrote = write(fd, content, len);
    if (wrote < 0 || (size_t)wrote != len) {
        set_err(err, err_len, "write %s failed: %s", path, strerror(errno));
        close(fd);
        return -1;
    }
    fsync(fd);
    close(fd);
    return 0;
}

/** \brief Execute a command and wait for completion. */
static int run_command(char *const argv[], char *err, size_t err_len) {
    pid_t pid = fork();
    if (pid < 0) {
        set_err(err, err_len, "fork failed: %s", strerror(errno));
        return -1;
    }
    if (pid == 0) {
        execvp(argv[0], argv);
        _exit(127);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        set_err(err, err_len, "waitpid failed: %s", strerror(errno));
        return -1;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        set_err(err, err_len, "%s failed", argv[0]);
        return -1;
    }
    return 0;
}

/** \brief Build a cloud-init seed ISO with the supplied user and SSH key. */
static int build_seed_iso(const char *dir, const char *instance_name,
                          const char *ssh_user, const char *ssh_key,
                          const char *out_iso, char *err, size_t err_len) {
    if (!dir || !instance_name || !ssh_user || !ssh_key || !out_iso) {
        set_err(err, err_len, "invalid seed arguments");
        return -1;
    }

    char user_data[2048];
    snprintf(user_data, sizeof(user_data),
             "#cloud-config\n"
             "users:\n"
             "  - name: %s\n"
             "    sudo: ALL=(ALL) NOPASSWD:ALL\n"
             "    groups: users, admin, sudo\n"
             "    shell: /bin/bash\n"
             "    ssh_authorized_keys:\n"
             "      - %s\n"
             "ssh_pwauth: false\n"
             "disable_root: true\n",
             ssh_user, ssh_key);

    char meta_data[512];
    snprintf(meta_data, sizeof(meta_data),
             "instance-id: %s\nlocal-hostname: %s\n",
             instance_name, instance_name);

    char user_path[512];
    char meta_path[512];
    if (join_path(dir, "user-data", user_path, sizeof(user_path)) != 0 ||
        join_path(dir, "meta-data", meta_path, sizeof(meta_path)) != 0) {
        set_err(err, err_len, "failed to build seed paths");
        return -1;
    }

    if (write_file(user_path, user_data, err, err_len) != 0 ||
        write_file(meta_path, meta_data, err, err_len) != 0) {
        return -1;
    }

    char *argv_geniso[] = {
        (char *)"genisoimage",
        (char *)"-output",
        (char *)out_iso,
        (char *)"-volid",
        (char *)"cidata",
        (char *)"-joliet",
        (char *)"-rock",
        (char *)dir,
        NULL
    };

    char *argv_xorriso[] = {
        (char *)"xorriso",
        (char *)"-as",
        (char *)"mkisofs",
        (char *)"-output",
        (char *)out_iso,
        (char *)"-volid",
        (char *)"cidata",
        (char *)"-joliet",
        (char *)"-rock",
        (char *)dir,
        NULL
    };

    if (run_command(argv_geniso, err, err_len) == 0) {
        return 0;
    }

    if (run_command(argv_xorriso, err, err_len) == 0) {
        return 0;
    }

    set_err(err, err_len, "genisoimage/xorriso not available");
    return -1;
}

/** \brief Create a qcow2 overlay using qemu-img. */
static int create_overlay(const char *base, const char *out, char *err, size_t err_len) {
    char *argv_img[] = {
        (char *)"qemu-img",
        (char *)"create",
        (char *)"-f",
        (char *)"qcow2",
        (char *)"-b",
        (char *)base,
        (char *)out,
        NULL
    };

    if (run_command(argv_img, err, err_len) == 0) {
        return 0;
    }

    set_err(err, err_len, "qemu-img failed (required to create overlay)");
    return -1;
}

/** \brief Create a raw data disk file of the requested size. */
static int create_data_disk(const char *path, uint64_t size_gib, char *err, size_t err_len) {
    int fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0) {
        set_err(err, err_len, "open data disk failed: %s", strerror(errno));
        return -1;
    }

    off_t size_bytes = (off_t)(size_gib * 1024ULL * 1024ULL * 1024ULL);
    if (size_bytes <= 0) {
        close(fd);
        set_err(err, err_len, "invalid disk size");
        return -1;
    }

    int rc = posix_fallocate(fd, 0, size_bytes);
    if (rc != 0) {
        if (ftruncate(fd, size_bytes) != 0) {
            close(fd);
            set_err(err, err_len, "ftruncate failed: %s", strerror(errno));
            return -1;
        }
    }

    close(fd);
    return 0;
}

/** \brief Attach a file to a free loop device using ioctl. */
static int setup_loop_device(const char *path, char *loop_out, size_t loop_len, char *err, size_t err_len) {
    int ctl = open("/dev/loop-control", O_RDWR | O_CLOEXEC);
    if (ctl < 0) {
        set_err(err, err_len, "open /dev/loop-control failed: %s", strerror(errno));
        return -1;
    }

    int loop_idx = ioctl(ctl, LOOP_CTL_GET_FREE);
    close(ctl);
    if (loop_idx < 0) {
        set_err(err, err_len, "LOOP_CTL_GET_FREE failed: %s", strerror(errno));
        return -1;
    }

    char loop_path[64];
    snprintf(loop_path, sizeof(loop_path), "/dev/loop%d", loop_idx);

    int file_fd = open(path, O_RDWR | O_CLOEXEC);
    if (file_fd < 0) {
        set_err(err, err_len, "open data disk failed: %s", strerror(errno));
        return -1;
    }

    int loop_fd = open(loop_path, O_RDWR | O_CLOEXEC);
    if (loop_fd < 0) {
        close(file_fd);
        set_err(err, err_len, "open loop device failed: %s", strerror(errno));
        return -1;
    }

    if (ioctl(loop_fd, LOOP_SET_FD, file_fd) != 0) {
        close(loop_fd);
        close(file_fd);
        set_err(err, err_len, "LOOP_SET_FD failed: %s", strerror(errno));
        return -1;
    }

    struct loop_info64 info;
    memset(&info, 0, sizeof(info));
    snprintf((char *)info.lo_file_name, LO_NAME_SIZE, "%s", path);
    info.lo_flags = LO_FLAGS_AUTOCLEAR;

    if (ioctl(loop_fd, LOOP_SET_STATUS64, &info) != 0) {
        ioctl(loop_fd, LOOP_CLR_FD, 0);
        close(loop_fd);
        close(file_fd);
        set_err(err, err_len, "LOOP_SET_STATUS64 failed: %s", strerror(errno));
        return -1;
    }

    close(loop_fd);
    close(file_fd);

    snprintf(loop_out, loop_len, "%s", loop_path);
    return 0;
}

/** \brief Detach a loop device from its backing file. */
static int detach_loop_device(const char *loop_path, char *err, size_t err_len) {
    if (!loop_path || loop_path[0] == '\0') {
        return 0;
    }
    int loop_fd = open(loop_path, O_RDWR | O_CLOEXEC);
    if (loop_fd < 0) {
        set_err(err, err_len, "open loop device failed: %s", strerror(errno));
        return -1;
    }
    if (ioctl(loop_fd, LOOP_CLR_FD, 0) != 0) {
        close(loop_fd);
        set_err(err, err_len, "LOOP_CLR_FD failed: %s", strerror(errno));
        return -1;
    }
    close(loop_fd);
    return 0;
}

/** \brief Persist instance state to disk for later management. */
static int write_instance_state(const char *path, const iaasd_instance_t *inst, char *err, size_t err_len) {
    if (!path || !inst) {
        set_err(err, err_len, "invalid instance state");
        return -1;
    }

    char buf[2048];
    snprintf(buf, sizeof(buf),
             "name=%s\n"
             "root_disk=%s\n"
             "data_disk=%s\n"
             "seed_iso=%s\n"
             "loop_dev=%s\n"
             "ssh_user=%s\n"
             "ssh_port=%d\n"
             "vcpus=%d\n"
             "ram_mib=%llu\n"
             "disk_gib=%llu\n"
             "pid=%d\n",
             inst->name,
             inst->root_disk,
             inst->data_disk,
             inst->seed_iso,
             inst->loop_dev,
             inst->ssh_user,
             inst->ssh_port,
             inst->vcpus,
             (unsigned long long)inst->ram_mib,
             (unsigned long long)inst->disk_gib,
             (int)inst->pid);

    return write_file(path, buf, err, err_len);
}

/** \brief Load instance metadata from its state file. */
static int load_instance_state(const char *path, iaasd_instance_t *out, char *err, size_t err_len) {
    if (!path || !out) {
        set_err(err, err_len, "invalid instance state path");
        return -1;
    }

    FILE *fp = fopen(path, "re");
    if (!fp) {
        set_err(err, err_len, "open instance state failed: %s", strerror(errno));
        return -1;
    }

    char line[512];
    memset(out, 0, sizeof(*out));
    while (fgets(line, sizeof(line), fp)) {
        char *s = line;
        while (*s && isspace((unsigned char)*s)) s++;
        if (*s == '\0' || *s == '#') continue;
        char *eq = strchr(s, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key = s;
        char *val = eq + 1;
        val[strcspn(val, "\r\n")] = '\0';

        if (strcmp(key, "name") == 0) {
            snprintf(out->name, sizeof(out->name), "%s", val);
        } else if (strcmp(key, "root_disk") == 0) {
            snprintf(out->root_disk, sizeof(out->root_disk), "%s", val);
        } else if (strcmp(key, "data_disk") == 0) {
            snprintf(out->data_disk, sizeof(out->data_disk), "%s", val);
        } else if (strcmp(key, "seed_iso") == 0) {
            snprintf(out->seed_iso, sizeof(out->seed_iso), "%s", val);
        } else if (strcmp(key, "loop_dev") == 0) {
            snprintf(out->loop_dev, sizeof(out->loop_dev), "%s", val);
        } else if (strcmp(key, "ssh_user") == 0) {
            snprintf(out->ssh_user, sizeof(out->ssh_user), "%s", val);
        } else if (strcmp(key, "ssh_port") == 0) {
            out->ssh_port = atoi(val);
        } else if (strcmp(key, "vcpus") == 0) {
            out->vcpus = atoi(val);
        } else if (strcmp(key, "ram_mib") == 0) {
            out->ram_mib = strtoull(val, NULL, 10);
        } else if (strcmp(key, "disk_gib") == 0) {
            out->disk_gib = strtoull(val, NULL, 10);
        } else if (strcmp(key, "pid") == 0) {
            out->pid = (pid_t)atoi(val);
        }
    }

    fclose(fp);
    return 0;
}

/** \brief Read a PID from a pidfile written by QEMU. */
static int read_pidfile(const char *path, pid_t *pid_out, char *err, size_t err_len) {
    char buf[64];
    if (read_first_line(path, buf, sizeof(buf), err, err_len) != 0) {
        return -1;
    }
    long pid = strtol(buf, NULL, 10);
    if (pid <= 0) {
        set_err(err, err_len, "invalid pid in %s", path);
        return -1;
    }
    *pid_out = (pid_t)pid;
    return 0;
}

/** \brief Launch QEMU in daemonized mode for an instance. */
static int spawn_qemu(const iaasd_instance_t *inst, const char *pidfile, char *err, size_t err_len) {
    char ram_arg[32];
    char smp_arg[32];
    char netdev_arg[128];
    char pidfile_arg[512];

    snprintf(ram_arg, sizeof(ram_arg), "%llu", (unsigned long long)inst->ram_mib);
    snprintf(smp_arg, sizeof(smp_arg), "%d", inst->vcpus);
    snprintf(netdev_arg, sizeof(netdev_arg), "user,id=net0,hostfwd=tcp::%d-:22", inst->ssh_port);
    snprintf(pidfile_arg, sizeof(pidfile_arg), "%s", pidfile);

    bool use_kvm = (access("/dev/kvm", R_OK | W_OK) == 0);

    char *argv[32];
    int idx = 0;
    argv[idx++] = (char *)"qemu-system-x86_64";
    if (use_kvm) {
        argv[idx++] = (char *)"-enable-kvm";
    }
    argv[idx++] = (char *)"-m";
    argv[idx++] = ram_arg;
    argv[idx++] = (char *)"-smp";
    argv[idx++] = smp_arg;
    char root_arg[1024];
    char data_arg[1024];
    char seed_arg[1024];
    snprintf(root_arg, sizeof(root_arg), "file=%s,if=virtio,format=qcow2", inst->root_disk);
    snprintf(data_arg, sizeof(data_arg), "file=%s,if=virtio,format=raw", inst->loop_dev);
    snprintf(seed_arg, sizeof(seed_arg), "file=%s,if=virtio,format=raw", inst->seed_iso);

    argv[idx++] = (char *)"-drive";
    argv[idx++] = root_arg;
    argv[idx++] = (char *)"-drive";
    argv[idx++] = data_arg;
    argv[idx++] = (char *)"-drive";
    argv[idx++] = seed_arg;

    argv[idx++] = (char *)"-netdev";
    argv[idx++] = netdev_arg;
    argv[idx++] = (char *)"-device";
    argv[idx++] = (char *)"virtio-net-pci,netdev=net0";
    argv[idx++] = (char *)"-daemonize";
    argv[idx++] = (char *)"-pidfile";
    argv[idx++] = pidfile_arg;
    argv[idx++] = (char *)"-display";
    argv[idx++] = (char *)"none";
    argv[idx] = NULL;

    if (run_command(argv, err, err_len) != 0) {
        return -1;
    }

    return 0;
}

/** \brief Check if a pid represents a running process. */
static bool pid_running(pid_t pid) {
    if (pid <= 0) {
        return false;
    }
    if (kill(pid, 0) == 0) {
        return true;
    }
    return errno == EPERM;
}

/** \brief Wait for a process to exit after a termination signal. */
static void wait_for_exit(pid_t pid) {
    for (int i = 0; i < 50; i++) {
        if (!pid_running(pid)) {
            return;
        }
        usleep(100000);
    }
}

int instance_create(const iaasd_instance_req_t *req, const iaasd_state_t *limits,
                    iaasd_instance_t *out, char *err, size_t err_len) {
    if (!req || !limits || !out) {
        set_err(err, err_len, "invalid instance request");
        return -1;
    }

    if (!validate_name(req->name)) {
        set_err(err, err_len, "invalid instance name");
        return -1;
    }

    if (req->ram_mib == 0 || req->disk_gib == 0 || req->vcpus <= 0) {
        set_err(err, err_len, "resource values must be positive");
        return -1;
    }

    if (req->ram_mib > limits->quota_ram_mib || req->disk_gib > limits->quota_disk_gib) {
        set_err(err, err_len, "requested resources exceed quota");
        return -1;
    }

    if (req->ssh_port <= 0 || req->ssh_port > 65535) {
        set_err(err, err_len, "invalid ssh port");
        return -1;
    }

    if (req->image_path[0] != '/' || req->ssh_key_path[0] != '/') {
        set_err(err, err_len, "image and key paths must be absolute");
        return -1;
    }

    char base_dir[512];
    char inst_dir[512];
    char seed_dir[512];
    snprintf(base_dir, sizeof(base_dir), "%s", IAASD_INSTANCE_DIR);
    if (ensure_dir("/run/iaasd", 0700, err, err_len) != 0) return -1;
    if (ensure_dir("/var/log/iaasd", 0700, err, err_len) != 0) return -1;
    if (ensure_dir("/var/lib/iaasd", 0700, err, err_len) != 0) return -1;
    if (ensure_dir(base_dir, 0700, err, err_len) != 0) return -1;

    if (join_path(base_dir, req->name, inst_dir, sizeof(inst_dir)) != 0) {
        set_err(err, err_len, "failed to build instance dir");
        return -1;
    }

    if (ensure_dir(inst_dir, 0700, err, err_len) != 0) {
        return -1;
    }

    if (join_path(inst_dir, "seed", seed_dir, sizeof(seed_dir)) != 0) {
        set_err(err, err_len, "failed to build seed dir");
        return -1;
    }

    if (ensure_dir(seed_dir, 0700, err, err_len) != 0) {
        return -1;
    }

    char state_path[512];
    if (join_path(inst_dir, IAASD_STATEFILE_NAME, state_path, sizeof(state_path)) != 0) {
        set_err(err, err_len, "failed to build state path");
        return -1;
    }

    if (access(state_path, F_OK) == 0) {
        set_err(err, err_len, "instance already exists");
        return -1;
    }

    iaasd_instance_t inst;
    memset(&inst, 0, sizeof(inst));
    snprintf(inst.name, sizeof(inst.name), "%s", req->name);
    snprintf(inst.ssh_user, sizeof(inst.ssh_user), "%s", req->ssh_user);
    inst.ssh_port = req->ssh_port;
    inst.vcpus = req->vcpus;
    inst.ram_mib = req->ram_mib;
    inst.disk_gib = req->disk_gib;

    if (join_path(inst_dir, IAASD_ROOT_DISK_NAME, inst.root_disk, sizeof(inst.root_disk)) != 0 ||
        join_path(inst_dir, IAASD_DATA_DISK_NAME, inst.data_disk, sizeof(inst.data_disk)) != 0 ||
        join_path(inst_dir, IAASD_SEED_ISO_NAME, inst.seed_iso, sizeof(inst.seed_iso)) != 0) {
        set_err(err, err_len, "failed to build disk paths");
        return -1;
    }

    if (create_overlay(req->image_path, inst.root_disk, err, err_len) != 0) {
        return -1;
    }

    if (create_data_disk(inst.data_disk, inst.disk_gib, err, err_len) != 0) {
        return -1;
    }

    bool loop_attached = false;
    if (setup_loop_device(inst.data_disk, inst.loop_dev, sizeof(inst.loop_dev), err, err_len) != 0) {
        return -1;
    }
    loop_attached = true;

    char ssh_key[1024];
    if (read_first_line(req->ssh_key_path, ssh_key, sizeof(ssh_key), err, err_len) != 0) {
        goto cleanup_loop;
    }

    if (build_seed_iso(seed_dir, inst.name, inst.ssh_user, ssh_key, inst.seed_iso, err, err_len) != 0) {
        goto cleanup_loop;
    }

    char pidfile[512];
    if (join_path(inst_dir, IAASD_PIDFILE_NAME, pidfile, sizeof(pidfile)) != 0) {
        set_err(err, err_len, "failed to build pidfile path");
        goto cleanup_loop;
    }

    if (spawn_qemu(&inst, pidfile, err, err_len) != 0) {
        goto cleanup_loop;
    }

    if (read_pidfile(pidfile, &inst.pid, err, err_len) != 0) {
        goto cleanup_loop;
    }

    if (write_instance_state(state_path, &inst, err, err_len) != 0) {
        goto cleanup_loop;
    }

    *out = inst;
    return 0;

cleanup_loop:
    if (loop_attached) {
        char det_err[128] = "";
        if (detach_loop_device(inst.loop_dev, det_err, sizeof(det_err)) != 0) {
            WARN("loop detach failed: %s", det_err);
        }
    }
    return -1;
}

/** \brief Start a stopped instance using existing disks and metadata. */
int instance_start(const char *name, char *err, size_t err_len) {
    if (!validate_name(name)) {
        set_err(err, err_len, "invalid instance name");
        return -1;
    }

    char inst_dir[512];
    char state_path[512];
    if (join_path(IAASD_INSTANCE_DIR, name, inst_dir, sizeof(inst_dir)) != 0 ||
        join_path(inst_dir, IAASD_STATEFILE_NAME, state_path, sizeof(state_path)) != 0) {
        set_err(err, err_len, "failed to build instance path");
        return -1;
    }

    iaasd_instance_t inst;
    if (load_instance_state(state_path, &inst, err, err_len) != 0) {
        return -1;
    }

    if (pid_running(inst.pid)) {
        set_err(err, err_len, "instance already running");
        return -1;
    }

    bool loop_attached = false;
    if (setup_loop_device(inst.data_disk, inst.loop_dev, sizeof(inst.loop_dev), err, err_len) != 0) {
        return -1;
    }
    loop_attached = true;

    char pidfile[512];
    if (join_path(inst_dir, IAASD_PIDFILE_NAME, pidfile, sizeof(pidfile)) != 0) {
        set_err(err, err_len, "failed to build pidfile path");
        goto cleanup_loop;
    }

    if (spawn_qemu(&inst, pidfile, err, err_len) != 0) {
        goto cleanup_loop;
    }

    if (read_pidfile(pidfile, &inst.pid, err, err_len) != 0) {
        goto cleanup_loop;
    }

    if (write_instance_state(state_path, &inst, err, err_len) != 0) {
        goto cleanup_loop;
    }

    return 0;

cleanup_loop:
    if (loop_attached) {
        char det_err[128] = "";
        if (detach_loop_device(inst.loop_dev, det_err, sizeof(det_err)) != 0) {
            WARN("loop detach failed: %s", det_err);
        }
    }
    return -1;
}

/** \brief Stop a running instance and detach its loop device. */
int instance_stop(const char *name, char *err, size_t err_len) {
    if (!validate_name(name)) {
        set_err(err, err_len, "invalid instance name");
        return -1;
    }

    char inst_dir[512];
    char state_path[512];
    if (join_path(IAASD_INSTANCE_DIR, name, inst_dir, sizeof(inst_dir)) != 0 ||
        join_path(inst_dir, IAASD_STATEFILE_NAME, state_path, sizeof(state_path)) != 0) {
        set_err(err, err_len, "failed to build instance path");
        return -1;
    }

    iaasd_instance_t inst;
    if (load_instance_state(state_path, &inst, err, err_len) != 0) {
        return -1;
    }

    if (inst.pid > 0 && pid_running(inst.pid)) {
        kill(inst.pid, SIGTERM);
        wait_for_exit(inst.pid);
        if (pid_running(inst.pid)) {
            kill(inst.pid, SIGKILL);
        }
    }

    char det_err[128] = "";
    if (detach_loop_device(inst.loop_dev, det_err, sizeof(det_err)) != 0) {
        WARN("loop detach failed: %s", det_err);
    }

    inst.pid = 0;
    inst.loop_dev[0] = '\0';
    if (write_instance_state(state_path, &inst, err, err_len) != 0) {
        return -1;
    }

    return 0;
}

int instance_status(const char *name, iaasd_instance_t *out, bool *running,
                    char *err, size_t err_len) {
    if (!validate_name(name)) {
        set_err(err, err_len, "invalid instance name");
        return -1;
    }

    char inst_dir[512];
    char state_path[512];
    if (join_path(IAASD_INSTANCE_DIR, name, inst_dir, sizeof(inst_dir)) != 0 ||
        join_path(inst_dir, IAASD_STATEFILE_NAME, state_path, sizeof(state_path)) != 0) {
        set_err(err, err_len, "failed to build instance path");
        return -1;
    }

    iaasd_instance_t inst;
    if (load_instance_state(state_path, &inst, err, err_len) != 0) {
        return -1;
    }

    if (running) {
        *running = pid_running(inst.pid);
    }
    if (out) {
        *out = inst;
    }
    return 0;
}
