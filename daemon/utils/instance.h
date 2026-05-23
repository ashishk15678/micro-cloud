// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Aman Deep (amdeep.dev@gmail.com)
// SPDX-FileCopyrightText: 2026 Ashish Kumar <15678ashishk@gmail.com>

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <stddef.h>

#include "state.h"

#define IAASD_INSTANCE_NAME_MAX 64

typedef struct {
    char     name[IAASD_INSTANCE_NAME_MAX];
    char     image_path[512];
    char     ssh_key_path[512];
    char     ssh_user[64];
    uint64_t ram_mib;
    uint64_t disk_gib;
    int      vcpus;
    int      ssh_port;
} iaasd_instance_req_t;

typedef struct {
    char     name[IAASD_INSTANCE_NAME_MAX];
    char     root_disk[512];
    char     data_disk[512];
    char     seed_iso[512];
    char     loop_dev[64];
    char     ssh_user[64];
    int      ssh_port;
    int      vcpus;
    uint64_t ram_mib;
    uint64_t disk_gib;
    pid_t    pid;
} iaasd_instance_t;

/** \brief Create and boot a new instance using the request details. */
int instance_create(const iaasd_instance_req_t *req, const iaasd_state_t *limits,
                    iaasd_instance_t *out, char *err, size_t err_len);

/** \brief Start a stopped instance from its saved state. */
int instance_start(const char *name, char *err, size_t err_len);

/** \brief Stop a running instance and detach its loop device. */
int instance_stop(const char *name, char *err, size_t err_len);

/** \brief Read instance status from disk and check if QEMU is running. */
int instance_status(const char *name, iaasd_instance_t *out, bool *running,
                    char *err, size_t err_len);
