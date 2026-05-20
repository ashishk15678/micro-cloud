// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Aman Deep (amdeep.dev@gmail.com)
// SPDX-FileCopyrightText: 2026 Ashish Kumar <15678ashishk@gmail.com>

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define IAASD_ADMIN_USER_MAX 64
#define IAASD_ADMIN_HASH_MAX 256
#define IAASD_TOKEN_MAX 128

typedef struct {
    char     admin_user[IAASD_ADMIN_USER_MAX];
    char     admin_hash[IAASD_ADMIN_HASH_MAX];
    uint64_t quota_ram_mib;
    uint64_t quota_disk_gib;
    uint64_t quota_net_mbps;

    char     token[IAASD_TOKEN_MAX];
    int64_t  token_expires;
} iaasd_state_t;

int state_load_or_init(const char *path, iaasd_state_t *out, char *err, size_t err_len);
int state_save(const char *path, const iaasd_state_t *state, char *err, size_t err_len);

int state_authenticate(iaasd_state_t *state, const char *user, const char *password,
                       char *token_out, size_t token_len, int64_t *expires_out,
                       char *err, size_t err_len);

bool state_token_valid(const iaasd_state_t *state, const char *token, int64_t now);
