// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Aman Deep (amdeep.dev@gmail.com)
// SPDX-FileCopyrightText: 2026 Ashish Kumar <15678ashishk@gmail.com>

#include "state.h"
#include "password.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/random.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>

#define IAASD_DEFAULT_ADMIN_USER "admin"
#define IAASD_DEFAULT_ADMIN_PASS "admin"
#define IAASD_DEFAULT_RAM_MIB 8192
#define IAASD_DEFAULT_DISK_GIB 200
#define IAASD_DEFAULT_NET_MBPS 1000
#define IAASD_TOKEN_TTL_SEC 3600

/** \brief Populate an error message buffer with a static string. */
static void set_err(char *err, size_t err_len, const char *msg) {
    if (err && err_len > 0) {
        snprintf(err, err_len, "%s", msg);
    }
}

/** \brief Trim leading and trailing whitespace from a string in-place. */
static char *trim(char *s) {
    while (*s && (*s == ' ' || *s == '\t' || *s == '\n' || *s == '\r')) s++;
    if (*s == '\0') return s;
    char *end = s + strlen(s) - 1;
    while (end > s && (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r')) end--;
    *(end + 1) = '\0';
    return s;
}

/** \brief Constant-time memory comparison helper. */
static bool ct_memeq(const void *a, const void *b, size_t n) {
    const unsigned char *pa = (const unsigned char *)a;
    const unsigned char *pb = (const unsigned char *)b;
    unsigned char diff = 0;
    for (size_t i = 0; i < n; i++) {
        diff |= (unsigned char)(pa[i] ^ pb[i]);
    }
    return diff == 0;
}

/** \brief Encode bytes into a hex string. */
static void hex_encode(const uint8_t *in, size_t inlen, char *out, size_t outlen) {
    static const char hex[] = "0123456789abcdef";
    size_t max = (outlen - 1) / 2;
    size_t n = inlen < max ? inlen : max;
    for (size_t i = 0; i < n; i++) {
        out[i * 2] = hex[in[i] >> 4];
        out[i * 2 + 1] = hex[in[i] & 0x0F];
    }
    out[n * 2] = '\0';
}

/** \brief Generate a random token and return it as hex. */
static int generate_token(char *out, size_t outlen) {
    uint8_t bytes[32];
    ssize_t n = getrandom(bytes, sizeof(bytes), 0);
    if (n != (ssize_t)sizeof(bytes)) {
        return -1;
    }
    hex_encode(bytes, sizeof(bytes), out, outlen);
    return 0;
}

/** \brief Persist daemon state to disk with secure permissions. */
int state_save(const char *path, const iaasd_state_t *state, char *err, size_t err_len) {
    if (!path || !state) {
        set_err(err, err_len, "invalid state path");
        return -1;
    }

    char tmp_path[512];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", path);

    int fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) {
        set_err(err, err_len, "failed to open state temp file");
        return -1;
    }

    FILE *fp = fdopen(fd, "w");
    if (!fp) {
        close(fd);
        set_err(err, err_len, "failed to fdopen state file");
        return -1;
    }

    fprintf(fp, "admin_user=%s\n", state->admin_user);
    fprintf(fp, "admin_hash=%s\n", state->admin_hash);
    fprintf(fp, "quota_ram_mib=%llu\n", (unsigned long long)state->quota_ram_mib);
    fprintf(fp, "quota_disk_gib=%llu\n", (unsigned long long)state->quota_disk_gib);
    fprintf(fp, "quota_net_mbps=%llu\n", (unsigned long long)state->quota_net_mbps);

    fflush(fp);
    fsync(fd);
    fclose(fp);

    if (rename(tmp_path, path) != 0) {
        set_err(err, err_len, "failed to move state file");
        unlink(tmp_path);
        return -1;
    }

    chmod(path, 0600);
    return 0;
}

/** \brief Load state from disk, or initialize defaults on first run. */
int state_load_or_init(const char *path, iaasd_state_t *out, char *err, size_t err_len) {
    if (!path || !out) {
        set_err(err, err_len, "invalid state path");
        return -1;
    }

    memset(out, 0, sizeof(*out));
    snprintf(out->admin_user, sizeof(out->admin_user), "%s", IAASD_DEFAULT_ADMIN_USER);
    out->quota_ram_mib = IAASD_DEFAULT_RAM_MIB;
    out->quota_disk_gib = IAASD_DEFAULT_DISK_GIB;
    out->quota_net_mbps = IAASD_DEFAULT_NET_MBPS;

    if (access(path, F_OK) != 0) {
        if (password_hash(IAASD_DEFAULT_ADMIN_PASS, out->admin_hash, sizeof(out->admin_hash)) != 0) {
            set_err(err, err_len, "failed to hash default admin password");
            return -1;
        }
        if (state_save(path, out, err, err_len) != 0) {
            return -1;
        }
        return 0;
    }

    FILE *fp = fopen(path, "re");
    if (!fp) {
        set_err(err, err_len, "failed to open state file");
        return -1;
    }

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        char *s = trim(line);
        if (*s == '\0' || *s == '#' || *s == ';') continue;

        char *eq = strchr(s, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key = trim(s);
        char *val = trim(eq + 1);

        if (strcmp(key, "admin_user") == 0) {
            snprintf(out->admin_user, sizeof(out->admin_user), "%s", val);
        } else if (strcmp(key, "admin_hash") == 0) {
            snprintf(out->admin_hash, sizeof(out->admin_hash), "%s", val);
        } else if (strcmp(key, "quota_ram_mib") == 0) {
            out->quota_ram_mib = strtoull(val, NULL, 10);
        } else if (strcmp(key, "quota_disk_gib") == 0) {
            out->quota_disk_gib = strtoull(val, NULL, 10);
        } else if (strcmp(key, "quota_net_mbps") == 0) {
            out->quota_net_mbps = strtoull(val, NULL, 10);
        }
    }

    fclose(fp);

    if (out->admin_user[0] == '\0' || out->admin_hash[0] == '\0') {
        set_err(err, err_len, "state file missing admin credentials");
        return -1;
    }

    return 0;
}

/** \brief Validate admin credentials and issue a session token. */
int state_authenticate(iaasd_state_t *state, const char *user, const char *password,
                       char *token_out, size_t token_len, int64_t *expires_out,
                       char *err, size_t err_len) {
    if (!state || !user || !password) {
        set_err(err, err_len, "invalid auth request");
        return -1;
    }

    if (strcmp(user, state->admin_user) != 0) {
        set_err(err, err_len, "invalid credentials");
        return -1;
    }

    if (password_verify(password, state->admin_hash) != 0) {
        set_err(err, err_len, "invalid credentials");
        return -1;
    }

    if (generate_token(state->token, sizeof(state->token)) != 0) {
        set_err(err, err_len, "token generation failed");
        return -1;
    }

    state->token_expires = (int64_t)time(NULL) + IAASD_TOKEN_TTL_SEC;
    if (token_out && token_len > 0) {
        snprintf(token_out, token_len, "%s", state->token);
    }
    if (expires_out) {
        *expires_out = state->token_expires;
    }

    return 0;
}

/** \brief Check whether a session token is valid and unexpired. */
bool state_token_valid(const iaasd_state_t *state, const char *token, int64_t now) {
    if (!state || !token || state->token[0] == '\0') return false;
    if (now >= state->token_expires) return false;
    size_t len = strlen(state->token);
    if (len == 0 || strlen(token) != len) return false;
    return ct_memeq(state->token, token, len);
}
