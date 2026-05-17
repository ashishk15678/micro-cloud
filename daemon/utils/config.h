
#ifndef IS_CONFIG_H
#define IS_CONFIG_H

#include <stdint.h>
#include <stdbool.h>
#include "defaults.h"

typedef struct {
    char     user[64];
    char     group[64];
    char     pid_file[IS_MAX_PATH_LEN];
    bool     foreground;     /* don't daemonise */
} cfg_daemon_t;

typedef struct {
    char     bind_address[64];
    uint16_t port;
    uint16_t tls_port;
    char     tls_cert[IS_MAX_PATH_LEN];
    char     tls_key[IS_MAX_PATH_LEN];
    uint32_t thread_pool_size;
    uint32_t request_timeout;    /* seconds */
    uint32_t rate_limit_rps;     /* requests per second per IP, 0=disabled */
} cfg_api_t;

typedef struct {
    char     path[IS_MAX_PATH_LEN];
} cfg_db_t;

typedef struct {
    char     volume_dir[IS_MAX_PATH_LEN];
    uint64_t max_volume_gib;
} cfg_storage_t;

typedef struct {
    char     qemu_binary[IS_MAX_PATH_LEN];
    char     image_dir[IS_MAX_PATH_LEN];
    uint16_t vnc_base_port;
} cfg_compute_t;

typedef struct {
    char     level[16];
    char     file[IS_MAX_PATH_LEN];
    bool     syslog;
} cfg_logging_t;

typedef struct {
    cfg_daemon_t  daemon;
    cfg_api_t     api;
    cfg_db_t      db;
    cfg_storage_t storage;
    cfg_compute_t compute;
    cfg_logging_t logging;
} IS_config_t;

/**
 * Parse config file at @path into *out.
 * Returns IS_OK or an error code; logs reason to stderr.
 */
IS_err_t config_load(const char *path, IS_config_t *out);

/** Fill *out with safe built-in defaults (no file I/O). */
void config_defaults(IS_config_t *out);

/** Print effective configuration to stdout (masks secrets). */
void config_dump(const IS_config_t *cfg);

#endif /* IS_CONFIG_H */
