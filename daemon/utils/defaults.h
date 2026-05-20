// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ashish Kumar <15678ashishk@gmail.com>

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <time.h>

#define IS_VERSION_MAJOR  0
#define IS_VERSION_MINOR  1
#define IS_VERSION_PATCH  0
#define IS_VERSION        "0.1.0"

#define DEFAULT_PORT           8080
#define DEFAULT_TLS_PORT       8443
#define DEFAULT_CONFIG         "/etc/ISd/ISd.conf"
#define DEFAULT_PID_FILE       "/run/ISd/ISd.pid"
#define DEFAULT_LOG_FILE       "/var/log/ISd/ISd.log"
#define DEFAULT_DB_PATH        "/var/lib/ISd/ISd.db"
#define DEFAULT_STORAGE_DIR    "/var/lib/ISd/volumes"
#define DEFAULT_IMAGE_DIR      "/var/lib/ISd/images"
#define DEFAULT_QEMU_BIN       "/usr/bin/qemu-system-x86_64"
#define DEFAULT_USER           "ISd"
#define DEFAULT_GROUP          "ISd"

#define IS_TOKEN_BYTES        32    /* raw entropy bytes */
#define IS_TOKEN_HEX_LEN      65    /* hex string + NUL */
#define IS_TOKEN_TTL_SEC      3600  /* 1 hour */
#define IS_UUID_STR_LEN       37    /* 36 chars + NUL */
#define IS_MAX_NAME_LEN       64
#define IS_MAX_PATH_LEN       512
#define IS_MAX_HEADER_BYTES   8192
#define IS_MAX_BODY_BYTES     (1u << 20)  /* 1 MiB */
#define IS_THREAD_POOL_SIZE   16
#define IS_CONN_BACKLOG       128
#define IS_READ_TIMEOUT_SEC   30
#define IS_KEEPALIVE_SEC      60
#define IS_PBKDF2_ITER        310000  /* NIST SP 800-132 minimum for SHA-256 */
#define IS_SALT_BYTES         32
#define IS_HASH_BYTES         32

#ifndef IS_MAX_CONNECTIONS
#  define IS_MAX_CONNECTIONS  1024
#endif

typedef enum IS_err {
    IS_OK           =  0,
    IS_ERR_NOMEM    = -1,
    IS_ERR_INVAL    = -2,
    IS_ERR_IO       = -3,
    IS_ERR_NOTFOUND = -4,
    IS_ERR_EXISTS   = -5,
    IS_ERR_PERM     = -6,
    IS_ERR_TIMEOUT  = -7,
    IS_ERR_INTERNAL = -8,
    IS_ERR_AUTH     = -9,
    IS_ERR_QUOTA    = -10,
    IS_ERR_BUSY     = -11,
    IS_ERR_TRUNC    = -12,  /* output was truncated */
} IS_err_t;

const char *IS_strerror(IS_err_t err);

typedef struct { uint8_t b[16]; } IS_uuid_t;

IS_err_t IS_uuid_generate(IS_uuid_t *out);
void         IS_uuid_to_str(const IS_uuid_t *u, char out[IS_UUID_STR_LEN]);
IS_err_t IS_uuid_from_str(const char *s, IS_uuid_t *out);
bool         IS_uuid_equal(const IS_uuid_t *a, const IS_uuid_t *b);

typedef enum {
    INSTANCE_STATE_PENDING  = 0,
    INSTANCE_STATE_RUNNING  = 1,
    INSTANCE_STATE_STOPPED  = 2,
    INSTANCE_STATE_ERROR    = 3,
    INSTANCE_STATE_DELETED  = 4,
} instance_state_t;

const char *instance_state_str(instance_state_t s);
typedef enum {
    VOLUME_STATE_AVAILABLE = 0,
    VOLUME_STATE_IN_USE    = 1,
    VOLUME_STATE_ERROR     = 2,
    VOLUME_STATE_DELETED   = 3,
} volume_state_t;

const char *volume_state_str(volume_state_t s);

typedef enum {
    ROLE_MEMBER = 0,
    ROLE_ADMIN  = 1,
} IS_role_t;

#define HTTP_200_OK           200
#define HTTP_201_CREATED      201
#define HTTP_202_ACCEPTED     202
#define HTTP_204_NO_CONTENT   204
#define HTTP_400_BAD_REQUEST  400
#define HTTP_401_UNAUTHORIZED 401
#define HTTP_403_FORBIDDEN    403
#define HTTP_404_NOT_FOUND    404
#define HTTP_409_CONFLICT     409
#define HTTP_422_UNPROC       422
#define HTTP_429_TOO_MANY     429
#define HTTP_500_INTERNAL     500
#define HTTP_503_UNAVAIL      503

#define IS_UNUSED(x)    ((void)(x))
#define IS_ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))

#define IS_ZALLOC(T) ((T *)IS_zalloc(sizeof(T)))

void *IS_zalloc(size_t n);
void  IS_free(void **pp);

void IS_memzero(void *p, size_t n);
bool IS_ct_memeq(const void *a, const void *b, size_t n);
