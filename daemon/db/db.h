
#ifndef IS_DB_H
#define IS_DB_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include "../utils/defaults.h"

typedef struct IS_db IS_db_t;

IS_err_t db_open(const char *path, IS_db_t **out);
void         db_close(IS_db_t *db);
IS_err_t db_migrate(IS_db_t *db);

typedef struct {
    char     id[IS_UUID_STR_LEN];
    char     name[IS_MAX_NAME_LEN];
    char     pwhash[256];   /* PBKDF2 encoded string  */
    int      role;          /* IS_role_t */
    int64_t  created_at;    /* Unix timestamp */
} db_user_t;

IS_err_t db_user_create(IS_db_t *db, const db_user_t *u);
IS_err_t db_user_get_by_name(IS_db_t *db, const char *name, db_user_t *out);
IS_err_t db_user_get_by_id  (IS_db_t *db, const char *id,   db_user_t *out);
IS_err_t db_user_delete(IS_db_t *db, const char *id);
/* List: returns IS_OK; caller passes buffer + count; *n_out = rows written */
IS_err_t db_user_list(IS_db_t *db, db_user_t *buf, size_t cap, size_t *n_out);

typedef struct {
    char    id[IS_UUID_STR_LEN];
    char    user_id[IS_UUID_STR_LEN];
    char    value[IS_TOKEN_HEX_LEN];  /* hex-encoded token bytes */
    int64_t expires_at;
} db_token_t;

IS_err_t db_token_create(IS_db_t *db, const db_token_t *t);
IS_err_t db_token_get   (IS_db_t *db, const char *value, db_token_t *out);
IS_err_t db_token_delete(IS_db_t *db, const char *value);
IS_err_t db_token_purge_expired(IS_db_t *db);

typedef struct {
    char     id[IS_UUID_STR_LEN];
    char     name[IS_MAX_NAME_LEN];
    char     user_id[IS_UUID_STR_LEN];
    char     image_id[IS_UUID_STR_LEN];
    int      vcpus;
    int64_t  ram_mib;
    int64_t  disk_gib;
    int      state;         /* instance_state_t */
    int      pid;           /* QEMU PID, 0 if stopped */
    int      vnc_port;
    int64_t  created_at;
    int64_t  updated_at;
} db_instance_t;

IS_err_t db_instance_create(IS_db_t *db, const db_instance_t *inst);
IS_err_t db_instance_get(IS_db_t *db, const char *id, db_instance_t *out);
IS_err_t db_instance_update_state(IS_db_t *db, const char *id,
                                       int state, int pid);
IS_err_t db_instance_delete(IS_db_t *db, const char *id);
IS_err_t db_instance_list(IS_db_t *db, const char *user_id,
                               db_instance_t *buf, size_t cap, size_t *n_out);

typedef struct {
    char     id[IS_UUID_STR_LEN];
    char     name[IS_MAX_NAME_LEN];
    char     user_id[IS_UUID_STR_LEN];
    char     instance_id[IS_UUID_STR_LEN]; /* empty if not attached */
    char     path[IS_MAX_PATH_LEN];         /* loop-backing file path */
    int64_t  size_gib;
    int      state;         /* volume_state_t */
    int64_t  created_at;
} db_volume_t;

IS_err_t db_volume_create(IS_db_t *db, const db_volume_t *v);
IS_err_t db_volume_get(IS_db_t *db, const char *id, db_volume_t *out);
IS_err_t db_volume_update(IS_db_t *db, const db_volume_t *v);
IS_err_t db_volume_delete(IS_db_t *db, const char *id);
IS_err_t db_volume_list(IS_db_t *db, const char *user_id,
                             db_volume_t *buf, size_t cap, size_t *n_out);

typedef struct {
    char     id[IS_UUID_STR_LEN];
    char     name[IS_MAX_NAME_LEN];
    char     user_id[IS_UUID_STR_LEN];
    char     cidr[32];        /* e.g. "10.42.0.0/24" */
    char     bridge[IS_MAX_NAME_LEN];  /* host bridge interface name */
    int      state;
    int64_t  created_at;
} db_network_t;

IS_err_t db_network_create(IS_db_t *db, const db_network_t *n);
IS_err_t db_network_get(IS_db_t *db, const char *id, db_network_t *out);
IS_err_t db_network_delete(IS_db_t *db, const char *id);
IS_err_t db_network_list(IS_db_t *db, const char *user_id,
                              db_network_t *buf, size_t cap, size_t *n_out);

#endif /* IS_DB_H */
