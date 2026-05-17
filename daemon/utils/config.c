
#define _GNU_SOURCE
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include "defaults.h"

#define MAX_LINE     512
#define MAX_SECTION  64
#define MAX_KEY      64
#define MAX_VAL      IS_MAX_PATH_LEN

static char *trim(char *s)
{
    while (isspace((unsigned char)*s)) s++;
    if (*s == '\0') return s;
    char *end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) end--;
    *(end + 1) = '\0';
    return s;
}

static void safe_strcpy(char *dst, const char *src, size_t dstsize)
{
    if (dstsize == 0) return;
    size_t slen = strlen(src);
    size_t n    = slen < (dstsize - 1) ? slen : (dstsize - 1);
    memcpy(dst, src, n);
    dst[n] = '\0';
}

static bool parse_uint(const char *s, unsigned long long *out,
                        unsigned long long min_val, unsigned long long max_val)
{
    if (!s || *s == '\0') return false;
    char *endp;
    errno = 0;
    unsigned long long v = strtoull(s, &endp, 10);
    if (errno != 0 || endp == s || *endp != '\0') return false;
    if (v < min_val || v > max_val) return false;
    *out = v;
    return true;
}

static bool parse_bool(const char *s, bool *out)
{
    if (strcasecmp(s, "true") == 0 || strcmp(s, "1") == 0
        || strcasecmp(s, "yes") == 0 || strcasecmp(s, "on") == 0) {
        *out = true; return true;
    }
    if (strcasecmp(s, "false") == 0 || strcmp(s, "0") == 0
        || strcasecmp(s, "no") == 0  || strcasecmp(s, "off") == 0) {
        *out = false; return true;
    }
    return false;
}

void config_defaults(IS_config_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));

    /* daemon */
    safe_strcpy(cfg->daemon.user,     DEFAULT_USER,  sizeof(cfg->daemon.user));
    safe_strcpy(cfg->daemon.group,    DEFAULT_GROUP, sizeof(cfg->daemon.group));
    safe_strcpy(cfg->daemon.pid_file, DEFAULT_PID_FILE, sizeof(cfg->daemon.pid_file));
    cfg->daemon.foreground = false;

    /* api */
    safe_strcpy(cfg->api.bind_address, "127.0.0.1", sizeof(cfg->api.bind_address));
    cfg->api.port              = DEFAULT_PORT;
    cfg->api.tls_port          = DEFAULT_TLS_PORT;
    cfg->api.thread_pool_size  = IS_THREAD_POOL_SIZE;
    cfg->api.request_timeout   = IS_READ_TIMEOUT_SEC;
    cfg->api.rate_limit_rps    = 100;

    /* db */
    safe_strcpy(cfg->db.path, DEFAULT_DB_PATH, sizeof(cfg->db.path));

    /* storage */
    safe_strcpy(cfg->storage.volume_dir, DEFAULT_STORAGE_DIR,
                sizeof(cfg->storage.volume_dir));
    cfg->storage.max_volume_gib = 1024;

    /* compute */
    safe_strcpy(cfg->compute.qemu_binary, DEFAULT_QEMU_BIN,
                sizeof(cfg->compute.qemu_binary));
    safe_strcpy(cfg->compute.image_dir, DEFAULT_IMAGE_DIR,
                sizeof(cfg->compute.image_dir));
    cfg->compute.vnc_base_port = 5900;

    /* logging */
    safe_strcpy(cfg->logging.level, "info", sizeof(cfg->logging.level));
    safe_strcpy(cfg->logging.file,  DEFAULT_LOG_FILE, sizeof(cfg->logging.file));
    cfg->logging.syslog = true;
}

static void apply_kv(IS_config_t *cfg,
                     const char *section, const char *key, const char *val,
                     const char *path, int lineno)
{
    unsigned long long uv;

#define WARN(msg) fprintf(stderr, "%s:%d: warning: " msg " (key=%s)\n", path, lineno, key)
#define SAFE_PATH(dst) do { \
    if (val[0] != '/') { WARN("path must be absolute"); return; } \
    safe_strcpy((dst), val, sizeof(dst)); \
} while (0)

    if (strcasecmp(section, "daemon") == 0) {
        if      (strcasecmp(key, "user")       == 0) safe_strcpy(cfg->daemon.user, val, sizeof(cfg->daemon.user));
        else if (strcasecmp(key, "group")      == 0) safe_strcpy(cfg->daemon.group, val, sizeof(cfg->daemon.group));
        else if (strcasecmp(key, "pid_file")   == 0) SAFE_PATH(cfg->daemon.pid_file);
        else if (strcasecmp(key, "foreground") == 0) parse_bool(val, &cfg->daemon.foreground);

    } else if (strcasecmp(section, "api") == 0) {
        if (strcasecmp(key, "bind_address") == 0) {
            safe_strcpy(cfg->api.bind_address, val, sizeof(cfg->api.bind_address));
        } else if (strcasecmp(key, "port") == 0) {
            if (parse_uint(val, &uv, 1, 65535)) cfg->api.port = (uint16_t)uv;
            else WARN("invalid port");
        } else if (strcasecmp(key, "tls_port") == 0) {
            if (parse_uint(val, &uv, 1, 65535)) cfg->api.tls_port = (uint16_t)uv;
            else WARN("invalid tls_port");
        } else if (strcasecmp(key, "tls_cert") == 0) SAFE_PATH(cfg->api.tls_cert);
        else if  (strcasecmp(key, "tls_key")  == 0) SAFE_PATH(cfg->api.tls_key);
        else if (strcasecmp(key, "thread_pool_size") == 0) {
            if (parse_uint(val, &uv, 1, 256)) cfg->api.thread_pool_size = (uint32_t)uv;
            else WARN("invalid thread_pool_size");
        } else if (strcasecmp(key, "request_timeout") == 0) {
            if (parse_uint(val, &uv, 1, 300)) cfg->api.request_timeout = (uint32_t)uv;
            else WARN("invalid request_timeout");
        } else if (strcasecmp(key, "rate_limit_rps") == 0) {
            if (parse_uint(val, &uv, 0, 100000)) cfg->api.rate_limit_rps = (uint32_t)uv;
            else WARN("invalid rate_limit_rps");
        }

    } else if (strcasecmp(section, "database") == 0) {
        if (strcasecmp(key, "path") == 0) SAFE_PATH(cfg->db.path);

    } else if (strcasecmp(section, "storage") == 0) {
        if      (strcasecmp(key, "volume_dir")     == 0) SAFE_PATH(cfg->storage.volume_dir);
        else if (strcasecmp(key, "max_volume_gib") == 0) {
            if (parse_uint(val, &uv, 1, (1ULL << 30))) cfg->storage.max_volume_gib = uv;
            else WARN("invalid max_volume_gib");
        }

    } else if (strcasecmp(section, "compute") == 0) {
        if      (strcasecmp(key, "qemu_binary")  == 0) SAFE_PATH(cfg->compute.qemu_binary);
        else if (strcasecmp(key, "image_dir")    == 0) SAFE_PATH(cfg->compute.image_dir);
        else if (strcasecmp(key, "vnc_base_port") == 0) {
            if (parse_uint(val, &uv, 1, 65535)) cfg->compute.vnc_base_port = (uint16_t)uv;
            else WARN("invalid vnc_base_port");
        }

    } else if (strcasecmp(section, "logging") == 0) {
        if      (strcasecmp(key, "level")  == 0) safe_strcpy(cfg->logging.level, val, sizeof(cfg->logging.level));
        else if (strcasecmp(key, "file")   == 0) SAFE_PATH(cfg->logging.file);
        else if (strcasecmp(key, "syslog") == 0) parse_bool(val, &cfg->logging.syslog);
    }
#undef WARN
#undef SAFE_PATH
}

IS_err_t config_load(const char *path, IS_config_t *cfg)
{
    if (!path || !cfg) return IS_ERR_INVAL;

    config_defaults(cfg);

    FILE *fp = fopen(path, "re");   /* 'e' = O_CLOEXEC */
    if (!fp) {
        fprintf(stderr, "ISd: cannot open config %s: %s\n", path, strerror(errno));
        return IS_ERR_IO;
    }

    char    line[MAX_LINE];
    char    section[MAX_SECTION] = "";
    int     lineno = 0;

    while (fgets(line, sizeof(line), fp)) {
        lineno++;

        /* Check for lines that are too long (didn't get a newline and not EOF) */
        size_t len = strlen(line);
        if (len == sizeof(line) - 1 && line[len - 1] != '\n' && !feof(fp)) {
            fprintf(stderr, "%s:%d: line too long (max %d bytes)\n",
                    path, lineno, MAX_LINE);
            fclose(fp);
            return IS_ERR_INVAL;
        }

        char *s = trim(line);
        if (*s == '\0' || *s == '#' || *s == ';') continue;

        /* Section header */
        if (*s == '[') {
            char *end = strchr(s, ']');
            if (!end) {
                fprintf(stderr, "%s:%d: malformed section header\n", path, lineno);
                fclose(fp);
                return IS_ERR_INVAL;
            }
            *end = '\0';
            s++;
            char *sec = trim(s);
            if (strlen(sec) >= MAX_SECTION) {
                fprintf(stderr, "%s:%d: section name too long\n", path, lineno);
                fclose(fp);
                return IS_ERR_INVAL;
            }
            safe_strcpy(section, sec, sizeof(section));
            continue;
        }

        /* Key = Value */
        char *eq = strchr(s, '=');
        if (!eq) {
            fprintf(stderr, "%s:%d: expected key=value\n", path, lineno);
            fclose(fp);
            return IS_ERR_INVAL;
        }
        *eq = '\0';

        char key[MAX_KEY];
        char val[MAX_VAL];
        char *ktrim = trim(s);
        char *vtrim = trim(eq + 1);

        /* Strip inline comment from value */
        char *comment = strpbrk(vtrim, "#;");
        if (comment && (comment == vtrim || isspace((unsigned char)*(comment - 1)))) {
            *comment = '\0';
            vtrim = trim(vtrim);
        }

        if (strlen(ktrim) >= MAX_KEY || strlen(vtrim) >= MAX_VAL) {
            fprintf(stderr, "%s:%d: key or value too long\n", path, lineno);
            fclose(fp);
            return IS_ERR_INVAL;
        }

        safe_strcpy(key, ktrim, sizeof(key));
        safe_strcpy(val, vtrim, sizeof(val));

        if (section[0] == '\0') {
            fprintf(stderr, "%s:%d: key outside any section\n", path, lineno);
            fclose(fp);
            return IS_ERR_INVAL;
        }

        apply_kv(cfg, section, key, val, path, lineno);
    }

    fclose(fp);
    return IS_OK;
}

void config_dump(const IS_config_t *cfg)
{
    printf("[daemon]\n"
           "  user             = %s\n"
           "  group            = %s\n"
           "  pid_file         = %s\n"
           "  foreground       = %s\n",
           cfg->daemon.user, cfg->daemon.group,
           cfg->daemon.pid_file, cfg->daemon.foreground ? "true" : "false");

    printf("[api]\n"
           "  bind_address     = %s\n"
           "  port             = %u\n"
           "  thread_pool_size = %u\n"
           "  rate_limit_rps   = %u\n",
           cfg->api.bind_address, cfg->api.port,
           cfg->api.thread_pool_size, cfg->api.rate_limit_rps);

    printf("[database]\n  path = %s\n", cfg->db.path);
    printf("[storage]\n  volume_dir = %s\n", cfg->storage.volume_dir);
    printf("[compute]\n  qemu_binary = %s\n", cfg->compute.qemu_binary);
    printf("[logging]\n  level = %s\n", cfg->logging.level);
}
