// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ashish Kumar <15678ashishk@gmail.com>

#include "../../include/log/log.h"

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

static FILE *g_log_fp = NULL;
static bool g_log_syslog = true;

/** \brief Map syslog levels to human-readable strings. */
static const char *level_to_str(int level) {
    switch (level) {
        case LOG_DEBUG:   return "DEBUG";
        case LOG_INFO:    return "INFO";
        case LOG_WARNING: return "WARN";
        case LOG_ERR:     return "ERROR";
        case LOG_CRIT:    return "CRIT";
        default:          return "LOG";
    }
}

/** \brief Initialize logging sinks (syslog and/or file). */
void log_init(const char *ident, const char *file_path, bool use_syslog) {
    g_log_syslog = use_syslog;
    if (g_log_syslog) {
        openlog(ident, LOG_PID | LOG_CONS | LOG_NDELAY, LOG_DAEMON);
    }

    if (file_path && file_path[0] != '\0') {
        int fd = open(file_path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
        if (fd >= 0) {
            fchmod(fd, 0600);
            g_log_fp = fdopen(fd, "a");
            if (g_log_fp) {
                setvbuf(g_log_fp, NULL, _IOLBF, 0);
            } else {
                close(fd);
                if (g_log_syslog) {
                    syslog(LOG_ERR, "log_init: fdopen failed for %s: %s", file_path, strerror(errno));
                }
            }
        } else if (g_log_syslog) {
            syslog(LOG_ERR, "log_init: open failed for %s: %s", file_path, strerror(errno));
        }
    }
}

/** \brief Emit a formatted log entry to enabled sinks. */
void log_write(int level, const char *file, int line, const char *fmt, ...) {
    va_list ap;

    if (g_log_syslog) {
        va_start(ap, fmt);
        vsyslog(level, fmt, ap);
        va_end(ap);
    }

    if (g_log_fp) {
        char ts[32];
        time_t now = time(NULL);
        struct tm tm_now;
        localtime_r(&now, &tm_now);
        strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm_now);

        fprintf(g_log_fp, "%s %s [%s:%d] ", ts, level_to_str(level), file, line);
        va_start(ap, fmt);
        vfprintf(g_log_fp, fmt, ap);
        va_end(ap);
        fputc('\n', g_log_fp);
    }
}

/** \brief Close any open logging resources. */
void log_close(void) {
    if (g_log_fp) {
        fclose(g_log_fp);
        g_log_fp = NULL;
    }

    if (g_log_syslog) {
        closelog();
    }
}
