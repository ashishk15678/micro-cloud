// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ashish Kumar <15678ashishk@gmail.com>

#pragma once

#include <syslog.h>
#include <stdlib.h>
#include <stdbool.h>

void log_init(const char *ident, const char *file_path, bool use_syslog);
void log_close(void);
void log_write(int level, const char *file, int line, const char *fmt, ...);

#define LOG(level, fmt, ...) \
    log_write(level, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define DEBUG(fmt, ...) LOG(LOG_DEBUG,   fmt, ##__VA_ARGS__)
#define INFO(fmt, ...)  LOG(LOG_INFO,    fmt, ##__VA_ARGS__)
#define WARN(fmt, ...)  LOG(LOG_WARNING, fmt, ##__VA_ARGS__)
#define ERROR(fmt, ...) LOG(LOG_ERR,     fmt, ##__VA_ARGS__)

#define LOG_FATAL(fmt, ...) \
    do { \
        LOG(LOG_CRIT, "FATAL: " fmt, ##__VA_ARGS__); \
        exit(EXIT_FAILURE); \
    } while (0)
