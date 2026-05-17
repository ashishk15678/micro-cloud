#pragma once

#include <syslog.h>
#include <stdlib.h>

#define LOG(level, fmt, ...) \
    syslog(level, "[%s:%d] " fmt, __FILE__, __LINE__, ##__VA_ARGS__)

#define DEBUG(fmt, ...) LOG(LOG_DEBUG,   fmt, ##__VA_ARGS__)
#define INFO(fmt, ...)  LOG(LOG_INFO,    fmt, ##__VA_ARGS__)
#define WARN(fmt, ...)  LOG(LOG_WARNING, fmt, ##__VA_ARGS__)
#define ERROR(fmt, ...) LOG(LOG_ERR,     fmt, ##__VA_ARGS__)

#define LOG_FATAL(fmt, ...) \
    do { \
        LOG(LOG_CRIT, "FATAL: " fmt, ##__VA_ARGS__); \
        exit(EXIT_FAILURE); \
    } while (0)

static inline void log_init(const char *ident) {
    // LOG_PID: Include process ID with each message
    // LOG_CONS: Write directly to system console if there is an error in sending to system logger
    // LOG_NDELAY: Open the connection immediately
    openlog(ident, LOG_PID | LOG_CONS | LOG_NDELAY, LOG_DAEMON);
}

static inline void log_close(void) {
    closelog();
}
