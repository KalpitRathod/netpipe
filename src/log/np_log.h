/*
 * np_log.h — internal logging subsystem
 *
 * Usage:
 *   np_log_set_level(NP_LOG_DEBUG);
 *   NP_LOG_INFO("capture started on %s", device);
 */

#pragma once
#ifndef NP_LOG_H
#define NP_LOG_H

#include <stdio.h>
#include <time.h>

typedef enum {
    NP_LOG_TRACE = 0,
    NP_LOG_DEBUG,
    NP_LOG_INFO,
    NP_LOG_WARN,
    NP_LOG_ERROR,
    NP_LOG_FATAL,
    NP_LOG_OFF,
} np_log_level_t;

void np_log_set_level(np_log_level_t level);
void np_log_set_color(bool enable);
void np_log_set_file(FILE *fp);

np_log_level_t np_log_get_level(void);

void _np_log(np_log_level_t level,
             const char *file, int line, const char *func,
             const char *fmt, ...)
    __attribute__((format(printf, 5, 6)));

#define NP_LOG(level, ...) \
    _np_log((level), __FILE__, __LINE__, __func__, __VA_ARGS__)

#define NP_LOG_TRACE(...) NP_LOG(NP_LOG_TRACE, __VA_ARGS__)
#define NP_LOG_DEBUG(...) NP_LOG(NP_LOG_DEBUG, __VA_ARGS__)
#define NP_LOG_INFO(...)  NP_LOG(NP_LOG_INFO,  __VA_ARGS__)
#define NP_LOG_WARN(...)  NP_LOG(NP_LOG_WARN,  __VA_ARGS__)
#define NP_LOG_ERROR(...) NP_LOG(NP_LOG_ERROR, __VA_ARGS__)
#define NP_LOG_FATAL(...) NP_LOG(NP_LOG_FATAL, __VA_ARGS__)

#endif /* NP_LOG_H */
