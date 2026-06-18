/*
 * np_log.c — ANSI-colour, thread-safe logger
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <stdbool.h>

#include "np_log.h"

static struct {
    np_log_level_t level;
    bool           color;
    FILE          *fp;
    pthread_mutex_t lock;
} g_log = {
    .level = NP_LOG_INFO,
    .color = true,
    .fp    = NULL,
};

static pthread_once_t  g_once = PTHREAD_ONCE_INIT;

static void log_init_once(void) {
    pthread_mutex_init(&g_log.lock, NULL);
    g_log.fp = stderr;
}

void np_log_set_level(np_log_level_t level) {
    pthread_once(&g_once, log_init_once);
    g_log.level = level;
}
void np_log_set_color(bool enable) {
    pthread_once(&g_once, log_init_once);
    g_log.color = enable;
}
void np_log_set_file(FILE *fp) {
    pthread_once(&g_once, log_init_once);
    g_log.fp = fp ? fp : stderr;
}
np_log_level_t np_log_get_level(void) {
    return g_log.level;
}

static const char *level_str[] = {
    "TRACE", "DEBUG", "INFO ", "WARN ", "ERROR", "FATAL"
};

/* ANSI colour codes */
static const char *level_col[] = {
    "\033[90m",  /* TRACE  — dark grey  */
    "\033[36m",  /* DEBUG  — cyan       */
    "\033[32m",  /* INFO   — green      */
    "\033[33m",  /* WARN   — yellow     */
    "\033[31m",  /* ERROR  — red        */
    "\033[35m",  /* FATAL  — magenta    */
};
static const char *COL_RESET = "\033[0m";
static const char *COL_DIM   = "\033[2m";

void _np_log(np_log_level_t level,
             const char *file, int line, const char *func,
             const char *fmt, ...)
{
    /* Bug L1 fix: bounds-check the level before indexing the static
     * arrays.  A misuse of the macro (e.g. casting a random int to
     * np_log_level_t) would otherwise read off the end of level_str
     * / level_col. */
    static const int n_levels = (int)(sizeof(level_str)/sizeof(level_str[0]));
    if (level < 0 || level >= n_levels) return;

    /* Bug L4 fix: ensure g_log is initialized BEFORE we read
     * g_log.level.  The old code read level first, then called
     * pthread_once — a data race if another thread was concurrently
     * calling np_log_set_level before any log call had run. */
    pthread_once(&g_once, log_init_once);

    if (level < g_log.level) return;

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm;
    char timebuf[32];
    /* Bug L2 fix: check localtime_r return — on failure (e.g. negative
     * tv_sec) it returns NULL and tm is left uninitialized. */
    if (!localtime_r(&ts.tv_sec, &tm)) {
        snprintf(timebuf, sizeof(timebuf), "??:??:??.??????");
    } else {
        snprintf(timebuf, sizeof(timebuf), "%02d:%02d:%02d.%06ld",
                 tm.tm_hour, tm.tm_min, tm.tm_sec,
                 (long)(ts.tv_nsec / 1000));
    }

    /* Extract only the basename for brevity */
    const char *base = strrchr(file, '/');
    base = base ? base + 1 : file;

    va_list ap;
    va_start(ap, fmt);

    pthread_mutex_lock(&g_log.lock);

    FILE *fp = g_log.fp ? g_log.fp : stderr;

    if (g_log.color) {
        fprintf(fp, "%s%s%s %s%s%s %s%s:%d%s ",
                COL_DIM,   timebuf, COL_RESET,
                level_col[level], level_str[level], COL_RESET,
                COL_DIM,   base, line, COL_RESET);
    } else {
        fprintf(fp, "%s %s %s:%d ", timebuf, level_str[level], base, line);
    }

    (void)func; /* func available if needed for TRACE-level verbosity */
    vfprintf(fp, fmt, ap);
    fputc('\n', fp);
    fflush(fp);

    pthread_mutex_unlock(&g_log.lock);

    va_end(ap);

    if (level == NP_LOG_FATAL) abort();
}
