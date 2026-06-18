/*
 * np_evloop.h — epoll-based async event loop (Linux)
 *
 * This is the plumbing needed to handle tens-of-thousands of concurrent
 * network connections without thread-per-connection overhead — the same
 * reason nginx and Redis use epoll instead of blocking read().
 *
 * Usage:
 *   np_evloop_t *loop = np_evloop_create(128);
 *   np_evloop_add(loop, fd, NP_EV_READ, my_cb, userdata);
 *   np_evloop_run(loop);   // blocks until np_evloop_stop()
 *   np_evloop_free(loop);
 */

#pragma once
#ifndef NP_EVLOOP_H
#define NP_EVLOOP_H

#include <stdint.h>
#include <stdbool.h>

/* ------------------------------------------------------------------ */
/*  Event flags                                                         */
/* ------------------------------------------------------------------ */

#define NP_EV_READ    0x01
#define NP_EV_WRITE   0x02
#define NP_EV_ERROR   0x04
#define NP_EV_HUP     0x08

/* ------------------------------------------------------------------ */
/*  Callback                                                            */
/* ------------------------------------------------------------------ */

typedef struct np_evloop np_evloop_t;

/*
 * Called when events fire on fd.
 * Return 0 to keep fd registered, -1 to remove it from the loop.
 */
typedef int (*np_ev_cb)(np_evloop_t *loop, int fd,
                         uint32_t events, void *userdata);

/* ------------------------------------------------------------------ */
/*  API                                                                 */
/* ------------------------------------------------------------------ */

/* Create an event loop; max_events is the epoll_wait batch size.     */
np_evloop_t *np_evloop_create(int max_events);

/* Add or modify a file descriptor in the loop.                        */
int np_evloop_add(np_evloop_t *loop, int fd, uint32_t events,
                   np_ev_cb cb, void *userdata);

/* Remove a file descriptor from the loop.                             */
int np_evloop_del(np_evloop_t *loop, int fd);

/*
 * Run the event loop forever (or until np_evloop_stop() is called from
 * a callback or another thread).
 */
void np_evloop_run(np_evloop_t *loop);

/* Signal the loop to stop after the current epoll_wait returns.       */
void np_evloop_stop(np_evloop_t *loop);

/*
 * Free the loop.  Regular (non-timer) fds are NOT closed — caller
 * owns them.  Timer fds created via np_evloop_add_timer() ARE closed
 * and their timer_ctx_t is freed (the loop owns these).  Caller must
 * ensure no other thread is inside np_evloop_run() when this is called.
 */
void np_evloop_free(np_evloop_t *loop);

/* ------------------------------------------------------------------ */
/*  Timer support                                                       */
/* ------------------------------------------------------------------ */

/*
 * Schedule a one-shot callback after `ms` milliseconds.
 * Returns a timer id (>= 0) or -1 on error.
 */
typedef void (*np_timer_cb)(np_evloop_t *loop, int timer_id, void *userdata);

int np_evloop_add_timer(np_evloop_t *loop, int ms,
                         np_timer_cb cb, void *userdata);
void np_evloop_del_timer(np_evloop_t *loop, int timer_id);

#endif /* NP_EVLOOP_H */
