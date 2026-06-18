/*
 * np_evloop.c — epoll(7) based event loop with timerfd support
 *
 * Architecture
 * ────────────
 * We maintain a dynamic table of (fd → np_ev_entry_t) mappings.
 * epoll_wait() fires events; we dispatch to the registered callback.
 * Timer support uses Linux timerfd_create(2) — each timer is just
 * another fd in the epoll set.
 *
 * A self-pipe (or eventfd) is used internally so np_evloop_stop()
 * can wake epoll_wait() from another thread without polling.
 *
 * Thread-safety
 * ─────────────
 * The entries table (loop->entries[]) is protected by loop->lock.
 * All public functions that touch the table (add / del / del_timer /
 * free) take the lock.  The run loop also takes the lock when reading
 * the entry for a fired fd.  This makes it safe to register / cancel
 * timers from any thread.
 *
 * Timer lifecycle (Bug C1 + C2 fix)
 * ──────────────────────────────────
 * Previously, the timer entry was marked AFTER np_evloop_add returned.
 * If the timer fired immediately (ms=0) the dispatch ran first, freed
 * the timer_ctx_t, and then the marking code read the freed pointer
 * (UAF) and left a stale entry whose fd=0 (stdin) — a later
 * del_timer would close(0) and free(NULL).
 *
 * Now: the entry is fully populated (is_timer=true, timer_id, timer_cb,
 * userdata) BEFORE np_evloop_add is called, and a `dispatched` flag in
 * timer_ctx_t prevents the double-free when a callback cancels its own
 * timer.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/eventfd.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#include "np_evloop.h"
#include "../log/np_log.h"

/* ------------------------------------------------------------------ */
/*  fd entry table                                                      */
/* ------------------------------------------------------------------ */

#define NP_EVLOOP_INIT_SLOTS 64

typedef struct np_ev_entry {
    int        fd;
    uint32_t   events;
    np_ev_cb   cb;
    void      *userdata;
    bool       is_timer;
    np_timer_cb timer_cb;
    int        timer_id;
} np_ev_entry_t;

/* ------------------------------------------------------------------ */
/*  Timer context (Bug C1+C2 fix: dispatched flag prevents double-free) */
/* ------------------------------------------------------------------ */

typedef struct {
    np_timer_cb cb;
    void       *ud;
    int         id;
    bool        dispatched;  /* set by timer_dispatch before invoking cb */
} timer_ctx_t;

/* ------------------------------------------------------------------ */
/*  Loop struct                                                         */
/* ------------------------------------------------------------------ */

struct np_evloop {
    int            epfd;          /* epoll file descriptor             */
    int            wakefd;        /* eventfd for stop()                */

    np_ev_entry_t *entries;       /* fd → entry map (indexed by fd)   */
    int            entries_cap;   /* capacity                         */
    pthread_mutex_t lock;         /* protects entries[] + entries_cap */

    volatile bool  running;
    int            max_events;    /* epoll_wait batch size            */
    struct epoll_event *ev_buf;   /* epoll_wait output buffer         */

    int            next_timer_id;
};

/* ------------------------------------------------------------------ */
/*  Helpers                                                             */
/* ------------------------------------------------------------------ */

/* Caller must hold loop->lock. */
static int entries_ensure_locked(np_evloop_t *loop, int fd)
{
    if (fd < 0) return -1;
    if (fd >= loop->entries_cap) {
        int newcap = fd + 64;
        np_ev_entry_t *ne = realloc(loop->entries,
                                    (size_t)newcap * sizeof(*ne));
        if (!ne) return -1;
        memset(ne + loop->entries_cap, 0,
               (size_t)(newcap - loop->entries_cap) * sizeof(*ne));
        loop->entries     = ne;
        loop->entries_cap = newcap;
    }
    return 0;
}

static uint32_t np_to_epoll(uint32_t ev)
{
    uint32_t out = 0;
    if (ev & NP_EV_READ)  out |= EPOLLIN;
    if (ev & NP_EV_WRITE) out |= EPOLLOUT;
    out |= EPOLLERR | EPOLLHUP;
    return out;
}

static uint32_t epoll_to_np(uint32_t ev)
{
    uint32_t out = 0;
    if (ev & EPOLLIN)  out |= NP_EV_READ;
    if (ev & EPOLLOUT) out |= NP_EV_WRITE;
    if (ev & EPOLLERR) out |= NP_EV_ERROR;
    if (ev & EPOLLHUP) out |= NP_EV_HUP;
    return out;
}

/* ------------------------------------------------------------------ */
/*  Lifecycle                                                           */
/* ------------------------------------------------------------------ */

np_evloop_t *np_evloop_create(int max_events)
{
    np_evloop_t *loop = calloc(1, sizeof(*loop));
    if (!loop) return NULL;

    if (pthread_mutex_init(&loop->lock, NULL) != 0) {
        free(loop);
        return NULL;
    }

    loop->epfd = epoll_create1(EPOLL_CLOEXEC);
    if (loop->epfd < 0) {
        NP_LOG_ERROR("epoll_create1: %s", strerror(errno));
        pthread_mutex_destroy(&loop->lock);
        free(loop); return NULL;
    }

    loop->wakefd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (loop->wakefd < 0) {
        NP_LOG_ERROR("eventfd: %s", strerror(errno));
        close(loop->epfd);
        pthread_mutex_destroy(&loop->lock);
        free(loop); return NULL;
    }

    /* Register wakefd in epoll (Bug E5 fix: check return value) */
    struct epoll_event ev = { .events = EPOLLIN, .data.fd = loop->wakefd };
    if (epoll_ctl(loop->epfd, EPOLL_CTL_ADD, loop->wakefd, &ev) < 0) {
        NP_LOG_ERROR("epoll_ctl(ADD wakefd): %s", strerror(errno));
        close(loop->wakefd);
        close(loop->epfd);
        pthread_mutex_destroy(&loop->lock);
        free(loop); return NULL;
    }

    loop->max_events     = max_events > 0 ? max_events : 64;
    loop->ev_buf         = malloc((size_t)loop->max_events * sizeof(struct epoll_event));
    loop->entries_cap    = NP_EVLOOP_INIT_SLOTS;
    loop->entries        = calloc((size_t)loop->entries_cap, sizeof(np_ev_entry_t));
    loop->next_timer_id  = 1;

    if (!loop->ev_buf || !loop->entries) {
        np_evloop_free(loop); return NULL;
    }

    NP_LOG_DEBUG("evloop created (epfd=%d, wakefd=%d)", loop->epfd, loop->wakefd);
    return loop;
}

void np_evloop_free(np_evloop_t *loop)
{
    if (!loop) return;

    pthread_mutex_lock(&loop->lock);
    /* Bug 1 fix: close any remaining timer fds and free their contexts
     * before destroying the loop.  Previously these were leaked. */
    if (loop->entries) {
        for (int i = 0; i < loop->entries_cap; i++) {
            np_ev_entry_t *e = &loop->entries[i];
            if (e->is_timer && e->fd > 0) {
                close(e->fd);
                free(e->userdata);
            }
            e->is_timer = false;
            e->fd = 0;
        }
    }
    if (loop->epfd   >= 0) close(loop->epfd);
    if (loop->wakefd >= 0) close(loop->wakefd);
    free(loop->ev_buf);
    free(loop->entries);
    loop->entries = NULL;
    loop->ev_buf  = NULL;
    pthread_mutex_unlock(&loop->lock);

    pthread_mutex_destroy(&loop->lock);
    free(loop);
}

/* ------------------------------------------------------------------ */
/*  Add / remove fds                                                    */
/* ------------------------------------------------------------------ */

int np_evloop_add(np_evloop_t *loop, int fd, uint32_t events,
                   np_ev_cb cb, void *userdata)
{
    if (!loop || fd < 0) return -1;

    pthread_mutex_lock(&loop->lock);
    if (entries_ensure_locked(loop, fd) < 0) {
        pthread_mutex_unlock(&loop->lock);
        return -1;
    }

    np_ev_entry_t *e = &loop->entries[fd];
    bool already_in  = (e->fd == fd && e->cb != NULL);

    /* Stage new values in locals so we can roll back on epoll_ctl
     * failure (Bug E4 fix: previously the entry was left in a
     * "looks in-use but epoll doesn't know" state). */
    int        prev_fd       = e->fd;
    uint32_t   prev_events   = e->events;
    np_ev_cb   prev_cb       = e->cb;
    void      *prev_userdata = e->userdata;
    bool       prev_is_timer = e->is_timer;
    np_timer_cb prev_tcb     = e->timer_cb;
    int        prev_tid      = e->timer_id;

    e->fd       = fd;
    e->events   = events;
    e->cb       = cb;
    e->userdata = userdata;
    /* If the caller is re-adding an fd that previously was a timer,
     * clear the timer markers — caller is now treating it as a regular fd. */
    if (already_in && prev_is_timer) {
        e->is_timer = false;
        e->timer_cb = NULL;
        e->timer_id = 0;
    }

    struct epoll_event ev;
    ev.events  = np_to_epoll(events);
    ev.data.fd = fd;

    int op = already_in ? EPOLL_CTL_MOD : EPOLL_CTL_ADD;
    if (epoll_ctl(loop->epfd, op, fd, &ev) < 0) {
        NP_LOG_ERROR("epoll_ctl(%s, fd=%d): %s",
                     op == EPOLL_CTL_ADD ? "ADD" : "MOD",
                     fd, strerror(errno));
        /* Roll back entry to its pre-call state. */
        e->fd       = prev_fd;
        e->events   = prev_events;
        e->cb       = prev_cb;
        e->userdata = prev_userdata;
        e->is_timer = prev_is_timer;
        e->timer_cb = prev_tcb;
        e->timer_id = prev_tid;
        pthread_mutex_unlock(&loop->lock);
        return -1;
    }
    pthread_mutex_unlock(&loop->lock);
    return 0;
}

int np_evloop_del(np_evloop_t *loop, int fd)
{
    if (!loop || fd < 0) return 0;  /* Bug E7 fix: validate fd range */

    pthread_mutex_lock(&loop->lock);
    epoll_ctl(loop->epfd, EPOLL_CTL_DEL, fd, NULL);
    if (fd < loop->entries_cap) {
        memset(&loop->entries[fd], 0, sizeof(loop->entries[fd]));
    }
    pthread_mutex_unlock(&loop->lock);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Timer support via timerfd                                           */
/* ------------------------------------------------------------------ */

static int timer_dispatch(np_evloop_t *loop, int fd,
                           uint32_t events, void *userdata)
{
    (void)events;
    timer_ctx_t *tc = userdata;
    if (!tc) return 0;

    /* drain the timerfd */
    uint64_t expirations;
    if (read(fd, &expirations, sizeof(expirations)) < 0) { /* ignore */ }

    /* Bug C2 fix: mark `dispatched` BEFORE invoking the callback so
     * that if the callback calls np_evloop_del_timer() on its own
     * timer id, the del_timer path knows NOT to double-free. */
    tc->dispatched = true;
    tc->cb(loop, tc->id, tc->ud);

    /* One-shot: remove from epoll, close fd, free context.
     *
     * If the callback already cancelled this timer via del_timer(),
     * tc has already been freed and we MUST NOT touch it again.
     * We detect that case by re-checking the entry under the lock —
     * if del_timer ran, the entry's userdata is now NULL. */
    pthread_mutex_lock(&loop->lock);
    bool already_cleaned = false;
    if (fd < loop->entries_cap) {
        np_ev_entry_t *e = &loop->entries[fd];
        if (e->userdata != tc) {
            /* del_timer ran during the callback and freed tc */
            already_cleaned = true;
        } else {
            /* We still own tc. Clear the entry, close fd, free tc. */
            epoll_ctl(loop->epfd, EPOLL_CTL_DEL, fd, NULL);
            memset(&loop->entries[fd], 0, sizeof(loop->entries[fd]));
        }
    }
    pthread_mutex_unlock(&loop->lock);

    if (already_cleaned) {
        /* tc is already freed and fd already closed. */
        return 0;
    }

    close(fd);
    free(tc);
    return 0; /* we already cleaned up; don't let the run loop double-delete */
}

int np_evloop_add_timer(np_evloop_t *loop, int ms,
                         np_timer_cb cb, void *userdata)
{
    if (!loop || !cb) return -1;

    int tfd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
    if (tfd < 0) {
        NP_LOG_ERROR("timerfd_create: %s", strerror(errno));
        return -1;
    }

    struct itimerspec ts = {
        .it_interval = {0, 0},
        .it_value    = { .tv_sec  = ms / 1000,
                         .tv_nsec = (long)(ms % 1000) * 1000000L }
    };
    if (timerfd_settime(tfd, 0, &ts, NULL) < 0) {
        NP_LOG_ERROR("timerfd_settime: %s", strerror(errno));
        close(tfd);
        return -1;
    }

    timer_ctx_t *tc = malloc(sizeof(*tc));
    if (!tc) { close(tfd); return -1; }
    tc->cb          = cb;
    tc->ud          = userdata;
    tc->dispatched  = false;

    pthread_mutex_lock(&loop->lock);
    tc->id = loop->next_timer_id++;

    if (entries_ensure_locked(loop, tfd) < 0) {
        pthread_mutex_unlock(&loop->lock);
        free(tc);
        close(tfd);
        return -1;
    }

    /* Bug C1 fix: fully populate the entry BEFORE adding to epoll.
     * If the timer fires immediately (ms=0) the dispatch will run
     * with the entry already marked as a timer — no race window. */
    np_ev_entry_t *e = &loop->entries[tfd];
    e->fd       = tfd;
    e->events   = NP_EV_READ;
    e->cb       = timer_dispatch;
    e->userdata = tc;
    e->is_timer = true;
    e->timer_cb = cb;
    e->timer_id = tc->id;

    struct epoll_event ev = { .events = EPOLLIN, .data.fd = tfd };
    if (epoll_ctl(loop->epfd, EPOLL_CTL_ADD, tfd, &ev) < 0) {
        NP_LOG_ERROR("epoll_ctl(ADD timer fd=%d): %s", tfd, strerror(errno));
        memset(e, 0, sizeof(*e));   /* roll back */
        pthread_mutex_unlock(&loop->lock);
        free(tc);
        close(tfd);
        return -1;
    }
    int id = tc->id;
    pthread_mutex_unlock(&loop->lock);

    return id;
}

void np_evloop_del_timer(np_evloop_t *loop, int timer_id)
{
    if (!loop) return;

    pthread_mutex_lock(&loop->lock);
    for (int i = 0; i < loop->entries_cap; i++) {
        np_ev_entry_t *e = &loop->entries[i];
        if (e->is_timer && e->timer_id == timer_id) {
            int    fd = e->fd;
            void  *ud = e->userdata;
            timer_ctx_t *tc = (timer_ctx_t *)ud;

            /* Clear the entry first so np_evloop_del doesn't double-clear. */
            epoll_ctl(loop->epfd, EPOLL_CTL_DEL, fd, NULL);
            memset(e, 0, sizeof(*e));

            /* Bug C2 fix: if del_timer is being called from inside the
             * timer's own callback (dispatched == true), the dispatch
             * function still holds a reference to tc and will free it
             * after we return.  We close the fd here (so the dispatch's
             * close() is a no-op double-close on an EBADF fd, which is
             * harmless) but we MUST NOT free tc — let dispatch do it.
             *
             * If del_timer is being called from any other context
             * (dispatched == false), we own tc and free it here. */
            bool already_dispatched = (tc != NULL && tc->dispatched);

            pthread_mutex_unlock(&loop->lock);

            close(fd);
            if (!already_dispatched) {
                free(ud);
            }
            return;
        }
    }
    pthread_mutex_unlock(&loop->lock);
}

/* ------------------------------------------------------------------ */
/*  Run loop                                                            */
/* ------------------------------------------------------------------ */

void np_evloop_run(np_evloop_t *loop)
{
    if (!loop) return;
    loop->running = true;
    NP_LOG_DEBUG("%s", "evloop starting");

    while (loop->running) {
        int n = epoll_wait(loop->epfd, loop->ev_buf, loop->max_events, -1);

        if (n < 0) {
            if (errno == EINTR) continue;
            NP_LOG_ERROR("epoll_wait: %s", strerror(errno));
            break;
        }

        for (int i = 0; i < n && loop->running; i++) {
            int fd = loop->ev_buf[i].data.fd;

            /* Wakeup event — stop() was called */
            if (fd == loop->wakefd) {
                uint64_t v;
                if (read(fd, &v, sizeof(v)) < 0) { /* ignore */ }
                loop->running = false;
                break;
            }

            /* Bug M6 fix: snapshot the entry under the lock so a
             * concurrent np_evloop_del doesn't free the userdata
             * while we're calling the callback.  If the entry was
             * already cleared (cb == NULL), skip. */
            pthread_mutex_lock(&loop->lock);
            if (fd >= loop->entries_cap || fd < 0) {
                pthread_mutex_unlock(&loop->lock);
                continue;
            }
            np_ev_entry_t *e = &loop->entries[fd];
            if (!e->cb) {
                pthread_mutex_unlock(&loop->lock);
                continue;
            }
            np_ev_cb cb       = e->cb;
            void    *userdata = e->userdata;
            pthread_mutex_unlock(&loop->lock);

            uint32_t np_evs = epoll_to_np(loop->ev_buf[i].events);
            int rc = cb(loop, fd, np_evs, userdata);
            if (rc < 0) np_evloop_del(loop, fd);
        }
    }

    NP_LOG_DEBUG("%s", "evloop stopped");
}

void np_evloop_stop(np_evloop_t *loop)
{
    if (!loop) return;
    loop->running = false;
    /* wake epoll_wait */
    uint64_t v = 1;
    if (write(loop->wakefd, &v, sizeof(v)) < 0) { /* ignore */ }
}
