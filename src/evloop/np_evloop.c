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
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
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
/*  Loop struct                                                         */
/* ------------------------------------------------------------------ */

struct np_evloop {
    int            epfd;          /* epoll file descriptor             */
    int            wakefd;        /* eventfd for stop()                */

    np_ev_entry_t *entries;       /* fd → entry map (indexed by fd)   */
    int            entries_cap;   /* capacity                         */

    volatile bool  running;
    int            max_events;    /* epoll_wait batch size            */
    struct epoll_event *ev_buf;   /* epoll_wait output buffer         */

    int            next_timer_id;
};

/* ------------------------------------------------------------------ */
/*  Helpers                                                             */
/* ------------------------------------------------------------------ */

static int entries_ensure(np_evloop_t *loop, int fd)
{
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

    loop->epfd = epoll_create1(EPOLL_CLOEXEC);
    if (loop->epfd < 0) {
        NP_LOG_ERROR("epoll_create1: %s", strerror(errno));
        free(loop); return NULL;
    }

    loop->wakefd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (loop->wakefd < 0) {
        NP_LOG_ERROR("eventfd: %s", strerror(errno));
        close(loop->epfd); free(loop); return NULL;
    }

    /* Register wakefd in epoll */
    struct epoll_event ev = { .events = EPOLLIN, .data.fd = loop->wakefd };
    epoll_ctl(loop->epfd, EPOLL_CTL_ADD, loop->wakefd, &ev);

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
    /* Bug 1 fix: close any remaining timer fds and free their contexts
     * before destroying the loop.  Previously these were leaked. */
    if (loop->entries) {
        for (int i = 0; i < loop->entries_cap; i++) {
            np_ev_entry_t *e = &loop->entries[i];
            if (e->is_timer && e->fd > 0) {
                close(e->fd);
                free(e->userdata);
            }
        }
    }
    if (loop->epfd   >= 0) close(loop->epfd);
    if (loop->wakefd >= 0) close(loop->wakefd);
    free(loop->ev_buf);
    free(loop->entries);
    free(loop);
}

/* ------------------------------------------------------------------ */
/*  Add / remove fds                                                    */
/* ------------------------------------------------------------------ */

int np_evloop_add(np_evloop_t *loop, int fd, uint32_t events,
                   np_ev_cb cb, void *userdata)
{
    if (entries_ensure(loop, fd) < 0) return -1;

    np_ev_entry_t *e = &loop->entries[fd];
    bool already_in  = (e->fd == fd && e->cb != NULL);

    e->fd       = fd;
    e->events   = events;
    e->cb       = cb;
    e->userdata = userdata;

    struct epoll_event ev;
    ev.events  = np_to_epoll(events);
    ev.data.fd = fd;

    int op = already_in ? EPOLL_CTL_MOD : EPOLL_CTL_ADD;
    if (epoll_ctl(loop->epfd, op, fd, &ev) < 0) {
        NP_LOG_ERROR("epoll_ctl(%s, fd=%d): %s",
                     op == EPOLL_CTL_ADD ? "ADD" : "MOD",
                     fd, strerror(errno));
        return -1;
    }
    return 0;
}

int np_evloop_del(np_evloop_t *loop, int fd)
{
    epoll_ctl(loop->epfd, EPOLL_CTL_DEL, fd, NULL);
    if (fd < loop->entries_cap)
        memset(&loop->entries[fd], 0, sizeof(loop->entries[fd]));
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Timer support via timerfd                                           */
/* ------------------------------------------------------------------ */

typedef struct { np_timer_cb cb; void *ud; int id; } timer_ctx_t;

static int timer_dispatch(np_evloop_t *loop, int fd,
                           uint32_t events, void *userdata)
{
    (void)events;
    timer_ctx_t *tc = userdata;
    /* drain the timerfd */
    uint64_t expirations;
    if (read(fd, &expirations, sizeof(expirations)) < 0) { /* ignore */ }

    tc->cb(loop, tc->id, tc->ud);

    /* one-shot: remove from epoll, close fd, free context.
     *
     * Bug fix: the old code returned -1 to tell the run loop to call
     * np_evloop_del(loop, fd) again — but we already deleted the entry
     * and closed the fd here.  The run loop's np_evloop_del would then
     * operate on a stale (already-zeroed) entry and an already-closed
     * fd.  If the user callback (tc->cb) opened a new fd that happened
     * to reuse the same number, the run loop's np_evloop_del would
     * corrupt that new entry.  Now we return 0 (success) so the run
     * loop does NOT attempt a second cleanup — we handle it all here. */
    np_evloop_del(loop, fd);
    close(fd);
    free(tc);
    return 0; /* we already cleaned up; don't let the run loop double-delete */
}

int np_evloop_add_timer(np_evloop_t *loop, int ms,
                         np_timer_cb cb, void *userdata)
{
    int tfd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
    if (tfd < 0) return -1;

    struct itimerspec ts = {
        .it_interval = {0, 0},
        .it_value    = { .tv_sec  = ms / 1000,
                         .tv_nsec = (long)(ms % 1000) * 1000000L }
    };
    timerfd_settime(tfd, 0, &ts, NULL);

    timer_ctx_t *tc = malloc(sizeof(*tc));
    if (!tc) { close(tfd); return -1; }
    tc->cb = cb;
    tc->ud = userdata;
    tc->id = loop->next_timer_id++;

    if (np_evloop_add(loop, tfd, NP_EV_READ, timer_dispatch, tc) < 0) {
        free(tc);
        close(tfd);
        return -1;
    }

    /* Bug 1 fix: mark the entry as a timer so np_evloop_del_timer can
     * find it by timer_id.  Without this, del_timer was a silent no-op
     * and every cancelled timer leaked its fd + timer_ctx_t. */
    if (tfd < loop->entries_cap) {
        np_ev_entry_t *e = &loop->entries[tfd];
        e->is_timer  = true;
        e->timer_id  = tc->id;
        e->timer_cb  = cb;
    }

    return tc->id;
}

void np_evloop_del_timer(np_evloop_t *loop, int timer_id)
{
    /* Walk entries to find the timerfd with this id */
    for (int i = 0; i < loop->entries_cap; i++) {
        np_ev_entry_t *e = &loop->entries[i];
        if (e->is_timer && e->timer_id == timer_id) {
            int fd = e->fd;
            void *ud = e->userdata;
            /* Clear the entry first so np_evloop_del doesn't double-clear. */
            np_evloop_del(loop, fd);
            close(fd);
            /* Bug 1 fix: free the timer_ctx_t that was allocated in
             * np_evloop_add_timer.  Previously this was leaked. */
            free(ud);
            return;
        }
    }
}

/* ------------------------------------------------------------------ */
/*  Run loop                                                            */
/* ------------------------------------------------------------------ */

void np_evloop_run(np_evloop_t *loop)
{
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

            if (fd >= loop->entries_cap) continue;
            np_ev_entry_t *e = &loop->entries[fd];
            if (!e->cb) continue;

            uint32_t np_evs = epoll_to_np(loop->ev_buf[i].events);
            int rc = e->cb(loop, fd, np_evs, e->userdata);
            if (rc < 0) np_evloop_del(loop, fd);
        }
    }

    NP_LOG_DEBUG("%s", "evloop stopped");
}

void np_evloop_stop(np_evloop_t *loop)
{
    loop->running = false;
    /* wake epoll_wait */
    uint64_t v = 1;
    if (write(loop->wakefd, &v, sizeof(v)) < 0) { /* ignore */ }
}
