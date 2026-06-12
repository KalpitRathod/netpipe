/*
 * np_bufpool.h — reference-counted packet buffer pool
 *
 * Inspired by FFmpeg's AVBufferRef / AVBuffer system.
 * Instead of calling malloc()/free() for every packet, we maintain a
 * thread-safe free-list of pre-allocated buffers.  When a buffer's
 * refcount drops to zero it goes back to the pool rather than being
 * freed.
 *
 * Zero-copy cloning:
 *   np_buf_t *b2 = np_buf_ref(b1);   // just increments refcount
 *   np_buf_unref(&b2);               // decrements; returns to pool at 0
 */

#pragma once
#ifndef NP_BUFPOOL_H
#define NP_BUFPOOL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <pthread.h>

/* ------------------------------------------------------------------ */
/*  np_buf_t — a single reference-counted buffer                        */
/* ------------------------------------------------------------------ */

typedef struct np_buf {
    uint8_t        *data;      /* payload pointer (into _storage)     */
    size_t          size;      /* bytes currently used                 */
    size_t          capacity;  /* bytes allocated                      */

    /* reference counting */
    int             refcount;
    pthread_mutex_t reflock;

    /* pool back-pointer (NULL if heap-allocated outside pool)         */
    struct np_bufpool *pool;

    /* intrusive free-list link (valid only when refcount == 0)        */
    struct np_buf  *next_free;

    /* the actual storage immediately follows this struct in memory    */
    uint8_t         _storage[];
} np_buf_t;

/* ------------------------------------------------------------------ */
/*  np_bufpool_t — pool of fixed-capacity buffers                       */
/* ------------------------------------------------------------------ */

typedef struct np_bufpool {
    size_t          buf_capacity;  /* capacity of each buffer           */
    int             pool_size;     /* total slots allocated             */

    np_buf_t       *free_list;
    int             free_count;
    pthread_mutex_t lock;

    /* stats */
    uint64_t        allocs;        /* total times a buffer was handed out */
    uint64_t        misses;        /* times pool was empty → heap alloc  */
    uint64_t        returns;       /* times a buffer came back to pool    */
} np_bufpool_t;

/* ------------------------------------------------------------------ */
/*  API                                                                 */
/* ------------------------------------------------------------------ */

/*
 * Create a pool with `pool_size` pre-allocated buffers, each of
 * `buf_capacity` bytes.
 */
np_bufpool_t *np_bufpool_create(size_t buf_capacity, int pool_size);

/*
 * Destroy the pool and free all memory.
 * Calling this while buffers are still referenced is undefined behaviour.
 */
void np_bufpool_destroy(np_bufpool_t *pool);

/*
 * Acquire a buffer from the pool (or heap-allocate if pool is empty).
 * The returned buffer has refcount == 1.
 */
np_buf_t *np_buf_alloc(np_bufpool_t *pool, size_t needed);

/*
 * Increment the reference count and return the same pointer.
 * The buffer will not be recycled until all references are dropped.
 */
np_buf_t *np_buf_ref(np_buf_t *buf);

/*
 * Decrement the reference count.  Sets *pbuf to NULL.
 * When refcount reaches 0 the buffer is returned to its pool
 * (or freed if it was heap-allocated outside a pool).
 */
void np_buf_unref(np_buf_t **pbuf);

/*
 * Print pool statistics to fp.
 */
void np_bufpool_stats(const np_bufpool_t *pool, FILE *fp);

#endif /* NP_BUFPOOL_H */
