/*
 * np_bufpool.c — thread-safe, reference-counted packet buffer pool
 *
 * Design notes
 * ────────────
 * Each pool is a pre-allocated array of (np_buf_t + storage[capacity])
 * blocks.  The blocks are linked into a free-list protected by a single
 * mutex.  For a single-threaded pipeline this is zero contention; for a
 * multi-threaded fan-in the lock is held only for pointer swaps, so
 * contention is negligible.
 *
 * If the pool is exhausted on alloc, we fall back to a plain malloc so
 * captures never drop packets — we just pay the malloc cost and record a
 * "miss" in the stats.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <assert.h>

#include "np_bufpool.h"
#include "../log/np_log.h"

/* ------------------------------------------------------------------ */
/*  Internal helpers                                                    */
/* ------------------------------------------------------------------ */

/* total bytes for one block: header + storage */
static inline size_t block_size(size_t cap) {
    return sizeof(np_buf_t) + cap;
}

static np_buf_t *block_at(void *base, size_t cap, int idx) {
    return (np_buf_t *)((uint8_t *)base + (size_t)idx * block_size(cap));
}

/* ------------------------------------------------------------------ */
/*  Pool creation / destruction                                         */
/* ------------------------------------------------------------------ */

np_bufpool_t *np_bufpool_create(size_t buf_capacity, int pool_size)
{
    assert(buf_capacity > 0 && pool_size > 0);

    np_bufpool_t *pool = calloc(1, sizeof(*pool));
    if (!pool) return NULL;

    pool->buf_capacity = buf_capacity;
    pool->pool_size    = pool_size;
    pthread_mutex_init(&pool->lock, NULL);

    /* Allocate all blocks in one contiguous slab */
    uint8_t *slab = malloc((size_t)pool_size * block_size(buf_capacity));
    if (!slab) { free(pool); return NULL; }
    pool->slab = slab;

    /* Initialise each block and thread it onto the free-list */
    pool->free_list  = NULL;
    pool->free_count = pool_size;

    for (int i = pool_size - 1; i >= 0; i--) {
        np_buf_t *b = block_at(slab, buf_capacity, i);
        b->data      = b->_storage;
        b->size      = 0;
        b->capacity  = buf_capacity;
        b->refcount  = 0;
        b->pool      = pool;
        b->next_free = pool->free_list;
        pthread_mutex_init(&b->reflock, NULL);
        pool->free_list = b;
    }

    NP_LOG_DEBUG("bufpool created: %d × %zu B  (slab=%p)",
                 pool_size, buf_capacity, (void *)slab);
    return pool;
}

void np_bufpool_destroy(np_bufpool_t *pool)
{
    if (!pool) return;

    if (pool->slab) {
        for (int i = 0; i < pool->pool_size; i++) {
            np_buf_t *b = block_at(pool->slab, pool->buf_capacity, i);
            pthread_mutex_destroy(&b->reflock);
        }
        free(pool->slab);
    }

    pthread_mutex_destroy(&pool->lock);
    free(pool);
}

/* ------------------------------------------------------------------ */
/*  Alloc / ref / unref                                                 */
/* ------------------------------------------------------------------ */

np_buf_t *np_buf_alloc(np_bufpool_t *pool, size_t needed)
{
    np_buf_t *b = NULL;

    if (pool) {
        pthread_mutex_lock(&pool->lock);
        if (pool->free_list && pool->buf_capacity >= needed) {
            b               = pool->free_list;
            pool->free_list = b->next_free;
            pool->free_count--;
            pool->allocs++;
        } else {
            pool->misses++;
        }
        pthread_mutex_unlock(&pool->lock);
    }

    if (!b) {
        /* Pool miss or no pool — heap allocate */
        b = malloc(sizeof(np_buf_t) + needed);
        if (!b) return NULL;
        b->data     = b->_storage;
        b->capacity = needed;
        b->pool     = pool;   /* still track pool for stats */
        pthread_mutex_init(&b->reflock, NULL);
    }

    b->size      = 0;
    b->refcount  = 1;
    b->next_free = NULL;
    return b;
}

np_buf_t *np_buf_ref(np_buf_t *buf)
{
    if (!buf) return NULL;
    pthread_mutex_lock(&buf->reflock);
    buf->refcount++;
    pthread_mutex_unlock(&buf->reflock);
    return buf;
}

void np_buf_unref(np_buf_t **pbuf)
{
    if (!pbuf || !*pbuf) return;
    np_buf_t *b = *pbuf;
    *pbuf = NULL;

    pthread_mutex_lock(&b->reflock);
    int rc = --b->refcount;
    pthread_mutex_unlock(&b->reflock);

    if (rc > 0) return;

    /* refcount hit 0 */
    np_bufpool_t *pool = b->pool;

    int is_slab = 0;
    if (pool && pool->slab) {
        uintptr_t ptr = (uintptr_t)b;
        uintptr_t start = (uintptr_t)pool->slab;
        size_t stride = sizeof(np_buf_t) + pool->buf_capacity;
        uintptr_t end = start + (uintptr_t)pool->pool_size * stride;
        /* Bug 6.1 hardening: verify not just that ptr is within the slab's
         * address range, but also that it's at a valid block boundary
         * (i.e. (ptr - start) is a multiple of stride).  Without this
         * check, a heap allocation that happens to fall within the slab's
         * range could be misclassified as a slab buffer, leading to
         * use-after-free / double-handout. */
        if (ptr >= start && ptr < end) {
            uintptr_t offset = ptr - start;
            if (offset % stride == 0) {
                is_slab = 1;
            }
        }
    }

    if (is_slab) {
        /* Return to pool */
        pthread_mutex_lock(&pool->lock);
        b->size      = 0;
        b->next_free = pool->free_list;
        pool->free_list = b;
        pool->free_count++;
        pool->returns++;
        pthread_mutex_unlock(&pool->lock);
    } else {
        /* Heap-allocated (overflow) — just free */
        pthread_mutex_destroy(&b->reflock);
        free(b);
    }
}

/* ------------------------------------------------------------------ */
/*  Diagnostics                                                         */
/* ------------------------------------------------------------------ */

void np_bufpool_stats(const np_bufpool_t *pool, FILE *fp)
{
    if (!pool || !fp) return;
    fprintf(fp,
        "bufpool  cap=%-6zu slots=%-4d free=%-4d "
        "allocs=%-8lu misses=%-6lu returns=%-8lu  hit_rate=%.1f%%\n",
        pool->buf_capacity, pool->pool_size, pool->free_count,
        (unsigned long)pool->allocs,
        (unsigned long)pool->misses,
        (unsigned long)pool->returns,
        (pool->allocs + pool->misses) > 0
            ? 100.0 * (double)pool->allocs / (double)(pool->allocs + pool->misses)
            : 100.0);
}
