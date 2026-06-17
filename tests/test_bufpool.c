#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>

#include "netpipe.h"
#include "bufpool/np_bufpool.h"

#define NUM_THREADS 4
#define ITERATIONS 1000

typedef struct {
    np_bufpool_t *pool;
    int thread_id;
} thread_arg_t;

static void *worker_fn(void *arg)
{
    thread_arg_t *targ = arg;
    np_bufpool_t *pool = targ->pool;

    for (int i = 0; i < ITERATIONS; i++) {
        /* Allocate a buffer */
        np_buf_t *buf = np_buf_alloc(pool, 500);
        assert(buf != NULL);
        assert(buf->refcount == 1);

        /* Reference it */
        np_buf_t *ref = np_buf_ref(buf);
        assert(ref == buf);
        assert(buf->refcount == 2);

        /* Unref first pointer */
        np_buf_unref(&buf);
        assert(buf == NULL);
        assert(ref->refcount == 1);

        /* Unref second pointer */
        np_buf_unref(&ref);
        assert(ref == NULL);
    }

    return NULL;
}

int main(void)
{
    np_init();
    printf("Running buffer pool stress and functionality tests...\n");

    /* 1. Create a small pool (size 5) */
    np_bufpool_t *pool = np_bufpool_create(1000, 5);
    assert(pool != NULL);
    assert(pool->free_count == 5);
    assert(pool->buf_capacity == 1000);

    /* 2. Allocate all slots */
    np_buf_t *bufs[5];
    for (int i = 0; i < 5; i++) {
        bufs[i] = np_buf_alloc(pool, 1000);
        assert(bufs[i] != NULL);
        assert(bufs[i]->capacity == 1000);
    }
    assert(pool->free_count == 0);

    /* 3. Pool exhaustion: 6th alloc should fall back to heap */
    np_buf_t *overflow = np_buf_alloc(pool, 1000);
    assert(overflow != NULL);
    assert(pool->misses == 1);

    /* 4. Release all including overflow */
    for (int i = 0; i < 5; i++) {
        np_buf_unref(&bufs[i]);
        assert(bufs[i] == NULL);
    }
    assert(pool->free_count == 5);

    np_buf_unref(&overflow);
    assert(overflow == NULL);

    /* 5. Multithreaded concurrency test */
    pthread_t threads[NUM_THREADS];
    thread_arg_t args[NUM_THREADS];

    for (int i = 0; i < NUM_THREADS; i++) {
        args[i].pool = pool;
        args[i].thread_id = i;
        pthread_create(&threads[i], NULL, worker_fn, &args[i]);
    }

    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    /* Print stats diagnostics */
    np_bufpool_stats(pool, stdout);

    np_bufpool_destroy(pool);
    np_cleanup();

    printf("All buffer pool tests PASSED!\n");
    return 0;
}
