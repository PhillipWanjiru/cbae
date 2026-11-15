/**
 * @file thread_pool.c
 * @brief Fixed-size pool of POSIX threads running a FIFO queue of tasks.
 */
#include "platform/thread_pool.h"
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

typedef struct work_item {
    cbae_work_fn      fn;
    void             *arg;
    struct work_item *next;
} work_item_t;

struct cbae_thread_pool {
    pthread_t       *threads;                    /* the workers started so far: threads[0 .. thread_count - 1] */
    int              thread_count;
    work_item_t     *head, *tail;                /* the queue, oldest first */
    size_t           active;                     /* tasks running now */
    bool             shutdown;                   /* destroy has begun: no new tasks, workers leave when the queue is empty */
    pthread_mutex_t  mu;                         /* guards everything above */
    pthread_cond_t   work_ready;                 /* the queue is not empty, or shutdown */
    pthread_cond_t   work_done;                  /* the queue is empty and nothing is running */
};

static void *worker_main(void *arg) {
    cbae_thread_pool_t *pool = (cbae_thread_pool_t *)arg;
    pthread_mutex_lock(&pool->mu);
    for (;;) {
        while (!pool->head && !pool->shutdown) pthread_cond_wait(&pool->work_ready, &pool->mu);
        if (!pool->head) break;                                  /* shutting down and nothing left to run */
        work_item_t *item = pool->head;
        pool->head = item->next;
        if (!pool->head) pool->tail = NULL;
        pool->active++;
        pthread_mutex_unlock(&pool->mu);

        item->fn(item->arg);
        free(item);

        pthread_mutex_lock(&pool->mu);
        pool->active--;
        if (pool->active == 0 && !pool->head) pthread_cond_broadcast(&pool->work_done);
    }
    pthread_mutex_unlock(&pool->mu);
    return NULL;
}

/* Stops and joins the workers that were started, runs what is queued, and frees the pool. The lock and the two
 * condition variables must have been created. */
static void pool_teardown(cbae_thread_pool_t *p) {
    pthread_mutex_lock(&p->mu);
    p->shutdown = true;
    pthread_cond_broadcast(&p->work_ready);
    pthread_mutex_unlock(&p->mu);
    for (int i = 0; i < p->thread_count; i++) pthread_join(p->threads[i], NULL);
    pthread_cond_destroy(&p->work_done);
    pthread_cond_destroy(&p->work_ready);
    pthread_mutex_destroy(&p->mu);
    free(p->threads);
    free(p);
}

cbae_err_t cbae_thread_pool_create(cbae_thread_pool_t **out, int n) {
    if (!out) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "null output pointer");
    *out = NULL;
    if (n < 1 || n > CBAE_THREAD_POOL_MAX_THREADS)
        CBAE_RETURN_ERR(CBAE_ERR_INVALID, "a pool has 1 to %d threads, not %d", CBAE_THREAD_POOL_MAX_THREADS, n);

    cbae_thread_pool_t *p = (cbae_thread_pool_t *)calloc(1, sizeof *p);
    if (!p) CBAE_RETURN_ERR(CBAE_ERR_OOM, "thread pool allocation failed");
    p->threads = (pthread_t *)calloc((size_t)n, sizeof *p->threads);
    if (!p->threads) { free(p); CBAE_RETURN_ERR(CBAE_ERR_OOM, "thread pool allocation of %d threads failed", n); }

    int rc = pthread_mutex_init(&p->mu, NULL);
    if (rc != 0) { free(p->threads); free(p); CBAE_RETURN_ERR(CBAE_ERR_THREAD, "cannot create the pool's lock (error %d)", rc); }
    rc = pthread_cond_init(&p->work_ready, NULL);
    if (rc != 0) { pthread_mutex_destroy(&p->mu); free(p->threads); free(p); CBAE_RETURN_ERR(CBAE_ERR_THREAD, "cannot create a condition variable (error %d)", rc); }
    rc = pthread_cond_init(&p->work_done, NULL);
    if (rc != 0) { pthread_cond_destroy(&p->work_ready); pthread_mutex_destroy(&p->mu); free(p->threads); free(p); CBAE_RETURN_ERR(CBAE_ERR_THREAD, "cannot create a condition variable (error %d)", rc); }

    for (int i = 0; i < n; i++) {
        rc = pthread_create(&p->threads[i], NULL, worker_main, p);
        if (rc != 0) {
            pool_teardown(p);                                    /* joins the i workers that did start */
            CBAE_RETURN_ERR(CBAE_ERR_THREAD, "cannot start thread %d of %d (error %d)", i + 1, n, rc);
        }
        p->thread_count = i + 1;
    }
    *out = p;
    return CBAE_OK;
}

cbae_err_t cbae_thread_pool_submit(cbae_thread_pool_t *pool, cbae_work_fn fn, void *arg) {
    if (!pool) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "null thread pool");
    if (!fn)   CBAE_RETURN_ERR(CBAE_ERR_INVALID, "null task function");
    work_item_t *item = (work_item_t *)malloc(sizeof *item);
    if (!item) CBAE_RETURN_ERR(CBAE_ERR_OOM, "task allocation failed");
    item->fn = fn;
    item->arg = arg;
    item->next = NULL;

    pthread_mutex_lock(&pool->mu);
    if (pool->shutdown) {
        pthread_mutex_unlock(&pool->mu);
        free(item);
        CBAE_RETURN_ERR(CBAE_ERR_INVALID, "the thread pool is being destroyed");
    }
    if (pool->tail) pool->tail->next = item; else pool->head = item;
    pool->tail = item;
    pthread_cond_signal(&pool->work_ready);
    pthread_mutex_unlock(&pool->mu);
    return CBAE_OK;
}

void cbae_thread_pool_wait(cbae_thread_pool_t *pool) {
    if (!pool) return;
    pthread_mutex_lock(&pool->mu);
    while (pool->active || pool->head) pthread_cond_wait(&pool->work_done, &pool->mu);
    pthread_mutex_unlock(&pool->mu);
}

void cbae_thread_pool_destroy(cbae_thread_pool_t *pool) {
    if (pool) pool_teardown(pool);
}
