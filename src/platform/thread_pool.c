/**
 * @file thread_pool.c
 * @brief POSIX fixed-size thread pool for parallel analysis passes.
 */
#include "cbae/cbae_error.h"
#include "platform/logging.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdbool.h>

typedef void (*cbae_work_fn)(void *arg);

typedef struct work_item {
    cbae_work_fn      fn;
    void             *arg;
    struct work_item *next;
} work_item_t;

typedef struct cbae_thread_pool {
    pthread_t       *threads;
    int              thread_count;
    work_item_t     *head;
    work_item_t     *tail;
    size_t           queue_size;
    pthread_mutex_t  mu;
    pthread_cond_t   work_ready;
    pthread_cond_t   work_done;
    bool             shutdown;
    size_t           active;
} cbae_thread_pool_t;

static void *worker_main(void *arg) {
    cbae_thread_pool_t *pool = (cbae_thread_pool_t *)arg;
    for(;;) {
        pthread_mutex_lock(&pool->mu);
        while(!pool->head && !pool->shutdown)
            pthread_cond_wait(&pool->work_ready, &pool->mu);
        if(pool->shutdown && !pool->head) {
            pthread_mutex_unlock(&pool->mu); return NULL;
        }
        work_item_t *item = pool->head;
        pool->head = item->next;
        if(!pool->head) pool->tail = NULL;
        pool->queue_size--;
        pool->active++;
        pthread_mutex_unlock(&pool->mu);
        item->fn(item->arg);
        free(item);
        pthread_mutex_lock(&pool->mu);
        pool->active--;
        if(!pool->active && !pool->head)
            pthread_cond_broadcast(&pool->work_done);
        pthread_mutex_unlock(&pool->mu);
    }
}

cbae_err_t cbae_thread_pool_create(cbae_thread_pool_t **out, int n) {
    if(!out || n <= 0) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "bad thread pool params");
    cbae_thread_pool_t *p = calloc(1, sizeof(*p));
    p->threads = malloc(sizeof(pthread_t) * (size_t)n);
    if(!p || !p->threads) { free(p); CBAE_RETURN_ERR(CBAE_ERR_OOM, "thread pool alloc"); }
    p->thread_count = n;
    pthread_mutex_init(&p->mu, NULL);
    pthread_cond_init(&p->work_ready, NULL);
    pthread_cond_init(&p->work_done,  NULL);
    for(int i = 0; i < n; i++) pthread_create(&p->threads[i], NULL, worker_main, p);
    *out = p;
    return CBAE_OK;
}

void cbae_thread_pool_wait(cbae_thread_pool_t *pool) {
    pthread_mutex_lock(&pool->mu);
    while(pool->active || pool->head)
        pthread_cond_wait(&pool->work_done, &pool->mu);
    pthread_mutex_unlock(&pool->mu);
}

void cbae_thread_pool_destroy(cbae_thread_pool_t *pool) {
    if(!pool) return;
    pthread_mutex_lock(&pool->mu);
    pool->shutdown = true;
    pthread_cond_broadcast(&pool->work_ready);
    pthread_mutex_unlock(&pool->mu);
    for(int i = 0; i < pool->thread_count; i++) pthread_join(pool->threads[i], NULL);
    pthread_mutex_destroy(&pool->mu);
    pthread_cond_destroy(&pool->work_ready);
    pthread_cond_destroy(&pool->work_done);
    free(pool->threads);
    free(pool);
}
