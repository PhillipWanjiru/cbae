/**
 * @file thread_pool.h
 * @brief A fixed number of worker threads that run queued tasks, for passes that can work in parallel.
 *
 * cbae_thread_pool_create starts the workers. cbae_thread_pool_submit queues a task (a function and one
 * argument); an idle worker takes the oldest task in the queue and runs it, so with one worker the tasks run in
 * the order they were submitted. The pool never looks at a task's argument or result: a task that has something
 * to report writes it where the submitter will look after cbae_thread_pool_wait, which makes everything the
 * tasks wrote visible to the thread that returns from it (and likewise for cbae_thread_pool_destroy).
 *
 * Which thread may make which call:
 *
 *   create, destroy   one thread, with no other call on that pool in progress or to follow
 *   submit            any thread, also a task running in the pool
 *   wait              any thread except a task running in the pool (it would wait for itself)
 *
 * destroy runs every task that is still queued, then stops the workers and frees the pool. A task submitted after
 * destroy has begun (by a task that is still running) is refused. A task that is accepted always runs.
 */
#ifndef CBAE_THREAD_POOL_H
#define CBAE_THREAD_POOL_H

#include "cbae/cbae_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/** The most workers a pool may have. */
#define CBAE_THREAD_POOL_MAX_THREADS 256

typedef struct cbae_thread_pool cbae_thread_pool_t;

typedef void (*cbae_work_fn)(void *arg);

/**
 * Starts a pool of @p threads workers (1 to CBAE_THREAD_POOL_MAX_THREADS) and stores it in *out.
 * On failure *out is NULL and nothing is left running: CBAE_ERR_INVALID for a NULL @p out or a thread count
 * outside the range, CBAE_ERR_OOM if memory ran out, CBAE_ERR_THREAD if the system would not start a thread
 * or create a lock.
 */
cbae_err_t cbae_thread_pool_create (cbae_thread_pool_t **out, int threads);

/**
 * Queues @p fn(@p arg). CBAE_ERR_INVALID for a NULL pool or function, or if the pool is being destroyed;
 * CBAE_ERR_OOM if the queue entry could not be allocated. In both cases the task is not queued.
 */
cbae_err_t cbae_thread_pool_submit (cbae_thread_pool_t *pool, cbae_work_fn fn, void *arg);

/** Returns when the queue is empty and no task is running (also tasks that were submitted by tasks). A NULL pool is ignored. */
void       cbae_thread_pool_wait   (cbae_thread_pool_t *pool);

/** Runs what is queued, stops and joins the workers and frees the pool. A NULL pool is ignored. */
void       cbae_thread_pool_destroy(cbae_thread_pool_t *pool);

#ifdef __cplusplus
}
#endif

#endif /* CBAE_THREAD_POOL_H */
