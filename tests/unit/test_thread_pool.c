/**
 * @file test_thread_pool.c
 * @brief Unit tests for the thread pool (audit A-033): arguments, every task runs exactly once, order with one
 *        worker, wait, tasks that submit tasks, destroy with work queued, a refused late submission, many
 *        submitters, and every way creation can fail (the system refusing a thread or a lock, memory running out).
 */
#define _GNU_SOURCE
#include "alloc_inject.h"
#include "oom_sweep.h"
#include "platform/thread_pool.h"
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define PASS(name) printf("  [PASS] %s\n", name)
#define QUICK (getenv("CBAE_TEST_QUICK") != NULL)

/* ---- the system refusing to start a thread or create a lock: the k-th such call from the moment of arming fails.
 * Needs   -Wl,--wrap=pthread_create,--wrap=pthread_mutex_init,--wrap=pthread_cond_init   (tests/CMakeLists.txt). ---- */

int __real_pthread_create(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
int __real_pthread_mutex_init(pthread_mutex_t *, const pthread_mutexattr_t *);
int __real_pthread_cond_init(pthread_cond_t *, const pthread_condattr_t *);

static _Atomic int pj_countdown;                       /* 0: not armed */
static _Atomic int pj_calls;                           /* wrapped calls since the last pj_arm */

static void pj_arm(int k)    { atomic_store(&pj_calls, 0); atomic_store(&pj_countdown, k); }
static void pj_disarm(void)  { atomic_store(&pj_countdown, 0); }

static bool pj_should_fail(void) {
    atomic_fetch_add(&pj_calls, 1);
    int c = atomic_load(&pj_countdown);
    while (c > 0)
        if (atomic_compare_exchange_weak(&pj_countdown, &c, c - 1)) return c == 1;
    return false;
}

int __wrap_pthread_create(pthread_t *t, const pthread_attr_t *a, void *(*fn)(void *), void *arg) {
    if (pj_should_fail()) return EAGAIN;
    return __real_pthread_create(t, a, fn, arg);
}
int __wrap_pthread_mutex_init(pthread_mutex_t *m, const pthread_mutexattr_t *a) {
    if (pj_should_fail()) return ENOMEM;
    return __real_pthread_mutex_init(m, a);
}
int __wrap_pthread_cond_init(pthread_cond_t *c, const pthread_condattr_t *a) {
    if (pj_should_fail()) return ENOMEM;
    return __real_pthread_cond_init(c, a);
}

/* ---- helpers ---- */

static int count_threads(void) {
    DIR *d = opendir("/proc/self/task");
    assert(d);
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d))) if (e->d_name[0] != '.') n++;
    closedir(d);
    return n;
}

/* The process is back to @p baseline threads. A joined thread can take a moment to leave /proc, so wait for it;
 * a thread that was left running never leaves. */
static void expect_threads(int baseline) {
    for (int i = 0; i < 5000; i++) {
        if (count_threads() == baseline) return;
        usleep(1000);
    }
    fprintf(stderr, "%d threads, expected %d\n", count_threads(), baseline);
    assert(!"threads were left running");
}

static void sleep_ms(long ms) {
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

static _Atomic long g_count;
static void count_task(void *arg) { (void)arg; atomic_fetch_add(&g_count, 1); }
static void flag_task(void *arg)  { atomic_fetch_add((atomic_int *)arg, 1); }
typedef struct { atomic_int started, done; } slow_t;
static void slow_task(void *arg) {
    slow_t *s = (slow_t *)arg;
    atomic_fetch_add(&s->started, 1);
    sleep_ms(30);
    atomic_fetch_add(&s->done, 1);
}

/* ================================================================ tests */

static void test_arguments(void) {
    cbae_thread_pool_t *p;
    assert(cbae_thread_pool_create(NULL, 1) == CBAE_ERR_INVALID);
    static const int BAD[] = { 0, -1, INT_MIN, CBAE_THREAD_POOL_MAX_THREADS + 1, 1 << 20, INT_MAX };
    for (size_t i = 0; i < sizeof BAD / sizeof BAD[0]; i++) {
        p = (cbae_thread_pool_t *)(uintptr_t)1;
        assert(cbae_thread_pool_create(&p, BAD[i]) == CBAE_ERR_INVALID);
        assert(p == NULL);                                       /* the output is empty on every failure */
    }

    const int baseline = count_threads();
    assert(cbae_thread_pool_create(&p, CBAE_THREAD_POOL_MAX_THREADS) == CBAE_OK);          /* the largest pool */
    assert(count_threads() == baseline + CBAE_THREAD_POOL_MAX_THREADS);
    cbae_thread_pool_destroy(p);
    expect_threads(baseline);

    atomic_store(&g_count, 0);
    assert(cbae_thread_pool_create(&p, 1) == CBAE_OK && p);
    assert(cbae_thread_pool_submit(NULL, count_task, NULL) == CBAE_ERR_INVALID);
    assert(cbae_thread_pool_submit(p, NULL, NULL) == CBAE_ERR_INVALID);
    cbae_thread_pool_wait(NULL);                                 /* ignored */
    cbae_thread_pool_destroy(NULL);                              /* ignored */
    cbae_thread_pool_wait(p);                                    /* an idle pool: returns at once */
    cbae_thread_pool_wait(p);
    cbae_thread_pool_destroy(p);
    assert(atomic_load(&g_count) == 0);                          /* a refused task never ran */
    expect_threads(baseline);
    PASS("arguments are checked; the output is empty on every failure; NULL is ignored; 256 threads start and stop");
}

static void test_every_task_runs_once(void) {
    const int tasks = QUICK ? 500 : 5000;
    static const int WORKERS[] = { 1, 2, 3, 8 };
    for (size_t w = 0; w < sizeof WORKERS / sizeof WORKERS[0]; w++) {
        atomic_int *ran = (atomic_int *)calloc((size_t)tasks, sizeof *ran);
        assert(ran);
        cbae_thread_pool_t *p;
        assert(cbae_thread_pool_create(&p, WORKERS[w]) == CBAE_OK);
        for (int i = 0; i < tasks; i++) assert(cbae_thread_pool_submit(p, flag_task, &ran[i]) == CBAE_OK);
        cbae_thread_pool_wait(p);
        for (int i = 0; i < tasks; i++) assert(atomic_load(&ran[i]) == 1);                  /* once, not twice, not never */
        cbae_thread_pool_destroy(p);
        free(ran);
    }
    PASS("every submitted task runs exactly once, with 1, 2, 3 and 8 workers");
}

typedef struct { int *log; int *used; int id; } order_t;
static void order_task(void *arg) { order_t *o = (order_t *)arg; o->log[(*o->used)++] = o->id; }

static void test_order_with_one_worker(void) {
    enum { N = 1000 };
    static int log[N];
    int used = 0;
    static order_t t[N];
    cbae_thread_pool_t *p;
    assert(cbae_thread_pool_create(&p, 1) == CBAE_OK);
    for (int i = 0; i < N; i++) { t[i] = (order_t){ log, &used, i }; assert(cbae_thread_pool_submit(p, order_task, &t[i]) == CBAE_OK); }
    cbae_thread_pool_wait(p);
    assert(used == N);
    for (int i = 0; i < N; i++) assert(log[i] == i);
    cbae_thread_pool_destroy(p);
    PASS("with one worker the tasks run in the order they were submitted");
}

typedef struct { cbae_thread_pool_t *pool; slow_t *tasks; int seen; } waiter_t;
static void *waiter_main(void *arg) {
    waiter_t *w = (waiter_t *)arg;
    cbae_thread_pool_wait(w->pool);
    w->seen = atomic_load(&w->tasks->done);                      /* what the tasks wrote is visible after wait */
    return NULL;
}

static void test_wait(void) {
    slow_t t;
    memset(&t, 0, sizeof t);
    cbae_thread_pool_t *p;
    assert(cbae_thread_pool_create(&p, 4) == CBAE_OK);
    for (int i = 0; i < 4; i++) assert(cbae_thread_pool_submit(p, slow_task, &t) == CBAE_OK);
    while (atomic_load(&t.started) < 4) usleep(100);             /* all four are out of the queue and running: the queue is empty */
    cbae_thread_pool_wait(p);                                    /* returns when the running tasks have finished, not before */
    assert(atomic_load(&t.done) == 4);

    memset(&t, 0, sizeof t);                                     /* three threads wait together */
    for (int i = 0; i < 8; i++) assert(cbae_thread_pool_submit(p, slow_task, &t) == CBAE_OK);
    pthread_t th[3];
    waiter_t w[3];
    for (int i = 0; i < 3; i++) { w[i] = (waiter_t){ p, &t, -1 }; assert(pthread_create(&th[i], NULL, waiter_main, &w[i]) == 0); }
    for (int i = 0; i < 3; i++) { assert(pthread_join(th[i], NULL) == 0); assert(w[i].seen == 8); }
    cbae_thread_pool_destroy(p);
    PASS("wait returns only when every queued and running task is done, for several waiters at once");
}

typedef struct fan { cbae_thread_pool_t *pool; struct fan *base; long idx, total; } fan_t;
static _Atomic long g_fan;
static void fan_task(void *arg) {
    const fan_t *f = (const fan_t *)arg;
    atomic_fetch_add(&g_fan, 1);
    for (long c = 2 * f->idx + 1; c <= 2 * f->idx + 2; c++)
        if (c < f->total) assert(cbae_thread_pool_submit(f->pool, fan_task, &f->base[c]) == CBAE_OK);
}

static void test_tasks_submit_tasks(void) {
    const long total = QUICK ? 255 : 2047;                       /* a complete binary tree of tasks */
    fan_t *nodes = (fan_t *)calloc((size_t)total, sizeof *nodes);
    assert(nodes);
    cbae_thread_pool_t *p;
    assert(cbae_thread_pool_create(&p, 4) == CBAE_OK);
    for (long i = 0; i < total; i++) nodes[i] = (fan_t){ p, nodes, i, total };
    atomic_store(&g_fan, 0);
    assert(cbae_thread_pool_submit(p, fan_task, &nodes[0]) == CBAE_OK);
    cbae_thread_pool_wait(p);                                    /* also waits for the tasks the tasks submitted */
    assert(atomic_load(&g_fan) == total);
    cbae_thread_pool_destroy(p);
    free(nodes);
    PASS("tasks that submit tasks: wait covers the whole tree");
}

static atomic_int g_gate;
static void gate_task(void *arg) { (void)arg; while (!atomic_load(&g_gate)) usleep(200); }
static void *destroyer_main(void *arg) { cbae_thread_pool_destroy((cbae_thread_pool_t *)arg); return NULL; }

static void test_destroy_runs_the_queue(void) {
    cbae_thread_pool_t *p;
    atomic_store(&g_count, 0);
    atomic_store(&g_gate, 0);
    assert(cbae_thread_pool_create(&p, 1) == CBAE_OK);
    assert(cbae_thread_pool_submit(p, gate_task, NULL) == CBAE_OK);          /* the only worker is busy ... */
    for (int i = 0; i < 500; i++) assert(cbae_thread_pool_submit(p, count_task, NULL) == CBAE_OK);   /* ... so these wait in the queue */
    pthread_t th;
    assert(pthread_create(&th, NULL, destroyer_main, p) == 0);
    sleep_ms(30);                                                /* destroy begins with the queue full (it does not matter if it is slower) */
    atomic_store(&g_gate, 1);
    assert(pthread_join(th, NULL) == 0);
    assert(atomic_load(&g_count) == 500);                        /* destroy ran everything that was queued */
    PASS("destroy runs the tasks that are still queued");
}

typedef struct { cbae_thread_pool_t *pool; atomic_int started, refused, accepted; } late_t;
static void late_task(void *arg) {
    late_t *l = (late_t *)arg;
    atomic_store(&l->started, 1);
    struct timespec t0, now;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (;;) {                                                   /* submit until destroy has begun and the pool says no */
        const cbae_err_t rc = cbae_thread_pool_submit(l->pool, count_task, NULL);
        if (rc == CBAE_OK) atomic_fetch_add(&l->accepted, 1);
        else { assert(rc == CBAE_ERR_INVALID); atomic_store(&l->refused, 1); return; }
        clock_gettime(CLOCK_MONOTONIC, &now);
        assert(now.tv_sec - t0.tv_sec < 30 && "destroy never began");
        usleep(100);
    }
}

static void test_late_submission_refused(void) {
    late_t l;
    memset(&l, 0, sizeof l);
    atomic_store(&g_count, 0);
    assert(cbae_thread_pool_create(&l.pool, 1) == CBAE_OK);
    assert(cbae_thread_pool_submit(l.pool, late_task, &l) == CBAE_OK);
    while (!atomic_load(&l.started)) usleep(100);
    pthread_t th;
    assert(pthread_create(&th, NULL, destroyer_main, l.pool) == 0);
    assert(pthread_join(th, NULL) == 0);                         /* returns once the task has seen the refusal and the queue is drained */
    assert(atomic_load(&l.refused) == 1);
    assert(atomic_load(&g_count) == atomic_load(&l.accepted));   /* what was accepted ran, what was refused did not */
    PASS("a task submitted once destroy has begun is refused; every task that was accepted ran");
}

static void test_create_destroy_cycles(void) {
    const int cycles = QUICK ? 60 : 300;
    atomic_store(&g_count, 0);
    const int baseline = count_threads();
    for (int i = 0; i < cycles; i++) {
        cbae_thread_pool_t *p;
        assert(cbae_thread_pool_create(&p, 3) == CBAE_OK);
        if (i & 1) for (int k = 0; k < 3; k++) assert(cbae_thread_pool_submit(p, count_task, NULL) == CBAE_OK);
        cbae_thread_pool_destroy(p);                             /* destroy right after create: workers that have not yet started still stop */
    }
    assert(atomic_load(&g_count) == 3L * (cycles / 2));
    expect_threads(baseline);
    PASS("pools created and destroyed in a loop, with and without work");
}

#define SUBMITTERS 4
typedef struct { cbae_thread_pool_t *pool; int count; } submitter_t;
static void *submitter_main(void *arg) {
    const submitter_t *s = (const submitter_t *)arg;
    for (int i = 0; i < s->count; i++) assert(cbae_thread_pool_submit(s->pool, count_task, NULL) == CBAE_OK);
    return NULL;
}

static void test_many_submitters(void) {
    const int per = QUICK ? 1000 : 5000;
    cbae_thread_pool_t *p;
    atomic_store(&g_count, 0);
    assert(cbae_thread_pool_create(&p, 4) == CBAE_OK);
    pthread_t th[SUBMITTERS];
    submitter_t s = { p, per };
    for (int i = 0; i < SUBMITTERS; i++) assert(pthread_create(&th[i], NULL, submitter_main, &s) == 0);
    for (int i = 0; i < SUBMITTERS; i++) assert(pthread_join(th[i], NULL) == 0);
    cbae_thread_pool_wait(p);
    assert(atomic_load(&g_count) == (long)SUBMITTERS * per);
    cbae_thread_pool_destroy(p);
    PASS("tasks submitted from several threads at once are all run");
}

static void test_system_refuses(void) {
    enum { WORKERS = 4, CALLS = 3 + WORKERS };                   /* one lock, two condition variables, one thread per worker */
    const int baseline = count_threads();
    for (int k = 1; k <= CALLS; k++) {
        cbae_thread_pool_t *p = (cbae_thread_pool_t *)(uintptr_t)1;
        pj_arm(k);
        const cbae_err_t rc = cbae_thread_pool_create(&p, WORKERS);
        pj_disarm();
        assert(rc == CBAE_ERR_THREAD);                           /* not a success with fewer workers, not a crash */
        assert(p == NULL);
        expect_threads(baseline);                                /* the workers that did start were stopped and joined */
    }

    cbae_thread_pool_t *p;                                       /* and with nothing failing, exactly that many calls were made */
    pj_arm(CALLS + 1);
    assert(cbae_thread_pool_create(&p, WORKERS) == CBAE_OK);
    assert(atomic_load(&pj_calls) == CALLS);
    pj_disarm();
    atomic_store(&g_count, 0);
    for (int i = 0; i < 10; i++) assert(cbae_thread_pool_submit(p, count_task, NULL) == CBAE_OK);
    cbae_thread_pool_wait(p);
    assert(atomic_load(&g_count) == 10);
    cbae_thread_pool_destroy(p);
    expect_threads(baseline);
    PASS("a refused thread or lock at any point of creation: an error, nothing left running, nothing leaked");
}

static cbae_err_t pool_body(void *ctx, uint64_t failing) {
    (void)ctx; (void)failing;
    atomic_store(&g_count, 0);
    cbae_thread_pool_t *p = (cbae_thread_pool_t *)(uintptr_t)1;
    const cbae_err_t rc = cbae_thread_pool_create(&p, 3);
    if (rc != CBAE_OK) { assert(rc == CBAE_ERR_OOM && p == NULL); return rc; }
    int accepted = 0;
    cbae_err_t first = CBAE_OK;
    for (int i = 0; i < 5; i++) {
        const cbae_err_t r = cbae_thread_pool_submit(p, count_task, NULL);
        if (r == CBAE_OK) accepted++;
        else { assert(r == CBAE_ERR_OOM); if (first == CBAE_OK) first = r; }
    }
    cbae_thread_pool_wait(p);
    assert(atomic_load(&g_count) == accepted);                   /* a refused task did not run, an accepted one did */
    cbae_thread_pool_destroy(p);
    return first;
}

static void test_allocation_failure(void) {
    const int baseline = count_threads();
    const oom_report_t r = oom_sweep(pool_body, NULL, true);
    assert(r.allocations == 2 + 5);                              /* the pool, its thread table, five queue entries */
    assert(r.runs > 0 && r.reported == r.runs && r.swallowed == 0);
    expect_threads(baseline);
    PASS("every allocation failure is reported (create and submit) and leaves nothing behind");
}

int main(void) {
    printf("=== test_thread_pool ===\n");
    test_arguments();
    test_every_task_runs_once();
    test_order_with_one_worker();
    test_wait();
    test_tasks_submit_tasks();
    test_destroy_runs_the_queue();
    test_late_submission_refused();
    test_create_destroy_cycles();
    test_many_submitters();
    test_system_refuses();
    test_allocation_failure();
    printf("All thread pool tests passed.\n");
    return 0;
}
