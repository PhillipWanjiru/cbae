/* A-033: the Phase 1 thread pool, driven through failures. The original .c file is included so that its private type is visible. */
#define _GNU_SOURCE
#include "alloc_inject.h"
#include <dirent.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int __real_pthread_create(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
static int g_calls, g_fail_from = 0;
int __wrap_pthread_create(pthread_t *t, const pthread_attr_t *a, void *(*f)(void *), void *p) {
    g_calls++;
    if (g_fail_from && g_calls >= g_fail_from) return EAGAIN;
    return __real_pthread_create(t, a, f, p);
}
#include THREAD_POOL_C
int main(int argc, char **argv) {
    const int mode = argc > 1 ? atoi(argv[1]) : 0;
    alarm(10);
    cbae_thread_pool_t *p = NULL;
    if (mode == 1) {                                   /* the allocation of the pool fails */
        ai_fail_at(1);
        cbae_err_t rc = cbae_thread_pool_create(&p, 4);
        printf("create returned %d\n", (int)rc);
    } else if (mode == 2) {                            /* the system refuses the third thread of four */
        g_fail_from = 3;
        cbae_err_t rc = cbae_thread_pool_create(&p, 4);
        int live = 0; DIR *d = opendir("/proc/self/task"); while (readdir(d)) live++; closedir(d); live -= 3;                                  // ".", ".." and the main thread
        printf("create returned %d (0 = success), pool %s; 4 workers asked for, %d running\n", (int)rc, p ? "returned" : "NULL", live);
        g_fail_from = 0;
        fflush(stdout);
        cbae_thread_pool_destroy(p);
        printf("destroy returned\n");
    } else if (mode == 5) {                            /* as mode 2, on a heap that holds old data (the thread table is malloc'ed, not cleared) */
        void *junk = malloc(sizeof(pthread_t) * 4);
        memset(junk, 0xAA, sizeof(pthread_t) * 4);
        free(junk);
        g_fail_from = 3;
        cbae_err_t rc = cbae_thread_pool_create(&p, 4);
        printf("create returned %d (0 = success)\n", (int)rc);
        g_fail_from = 0;
        fflush(stdout);
        cbae_thread_pool_destroy(p);                   /* joins threads[0..3], two of which were never created */
        printf("destroy returned\n");
    } else if (mode == 3) {                            /* 100000 threads asked for, the system refuses every one */
        g_fail_from = 1;
        cbae_err_t rc = cbae_thread_pool_create(&p, 100000);
        printf("create returned %d (0 = success), pthread_create was called %d times\n", (int)rc, g_calls);
    } else if (mode == 4) {
        cbae_thread_pool_wait(NULL);
        printf("wait(NULL) returned\n");
    }
    return 0;
}
