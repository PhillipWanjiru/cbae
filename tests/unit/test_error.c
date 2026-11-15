/**
 * @file test_error.c
 * @brief Unit tests for the thread-local error context (audit A-034, cbae_error_set).
 *
 * The defect: cbae_error_set formatted straight into the context's own message buffer, so the wrapper
 * idiom CBAE_SET_ERR(code, "context: %s", cbae_last_error()) read and wrote the same bytes (undefined
 * behaviour; the old code produced "wrapped: wrapped: ...").
 */
#include "cbae/cbae_error.h"
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#define PASS(name) printf("  [PASS] %s\n", name)

static void test_set_and_get(void) {
    cbae_error_clear();
    CBAE_SET_ERR(CBAE_ERR_PARSE, "bad token %d at %s", 42, "line 7");
    const cbae_error_context_t *c = cbae_error_get_context();
    assert(c->code == CBAE_ERR_PARSE && strcmp(c->message, "bad token 42 at line 7") == 0);
    assert(c->file && strstr(c->file, "test_error.c") && c->line > 0 && strcmp(c->func, "test_set_and_get") == 0);
    assert(strcmp(cbae_last_error(), "bad token 42 at line 7") == 0);
    PASS("code, message, file, line and function are recorded");
}

static void test_fallback_text(void) {
    cbae_error_clear();
    assert(strcmp(cbae_last_error(), "ok") == 0);                    /* nothing recorded: the text of code 0 */
    CBAE_SET_ERR(CBAE_ERR_OOM, "%s", "");
    assert(strcmp(cbae_last_error(), "out of memory") == 0);         /* an empty message falls back to the code's text */
    cbae_error_set(CBAE_ERR_IO, __FILE__, __LINE__, __func__, NULL);
    assert(cbae_error_get_context()->code == CBAE_ERR_IO && strcmp(cbae_last_error(), "I/O error") == 0);
    PASS("empty or NULL format: last_error falls back to the code's text");
}

static void test_wrapper_idiom(void) {
    cbae_error_clear();
    CBAE_SET_ERR(CBAE_ERR_IO, "inner failure: disk full");
    CBAE_SET_ERR(CBAE_ERR_DB, "wrapped: %s", cbae_last_error());
    assert(strcmp(cbae_last_error(), "wrapped: inner failure: disk full") == 0);
    assert(cbae_error_get_context()->code == CBAE_ERR_DB);
    for (int i = 0; i < 3; i++) CBAE_SET_ERR(CBAE_ERR_DB, "[%s]", cbae_last_error());
    assert(strcmp(cbae_last_error(), "[[[wrapped: inner failure: disk full]]]") == 0);
    /* the old buffer is read after the new text is formatted, not while: a long message wrapped again is cut, not corrupted */
    char longmsg[300];
    memset(longmsg, 'x', sizeof longmsg - 1);
    longmsg[sizeof longmsg - 1] = '\0';
    CBAE_SET_ERR(CBAE_ERR_IO, "%s", longmsg);
    assert(strlen(cbae_last_error()) == CBAE_ERR_MSG_MAX - 1);
    CBAE_SET_ERR(CBAE_ERR_IO, "w: %s", cbae_last_error());
    assert(strlen(cbae_last_error()) == CBAE_ERR_MSG_MAX - 1 && strncmp(cbae_last_error(), "w: xxx", 6) == 0);
    PASS("the wrapper idiom CBAE_SET_ERR(.., \"%s\", cbae_last_error()) works, repeatedly and at the size limit");
}

static void test_truncation(void) {
    char longmsg[1000];
    memset(longmsg, 'a', sizeof longmsg - 1);
    longmsg[sizeof longmsg - 1] = '\0';
    CBAE_SET_ERR(CBAE_ERR_GENERIC, "%s", longmsg);
    const cbae_error_context_t *c = cbae_error_get_context();
    assert(strlen(c->message) == CBAE_ERR_MSG_MAX - 1 && c->message[CBAE_ERR_MSG_MAX - 1] == '\0');
    CBAE_SET_ERR(CBAE_ERR_GENERIC, "100%% of %d", 7);
    assert(strcmp(cbae_last_error(), "100% of 7") == 0);
    PASS("long messages are cut at the buffer size and stay terminated; %% works");
}

static void test_encoding_error(void) {
    /* a conversion that fails makes vsnprintf return a negative number: the message must be empty, not stale or garbage */
    cbae_error_clear();
    CBAE_SET_ERR(CBAE_ERR_IO, "previous");
    const wchar_t bad[] = { (wchar_t)0x7fffffff, 0 };                /* not a valid wide character in any locale */
    CBAE_SET_ERR(CBAE_ERR_PARSE, "value %ls", bad);
    const cbae_error_context_t *c = cbae_error_get_context();
    assert(c->code == CBAE_ERR_PARSE);
    assert(strcmp(c->message, "previous") != 0);
    assert(c->message[0] == '\0' || strncmp(c->message, "value ", 6) == 0);
    PASS("a format that cannot be converted leaves no stale message");
}

static void *thread_body(void *arg) {
    (void)arg;
    assert(cbae_error_get_context()->code == CBAE_OK && cbae_last_error()[0] != '\0');   /* a new thread starts clean */
    CBAE_SET_ERR(CBAE_ERR_TIMEOUT, "from the thread");
    return NULL;
}

static void test_per_thread(void) {
    cbae_error_clear();
    CBAE_SET_ERR(CBAE_ERR_BUSY, "main thread error");
    pthread_t t;
    assert(pthread_create(&t, NULL, thread_body, NULL) == 0);
    assert(pthread_join(t, NULL) == 0);
    assert(cbae_error_get_context()->code == CBAE_ERR_BUSY && strcmp(cbae_last_error(), "main thread error") == 0);
    cbae_error_clear();
    assert(cbae_error_get_context()->code == CBAE_OK && cbae_error_get_context()->message[0] == '\0' && cbae_error_get_context()->file == NULL);
    PASS("each thread has its own context; clear resets it");
}

static void test_err_str(void) {
    static const cbae_err_t codes[] = {
        CBAE_OK, CBAE_ERR_GENERIC, CBAE_ERR_OOM, CBAE_ERR_IO, CBAE_ERR_INVALID, CBAE_ERR_NOT_FOUND, CBAE_ERR_PARSE,
        CBAE_ERR_DB, CBAE_ERR_OVERFLOW, CBAE_ERR_UNSUPPORTED, CBAE_ERR_BUSY, CBAE_ERR_TIMEOUT, CBAE_ERR_THREAD };
    const size_t n = sizeof codes / sizeof codes[0];
    for (size_t i = 0; i < n; i++) {
        assert(cbae_err_str(codes[i])[0] != '\0' && strcmp(cbae_err_str(codes[i]), "unknown error") != 0);
        for (size_t j = i + 1; j < n; j++) assert(strcmp(cbae_err_str(codes[i]), cbae_err_str(codes[j])) != 0);
    }
    assert(strcmp(cbae_err_str((cbae_err_t)-99), "unknown error") == 0 && strcmp(cbae_err_str((cbae_err_t)5), "unknown error") == 0);
    PASS("every code has its own text; an unknown code says so");
}

int main(void) {
    printf("=== test_error ===\n");
    test_set_and_get();
    test_fallback_text();
    test_wrapper_idiom();
    test_truncation();
    test_encoding_error();
    test_per_thread();
    test_err_str();
    printf("All error tests passed.\n");
    return 0;
}
