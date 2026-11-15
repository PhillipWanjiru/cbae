/* Survey (not shipped): what do the CIR serializer's old and new versions do with each hostile blob and each corrupt
 * function? Each case runs in a child process so that a crash is a result, not the end of the survey. */
#define main orig_main
#include "../../../tests/unit/test_cir_serializer.c"
#undef main
#include <sys/wait.h>
#include <unistd.h>

static int in_child(int (*fn)(size_t), size_t i, size_t *maxreq) {
    int fd[2];
    assert(pipe(fd) == 0);
    fflush(NULL);
    const pid_t p = fork();
    if (p == 0) {
        close(fd[0]);
        ai_reset();
        const int r = fn(i);
        const size_t m = ai_max_request();
        if (write(fd[1], &m, sizeof m) != (ssize_t)sizeof m) _exit(99);
        _exit(r);
    }
    close(fd[1]);
    int st;
    waitpid(p, &st, 0);
    *maxreq = 0;
    if (read(fd[0], maxreq, sizeof *maxreq) != (ssize_t)sizeof *maxreq) *maxreq = 0;
    close(fd[0]);
    if (WIFSIGNALED(st)) return 100 + WTERMSIG(st);
    return WEXITSTATUS(st);
}

static int hostile_child(size_t i) {
    mfunc_t m = base_model();
    HOSTILE[i].fn(&m);
    blob_t b = write_model(&m);
    cbae_cir_function_t *f;
    const cbae_err_t rc = deserialize_blob(&b, &f);
    return rc == CBAE_OK ? 1 : (rc == CBAE_ERR_PARSE ? 0 : 2);
}

static int corruption_child(size_t i) {
    g_long_name = malloc(65537);
    memset(g_long_name, 'n', 65536); g_long_name[65536] = '\0';
    cbae_arena_t arena;
    assert(cbae_arena_init(&arena, 256 * 1024) == CBAE_OK);
    cbae_cir_function_t *f = rich_function(&arena, true);
    CORRUPTIONS[i].fn(f);
    uint8_t *buf = NULL;
    size_t n = 0;
    const cbae_err_t rc = cbae_cir_serialize_function(f, &buf, &n);
    return rc == CORRUPTIONS[i].expect ? 0 : (rc == CBAE_OK ? 1 : 2);
}

static const char *verdict(int r, const char *refused) {
    static char buf[64];
    if (r == 0) return refused;
    if (r == 1) return "ACCEPTED (wrong)";
    if (r == 2) return "refused with another error code";
    snprintf(buf, sizeof buf, "CRASH (signal %d)", r - 100);
    return buf;
}

int main(void) {
    cbae_log_init(CBAE_LOG_ERROR, NULL, 0);
    int bad = 0, total = 0;
    printf("Hostile blobs (deserializer):\n");
    for (size_t i = 0; i < sizeof HOSTILE / sizeof HOSTILE[0]; i++) {
        size_t mx;
        const int r = in_child(hostile_child, i, &mx);
        printf("  %-86s %s%s\n", HOSTILE[i].what, verdict(r, "refused (PARSE)"), mx >= 4u * 1024 * 1024 ? "  [asked malloc for a huge block]" : "");
        bad += r != 0 || mx >= 4u * 1024 * 1024; total++;
    }
    printf("Corrupt functions (serializer):\n");
    for (size_t i = 0; i < sizeof CORRUPTIONS / sizeof CORRUPTIONS[0]; i++) {
        size_t mx;
        const int r = in_child(corruption_child, i, &mx);
        printf("  %-86s %s\n", CORRUPTIONS[i].what, verdict(r, "refused"));
        bad += r != 0; total++;
    }
    printf("%d of %d cases are not handled correctly\n", bad, total);
    return 0;
}
