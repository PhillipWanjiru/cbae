#define _GNU_SOURCE
#include "platform/logging.h"
#include <dirent.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int fds(void) { DIR *d = opendir("/proc/self/fd"); int n = 0; while (readdir(d)) n++; closedir(d); return n; }
static void logv(cbae_log_level_t lv, const char *f, int l, const char *fn, const char *fmt, ...) { va_list ap; va_start(ap, fmt); cbae_log_write_v(lv, f, l, fn, fmt, ap); va_end(ap); }
int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "";
    if (!strcmp(mode, "forge")) {
        remove("/tmp/a042/t.log"); remove("/tmp/a042/j.log");
        cbae_log_init(CBAE_LOG_INFO, "/tmp/a042/t.log", 0);
        LOG_INFO("%s", "section .text\n[2026-01-01T00:00:00] ERROR  loader/pe_loader.c:1 (cbae_pe_load)  signature check FAILED for ntoskrnl.exe\x1b[2J");
        cbae_log_shutdown();
        cbae_log_init(CBAE_LOG_INFO, "/tmp/a042/j.log", 1);
        LOG_INFO("%s", "export \"evil\"}\n{\"ts\":\"x\",\"level\":\"ERROR\",\"file\":\"f\",\"line\":1,\"func\":\"f\",\"msg\":\"forged\"}");
        cbae_log_shutdown();
    } else if (!strcmp(mode, "fds")) {
        const int before = fds();
        for (int i = 0; i < 40; i++) cbae_log_init(CBAE_LOG_INFO, i & 1 ? "/tmp/a042/ra.log" : "/tmp/a042/rb.log", 0);
        cbae_log_shutdown();
        printf("open descriptors after 40 restarts and a shutdown: %d more than before\n", fds() - before);
    } else if (!strcmp(mode, "null")) {
        cbae_log_init(CBAE_LOG_INFO, "/tmp/a042/n.log", 0);
        logv(CBAE_LOG_INFO, "f.c", 1, "fn", NULL);
        cbae_log_shutdown();
        puts("survived a NULL format");
    } else if (!strcmp(mode, "none")) {
        remove("/tmp/a042/l.log");
        cbae_log_init(CBAE_LOG_TRACE, "/tmp/a042/l.log", 0);
        cbae_log_write(CBAE_LOG_NONE, "f.c", 1, "fn", "a message at level NONE");
        cbae_log_shutdown();
    } else if (!strcmp(mode, "fallback")) {
        cbae_log_init(CBAE_LOG_INFO, "/nonexistent-dir/x.log", 0);
        LOG_INFO("where does this go?");
        cbae_log_shutdown();
    }
    return 0;
}
