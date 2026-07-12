/**
 * @file platform_linux.c
 * @brief Linux-specific helpers: /proc, sysfs, system info.
 */
#include "platform/platform_linux.h"
#include "cbae/cbae_error.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/utsname.h>

cbae_err_t cbae_linux_kernel_version(int *major, int *minor, int *patch) {
    struct utsname u;
    if(uname(&u) < 0) CBAE_RETURN_ERR(CBAE_ERR_IO, "uname failed");
    if(sscanf(u.release, "%d.%d.%d", major, minor, patch) < 2)
        CBAE_RETURN_ERR(CBAE_ERR_PARSE, "cannot parse kernel version: %s", u.release);
    return CBAE_OK;
}

cbae_err_t cbae_linux_read_proc_file(const char *path, char *buf, size_t bufsz) {
    if(!path || !buf || !bufsz) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "null arg");
    FILE *f = fopen(path, "r");
    if(!f) CBAE_RETURN_ERR(CBAE_ERR_IO, "fopen(%s) failed", path);
    size_t n = fread(buf, 1, bufsz - 1, f);
    buf[n] = '\0';
    fclose(f);
    return CBAE_OK;
}

long cbae_linux_cpu_count(void) { return sysconf(_SC_NPROCESSORS_ONLN); }
long cbae_linux_page_size(void) { return sysconf(_SC_PAGESIZE); }
