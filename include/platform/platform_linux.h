/**
 * @file platform_linux.h
 * @brief Linux-specific platform API.
 */
#ifndef CBAE_PLATFORM_LINUX_H
#define CBAE_PLATFORM_LINUX_H

#include "cbae/cbae_error.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

cbae_err_t cbae_linux_kernel_version(int *major, int *minor, int *patch);
cbae_err_t cbae_linux_read_proc_file(const char *path, char *buf, size_t bufsz);
long       cbae_linux_cpu_count(void);
long       cbae_linux_page_size(void);

#ifdef __cplusplus
}
#endif

#endif /* CBAE_PLATFORM_LINUX_H */
