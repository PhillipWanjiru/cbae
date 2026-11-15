/**
 * @file file_io.c
 * @brief Memory-mapped file I/O helpers.
 */
#include "cbae/cbae_types.h"
#include "cbae/cbae_error.h"
#include "platform/logging.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

typedef struct cbae_mapped_file {
    void   *data;
    size_t  size;
    int     fd;
} cbae_mapped_file_t;

cbae_err_t cbae_file_map(const char *path, cbae_mapped_file_t *out) {
    if(!path || !out) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "null argument");
    int fd = open(path, O_RDONLY);
    if(fd < 0) CBAE_RETURN_ERR(CBAE_ERR_IO, "open(%s): %s", path, strerror(errno));
    struct stat st;
    if(fstat(fd, &st) < 0) {
        close(fd); CBAE_RETURN_ERR(CBAE_ERR_IO, "fstat: %s", strerror(errno));
    }
    void *data = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if(data == MAP_FAILED) {
        close(fd); CBAE_RETURN_ERR(CBAE_ERR_IO, "mmap: %s", strerror(errno));
    }
    out->data = data;
    out->size = (size_t)st.st_size;
    out->fd   = fd;
    return CBAE_OK;
}

void cbae_file_unmap(cbae_mapped_file_t *mf) {
    if(!mf) return;
    if(mf->data && mf->size) munmap(mf->data, mf->size);
    if(mf->fd >= 0) close(mf->fd);
    memset(mf, 0, sizeof(*mf));
    mf->fd = -1;
}

bool cbae_file_exists(const char *path) {
    struct stat st;
    return path && stat(path, &st) == 0;
}

const char *cbae_path_basename(const char *path) {
    if(!path) return "";
    const char *s = strrchr(path, '/');
    return s ? s + 1 : path;
}
