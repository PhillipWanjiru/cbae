/**
 * @file file_io.c
 * @brief Whole-file reads and path helpers (see platform/file_io.h).
 */
#include "platform/file_io.h"
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

cbae_err_t cbae_file_read(const char *path, cbae_file_data_t *out) {
    if (!out) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "file_read: out is NULL");
    out->data = NULL;
    out->size = 0;
    if (!path) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "file_read: path is NULL");

    /* O_NONBLOCK: opening a FIFO for reading would otherwise wait for a writer, forever; the type check
     * below then refuses it. It changes nothing for a regular file. */
    int fd;
    do { fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK); } while (fd < 0 && errno == EINTR);
    if (fd < 0) {
        const int e = errno;
        if (e == ENOENT) CBAE_RETURN_ERR(CBAE_ERR_NOT_FOUND, "'%.200s' does not exist", path);
        CBAE_RETURN_ERR(CBAE_ERR_IO, "cannot open '%.200s': %s", path, strerror(e));
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        const int e = errno;
        close(fd);
        CBAE_RETURN_ERR(CBAE_ERR_IO, "cannot stat '%.200s': %s", path, strerror(e));
    }
    if (!S_ISREG(st.st_mode)) {
        close(fd);
        CBAE_RETURN_ERR(CBAE_ERR_INVALID, "'%.200s' is not a regular file", path);
    }
    if (st.st_size < 0 || (uintmax_t)st.st_size > (uintmax_t)CBAE_FILE_MAX_BYTES) {
        close(fd);
        CBAE_RETURN_ERR(CBAE_ERR_OVERFLOW, "'%.200s' is larger than %zu bytes", path, CBAE_FILE_MAX_BYTES);
    }
    const size_t size = (size_t)st.st_size;
    if (size == 0) { close(fd); return CBAE_OK; }

    uint8_t *buf = (uint8_t *)malloc(size);
    if (!buf) {
        close(fd);
        CBAE_RETURN_ERR(CBAE_ERR_OOM, "cannot allocate %zu bytes to read '%.200s'", size, path);
    }
    size_t got = 0;
    while (got < size) {
        const ssize_t r = read(fd, buf + got, size - got);
        if (r < 0) {
            if (errno == EINTR) continue;
            const int e = errno;
            free(buf);
            close(fd);
            CBAE_RETURN_ERR(CBAE_ERR_IO, "cannot read '%.200s': %s", path, strerror(e));
        }
        if (r == 0) break;
        got += (size_t)r;
    }
    close(fd);
    if (got < size) {
        free(buf);
        CBAE_RETURN_ERR(CBAE_ERR_IO, "'%.200s' got shorter while it was being read (%zu of %zu bytes)", path, got, size);
    }
    out->data = buf;
    out->size = size;
    return CBAE_OK;
}

void cbae_file_release(cbae_file_data_t *f) {
    if (!f) return;
    free(f->data);
    f->data = NULL;
    f->size = 0;
}

bool cbae_file_exists(const char *path) {
    struct stat st;
    return path && stat(path, &st) == 0;
}

const char *cbae_path_basename(const char *path) {
    if (!path) return "";
    const char *s = strrchr(path, '/');
    return s ? s + 1 : path;
}
