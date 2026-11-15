/**
 * @file file_io.h
 * @brief Reading a whole input file into memory, and small path helpers.
 *
 * cbae_file_read copies the file into one heap block of exactly the file's size. It does not map the
 * file: a mapped file that is truncated by another process while it is being parsed kills the reader
 * with SIGBUS, and a hostile sample must not be able to do that. An exactly sized heap block also lets
 * AddressSanitizer and Valgrind see a parser that reads past the end of its input, which a mapping
 * (rounded up to a page) hides.
 */
#ifndef CBAE_FILE_IO_H
#define CBAE_FILE_IO_H

#include "cbae/cbae_error.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** The largest file cbae_file_read accepts. The input of the engine is untrusted, and everything the
 *  loaders allocate is sized from it. */
#define CBAE_FILE_MAX_BYTES ((size_t)1 << 30)

typedef struct cbae_file_data {
    uint8_t *data;      /**< heap block of exactly `size` bytes; NULL for an empty file */
    size_t   size;
} cbae_file_data_t;

/**
 * Reads the regular file at @p path into @p out.
 *
 * @return CBAE_OK; CBAE_ERR_INVALID for a NULL argument or a path that is not a regular file (a
 *         directory, a FIFO, a device); CBAE_ERR_NOT_FOUND if there is no such file; CBAE_ERR_OVERFLOW
 *         above CBAE_FILE_MAX_BYTES; CBAE_ERR_OOM; CBAE_ERR_IO for any other failure, including a file
 *         that is shorter at the end of the read than it was when it was opened.
 *
 * An empty file succeeds with data == NULL and size == 0: whether that is acceptable is for the
 * caller's format to say. On any error *out is {NULL, 0}.
 */
cbae_err_t cbae_file_read(const char *path, cbae_file_data_t *out);

/** Frees what cbae_file_read returned and empties @p f. NULL and an empty @p f are fine. */
void cbae_file_release(cbae_file_data_t *f);

bool        cbae_file_exists(const char *path);

/** The part of @p path after its last '/'; "" for NULL. The result points into @p path. */
const char *cbae_path_basename(const char *path);

#ifdef __cplusplus
}
#endif

#endif /* CBAE_FILE_IO_H */
