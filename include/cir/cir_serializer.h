/**
 * @file cir_serializer.h
 * @brief CIR function <-> binary blob, for the database. The format, and what a blob must satisfy, are written at the
 *        top of src/cir/cir_serializer.c.
 *
 * SCOPE: native-layout binary I/O (fixed-width fields in the host's byte order, which the build requires to be
 * little-endian), not a portable cross-architecture wire format - CBAE only targets x86-64 hosts, so byte-order
 * portability would be complexity with no present payoff.
 *
 * THE BLOB IS UNTRUSTED. It comes out of a database file that anything may have written to, so the deserializer
 * checks every field before it uses it and refuses what it cannot make sense of; it never reads past the buffer, never
 * allocates for a count that the bytes present could not hold, and never hands out a function that it could not walk.
 * The serializer, for its part, refuses to write a function that the deserializer would refuse, so that whatever was
 * written can be read back. The bytes are canonical: a function always gives the same bytes, and a function that was
 * read gives, when written, the bytes it was read from.
 */
#ifndef CBAE_CIR_SERIALIZER_H
#define CBAE_CIR_SERIALIZER_H

#include "cir_function.h"
#include "cbae/cbae_error.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Writes @p f as a blob. On success *out_buf is a buffer from malloc, which the caller frees, holding exactly
 * *out_size bytes. On failure *out_buf is NULL and *out_size is 0, @p f is untouched and the error context says why:
 *   CBAE_ERR_INVALID   a NULL argument, or a function that the format cannot hold (an empty block, value or instruction
 *                      slot, ids that are not the table indices, more operands than an instruction holds, a result
 *                      that is not attached to its instruction, an edge to a block that does not exist ...)
 *   CBAE_ERR_OVERFLOW  a count, a length or the total size that does not fit the format's fields
 *   CBAE_ERR_OOM       the buffer could not be allocated
 */
cbae_err_t cbae_cir_serialize_function(const cbae_cir_function_t *f,
                                        uint8_t **out_buf, size_t *out_size);

/**
 * Reads a blob into a function whose memory comes from @p arena; the function is released with
 * cbae_cir_function_destroy (and its memory with the arena). On failure *out is NULL, the error context says why, and
 * the arena may hold what the failed read had allocated (an arena cannot give memory back: reset or destroy it):
 *   CBAE_ERR_PARSE     the blob is not one this version wrote: the message says what is wrong and at which byte
 *   CBAE_ERR_OOM       the arena or the heap ran out of memory
 *   CBAE_ERR_INVALID   a NULL argument
 * What is returned is safe to walk, print and serialize again. Whether it is well-formed CIR (SSA form, operand counts,
 * types) is the verifier's question: cbae_cir_verify_function is not called here, because a function that is yet to be
 * put in SSA form is a legitimate thing to store.
 */
cbae_err_t cbae_cir_deserialize_function(const uint8_t *buf, size_t size,
                                          cbae_arena_t *arena,
                                          cbae_cir_function_t **out);

#ifdef __cplusplus
}
#endif

#endif /* CBAE_CIR_SERIALIZER_H */
