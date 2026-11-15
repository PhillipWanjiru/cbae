/**
 * @file cir_serializer.h
 * @brief CIR -> binary blob, for eventual DB storage (no consumer yet
 *        in the codebase -- this establishes the round-trip contract
 *        a later phase's persistence layer will build on).
 *
 * SCOPE: native-layout binary I/O (fixed-width fields, host byte
 * order), not a portable cross-architecture wire format -- CBAE only
 * targets x86-64 Linux hosts, so byte-order portability would be
 * complexity with no present payoff. Correctness is verified via
 * round-trip: serialize, deserialize into a fresh function, and
 * confirm the result is structurally identical to the original.
 */
#ifndef CBAE_CIR_SERIALIZER_H
#define CBAE_CIR_SERIALIZER_H

#include "cir_function.h"
#include "cbae/cbae_error.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

cbae_err_t cbae_cir_serialize_function(const cbae_cir_function_t *f,
                                        uint8_t **out_buf, size_t *out_size);

cbae_err_t cbae_cir_deserialize_function(const uint8_t *buf, size_t size,
                                          cbae_arena_t *arena,
                                          cbae_cir_function_t **out);

#ifdef __cplusplus
}
#endif

#endif /* CBAE_CIR_SERIALIZER_H */
