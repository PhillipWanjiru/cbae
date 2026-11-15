/**
 * @file sha256.h
 * @brief SHA-256 (FIPS 180-4). The identity of a binary in the database is the SHA-256 of its bytes.
 */
#ifndef CBAE_SHA256_H
#define CBAE_SHA256_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CBAE_SHA256_DIGEST_BYTES 32
#define CBAE_SHA256_HEX_BYTES    65      /* 64 hex digits and the NUL */

typedef struct cbae_sha256 {
    uint32_t state[8];
    uint64_t total;              /* bytes absorbed so far */
    uint8_t  block[64];
    size_t   fill;               /* bytes waiting in block */
} cbae_sha256_t;

void cbae_sha256_init  (cbae_sha256_t *c);
void cbae_sha256_update(cbae_sha256_t *c, const void *data, size_t len);
void cbae_sha256_final (cbae_sha256_t *c, uint8_t out[CBAE_SHA256_DIGEST_BYTES]);

/** One call for a whole buffer. @p data may be NULL when @p len is 0. */
void cbae_sha256(const void *data, size_t len, uint8_t out[CBAE_SHA256_DIGEST_BYTES]);

/** Lower-case hex of a digest, NUL-terminated. */
void cbae_sha256_hex(const uint8_t digest[CBAE_SHA256_DIGEST_BYTES], char out[CBAE_SHA256_HEX_BYTES]);

#ifdef __cplusplus
}
#endif

#endif /* CBAE_SHA256_H */
