/**
 * @file siphash.h
 * @brief SipHash-2-4: a keyed 64-bit hash for tables whose keys come from files an attacker controls.
 *
 * A symbol name in a hostile binary is chosen by the binary's author; with an unkeyed hash such as
 * FNV-1a the author can pick thousands of names that land in one bucket and turn every lookup into a
 * linear scan. With a secret per-table key that cannot be prepared in advance.
 */
#ifndef CBAE_SIPHASH_H
#define CBAE_SIPHASH_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** SipHash-2-4 of @p len bytes at @p data under the 128-bit @p key. @p data may be NULL when len is 0. */
uint64_t cbae_siphash24(const uint8_t key[16], const void *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* CBAE_SIPHASH_H */
