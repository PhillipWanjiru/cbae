/**
 * @file siphash.c
 * @brief SipHash-2-4 (Aumasson and Bernstein), checked in tests/unit/test_string_pool.c against the
 *        published test vectors.
 */
#include "platform/siphash.h"

#define ROTL64(x, b) (uint64_t)(((x) << (b)) | ((x) >> (64 - (b))))

#define SIPROUND                                                                           \
    do {                                                                                   \
        v0 += v1; v1 = ROTL64(v1, 13); v1 ^= v0; v0 = ROTL64(v0, 32);                    \
        v2 += v3; v3 = ROTL64(v3, 16); v3 ^= v2;                                           \
        v0 += v3; v3 = ROTL64(v3, 21); v3 ^= v0;                                           \
        v2 += v1; v1 = ROTL64(v1, 17); v1 ^= v2; v2 = ROTL64(v2, 32);                     \
    } while (0)

/* The algorithm is defined on little-endian words; assembling them byte by byte keeps the result the
 * same on every machine (compilers turn this into one load on x86-64). */
static uint64_t load_le64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = (v << 8) | p[i];
    return v;
}

uint64_t cbae_siphash24(const uint8_t key[16], const void *data, size_t len) {
    static const uint8_t empty = 0;
    const uint8_t *in = (len == 0 || !data) ? &empty : (const uint8_t *)data;
    if (!data) len = 0;
    const uint64_t k0 = load_le64(key), k1 = load_le64(key + 8);
    uint64_t v0 = 0x736f6d6570736575ULL ^ k0;
    uint64_t v1 = 0x646f72616e646f6dULL ^ k1;
    uint64_t v2 = 0x6c7967656e657261ULL ^ k0;
    uint64_t v3 = 0x7465646279746573ULL ^ k1;

    const uint8_t *const end = in + (len - (len & 7));
    for (; in != end; in += 8) {
        const uint64_t m = load_le64(in);
        v3 ^= m; SIPROUND; SIPROUND; v0 ^= m;
    }

    uint64_t b = (uint64_t)len << 56;
    switch (len & 7) {
    case 7: b |= (uint64_t)in[6] << 48; /* fallthrough */
    case 6: b |= (uint64_t)in[5] << 40; /* fallthrough */
    case 5: b |= (uint64_t)in[4] << 32; /* fallthrough */
    case 4: b |= (uint64_t)in[3] << 24; /* fallthrough */
    case 3: b |= (uint64_t)in[2] << 16; /* fallthrough */
    case 2: b |= (uint64_t)in[1] << 8;  /* fallthrough */
    case 1: b |= (uint64_t)in[0]; break;
    default: break;
    }
    v3 ^= b; SIPROUND; SIPROUND; v0 ^= b;
    v2 ^= 0xff;
    SIPROUND; SIPROUND; SIPROUND; SIPROUND;
    return v0 ^ v1 ^ v2 ^ v3;
}
