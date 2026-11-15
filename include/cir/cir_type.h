/**
 * @file cir_type.h
 * @brief CIR type system: int widths, pointer, void.
 */
#ifndef CBAE_CIR_TYPE_H
#define CBAE_CIR_TYPE_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum cbae_cir_type_kind {
    CIR_TYPE_VOID = 0,
    CIR_TYPE_I1,
    CIR_TYPE_I8,
    CIR_TYPE_I16,
    CIR_TYPE_I32,
    CIR_TYPE_I64,
    CIR_TYPE_PTR,
} cbae_cir_type_kind_t;

typedef struct cbae_cir_type {
    cbae_cir_type_kind_t kind;
} cbae_cir_type_t;

static inline cbae_cir_type_t cir_type_void(void) {
    cbae_cir_type_t t; t.kind = CIR_TYPE_VOID; return t;
}
static inline cbae_cir_type_t cir_type_ptr(void) {
    cbae_cir_type_t t; t.kind = CIR_TYPE_PTR; return t;
}
static inline cbae_cir_type_t cir_type_i1(void) {
    cbae_cir_type_t t; t.kind = CIR_TYPE_I1; return t;
}
cbae_cir_type_t cir_type_i(uint8_t bits);
uint8_t cir_type_bits(cbae_cir_type_t t);
static inline uint8_t cir_type_bytes(cbae_cir_type_t t) {
    uint8_t bits = cir_type_bits(t);
    return (uint8_t)((bits + 7) / 8);
}
const char *cir_type_str(cbae_cir_type_t t);
static inline bool cir_type_eq(cbae_cir_type_t a, cbae_cir_type_t b) {
    return a.kind == b.kind;
}

#ifdef __cplusplus
}
#endif

#endif /* CBAE_CIR_TYPE_H */
