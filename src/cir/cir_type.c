/**
 * @file cir_type.c
 * @brief CIR type system helper implementations.
 */
#include "cir/cir_type.h"

cbae_cir_type_t cir_type_i(uint8_t bits) {
    cbae_cir_type_t t;
    switch (bits) {
        case 1:  t.kind = CIR_TYPE_I1;  break;
        case 8:  t.kind = CIR_TYPE_I8;  break;
        case 16: t.kind = CIR_TYPE_I16; break;
        case 32: t.kind = CIR_TYPE_I32; break;
        case 64: t.kind = CIR_TYPE_I64; break;
        default: t.kind = CIR_TYPE_I64; break;
    }
    return t;
}

uint8_t cir_type_bits(cbae_cir_type_t t) {
    switch (t.kind) {
        case CIR_TYPE_VOID: return 0;
        case CIR_TYPE_I1:   return 1;
        case CIR_TYPE_I8:   return 8;
        case CIR_TYPE_I16:  return 16;
        case CIR_TYPE_I32:  return 32;
        case CIR_TYPE_I64:  return 64;
        case CIR_TYPE_PTR:  return 64;
        default:            return 0;
    }
}

const char *cir_type_str(cbae_cir_type_t t) {
    switch (t.kind) {
        case CIR_TYPE_VOID: return "void";
        case CIR_TYPE_I1:   return "i1";
        case CIR_TYPE_I8:   return "i8";
        case CIR_TYPE_I16:  return "i16";
        case CIR_TYPE_I32:  return "i32";
        case CIR_TYPE_I64:  return "i64";
        case CIR_TYPE_PTR:  return "ptr";
        default:            return "?";
    }
}
