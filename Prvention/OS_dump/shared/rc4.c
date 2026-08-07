// rc4.c — RC4 stream cipher implementation
#include "common.h"

typedef struct {
    BYTE S[256];
    BYTE i, j;
} RC4_CTX;

static void rc4_init(RC4_CTX* ctx, const BYTE* key, SIZE_T keyLen) {
    for (int i = 0; i < 256; i++) ctx->S[i] = (BYTE)i;
    BYTE j = 0;
    for (int i = 0; i < 256; i++) {
        j = (BYTE)(j + ctx->S[i] + key[i % keyLen]);
        BYTE tmp = ctx->S[i];
        ctx->S[i] = ctx->S[j];
        ctx->S[j] = tmp;
    }
    ctx->i = ctx->j = 0;
}

static BYTE rc4_next(RC4_CTX* ctx) {
    ctx->i = (BYTE)(ctx->i + 1);
    ctx->j = (BYTE)(ctx->j + ctx->S[ctx->i]);
    BYTE tmp = ctx->S[ctx->i];
    ctx->S[ctx->i] = ctx->S[ctx->j];
    ctx->S[ctx->j] = tmp;
    return ctx->S[(BYTE)(ctx->S[ctx->i] + ctx->S[ctx->j])];
}

void rc4(const BYTE* key, SIZE_T keyLen, const BYTE* input,
    SIZE_T inputLen, BYTE* output) {
    RC4_CTX ctx;
    rc4_init(&ctx, key, keyLen);
    for (SIZE_T i = 0; i < inputLen; i++) {
        output[i] = input[i] ^ rc4_next(&ctx);
    }
}
