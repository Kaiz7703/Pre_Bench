// md5.c — MD5 hash implementation (RFC 1321)
#include "common.h"

#define F(x,y,z) ((x & y) | (~x & z))
#define G(x,y,z) ((x & z) | (y & ~z))
#define H(x,y,z) (x ^ y ^ z)
#define I(x,y,z) (y ^ (x | ~z))
#define ROTATE_LEFT(x,n) ((x << n) | (x >> (32-n)))

#define FF(a,b,c,d,x,s,ac) { a += F(b,c,d) + x + ac; a = ROTATE_LEFT(a,s) + b; }
#define GG(a,b,c,d,x,s,ac) { a += G(b,c,d) + x + ac; a = ROTATE_LEFT(a,s) + b; }
#define HH(a,b,c,d,x,s,ac) { a += H(b,c,d) + x + ac; a = ROTATE_LEFT(a,s) + b; }
#define II(a,b,c,d,x,s,ac) { a += I(b,c,d) + x + ac; a = ROTATE_LEFT(a,s) + b; }

typedef struct {
    DWORD state[4];
    DWORD count[2];
    BYTE buffer[64];
} MD5_CTX;

static const DWORD S[64] = {
    7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
    5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
    4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
    6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21
};

static const DWORD K[64] = {
    0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
    0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
    0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
    0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
    0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
    0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
    0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
    0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
};

static BYTE PADDING[64] = { 0x80 };

static void md5_encode(BYTE* output, DWORD* input, DWORD len) {
    for (DWORD i = 0, j = 0; j < len; i++, j += 4) {
        output[j]   = (BYTE)(input[i] & 0xFF);
        output[j+1] = (BYTE)((input[i] >> 8) & 0xFF);
        output[j+2] = (BYTE)((input[i] >> 16) & 0xFF);
        output[j+3] = (BYTE)((input[i] >> 24) & 0xFF);
    }
}

static void md5_decode(DWORD* output, BYTE* input, DWORD len) {
    for (DWORD i = 0, j = 0; j < len; i++, j += 4)
        output[i] = ((DWORD)input[j]) | (((DWORD)input[j+1]) << 8) |
                    (((DWORD)input[j+2]) << 16) | (((DWORD)input[j+3]) << 24);
}

static void md5_init(MD5_CTX* ctx) {
    ctx->count[0] = ctx->count[1] = 0;
    ctx->state[0] = 0x67452301; ctx->state[1] = 0xefcdab89;
    ctx->state[2] = 0x98badcfe; ctx->state[3] = 0x10325476;
}

static void md5_transform(DWORD state[4], BYTE block[64]) {
    DWORD a = state[0], b = state[1], c = state[2], d = state[3], x[16];
    md5_decode(x, block, 64);
    for (int i = 0; i < 64; i++) {
        DWORD temp;
        if (i < 16) { FF(a,b,c,d,x[i],S[i],K[i]); temp = d; d = c; c = b; b = b; }
        else if (i < 32) { GG(a,b,c,d,x[(5*i+1)%16],S[i],K[i]); temp = d; d = c; c = b; }
        else if (i < 48) { HH(a,b,c,d,x[(3*i+5)%16],S[i],K[i]); temp = d; d = c; c = b; }
        else { II(a,b,c,d,x[(7*i)%16],S[i],K[i]); temp = d; d = c; c = b; }
        a = temp;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
}

static void md5_update(MD5_CTX* ctx, const BYTE* input, DWORD inputLen) {
    DWORD i, index = (ctx->count[0] >> 3) & 0x3F;
    if ((ctx->count[0] += ((DWORD)inputLen << 3)) < ((DWORD)inputLen << 3))
        ctx->count[1]++;
    ctx->count[1] += ((DWORD)inputLen >> 29);
    DWORD partLen = 64 - index;
    if (inputLen >= partLen) {
        memcpy(&ctx->buffer[index], input, partLen);
        md5_transform(ctx->state, ctx->buffer);
        for (i = partLen; i + 63 < inputLen; i += 64)
            md5_transform(ctx->state, (BYTE*)&input[i]);
        index = 0;
    } else i = 0;
    memcpy(&ctx->buffer[index], &input[i], inputLen - i);
}

static void md5_final(BYTE digest[16], MD5_CTX* ctx) {
    BYTE bits[8];
    md5_encode(bits, ctx->count, 8);
    DWORD index = (ctx->count[0] >> 3) & 0x3F;
    DWORD padLen = (index < 56) ? (56 - index) : (120 - index);
    md5_update(ctx, PADDING, padLen);
    md5_update(ctx, bits, 8);
    md5_encode(digest, ctx->state, 16);
    memset(ctx, 0, sizeof(*ctx));
}

void md5(const BYTE* data, SIZE_T len, BYTE* hash) {
    MD5_CTX ctx;
    md5_init(&ctx);
    md5_update(&ctx, data, (DWORD)len);
    md5_final(hash, &ctx);
}
