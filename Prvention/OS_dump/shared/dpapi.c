// dpapi.c — DPAPI-specific crypto: PBKDF2-HMAC-SHA1
// Used for DPAPI master key derivation
#include "common.h"

// ─── HMAC-SHA1 implementation ───
#define SHA1_BLOCK_SIZE 64
#define SHA1_DIGEST_SIZE 20

typedef struct {
    DWORD state[5];
    DWORD count[2];
    BYTE buffer[64];
} SHA1_CTX;

#define ROTL32(x,n) (((x) << (n)) | ((x) >> (32-(n))))

static void sha1_transform(DWORD state[5], const BYTE buffer[64]) {
    DWORD a, b, c, d, e, w[80];

    for (int i = 0; i < 16; i++) {
        w[i] = ((DWORD)buffer[i*4] << 24) | ((DWORD)buffer[i*4+1] << 16) |
               ((DWORD)buffer[i*4+2] << 8) | (DWORD)buffer[i*4+3];
    }
    for (int i = 16; i < 80; i++) {
        w[i] = ROTL32(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    }

    a = state[0]; b = state[1]; c = state[2]; d = state[3]; e = state[4];

    for (int i = 0; i < 80; i++) {
        DWORD f, k;
        if (i < 20)        { f = (b & c) | (~b & d);       k = 0x5A827999; }
        else if (i < 40)   { f = b ^ c ^ d;                k = 0x6ED9EBA1; }
        else if (i < 60)   { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
        else               { f = b ^ c ^ d;                k = 0xCA62C1D6; }

        DWORD temp = ROTL32(a, 5) + f + e + k + w[i];
        e = d; d = c; c = ROTL32(b, 30); b = a; a = temp;
    }

    state[0] += a; state[1] += b; state[2] += c;
    state[3] += d; state[4] += e;
}

static void sha1_init(SHA1_CTX* ctx) {
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;
    ctx->count[0] = ctx->count[1] = 0;
}

static void sha1_update(SHA1_CTX* ctx, const BYTE* data, SIZE_T len) {
    DWORD index = (ctx->count[0] >> 3) & 0x3F;
    ctx->count[0] += (DWORD)(len << 3);
    if (ctx->count[0] < (DWORD)(len << 3)) ctx->count[1]++;
    ctx->count[1] += (DWORD)(len >> 29);

    DWORD partLen = 64 - index;
    if (len >= partLen) {
        memcpy(&ctx->buffer[index], data, partLen);
        sha1_transform(ctx->state, ctx->buffer);
        for (SIZE_T i = partLen; i + 63 < len; i += 64)
            sha1_transform(ctx->state, (const BYTE*)&data[i]);
        index = 0;
    } else {
        partLen = 0;
    }
    memcpy(&ctx->buffer[index], &data[partLen], len - partLen);
}

static void sha1_final(SHA1_CTX* ctx, BYTE digest[20]) {
    BYTE bits[8];
    for (int i = 0; i < 8; i++)
        bits[i] = (BYTE)((ctx->count[i >= 4 ? 1 : 0] >> ((3-(i&3))*8)) & 0xFF);

    DWORD index = (ctx->count[0] >> 3) & 0x3F;
    DWORD padLen = (index < 56) ? (56 - index) : (120 - index);
    static BYTE PADDING[64] = { 0x80 };

    sha1_update(ctx, PADDING, padLen);
    sha1_update(ctx, bits, 8);

    for (int i = 0; i < 20; i++)
        digest[i] = (BYTE)((ctx->state[i>>2] >> ((3-(i&3))*8)) & 0xFF);
}

static void hmac_sha1(const BYTE* key, DWORD keyLen,
    const BYTE* data, DWORD dataLen, BYTE* digest) {

    BYTE ipad[64], opad[64], tk[20];
    SHA1_CTX ctx;

    if (keyLen > 64) {
        sha1_init(&ctx);
        sha1_update(&ctx, key, keyLen);
        sha1_final(&ctx, tk);
        key = tk;
        keyLen = 20;
    }

    memset(ipad, 0x36, 64);
    memset(opad, 0x5C, 64);

    for (DWORD i = 0; i < keyLen; i++) {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }

    sha1_init(&ctx);
    sha1_update(&ctx, ipad, 64);
    sha1_update(&ctx, data, dataLen);
    sha1_final(&ctx, digest);

    sha1_init(&ctx);
    sha1_update(&ctx, opad, 64);
    sha1_update(&ctx, digest, 20);
    sha1_final(&ctx, digest);
}

// ─── PBKDF2-HMAC-SHA1 ───
void pbkdf2_hmac_sha1(const BYTE* password, DWORD passLen,
    const BYTE* salt, DWORD saltLen, DWORD iterations,
    BYTE* output, DWORD outputLen) {

    BYTE U[20], T[20];
    DWORD blockCount = (outputLen + 19) / 20;
    DWORD bytesRemaining = outputLen;

    for (DWORD block = 0; block < blockCount; block++) {
        // Build salt || INT(block+1) in big-endian
        BYTE saltBlock[64 + 4];
        memcpy(saltBlock, salt, saltLen);
        DWORD be = block + 1;
        saltBlock[saltLen + 0] = (BYTE)(be >> 24);
        saltBlock[saltLen + 1] = (BYTE)(be >> 16);
        saltBlock[saltLen + 2] = (BYTE)(be >> 8);
        saltBlock[saltLen + 3] = (BYTE)(be);

        // U1 = HMAC(password, salt || INT(i))
        hmac_sha1(password, passLen, saltBlock, saltLen + 4, U);
        memcpy(T, U, 20);

        // Subsequent iterations
        for (DWORD iter = 1; iter < iterations; iter++) {
            hmac_sha1(password, passLen, U, 20, U);
            for (int j = 0; j < 20; j++) T[j] ^= U[j];
        }

        DWORD toCopy = min((DWORD)20, bytesRemaining);
        memcpy(output + block * 20, T, toCopy);
        bytesRemaining -= toCopy;
    }
}
