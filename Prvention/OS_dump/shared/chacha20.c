// chacha20.c — ChaCha20 stream cipher implementation
#include "common.h"

#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))
#define QR(a, b, c, d) do { \
    a += b; d ^= a; d = ROTL32(d, 16); \
    c += d; b ^= c; b = ROTL32(b, 12); \
    a += b; d ^= a; d = ROTL32(d, 8);  \
    c += d; b ^= c; b = ROTL32(b, 7);  \
} while (0)

static void chacha20_block(const DWORD* key, DWORD counter,
    const DWORD* nonce, DWORD* output) {
    DWORD x[16];
    // Initial state
    x[0] = 0x61707865; x[1] = 0x3320646e; x[2] = 0x79622d32; x[3] = 0x6b206574;
    x[4] = key[0];     x[5] = key[1];     x[6] = key[2];     x[7] = key[3];
    x[8] = key[4];     x[9] = key[5];     x[10] = key[6];    x[11] = key[7];
    x[12] = counter;   x[13] = nonce[0];  x[14] = nonce[1];  x[15] = nonce[2];

    // Copy working state
    DWORD j[16];
    memcpy(j, x, sizeof(x));

    // 20 rounds (10 double rounds)
    for (int i = 0; i < 10; i++) {
        // Column rounds
        QR(j[0], j[4], j[8],  j[12]);
        QR(j[1], j[5], j[9],  j[13]);
        QR(j[2], j[6], j[10], j[14]);
        QR(j[3], j[7], j[11], j[15]);
        // Diagonal rounds
        QR(j[0], j[5], j[10], j[15]);
        QR(j[1], j[6], j[11], j[12]);
        QR(j[2], j[7], j[8],  j[13]);
        QR(j[3], j[4], j[9],  j[14]);
    }

    // Add original state
    for (int i = 0; i < 16; i++) {
        output[i] = x[i] + j[i];
    }
}

void chacha20_encrypt(const BYTE* key, const BYTE* nonce,
    const BYTE* plaintext, SIZE_T len, BYTE* ciphertext) {
    DWORD key32[8];
    DWORD nonce32[3];
    DWORD block[16];
    BYTE keyStream[64];

    memcpy(key32, key, 32);
    memcpy(nonce32, nonce, 12);

    DWORD counter = 0;
    SIZE_T offset = 0;

    while (offset < len) {
        chacha20_block(key32, counter++, nonce32, block);

        // Convert block to byte stream
        for (int i = 0; i < 16; i++) {
            keyStream[i * 4 + 0] = (BYTE)(block[i] & 0xFF);
            keyStream[i * 4 + 1] = (BYTE)((block[i] >> 8) & 0xFF);
            keyStream[i * 4 + 2] = (BYTE)((block[i] >> 16) & 0xFF);
            keyStream[i * 4 + 3] = (BYTE)((block[i] >> 24) & 0xFF);
        }

        SIZE_T remaining = len - offset;
        SIZE_T toProcess = (remaining < 64) ? remaining : 64;

        for (SIZE_T i = 0; i < toProcess; i++) {
            ciphertext[offset + i] = plaintext[offset + i] ^ keyStream[i];
        }

        offset += toProcess;
    }
}
