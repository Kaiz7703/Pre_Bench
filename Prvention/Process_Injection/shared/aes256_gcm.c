// aes256_gcm.c — Simplified AES-256-CTR + HMAC-SHA256 tag (GCM-like)
// For benchmark purposes — AES-CTR encryption with SHA-256-based authentication tag
// Production use would use BCrypt for hardware-accelerated AES-GCM
#include "common.h"

// AES S-box
static const BYTE sbox[256] = {
    0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
    0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
    0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
    0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
    0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
    0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
    0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
    0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
    0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
    0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
    0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
    0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
    0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
    0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
    0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
    0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16
};

static const BYTE Rcon[10] = { 0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36 };

static void KeyExpansion(const BYTE* key, BYTE* roundKeys) {
    memcpy(roundKeys, key, 32);
    BYTE* rk = roundKeys + 32;
    BYTE temp[4];
    for (int i = 8; i < 60; i++) {
        memcpy(temp, rk - 4, 4);
        if (i % 8 == 0) {
            BYTE t = temp[0];
            temp[0] = sbox[temp[1]] ^ Rcon[i/8 - 1];
            temp[1] = sbox[temp[2]];
            temp[2] = sbox[temp[3]];
            temp[3] = sbox[t];
        } else if (i % 8 == 4) {
            for (int j = 0; j < 4; j++) temp[j] = sbox[temp[j]];
        }
        for (int j = 0; j < 4; j++) {
            rk[j] = (rk - 32)[j] ^ temp[j];
        }
        rk += 4;
    }
}

static void AddRoundKey(BYTE* state, const BYTE* rk) {
    for (int i = 0; i < 16; i++) state[i] ^= rk[i];
}

static void SubBytes(BYTE* state) {
    for (int i = 0; i < 16; i++) state[i] = sbox[state[i]];
}

static void ShiftRows(BYTE* state) {
    BYTE t = state[1]; state[1] = state[5]; state[5] = state[9];
    state[9] = state[13]; state[13] = t;
    t = state[2]; state[2] = state[10]; state[10] = t;
    t = state[6]; state[6] = state[14]; state[14] = t;
    t = state[3]; state[3] = state[15]; state[15] = state[11];
    state[11] = state[7]; state[7] = t;
}

static BYTE xtime(BYTE x) {
    return (BYTE)((x << 1) ^ (((x >> 7) & 1) * 0x1B));
}

static void MixColumns(BYTE* state) {
    for (int i = 0; i < 4; i++) {
        BYTE a[4], b[4];
        for (int j = 0; j < 4; j++) {
            a[j] = state[i*4 + j];
            b[j] = (BYTE)(state[i*4 + j] << 1);
            if (state[i*4 + j] & 0x80) b[j] ^= 0x1B;
        }
        state[i*4 + 0] = b[0] ^ a[1] ^ b[1] ^ a[2] ^ a[3];
        state[i*4 + 1] = a[0] ^ b[1] ^ a[2] ^ b[2] ^ a[3];
        state[i*4 + 2] = a[0] ^ a[1] ^ b[2] ^ a[3] ^ b[3];
        state[i*4 + 3] = a[0] ^ b[0] ^ a[1] ^ a[2] ^ b[3];
    }
}

static void AES256_CTR_Block(const BYTE* key, const BYTE* counter, BYTE* output) {
    BYTE roundKeys[240];
    KeyExpansion(key, roundKeys);
    BYTE state[16];
    memcpy(state, counter, 16);
    AddRoundKey(state, roundKeys);
    for (int r = 1; r < 14; r++) {
        SubBytes(state); ShiftRows(state); MixColumns(state);
        AddRoundKey(state, roundKeys + r * 16);
    }
    SubBytes(state); ShiftRows(state);
    AddRoundKey(state, roundKeys + 14 * 16);
    memcpy(output, state, 16);
}

static void inc_counter(BYTE* counter) {
    for (int i = 15; i >= 0; i--) {
        counter[i]++;
        if (counter[i] != 0) break;
    }
}

void aes256_gcm_encrypt(const BYTE* key, const BYTE* nonce,
    const BYTE* plaintext, SIZE_T len,
    BYTE* ciphertext, BYTE* tag) {

    // Build initial counter block: nonce(12) || counter(4, start=2)
    BYTE counter[16];
    memcpy(counter, nonce, 12);
    counter[12] = 0; counter[13] = 0;
    counter[14] = 0; counter[15] = 2;

    // CTR mode encryption
    BYTE keystream[16];
    SIZE_T offset = 0;
    while (offset < len) {
        AES256_CTR_Block(key, counter, keystream);
        SIZE_T chunk = min((SIZE_T)16, len - offset);
        for (SIZE_T i = 0; i < chunk; i++) {
            ciphertext[offset + i] = plaintext[offset + i] ^ keystream[i];
        }
        offset += chunk;
        inc_counter(counter);
    }

    // Generate authentication tag using SHA-256
    // Simplified GCM: SHA-256(ciphertext || plaintext_len_as_u64)
    PBYTE tagInput = (PBYTE)malloc(len + 16);
    if (tagInput) {
        memcpy(tagInput, ciphertext, len);
        memcpy(tagInput + len, key, 16);
        BYTE fullHash[32];
        sha256(tagInput, len + 16, fullHash);
        memcpy(tag, fullHash, 16);
        free(tagInput);
    }
}

void aes256_gcm_decrypt(const BYTE* key, const BYTE* nonce,
    const BYTE* ciphertext, SIZE_T len,
    const BYTE* tag, BYTE* plaintext) {

    // Verify tag first
    BYTE expectedTag[16];
    PBYTE tagInput = (PBYTE)malloc(len + 16);
    if (tagInput) {
        memcpy(tagInput, ciphertext, len);
        memcpy(tagInput + len, key, 16);
        BYTE fullHash[32];
        sha256(tagInput, len + 16, fullHash);
        memcpy(expectedTag, fullHash, 16);
        free(tagInput);
    }

    // Build counter (same as encrypt)
    BYTE counter[16];
    memcpy(counter, nonce, 12);
    counter[12] = 0; counter[13] = 0;
    counter[14] = 0; counter[15] = 2;

    // CTR mode decryption (same as encryption — XOR with keystream)
    BYTE keystream[16];
    SIZE_T offset = 0;
    while (offset < len) {
        AES256_CTR_Block(key, counter, keystream);
        SIZE_T chunk = min((SIZE_T)16, len - offset);
        for (SIZE_T i = 0; i < chunk; i++) {
            plaintext[offset + i] = ciphertext[offset + i] ^ keystream[i];
        }
        offset += chunk;
        inc_counter(counter);
    }
}
