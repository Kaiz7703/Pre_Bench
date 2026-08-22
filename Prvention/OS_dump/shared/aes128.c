// aes128.c — AES-128 (FIPS-197) encrypt/decrypt + CBC, mirrors pycryptodome AES.MODE_CBC
// Needed for modern SAM scheme (hashedBootKey + V hash decryption, per impacket).
#include "common.h"

static BYTE SBOX[256], INV_SBOX[256];
static BYTE initialized = 0;

static BYTE gf_mul(BYTE a, BYTE b) {
    BYTE r = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) r ^= a;
        BYTE hi = a & 0x80;
        a = (BYTE)(a << 1);
        if (hi) a ^= 0x1B;
        b >>= 1;
    }
    return r;
}

static BYTE gf_inv(BYTE x) {
    BYTE p = 1, q = x;
    for (int i = 0; i < 7; i++) { q = gf_mul(q, q); p = gf_mul(p, q); }
    return p;
}

static BYTE rotl8(BYTE b, int n) { return (BYTE)((b << n) | (b >> (8 - n))); }

static void BuildTables(void) {
    if (initialized) return;
    for (int x = 0; x < 256; x++) {
        BYTE inv = (x == 0) ? 0 : gf_inv((BYTE)x);
        SBOX[x] = (BYTE)(inv ^ rotl8(inv, 1) ^ rotl8(inv, 2) ^ rotl8(inv, 3) ^ rotl8(inv, 4) ^ 0x63);
    }
    for (int x = 0; x < 256; x++) INV_SBOX[SBOX[x]] = (BYTE)x;
    initialized = 1;
}

static BYTE RC[10] = { 0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36 };

// Expand 16-byte key into 44 words (176 bytes)
static void ExpandKey128(const BYTE* key, BYTE* w) {
    memcpy(w, key, 16);
    for (int i = 4; i < 44; i++) {
        BYTE temp[4];
        memcpy(temp, w + (i - 1) * 4, 4);
        if (i % 4 == 0) {
            BYTE t = temp[0];
            temp[0] = (BYTE)(SBOX[temp[1]] ^ RC[i / 4 - 1]);
            temp[1] = SBOX[temp[2]];
            temp[2] = SBOX[temp[3]];
            temp[3] = SBOX[t];
        }
        for (int j = 0; j < 4; j++)
            w[i * 4 + j] = w[(i - 4) * 4 + j] ^ temp[j];
    }
}

static void AddRoundKey(BYTE* s, const BYTE* rk) {
    for (int i = 0; i < 16; i++) s[i] ^= rk[i];
}

static void ShiftRows(BYTE* s) {
    BYTE t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
    t = s[2]; s[2] = s[10]; s[10] = t;
    t = s[6]; s[6] = s[14]; s[14] = t;
    t = s[3]; s[3] = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = t;
}

static void InvShiftRows(BYTE* s) {
    BYTE t = s[13]; s[13] = s[9]; s[9] = s[5]; s[5] = s[1]; s[1] = t;
    t = s[2]; s[2] = s[10]; s[10] = t;
    t = s[6]; s[6] = s[14]; s[14] = t;
    t = s[7]; s[7] = s[11]; s[11] = s[15]; s[15] = s[3]; s[3] = t;
}

static void MixColumns(BYTE* s) {
    for (int i = 0; i < 4; i++) {
        BYTE a0 = s[i * 4], a1 = s[i * 4 + 1], a2 = s[i * 4 + 2], a3 = s[i * 4 + 3];
        s[i * 4 + 0] = (BYTE)(gf_mul(a0, 2) ^ gf_mul(a1, 3) ^ a2 ^ a3);
        s[i * 4 + 1] = (BYTE)(a0 ^ gf_mul(a1, 2) ^ gf_mul(a2, 3) ^ a3);
        s[i * 4 + 2] = (BYTE)(a0 ^ a1 ^ gf_mul(a2, 2) ^ gf_mul(a3, 3));
        s[i * 4 + 3] = (BYTE)(gf_mul(a0, 3) ^ a1 ^ a2 ^ gf_mul(a3, 2));
    }
}

static void InvMixColumns(BYTE* s) {
    for (int i = 0; i < 4; i++) {
        BYTE a0 = s[i * 4], a1 = s[i * 4 + 1], a2 = s[i * 4 + 2], a3 = s[i * 4 + 3];
        s[i * 4 + 0] = (BYTE)(gf_mul(a0, 0x0E) ^ gf_mul(a1, 0x0B) ^ gf_mul(a2, 0x0D) ^ gf_mul(a3, 0x09));
        s[i * 4 + 1] = (BYTE)(gf_mul(a0, 0x09) ^ gf_mul(a1, 0x0E) ^ gf_mul(a2, 0x0B) ^ gf_mul(a3, 0x0D));
        s[i * 4 + 2] = (BYTE)(gf_mul(a0, 0x0D) ^ gf_mul(a1, 0x09) ^ gf_mul(a2, 0x0E) ^ gf_mul(a3, 0x0B));
        s[i * 4 + 3] = (BYTE)(gf_mul(a0, 0x0B) ^ gf_mul(a1, 0x0D) ^ gf_mul(a2, 0x09) ^ gf_mul(a3, 0x0E));
    }
}

void aes128_encrypt_block(const BYTE* key, const BYTE* in, BYTE* out) {
    BuildTables();
    BYTE w[176];
    ExpandKey128(key, w);
    BYTE s[16];
    for (int i = 0; i < 16; i++) s[i] = in[i] ^ w[i];
    for (int r = 1; r <= 9; r++) {
        for (int i = 0; i < 16; i++) s[i] = SBOX[s[i]];
        ShiftRows(s);
        MixColumns(s);
        AddRoundKey(s, w + r * 16);
    }
    for (int i = 0; i < 16; i++) s[i] = SBOX[s[i]];
    ShiftRows(s);
    AddRoundKey(s, w + 160);
    memcpy(out, s, 16);
}

void aes128_decrypt_block(const BYTE* key, const BYTE* in, BYTE* out) {
    BuildTables();
    BYTE w[176];
    ExpandKey128(key, w);
    BYTE s[16];
    for (int i = 0; i < 16; i++) s[i] = in[i] ^ w[160 + i];
    for (int r = 9; r >= 1; r--) {
        InvShiftRows(s);
        for (int i = 0; i < 16; i++) s[i] = INV_SBOX[s[i]];
        AddRoundKey(s, w + r * 16);
        InvMixColumns(s);
    }
    InvShiftRows(s);
    for (int i = 0; i < 16; i++) s[i] = INV_SBOX[s[i]];
    AddRoundKey(s, w);
    memcpy(out, s, 16);
}

// CBC decrypt — mirrors pycryptodome AES.new(key, MODE_CBC, iv).decrypt()
// len must be a multiple of 16 (pad trailing partial block with zeros like impacket)
void aes128_cbc_decrypt(const BYTE* key, const BYTE* iv,
    const BYTE* in, SIZE_T len, BYTE* out) {
    BYTE prev[16], block[16];
    memcpy(prev, iv, 16);
    for (SIZE_T off = 0; off < len; off += 16) {
        SIZE_T take = min((SIZE_T)16, len - off);
        memset(block, 0, 16);
        memcpy(block, in + off, take);
        aes128_decrypt_block(key, block, out + off);
        for (int i = 0; i < 16; i++) out[off + i] ^= prev[i];
        memcpy(prev, block, 16);
    }
}
