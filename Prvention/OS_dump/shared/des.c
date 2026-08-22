// des.c — Single DES (FIPS 46-3) block decrypt + SAM key derivation
// Mirrors pycryptodome DES.MODE_ECB decrypt as used by impacket secretsdump.
#include "common.h"

static const BYTE IP[64] = {
    58,50,42,34,26,18,10,2, 60,52,44,36,28,20,12,4,
    62,54,46,38,30,22,14,6, 64,56,48,40,32,24,16,8,
    57,49,41,33,25,17,9,1,  59,51,43,35,27,19,11,3,
    61,53,45,37,29,21,13,5, 63,55,47,39,31,23,15,7
};

static const BYTE FP[64] = {
    40,8,48,16,56,24,64,32, 39,7,47,15,55,23,63,31,
    38,6,46,14,54,22,62,30, 37,5,45,13,53,21,61,29,
    36,4,44,12,52,20,60,28, 35,3,43,11,51,19,59,27,
    34,2,42,10,50,18,58,26, 33,1,41,9,49,17,57,25
};

static const BYTE E[48] = {
    32,1,2,3,4,5, 4,5,6,7,8,9,
    8,9,10,11,12,13, 12,13,14,15,16,17,
    16,17,18,19,20,21, 20,21,22,23,24,25,
    24,25,26,27,28,29, 28,29,30,31,32,1
};

static const BYTE P[32] = {
    16,7,20,21,29,12,28,17, 1,15,23,26,5,18,31,10,
    2,8,24,14,32,27,3,9, 19,13,30,6,22,11,4,25
};

static const BYTE PC1[56] = {
    57,49,41,33,25,17,9, 1,58,50,42,34,26,18,
    10,2,59,51,43,35,27, 19,11,3,60,52,44,36,
    63,55,47,39,31,23,15, 7,62,54,46,38,30,22,
    14,6,61,53,45,37,29, 21,13,5,28,20,12,4
};

static const BYTE PC2[48] = {
    14,17,11,24,1,5, 3,28,15,6,21,10,
    23,19,12,4,26,8, 16,7,27,20,13,2,
    41,52,31,37,47,55, 30,40,51,45,33,48,
    44,49,39,56,34,53, 46,42,50,36,29,32
};

static const BYTE SHIFTS[16] = { 1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1 };

static const BYTE SBOXES[8][64] = {
    { 14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,
      0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
      4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,
      15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13 },
    { 15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,
      3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
      0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,
      13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9 },
    { 10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,
      13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
      13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,
      1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12 },
    { 7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,
      13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
      10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,
      3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14 },
    { 2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,
      14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
      4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,
      11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3 },
    { 12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,
      10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
      9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,
      4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13 },
    { 4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,
      13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
      1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,
      6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12 },
    { 13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,
      1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
      7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,
      2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11 }
};

static void make_subkeys(const BYTE key[8], BYTE subkeys[16][6]) {
    BYTE cd[56];
    for (int i = 0; i < 56; i++) {
        int bit = PC1[i] - 1;
        cd[i] = (BYTE)((key[bit >> 3] >> (7 - (bit & 7))) & 1);
    }
    for (int round = 0; round < 16; round++) {
        int s = SHIFTS[round];
        BYTE ncd[56];
        for (int i = 0; i < 56; i++) {
            if (i < 28) ncd[i] = cd[(i + s) % 28];
            else ncd[i] = cd[28 + ((i - 28 + s) % 28)];
        }
        memcpy(cd, ncd, 56);
        memset(subkeys[round], 0, 6);
        for (int i = 0; i < 48; i++) {
            int bit = PC2[i] - 1;
            subkeys[round][i >> 3] |= (BYTE)(cd[bit] << (7 - (i & 7)));
        }
    }
}

void des_decrypt_block(const BYTE key[8], const BYTE in[8], BYTE out[8]) {
    BYTE subkeys[16][6];
    make_subkeys(key, subkeys);

    BYTE perm[8] = { 0 }, r[8], l[8];
    for (int i = 0; i < 64; i++) {
        int bit = IP[i] - 1;
        perm[i >> 3] |= (BYTE)(((in[bit >> 3] >> (7 - (bit & 7))) & 1) << (7 - (i & 7)));
    }
    memcpy(l, perm, 4);
    memcpy(r, perm + 4, 4);

    for (int round = 15; round >= 0; round--) {
        // f(R, K)
        BYTE er[6] = { 0 };
        for (int i = 0; i < 48; i++) {
            int bit = E[i] - 1;
            er[i >> 3] |= (BYTE)(((r[bit >> 3] >> (7 - (bit & 7))) & 1) << (7 - (i & 7)));
        }
        for (int i = 0; i < 6; i++) er[i] ^= subkeys[round][i];

        BYTE sOut[4] = { 0 };
        for (int b = 0; b < 8; b++) {
            // row = 2*b1 + b6 (first and LAST bit of the 6-bit group)
            // col = b2 b3 b4 b5 (the middle 4 bits)
            int row = ((er[b * 6 / 8] >> (7 - (b * 6 % 8))) & 1) << 1;
            int lastBit = b * 6 + 5;
            row |= (er[lastBit / 8] >> (7 - (lastBit % 8))) & 1;
            int col = 0;
            for (int k = 1; k < 5; k++) {
                int bit = b * 6 + k;
                col = (col << 1) | ((er[bit / 8] >> (7 - (bit % 8))) & 1);
            }
            BYTE val = SBOXES[b][row * 16 + col];
            int outBit = b * 4;
            for (int k = 0; k < 4; k++) {
                if ((val >> (3 - k)) & 1)
                    sOut[outBit / 8] |= (BYTE)(1 << (7 - (outBit % 8)));
                outBit++;
            }
        }

        BYTE f[4] = { 0 };
        for (int i = 0; i < 32; i++) {
            int bit = P[i] - 1;
            f[i >> 3] |= (BYTE)(((sOut[bit >> 3] >> (7 - (bit & 7))) & 1) << (7 - (i & 7)));
        }

        BYTE newR[4];
        for (int i = 0; i < 4; i++) newR[i] = l[i] ^ f[i];
        memcpy(l, r, 4);
        memcpy(r, newR, 4);
    }

    BYTE joined[8], final[8] = { 0 };
    memcpy(joined, r, 4);
    memcpy(joined + 4, l, 4);
    for (int i = 0; i < 64; i++) {
        int bit = FP[i] - 1;
        final[i >> 3] |= (BYTE)(((joined[bit >> 3] >> (7 - (bit & 7))) & 1) << (7 - (i & 7)));
    }
    memcpy(out, final, 8);
}

// transformKey: 7 bytes -> 8-byte DES key (impacket crypto.transformKey, Section 5.1.3)
static void transform_key(const BYTE in[7], BYTE out[8]) {
    out[0] = (BYTE)(in[0] >> 1);
    out[1] = (BYTE)(((in[0] & 1) << 6) | (in[1] >> 2));
    out[2] = (BYTE)(((in[1] & 3) << 5) | (in[2] >> 3));
    out[3] = (BYTE)(((in[2] & 7) << 4) | (in[3] >> 4));
    out[4] = (BYTE)(((in[3] & 0xF) << 3) | (in[4] >> 5));
    out[5] = (BYTE)(((in[4] & 0x1F) << 2) | (in[5] >> 6));
    out[6] = (BYTE)(((in[5] & 0x3F) << 1) | (in[6] >> 7));
    out[7] = (BYTE)(in[6] & 0x7F);
    for (int i = 0; i < 8; i++) out[i] = (BYTE)((out[i] << 1) & 0xFE);
}

// Section 2.2.11.1.3 — Deriving Key1 and Key2 from a Little-Endian unsigned integer
void sam_derive_des_keys(DWORD rid, BYTE key1[8], BYTE key2[8]) {
    BYTE le[4] = { (BYTE)rid, (BYTE)(rid >> 8), (BYTE)(rid >> 16), (BYTE)(rid >> 24) };
    BYTE k1[7] = { le[0], le[1], le[2], le[3], le[0], le[1], le[2] };
    BYTE k2[7] = { le[3], le[0], le[1], le[2], le[3], le[0], le[1] };
    transform_key(k1, key1);
    transform_key(k2, key2);
}
