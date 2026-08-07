# Plan 1 — LSASS Memory Dump: Technical Specification

> **Target**: T1003.001 — LSASS Memory  
> **Pre-condition**: SYSTEM privilege (assumed already achieved)  
> **Scope**: Dump phase only — no privilege escalation  

---

## 1. Overview

Direct LSASS process memory dump using indirect syscalls to bypass userland hooks, with ETW patching to suppress telemetry. The dump is performed via a hollowed staging process, output encrypted and written to an Alternate Data Stream.

```
┌─────────────┐    ┌──────────────┐    ┌─────────────┐    ┌────────────┐
│ SeDebug     │    │ Hollowed     │    │ Indirect     │    │ Encrypted  │
│ Privilege   │───▶│ svchost.exe  │───▶│ Syscall      │───▶│ ADS Output │
│ Enable      │    │ (Staging)    │    │ LSASS Dump   │    │            │
└─────────────┘    └──────────────┘    └─────────────┘    └────────────┘
```

---

## 2. Functional Requirements

### FR-1: Privilege Enablement
| ID | Requirement |
|----|-------------|
| FR-1.1 | Enable `SeDebugPrivilege` via `RtlAdjustPrivilege` (native API) |
| FR-1.2 | Do NOT use `AdjustTokenPrivileges` (Win32, likely hooked) |
| FR-1.3 | Verify privilege enabled before proceeding |

### FR-2: Staging Process
| ID | Requirement |
|----|-------------|
| FR-2.1 | Create suspended `svchost.exe -k LocalService` via `NtCreateUserProcess` |
| FR-2.2 | PPID spoof to `services.exe` |
| FR-2.3 | Unmap original image via `NtUnmapViewOfSection` |
| FR-2.4 | Allocate RW memory at original image base, write reflective dumper DLL |
| FR-2.5 | Change protection to RX (no simultaneous RWX) |
| FR-2.6 | Reflective DLL must self-resolve imports, self-relocate, call entry point |

### FR-3: ETW Suppression
| ID | Requirement |
|----|-------------|
| FR-3.1 | Patch `EtwEventWrite` in ntdll.dll → return STATUS_SUCCESS (0) |
| FR-3.2 | Patch `EtwNotificationRegister` → disable Threat Intelligence provider |
| FR-3.3 | Patches applied in staging process memory only (not global) |
| FR-3.4 | Verify ETW suppression before LSASS access |

### FR-4: LSASS Memory Access
| ID | Requirement |
|----|-------------|
| FR-4.1 | Locate LSASS PID via `NtQuerySystemInformation(SystemProcessInformation)` |
| FR-4.2 | Resolve syscall numbers from clean `ntdll.dll` on disk (not hooked in-memory copy) |
| FR-4.3 | Build indirect syscall stubs: `syscall` + `ret` per function |
| FR-4.4 | Open LSASS handle: `NtOpenProcess(PROCESS_VM_READ \| PROCESS_QUERY_INFORMATION, LSASS_PID)` via indirect syscall |
| FR-4.5 | Handle the case where LSASS runs as PPL (Protected Process Light) |

### FR-5: Memory Dump
| ID | Requirement |
|----|-------------|
| FR-5.1 | Enumerate LSASS memory regions via `NtQueryVirtualMemory` |
| FR-5.2 | Read each readable region via `NtReadVirtualMemory` (indirect syscall) |
| FR-5.3 | Generate minidump-compatible output WITHOUT calling `MiniDumpWriteDump` |
| FR-5.4 | Output must contain: loaded modules list, memory regions, handles (optional) |
| FR-5.5 | Strip minidump signature "PSS" from header (avoid signature-based detection) |

### FR-6: Credential Extraction
| ID | Requirement |
|----|-------------|
| FR-6.1 | Parse dump in-memory to extract NTLM hashes |
| FR-6.2 | Extract Kerberos keys (AES256, AES128) from `lsasrv.dll` memory |
| FR-6.3 | Extract DPAPI master keys if present |
| FR-6.4 | Extract WDigest credentials if enabled |
| FR-6.5 | Output structured credential data (JSON or binary format) |

### FR-7: Output & Exfil
| ID | Requirement |
|----|-------------|
| FR-7.1 | Compress output with LZNT1 |
| FR-7.2 | Encrypt with ChaCha20, key = SHA256(machine SID + timestamp) |
| FR-7.3 | Write to ADS on legitimate system file |
| FR-7.4 | ADS target: `C:\Windows\System32\config\software.log:lsass` |
| FR-7.5 | Alternative: C2 channel exfil without touching disk |

### FR-8: Cleanup
| ID | Requirement |
|----|-------------|
| FR-8.1 | `VirtualFree` staging memory in svchost.exe |
| FR-8.2 | Close LSASS handle |
| FR-8.3 | Re-enable ETW if patched |
| FR-8.4 | Remove ADS or dump artifact |

---

## 3. Technical Architecture

### 3.1 Component Diagram

```
SAMnLSADump_LSASS.exe
├── privilege.c          — RtlAdjustPrivilege wrapper
├── staging.c            — Process creation + hollowing
├── syscall_resolver.c   — Read clean ntdll.dll, extract syscall numbers
├── syscall_stubs.asm    — Generated syscall stubs (per function)
├── etw_patch.c          — EtwEventWrite + EtwNotificationRegister patch
├── lsass_reader.c       — NtOpenProcess + NtReadVirtualMemory via syscall
├── minidump_engine.c    — Custom minidump generator (no MiniDumpWriteDump)
├── cred_extractor.c     — Parse dump → NTLM + Kerberos + DPAPI
├── ads_writer.c         — Encrypt + compress + ADS write
├── cleanup.c            — Memory free, handle close, ETW restore
├── reflective_loader.c  — PE self-loader for staging DLL
└── crypto/
    ├── chacha20.c       — ChaCha20 implementation
    └── sha256.c         — SHA256 for key derivation
```

### 3.2 Data Flow

```
[SYSTEM Shell]
    │
    ├─(1)─ RtlAdjustPrivilege(SeDebugPrivilege)
    │
    ├─(2)─ NtCreateUserProcess(svchost.exe, SUSPENDED)
    │      NtUnmapViewOfSection(original image)
    │      NtAllocateVirtualMemory + write reflective DLL
    │      → Resume thread → DLL runs in hollowed svchost
    │
    ├─(3)─ [In hollowed svchost.exe]
    │      Patch EtwEventWrite → return 0
    │      Patch EtwNotificationRegister → return 0
    │
    ├─(4)─ Resolve syscall# from disk ntdll.dll
    │      Build stub: syscall; ret
    │      NtOpenProcess(LSASS_PID) → handle
    │
    ├─(5)─ NtQueryVirtualMemory(LSASS) → region list
    │      For each readable region:
    │        NtReadVirtualMemory(LSASS, region) → buffer
    │      Build minidump from buffers
    │
    ├─(6)─ Parse minidump:
    │      Find lsasrv.dll → extract Kerberos keys
    │      Find MSV1_0.dll → extract NTLM hashes
    │      Find dpapisrv.dll → extract DPAPI keys
    │
    ├─(7)─ Compress(LZNT1) → Encrypt(ChaCha20) → Base64
    │      Write ADS: software.log:lsass
    │
    └─(8)─ VirtualFree + CloseHandle + ADS cleanup
```

---

## 4. Interface Definitions

### 4.1 Command Line

```
SAMnLSADump_LSASS.exe <command>

Commands:
  --dump-full        Full chain: privilege → stage → dump → parse → output
  --dump-only        Dump only (assumes privilege + staging ready)
  --parse <file>     Parse existing dump file
  --output-ads       Write encrypted output to ADS
  --output-file <f>  Write encrypted output to file
  --whoami           Check current privilege + integrity
  --cleanup          Remove artifacts (ADS, handles, memory)

Options:
  --no-compress      Skip LZNT1 compression
  --no-encrypt       Skip encryption (debug only)
  --ppl-bypass       Enable PPL bypass routines (needs kernel driver)
```

### 4.2 Internal API

```c
// privilege.c
NTSTATUS EnableDebugPrivilege(VOID);
BOOLEAN  IsDebugPrivilegeEnabled(VOID);

// staging.c
NTSTATUS CreateHollowedProcess(PWSTR imagePath, PHANDLE phProcess, PHANDLE phThread);
NTSTATUS InjectReflectiveDll(HANDLE hProcess, PBYTE dllData, SIZE_T dllSize);

// syscall_resolver.c
DWORD    GetSyscallNumber(PWSTR functionName);  // from disk ntdll.dll
NTSTATUS SysNtOpenProcess(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
NTSTATUS SysNtReadVirtualMemory(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
NTSTATUS SysNtQueryVirtualMemory(HANDLE, PVOID, MEMORY_INFORMATION_CLASS, PVOID, SIZE_T, PSIZE_T);
NTSTATUS SysNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);

// etw_patch.c
VOID PatchEtwEventWrite(HANDLE hProcess);
VOID PatchEtwNotificationRegister(HANDLE hProcess);
VOID RestoreEtwPatches(HANDLE hProcess);

// lsass_reader.c
DWORD    FindLsassPid(VOID);
HANDLE   OpenLsassProcess(DWORD pid, BOOL useSyscall);
NTSTATUS DumpLsassMemory(HANDLE hLsass, PBYTE* dumpBuffer, PSIZE_T dumpSize);

// minidump_engine.c
NTSTATUS CreateCustomMinidump(HANDLE hProcess, PBYTE* dumpBuffer, PSIZE_T dumpSize);

// cred_extractor.c
typedef struct { PWSTR username; DWORD rid; BYTE ntlm[16]; BYTE lm[16]; } NTLM_CRED;
typedef struct { PWSTR username; BYTE key[32]; DWORD keyType; } KERBEROS_KEY;
typedef struct { BYTE key[64]; PWSTR description; } DPAPI_KEY;

DWORD ExtractNtlmHashes(PBYTE dump, SIZE_T size, NTLM_CRED** creds);
DWORD ExtractKerberosKeys(PBYTE dump, SIZE_T size, KERBEROS_KEY** keys);
DWORD ExtractDpapiKeys(PBYTE dump, SIZE_T size, DPAPI_KEY** keys);

// ads_writer.c
NTSTATUS WriteEncryptedToAds(PWSTR targetFile, PWSTR adsName, PBYTE data, SIZE_T size);

// cleanup.c
VOID CleanupAll(HANDLE hStaging, HANDLE hLsass, PBYTE dumpBuffer);
```

### 4.3 Output Format

```
Binary credential blob (before encryption):
┌────────────────────────────────────┐
│ Header                             │
│  Magic: 0x4D50534C ("LSMP")       │
│  Version: 2                        │
│  Timestamp: FILETIME               │
│  CredType flags: NTLM|Kerb|DPAPI   │
│  Record count: uint32              │
├────────────────────────────────────┤
│ Machine Info                       │
│  Computer name (UTF-16LE)          │
│  Domain name (UTF-16LE)            │
│  Machine SID (binary)              │
├────────────────────────────────────┤
│ NTLM Credentials                   │
│  [RID:uint32][UserLen:uint16]      │
│  [Username:UTF-8][NTLM:16bytes]    │
│  [LM:16bytes][Flags:uint8]         │
├────────────────────────────────────┤
│ Kerberos Keys                      │
│  [KeyType:uint32][KeyLen:uint16]   │
│  [KeyData:variable]                │
├────────────────────────────────────┤
│ DPAPI Keys                         │
│  [KeyLen:uint32][KeyData:variable] │
│  [DescLen:uint16][Desc:UTF-8]      │
└────────────────────────────────────┘

→ LZNT1 compress → ChaCha20 encrypt (key=sha256(machineSID|timestamp))
→ Base64 encode → write to ADS
```

---

## 5. Bypass Strategy

| # | EDR Layer | How Detected | Bypass Method |
|---|-----------|-------------|---------------|
| 1 | Userland ntdll hook | `NtOpenProcess` hook sees LSASS target | Indirect syscall from clean disk ntdll.dll |
| 2 | ObRegisterCallbacks (kernel) | Pre-callback on LSASS handle open | Handle duplication from legitimate process (taskmgr.exe); or kernel driver |
| 3 | ETW Threat Intelligence | LSASS access event | Patch `EtwEventWrite` + `EtwNotificationRegister` |
| 4 | MiniDumpWriteDump hook | API call signature | Custom minidump implementation, no external DLL calls |
| 5 | Memory scan | RWX region detection | RW→write→RX transition; no simultaneous RWX |
| 6 | Module list | New DLL in Ldr | Reflective load — no Ldr entry |
| 7 | File scan | Dump file creation | ADS on legitimate file + encryption |
| 8 | PPL (RunAsPPL) | LSASS protected | `NtOpenProcess` with PROCESS_QUERY_LIMITED_INFORMATION + kernel driver bypass |

---

## 6. Test Cases

| TC | Scenario | Expected Result |
|----|----------|----------------|
| TC-01 | SYSTEM shell, LSASS not PPL | Full dump success, NTLM+Kerberos extracted |
| TC-02 | SYSTEM shell, LSASS PPL enabled | Dump fails gracefully or PPL bypass engages |
| TC-03 | HIGH integrity (no SYSTEM) | SeDebugPrivilege enable may fail → fallback needed |
| TC-04 | EDR with ObRegisterCallbacks | Handle open blocked → handle dup fallback |
| TC-05 | EDR with ETW TI monitoring | ETW patched → no events emitted |
| TC-06 | EDR with memory scan | No RWX detected → no alert |
| TC-07 | EDR with ADS monitoring | Encrypted blob in ADS → not flagged |
| TC-08 | Dump > 100MB (large LSASS) | LZNT1 compression keeps output manageable |
| TC-09 | Windows 10 22H2 | Full compatibility |
| TC-10 | Windows 11 23H2 | Full compatibility |
| TC-11 | Windows Server 2022 | Full compatibility (check PPL default) |

---

## 7. Success Criteria

- [ ] LSASS handle opened without triggering EDR callback block
- [ ] Full LSASS memory dump completed
- [ ] NTLM hashes extracted for all local accounts
- [ ] Kerberos keys extracted (AES256 + AES128)
- [ ] DPAPI master keys extracted
- [ ] Output encrypted and written to ADS
- [ ] No new files visible on disk (ADS only)
- [ ] No EDR alerts triggered
- [ ] No Event ID 4663 (file access) generated for SAM path
- [ ] Cleanup completed: memory freed, handles closed, ETW restored
