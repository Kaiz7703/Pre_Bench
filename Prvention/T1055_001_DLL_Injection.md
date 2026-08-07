# T1055.001 — Process Injection: Dynamic-link Library Injection — Evaluation Plans

> **MITRE ATT&CK**: T1055.001 — DLL Injection (Sub-technique of T1055: Process Injection)
> **EDR Assumption**: Medium-high maturity. EDR có kernel callbacks (PsSetCreateProcessNotifyRoutineEx, PsSetLoadImageNotifyRoutine, ObRegisterCallbacks), userland hook, ETW, memory scanning.
> **Design principle**: DLL injection làm bàn đạp để đạt HIGH integrity hoặc SYSTEM — từ đó chain sang technique khác (T1003 credential dump). Dựa trên CVE thực tế (2021-2026) có PoC.

---

## Evaluation Plan 1: DLL Side-Loading via CVE-2022-24528 + Elevated Context Chain → T1068 PE

### CVE Reference
| Field | Detail |
|-------|--------|
| **CVE** | CVE-2022-24528 (Windows WinRM DLL Hijacking) |
| **Published** | April 2022 |
| **PoC** | Public (GitHub: WinRM service DLL side-loading) |
| **Impact** | DLL injection vào `wsmprovhost.exe` (SYSTEM) qua WinRM service |
| **Patch** | KB5012636 (April 2022) |
| **Pre-req** | Low-privilege domain user + khả năng ghi vào user-writable path trong DLL search order |

### Chain Map
```
┌──────────────────────────────────────────────────────────────┐
│ CHAIN: DLL Side-Load → SYSTEM → Credential Dump               │
├──────────────────────────────────────────────────────────────┤
│ [Domain User / Local User]                                    │
│ [T1055.001 Plan 1] CVE-2022-24528 WinRM DLL Side-Load         │
│   ├─ Drop proxy DLL "wsmplpxy.dll" in user-writable path     │
│   ├─ WinRM service loads DLL with SYSTEM privilege            │
│   └─ C2 agent running as SYSTEM in wsmprovhost.exe            │
│   ▼ [NT AUTHORITY\SYSTEM via DLL injection]                    │
│ [T1003 Plan 1] LSASS Dump: Indirect Syscall + Reflective      │
│   ▼ [NTLM Hashes + Kerberos Keys Extracted]                    │
└──────────────────────────────────────────────────────────────┘
```

### Sub-techniques Leveraged
| ID | Name | Role |
|----|------|------|
| **T1055.001** | DLL Injection | Primary |
| **T1574.001** | DLL Search Order Hijacking | Side-load `wsmplpxy.dll` trong `wsmprovhost.exe` search order |
| **T1036.005** | Masquerading: Match Legitimate Resource Name or Location | Proxy DLL tên giống legitimate, forward exports |
| **T1218.007** | System Binary Proxy Execution: Msiexec | (Alternative) Trigger WinRM service load |
| **T1106** | Native API | `NtCreateFile` để tạo junction/redirect nếu cần |
| **T1620** | Reflective Code Loading | Payload reflectively loaded trong `DllMain` của proxy DLL |

### Test Scenario
1. **Tiền đề**: Domain user (không admin) có WinRM access (Remote Management Users group).
2. **Exploit chain**:
   - **Bước 1 — Target DLL Identification**:
     - `wsmprovhost.exe` (WinRM host process, chạy SYSTEM) load nhiều DLL, trong đó có `wsmplpxy.dll` (WSMAN plugin proxy).
     - DLL search order: (1) process directory → (2) System32 → (3) System → (4) Windows → (5) current directory → (6) PATH.
     - Nếu `wsmplpxy.dll` không tồn tại trong process directory → SYSTEM cố gắng load từ PATH → trong PATH có user-writable directory → **điểm yếu**.
   - **Bước 2 — Proxy DLL Construction**:
     - Build `wsmplpxy.dll` proxy:
       - Export-forwarding tất cả 12 functions đến `C:\Windows\System32\wsmplpxy.dll` (legitimate).
       - Trong `DllMain(DLL_PROCESS_ATTACH)`:
         - Decrypt embedded shellcode (ChaCha20).
         - Reflective load C2 agent DLL.
         - Trả về TRUE (DLL load thành công, application không crash).
     - Code-sign proxy DLL với stolen/leaked certificate.
   - **Bước 3 — Deployment**:
     - Drop `wsmplpxy.dll` vào `C:\Users\Public\Documents\` (trong PATH hoặc search order).
     - HOẶC: tạo directory junction `C:\Users\<user>\AppData\Local\Temp\3\{GUID}` → set current directory → WinRM load từ đây.
   - **Bước 4 — Trigger WinRM Load**:
     - `winrs -r:127.0.0.1 cmd` (hoặc dùng WinRM PowerShell: `Invoke-Command -ComputerName localhost`)
     - `wsmprovhost.exe` được khởi tạo bởi WinRM service → search và load `wsmplpxy.dll` từ hijacked path.
     - DLL load ở SYSTEM integrity → `DllMain` chạy → C2 agent SYSTEM.
   - **Bước 5 — Chain to T1003**:
     - Từ SYSTEM trong `wsmprovhost.exe`, thực hiện LSASS dump (T1003 Plan 1).
     - Hoặc migrate sang process khác để persistence.

### Bypass Methodology
| Layer | How It's Bypassed |
|-------|-------------------|
| **WinRM Access Control** | Attacker đã là Remote Management Users → WinRM access hợp lệ |
| **DLL Search Order Hijack** | `wsmplpxy.dll` không tồn tại trong System32 → Windows search PATH → tìm thấy trong user-writable directory |
| **`wsmprovhost.exe`** | Process SYSTEM signed by Microsoft; EDR trust processes này → ít monitor DLL load |
| **Proxy DLL** | Export-forwarding trong suốt → application không crash; khó phân biệt với legitimate DLL |
| **Code Signing** | Proxy DLL signed với cert hợp lệ → reputation pass |
| **DLL Load Event** | Windows Image Load event (Etw) fire cho DLL load → nhưng cả legits và malicious DLL đều có event; khó phân biệt |
| **`winrs.exe` Command Line** | `winrs -r:127.0.0.1 cmd` là command hợp lệ cho remote management |

### Success Criteria
- [ ] `wsmplpxy.dll` proxy được load bởi `wsmprovhost.exe` (SYSTEM)
- [ ] C2 agent chạy SYSTEM trong `wsmprovhost.exe`
- [ ] EDR không detect: (a) DLL side-loading, (b) WinRM process anomaly, (c) SYSTEM process spawning
- [ ] **Chain verification**: SYSTEM → T1003 LSASS dump thành công
- [ ] `wsmprovhost.exe` không crash (proxy transparent)
- [ ] Pre-patch Windows 10 21H2 / Server 2019

### Expected EDR Detection Points
- **`wsmprovhost.exe` spawning child process** → Nếu C2 agent spawn shell trực tiếp → anomalous (SYSTEM process từ WinRM host). Bypass: dùng APC injection sang process khác, không spawn child.
- **DLL từ non-System32 path** → EDR có thể monitor DLL load từ `C:\Users\Public\*` → **có thể detect.** Bypass: tìm path khác trong search order ít bị monitor hơn.
- **WinRM service trigger** → Nếu EDR correlate `winrs.exe` → `wsmprovhost.exe` + DLL load anomaly → có thể detect.

---

## Evaluation Plan 2: Shim Database (SDB) Persistence + Auto-Injection via CVE-2023-28272 — DLL Injection Without Remote Thread

### CVE Reference
| Field | Detail |
|-------|--------|
| **CVE** | CVE-2023-28272 (Windows Application Compatibility Shim DLL Injection) |
| **Published** | April 2023 |
| **PoC** | Public (Custom shim database + InjectDll shim type) |
| **Impact** | User → DLL injection vào target process mà không cần remote thread |
| **Patch** | KB5025221 (April 2023); shim engine behavior hardening |
| **Pre-req** | Administrator (để cài SDB) hoặc HIGH integrity |

### Chain Map
```
┌──────────────────────────────────────────────────────────────┐
│ CHAIN: UAC Bypass → HIGH → SDB Injection → Elevated C2        │
├──────────────────────────────────────────────────────────────┤
│ [T1548.002 Plan 1] CVE-2024-30057 → HIGH Integrity           │
│   ▼ [HIGH Integrity - Admin]                                  │
│ [T1055.001 Plan 2] CVE-2023-28272 SDB Shim Injection          │
│   ├─ Create custom .sdb database (InjectDll shim)            │
│   ├─ sdbinst.exe -q install                                  │
│   ├─ Registry: AppCompatFlags\Custom + InstalledSDB          │
│   └─ Target process auto-loads DLL at startup (Windows Loader)│
│   ▼ [C2 in explorer.exe / msedge.exe - user session]          │
│ [Lateral Movement / Credential Access]                        │
└──────────────────────────────────────────────────────────────┘
```

### Sub-techniques Leveraged
| ID | Name | Role |
|----|------|------|
| **T1055.001** | DLL Injection | Primary |
| **T1546.011** | Event Triggered Execution: Application Shimming | SDB database để inject DLL tự động |
| **T1112** | Modify Registry | Ghi registry AppCompatFlags |
| **T1127** | Trusted Developer Utilities Proxy Execution | `sdbinst.exe` — Microsoft signed binary |
| **T1574.001** | DLL Search Order Hijacking | (Alternative) Shim `RedirectDll` để đổi đường dẫn DLL load |
| **T1036.005** | Masquerading | SDB file + DLL đặt trong `C:\ProgramData\Microsoft\Crypto\` (legitimate-looking path) |

### Test Scenario
1. **Tiền đề**: ADMIN/HIGH integrity (từ T1548.002 Plan 1: CVE-2024-30057 COM elevation).
2. **Exploit chain**:
   - **Bước 1 — Custom SDB Creation**:
     - Dùng `sdb2xml` + custom XML → build `.sdb` database với shim `InjectDll`.
     - Target executable: `explorer.exe` (luôn chạy khi user login).
     - DLL path: `C:\ProgramData\Microsoft\Crypto\Keys\compatprov.dll` (masquerading legit crypto provider).
     - Shim flags: `SHIM_REGKEY_ADD_CMDLINE` + `FORCE_DLL_INJECT` để đảm bảo load.
   - **Bước 2 — SDB Installation**:
     - `sdbinst.exe -q -g "C:\ProgramData\Microsoft\Crypto\Keys\custom_compat.sdb"` → install silently.
     - `sdbinst.exe` signed by Microsoft → legitimate process, EDR ít flag.
     - Registry paths populated:
       - `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom\CustomDB`
       - `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB\{GUID}`
   - **Bước 3 — DLL Deployment**:
     - Drop `compatprov.dll` vào `C:\ProgramData\Microsoft\Crypto\Keys\`.
     - DLL là proxy: forward exports đến legitimate (nếu có) hoặc trả về 0.
     - Payload trong `DllMain`: reflective load C2 agent.
   - **Bước 4 — Trigger (Natural)**:
     - User login → `explorer.exe` start → Windows Loader parse AppCompat database.
     - Loader tìm SDB có matching entry cho `explorer.exe` → apply shim → `LoadLibrary("C:\ProgramData\Microsoft\Crypto\Keys\compatprov.dll")`.
     - DLL load trong context của `explorer.exe` (user session, có network access — hợp lệ).
   - **Bước 5 — C2 & Lateral Movement**:
     - C2 trong `explorer.exe` có user session context → truy cập network shares, domain resources.
     - Không cần escalation thêm vì user session đã có quyền truy cập.

### Bypass Methodology
| Layer | How It's Bypassed |
|-------|-------------------|
| **Remote Thread Detection** | Không remote thread — DLL được load bởi chính Windows Loader khi process khởi động |
| **`WriteProcessMemory`** | Không write memory — Loader map DLL từ disk (như legitimate module) |
| **`sdbinst.exe`** | Microsoft signed; thường dùng cho enterprise AppCompat deployment → ít bị flag |
| **AppCompat Registry** | Path `AppCompatFlags\Custom` ít EDR monitor; volume noise từ Windows Update + enterprise SDB |
| **DLL Load** | DLL được load bởi Windows Loader (kernel) trong quá trình init process → ETW image load event fire, nhưng trông như legitimate shim (Microsoft cũng dùng shim cho compat) |
| **Memory Scan** | DLL mapped như module bình thường (`Image` type, RX for .text) → không anomalous |
| **Network từ explorer.exe** | explorer.exe thường xuyên network (OneDrive, SharePoint, telemetry) → C2 traffic blend in |

### Success Criteria
- [ ] Custom SDB installed thành công, không bị detect
- [ ] DLL auto-loaded khi `explorer.exe` khởi động (user login)
- [ ] C2 agent hoạt động trong `explorer.exe` (user session)
- [ ] EDR không detect: (a) `sdbinst.exe` install, (b) AppCompat registry, (c) DLL load từ non-System32 trong explorer.exe
- [ ] **Chain verification**: HIGH integrity (từ T1548.002) → SDB install → C2 in explorer.exe → lateral movement
- [ ] Pre-patch Windows 10 22H2 / Windows 11 22H2

### Expected EDR Detection Points
- **SDB installation** → Một số EDR có rule "Shim Database Persistence" → **có thể detect** nếu `sdbinst.exe` + file `.sdb` từ non-standard path. Bypass: ký SDB với cert hợp lệ (SDB có thể được sign).
- **`sdbinst.exe -q`** → command line analysis: `-q` (quiet) + path trong `C:\ProgramData\*` → suspicious. Bypass: alternative install method (registry direct write, không qua sdbinst).
- **DLL load trong explorer.exe** → EDR có thể flag nếu DLL load từ `C:\ProgramData\*` trong system-critical process. Nhưng shim DLL là Microsoft compat feature → EDR cần phân biệt.

---

## Evaluation Plan 3: Module Stomping + APC Injection với Process State API — Chain từ T1548.002 → Injection → SYSTEM Token

### CVE Reference
| Field | Detail |
|-------|--------|
| **CVE** | Không dựa trên CVE cụ thể — technique chaining dựa trên CVE-2024-30057 (UAC bypass) + CVE-2023-28252 (CLFS PE, fallback) |
| **Technique** | Module Stomping + Early Bird APC Injection (evolution of Process Injection) |
| **Published** | Technique evolution 2022-2024 |
| **PoC** | Multiple frameworks (Cobalt Strike `blockdlls`, BruteRatel, Nighthawk) |
| **Impact** | DLL injection vào target process HOẶC token capture → escalate |

### Chain Map
```
┌──────────────────────────────────────────────────────────────────┐
│ CHAIN: UAC Bypass → HIGH → DLL Injection → Token → T1003          │
├──────────────────────────────────────────────────────────────────┤
│ [T1548.002 Plan 2] CVE-2023-21674 ALPC → HIGH Integrity          │
│   ▼ [HIGH Integrity]                                              │
│ [T1055.001 Plan 3] Module Stomping + Early Bird APC               │
│   ├─ Create suspended process (RuntimeBroker.exe)                │
│   ├─ Module stomping: overwrite msxml3.dll .text in target       │
│   ├─ APC injection: QueueUserAPC → entry point of payload        │
│   ├─ Payload: reflective DLL C2 agent                            │
│   └─ Alternative: hijack SYSTEM thread token (if SYSTEM process) │
│   ▼ [C2 in RuntimeBroker.exe (HIGH) OR SYSTEM via token]          │
│ [T1003 Plan 1] LSASS Dump (if SYSTEM achieved)                    │
└──────────────────────────────────────────────────────────────────┘
```

### Sub-techniques Leveraged
| ID | Name | Role |
|----|------|------|
| **T1055.001** | DLL Injection | Primary |
| **T1055.004** | Asynchronous Procedure Call (APC) | QueueUserAPC → entry point, không tạo thread mới |
| **T1620** | Reflective Code Loading | Payload DLL tự resolve imports + relocations |
| **T1106** | Native API | `NtMapViewOfSection`, `NtQueueApcThread`, `NtResumeThread`, `NtProtectVirtualMemory` |
| **T1027.007** | Dynamic API Resolution | PEB walk resolve tất cả API (không IAT, không GetProcAddress) |
| **T1134.001** | Token Impersonation/Theft | (Optional) Nếu inject vào SYSTEM process → duplicate token |
| **T1134.004** | Parent PID Spoofing | PPID của target = services.exe |

### Test Scenario
1. **Tiền đề**: HIGH integrity (từ T1548.002 Plan 2: CVE-2023-21674 ALPC bypass).
2. **Execution chain**:
   - **Bước 1 — Target Selection + Process Creation**:
     - **Option A**: Chọn existing `RuntimeBroker.exe` (HIGH integrity, có network) đang chạy.
     - **Option B**: Tạo mới `RuntimeBroker.exe` ở SUSPENDED với PPID = `services.exe`.
     - `NtCreateUserProcess(..., PS_CREATE_FLAGS_CREATE_SUSPENDED, ...)` với `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`.
   - **Bước 2 — Module Stomping**:
     - Enum loaded modules → chọn `C:\Windows\System32\msxml3.dll` (loaded trong hầu hết processes, signed Microsoft).
     - `NtProtectVirtualMemory(target, msxml3_dll_base, .text_size, PAGE_EXECUTE_READWRITE, ...)` → thay đổi permission.
     - `NtWriteVirtualMemory` → overwrite `.text` section với reflective DLL payload.
     - `NtProtectVirtualMemory` → đổi lại `PAGE_EXECUTE_READ`.
   - **Bước 3 — APC Injection (Early Bird)**:
     - Enum threads của target → `NtQuerySystemInformation(SystemProcessInformation)` + parse.
     - Với thread đầu tiên (hoặc thread alertable):
       - `NtQueueApcThread(hThread, (PKNORMAL_ROUTINE)&stomped_dll_entry, ...)` → queue APC.
       - Nếu target suspended: APC chưa chạy ngay → cần ResumeThread.
   - **Bước 4 — Execution**:
     - `NtResumeThread(hThread)` → thread resumed → APC delivered → payload entry point chạy.
     - Reflective DLL: parse PE + fix imports + fix relocations → `DllMain` → C2 agent alive.
   - **Bước 5 — Token Capture (If SYSTEM Target)**:
     - Nếu inject vào SYSTEM process (vd: `winlogon.exe`):
       - `OpenThreadToken(GetCurrentThread())` → thread có SYSTEM token (do impersonation nếu pipe-based).
       - `DuplicateTokenEx` → primary token.
       - `CreateProcessWithTokenW` → spawn SYSTEM shell.
   - **Bước 6 — Chain to T1003**:
     - Từ SYSTEM → LSASS dump (T1003 Plan 1).

### Bypass Methodology
| Layer | How It's Bypassed |
|-------|-------------------|
| **Remote Thread Detection** | APC injection: thread có sẵn, không tạo thread mới → `PsSetCreateThreadNotifyRoutine` không fire |
| **`CreateRemoteThread`** | Không gọi — APC queue trên thread có sẵn |
| **Module Stomping** | Memory vẫn có type `Image` → không tạo vùng `Private` RWX; EDR memory scan bỏ qua Image regions |
| **`LoadLibrary`** | Không gọi — reflective loading bypass `PsSetLoadImageNotifyRoutine` (image load callback) |
| **RWX Memory** | `.text` được protect: RW → write → RX → execute. Không có RWX đồng thời |
| **Process List Anomaly** | Module list vẫn hiển thị `msxml3.dll` (legit) → `EnumProcessModules` không thấy payload |
| **ETW Image Load** | Reflective load không fire ETW Image Load event → EDR không biết DLL mới đã load |
| **PPID Spoofing** | Parent process = services.exe → process tree trông legitimate |

### Success Criteria
- [ ] Module stomping thành công: `msxml3.dll` .text overwritten
- [ ] APC delivered → reflective DLL chạy trong target process
- [ ] C2 agent hoạt động: beacon + command execution
- [ ] EDR không detect: (a) module stomping, (b) APC injection, (c) reflective DLL load
- [ ] **Chain verification**: HIGH (từ T1548.002) → injection → (optional SYSTEM token) → T1003 LSASS dump
- [ ] Không crash target process (stable execution)
- [ ] Windows 10 22H2, Windows 11 23H2

### Expected EDR Detection Points
- **Module stomping (.text integrity)** → Nếu EDR lưu hash của `.text` section khi DLL load và so sánh định kỳ → **có thể detect.** Nhưng đòi hỏi performance impact cao, ít EDR làm.
- **`NtProtectVirtualMemory` trên Image section** → Nếu EDR monitor protection change từ RX → RWX → RX trên Image regions → **có thể detect.** Đây là detection vector cho code caves/module stomping.
- **APC injection** → `NtQueueApcThread` có thể bị hook (userland hoặc kernel). Nếu EDR kernel callback monitor APC queue đến non-debugger process → **có thể detect.**
- **Reflective loader artifact** → Nếu EDR scan memory cho PE headers (MZ/PE) trong non-Image regions → có thể detect staging areas. Nhưng module stomping giữ payload trong Image region.

---

## Inter-Plan Chain Reference

| This Plan | Injection Method | Receives From | Grants | Feeds Into |
|-----------|-----------------|---------------|--------|------------|
| Plan 1 | DLL Side-Loading (CVE-2022-24528) | Domain User + WinRM access | SYSTEM | **T1003 Plan 1** (LSASS Dump) |
| Plan 2 | SDB Shim Injection (CVE-2023-28272) | **T1548.002 Plan 1** (UAC → HIGH) | C2 in explorer.exe (user session) | Lateral Movement |
| Plan 3 | Module Stomping + APC | **T1548.002 Plan 2** (UAC → HIGH) | C2 HIGH or SYSTEM (via token) | **T1003 Plan 1** (LSASS Dump) |

---

## Summary: Detection Difficulty Matrix

| Plan | CVE / Technique | Year | Stealth | EDR Detection Difficulty | Key Blind Spot Tested |
|------|----------------|------|---------|--------------------------|----------------------|
| Plan 1 | CVE-2022-24528 (WinRM DLL) | 2022 | ★★★★☆ | **High** | DLL side-loading vào signed SYSTEM process; WinRM trust abuse |
| Plan 2 | CVE-2023-28272 (SDB Shim) | 2023 | ★★★★★ | **Very High** | Shim Database persistence; injection bởi chính Windows Loader |
| Plan 3 | Module Stomping + APC | 2023-24 | ★★★★☆ | **High** | Image section overwrite; APC threadless execution; reflective loading |
