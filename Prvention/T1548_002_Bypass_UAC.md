# T1548.002 — Abuse Elevation Control Mechanism: Bypass User Account Control — Evaluation Plans

> **MITRE ATT&CK**: T1548.002 — Bypass User Account Control
> **EDR Assumption**: Medium-high maturity. EDR có hook userland + kernel callbacks + ETW + AMSI. Đã loại bỏ test case tầm thường.
> **Design principle**: Mỗi plan dựa trên CVE thực tế (2021-2026) có PoC public, chain được với T1068 (PE) hoặc T1003 (Cred Dump).

---

## Evaluation Plan 1: CVE-2024-30057 — COM Elevation via AppInfo Trusted Path + Chain → T1068 BYOVD

### CVE Reference
| Field | Detail |
|-------|--------|
| **CVE** | CVE-2024-30057 (Windows AppInfo COM Elevation) |
| **Published** | May 2024 |
| **PoC** | Public (GitHub: UACME #68 variant, custom COM object masquerading) |
| **Impact** | Medium Integrity → High Integrity, UAC prompt bypassed |
| **Patch** | KB5037768 (May 2024 Patch Tuesday), pre-patch Win10 22H2 / Win11 23H2 |

### Chain Map
```
┌─────────────────────────────────────────────────────────┐
│ CHAIN: Initial Access → UAC Bypass → PE → Cred Dump     │
├─────────────────────────────────────────────────────────┤
│ [Standard User]                                          │
│   │ T1548.002: CVE-2024-30057 COM Elevation             │
│   ▼ [HIGH Integrity]                                     │
│   │ T1068 Plan 1: CVE-2024-26234 BYOVD (Proxy Driver)  │
│   ▼ [SYSTEM]                                             │
│   │ T1003.001: LSASS Dump (Indirect Syscall + Reflective)│
│   ▼ [Domain Credentials Compromised]                     │
└─────────────────────────────────────────────────────────┘
```

### Sub-techniques Leveraged
| ID | Name | Role |
|----|------|------|
| **T1548.002** | Bypass UAC | Primary |
| **T1574.001** | DLL Search Order Hijacking | Hijack `profapi.dll` trong path của elevated COM process |
| **T1036.005** | Masquerading: Match Legitimate Resource Name or Location | DLL proxy tên `profapi.dll` giả legit Windows DLL |
| **T1106** | Native API | `NtCreateKey` + `NtSetValueKey` ghi registry COM redirect |
| **T1112** | Modify Registry | `HKCU\Software\Classes\CLSID\{GUID}\InProcServer32` |
| **T1127** | Trusted Developer Utilities | Lợi dụng `sdclt.exe` (auto-elevated, signed) để trigger COM load |

### Test Scenario
1. **Tiền đề**: Attacker có shell Standard User (Medium IL) — ví dụ từ phishing doc macro đã bypass ASR.
2. **Exploit chain**:
   - **Bước 1 — COM Registry Hijack**:
     - Target COM object: `{GUID}` được gọi bởi `sdclt.exe` (Backup and Restore Center) — process có `autoElevate=true`.
     - Ghi `HKCU\Software\Classes\CLSID\{GUID}\InProcServer32\(Default)` = `C:\Users\Public\Downloads\profapi.dll`
     - Dùng `NtSetValueKey` thay vì `RegSetValueExW` → tránh userland hook.
   - **Bước 2 — DLL Proxy Construction**:
     - `profapi.dll` là export-forwarding proxy: forward tất cả exports đến `C:\Windows\System32\profapi.dll` (legit).
     - Trong `DllMain`, payload gọi `ShellExecuteExW` với `runas` verb → spawn `C2_stager.exe` ở HIGH integrity.
     - DLL signed bằng stolen/leaked code-signing certificate (VD: từ CVE-2023-35628 certificate leak).
   - **Bước 3 — Trigger Elevation**:
     - Chạy `sdclt.exe /KICKOFFELEVATION` → process được auto-elevate (không UAC prompt).
     - `sdclt.exe` load COM object → load `profapi.dll` từ hijacked path.
     - Payload execute ở HIGH integrity → spawn C2 agent HIGH.
   - **Bước 4 — Chain sang T1068 (PE)**:
     - Từ HIGH integrity, triển khai **T1068 Plan 1**: CVE-2024-26234 (Windows Proxy Driver PE) → SYSTEM.
     - (Xem file `T1068_Exploitation_for_Privilege_Escalation.md` Plan 1).
   - **Bước 5 — Chain sang T1003 (Cred Dump)**:
     - Từ SYSTEM, triển khai **T1003 Plan 1**: LSASS dump indirect syscall + reflective loading.
     - (Xem file `T1003_OS_Credential_Dumping.md` Plan 1).

### Bypass Methodology
| Layer | How It's Bypassed |
|-------|-------------------|
| **UAC Prompt** | `sdclt.exe` có manifest `<autoElevate>true</autoElevate>` → Windows tự động nâng quyền không prompt |
| **Registry Monitor** | `NtSetValueKey` native API bypass userland `RegSetValueExW` hook; `HKCU\Software\Classes\CLSID\` là path user-writable, noise cao |
| **DLL Load Path** | `profapi.dll` từ `C:\Users\Public\Downloads\` — EDR phải phân biệt giữa legit profapi từ System32 và proxy |
| **Code Signing** | DLL signed với cert hợp lệ (stolen, chưa revoked) → reputation check pass |
| **AMSI** | DLL không scan qua AMSI (không PowerShell, không .NET, không VBA macro ở giai đoạn này) |
| **ETW** | DLL proxy transparent → legit calls forwarded đến System32; application behavior unchanged |

### Success Criteria
- [ ] `sdclt.exe` auto-elevate thành công (không UAC prompt)
- [ ] `profapi.dll` proxy load → C2 agent chạy HIGH integrity
- [ ] EDR không detect: (a) registry hijack, (b) DLL proxy load, (c) integrity boundary crossing Medium→High
- [ ] **Chain verification**: HIGH integrity shell → T1068 BYOVD thành công → SYSTEM
- [ ] Hoạt động trên Windows 10 22H2 pre-May-2024 patch

### Expected EDR Detection Points
- **`sdclt.exe` spawn chain** → nếu sdclt.exe spawn cmd.exe/powershell.exe → anomalous parent. Bypass: spawn trực tiếp C2 agent (không qua cmd).
- **DLL unsigned/signed mismatch** → EDR so sánh cert của DLL trong System32 vs DLL trong user path → **có thể detect** nếu EDR check. Bypass: ký DLL với cert hợp lệ.
- **COM registry modification** → nếu EDR monitor `HKCU\Software\Classes\CLSID\` writes → noise rất cao, khó có rule chính xác.

---

## Evaluation Plan 2: CVE-2023-21674 — Event Viewer UAC Bypass + Chain → T1055.001 DLL Injection (Elevated Context)

### CVE Reference
| Field | Detail |
|-------|--------|
| **CVE** | CVE-2023-21674 (Windows Advanced Local Procedure Call - ALPC UAC bypass) |
| **Published** | January 2023 |
| **PoC** | Public (GitHub multiple PoCs, UACME #71) |
| **Impact** | Medium → High via elevated COM server ALPC call |
| **Patch** | KB5022282 (Jan 2023), pre-patch Win10 21H2 / Win11 22H2 |

### Chain Map
```
┌──────────────────────────────────────────────────────────────┐
│ CHAIN: UAC Bypass → HIGH Integrity → DLL Injection (elevated) │
├──────────────────────────────────────────────────────────────┤
│ [Standard User]                                               │
│   │ T1548.002: CVE-2023-21674 ALPC UAC Bypass               │
│   ▼ [HIGH Integrity]                                          │
│   │ T1055.001 Plan 1: Module Stomping + Early Bird APC       │
│   ▼ [C2 in RuntimeBroker.exe (HIGH)]                          │
│   │ Lateral Movement / Persistence                           │
└──────────────────────────────────────────────────────────────┘
```

### Sub-techniques Leveraged
| ID | Name | Role |
|----|------|------|
| **T1548.002** | Bypass UAC | Primary |
| **T1559.001** | Inter-Process Communication: ALPC | Lợi dụng ALPC để gọi elevated COM server |
| **T1134.001** | Access Token Manipulation: Token Impersonation | Mượn token từ elevated process |
| **T1574.002** | DLL Side-Loading | Side-load payload DLL qua Windows Task Scheduler MMC |
| **T1027.007** | Dynamic API Resolution | Custom `GetProcAddress` via PEB hash lookup |

### Test Scenario
1. **Tiền đề**: Standard User shell, target Windows 10 21H2 / Windows 11 22H2 pre-Jan-2023 patch.
2. **Exploit chain**:
   - **Bước 1 — ALPC Port Enumeration**:
     - Dùng `NtAlpcQueryInformation` để enum ALPC ports có `ElevationRequired` attribute.
     - Target: `\RPC Control\{GUID}_IUserNotification` — port của elevated COM server có lỗi xác thực (không verify caller integrity).
   - **Bước 2 — ALPC Message Spoof**:
     - Craft ALPC message với `VIEW_ATTRIBUTES.DataView` được set để bypass integrity check.
     - Gửi request tới elevated COM server → request được xử lý với HIGH integrity dù caller là Medium.
   - **Bước 3 — Token Capture**:
     - Elevated COM server phản hồi → trong response có handle đến token HIGH integrity.
     - Dùng `NtAlpcSendWaitReceivePort` để nhận → extract token handle → `DuplicateTokenEx` → primary token.
   - **Bước 4 — Spawn Elevated Process**:
     - `CreateProcessWithTokenW` với duplicated token → spawn C2 agent HIGH integrity.
     - PPID spoofing: `STARTUPINFOEX.lpAttributeList` → set `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` = `explorer.exe`.
   - **Bước 5 — Chain sang T1055.001**:
     - Từ HIGH integrity, thực hiện DLL injection vào `RuntimeBroker.exe` (HIGH, có network) dùng **Module Stomping + Early Bird APC**.
     - (Xem `T1055_001_DLL_Injection.md` Plan 1).

### Bypass Methodology
| Layer | How It's Bypassed |
|-------|-------------------|
| **UAC Prompt** | ALPC call trực tiếp tới elevated COM server — không qua AppInfo service (service quản lý UAC prompt) |
| **ALPC Monitoring** | ALPC là cơ chế IPC internal của Windows; rất ít EDR hook `NtAlpc*` functions |
| **Token Duplication** | Token được duplicate trong kernel context thông qua ALPC response — EDR userland không thấy |
| **Process Creation** | PPID spoofing → parent = explorer.exe (legitimate); command line trông như process bình thường |
| **Event ID 4688** | Windows ghi event "A new process has been created" với integrity level; nhưng nếu không có SIEM correlating Medium→High → bỏ lỡ |

### Success Criteria
- [ ] ALPC message spoof thành công → token HIGH integrity captured
- [ ] Elevated C2 agent chạy với HIGH integrity, PPID = explorer.exe
- [ ] EDR không detect: ALPC manipulation, token capture, integrity boundary crossing
- [ ] **Chain verification**: HIGH shell → T1055.001 DLL injection thành công vào RuntimeBroker.exe
- [ ] Pre-patch Windows 10 21H2 / Windows 11 22H2

### Expected EDR Detection Points
- **`NtAlpcSendWaitReceivePort`** → nếu EDR kernel component monitor ALPC → có thể detect anomalous ALPC traffic pattern (Medium→High). Nhưng hầu hết EDR không có rule này.
- **Token creation anomaly** → Nếu EDR monitor token operations qua `SeCreateTokenPrivilege` → có thể thấy token mới từ non-system process. **Detection vector tiềm năng.**
- **Process integrity jump** → Nếu EDR track parent-child integrity → thấy Medium parent spawn High child → anomaly. Bypass qua PPID spoofing.

---

## Evaluation Plan 3: CVE-2022-21922 — MSI Installer DLL Hijack UAC Bypass + Chain → T1003 Offline Hive Dump

### CVE Reference
| Field | Detail |
|-------|--------|
| **CVE** | CVE-2022-21922 (Windows Installer DLL Hijack via Malicious MSI) |
| **Published** | January 2022 |
| **PoC** | Public (msi.dll proxy technique, multiple tool implementations) |
| **Impact** | Medium → High via MSI repair/install elevated COM |
| **Patch** | KB5009543 (Jan 2022), pre-patch Win10 21H1 / Server 2019 |

### Chain Map
```
┌───────────────────────────────────────────────────────────────┐
│ CHAIN: MSI UAC Bypass → HIGH → Offline Credential Dump         │
├───────────────────────────────────────────────────────────────┤
│ [Standard User]                                                │
│   │ T1548.002: CVE-2022-21922 MSI DLL Hijack                 │
│   ▼ [HIGH Integrity]                                           │
│   │ T1003 Plan 2: SAM + LSA Secrets via Raw Volume + Offline  │
│   ▼ [NTLM Hashes + Cached Credentials Extracted]               │
└───────────────────────────────────────────────────────────────┘
```

### Sub-techniques Leveraged
| ID | Name | Role |
|----|------|------|
| **T1548.002** | Bypass UAC | Primary |
| **T1218.007** | System Binary Proxy Execution: Msiexec | `msiexec.exe` làm proxy để thực thi code elevated |
| **T1574.001** | DLL Search Order Hijacking | Hijack DLL load path của msiexec.exe |
| **T1036.005** | Masquerading: Match Legitimate Resource Name or Location | Drop DLL tại `C:\Windows\Installer\` (legit MSI cache dir) |
| **T1027.009** | Embedded Payloads | Payload DLL nén LZNT1 + mã hóa AES-256 trong MSI package |

### Test Scenario
1. **Tiền đề**: Standard User, khả năng ghi vào `C:\Windows\Installer\` (world-writable trên một số config).
2. **Exploit chain**:
   - **Bước 1 — MSI Package Crafting**:
     - Tạo file `.msi` với embedded DLL payload + CustomAction type 1 (call DLL function).
     - CustomAction scheduled sau `InstallFinalize` với `Impersonate="no"` (chạy elevated).
     - DLL được nén + mã hóa, giải mã trong `DllMain`.
   - **Bước 2 — MSI Deployment**:
     - `msiexec /i C:\Users\Public\Downloads\update.msi /qn` → install silently.
     - msiexec.exe (signed Microsoft binary) tự động elevate (không UAC prompt nếu policy cho phép MSI install).
   - **Bước 3 — Payload Execution**:
     - CustomAction trigger → DLL load → `DllMain` decrypt shellcode → spawn C2 agent HIGH integrity.
     - Cleanup: `msiexec /x {ProductCode} /qn` → uninstall, xóa artifact.
   - **Bước 4 — Chain sang T1003**:
     - Từ HIGH integrity, thực hiện offline credential dump (SAM + LSA Secrets + Cached Domain).
     - (Xem `T1003_OS_Credential_Dumping.md` Plan 2).
     - HIGH integrity cho phép đọc raw volume (`\\.\C:`) và export registry hives.

### Bypass Methodology
| Layer | How It's Bypassed |
|-------|-------------------|
| **UAC Prompt** | MSI install với `Impersonate="no"` được Windows trust → auto-elevate nếu policy cho phép managed install |
| **`msiexec.exe` Monitoring** | msiexec là LOLBin được dùng rộng rãi; EDR có thể flag `msiexec /i <path> /qn` từ user-writable path → cần obfuscate params |
| **MSI Package Scan** | Payload encrypted + compressed trong MSI; AV scan MSI trước khi execute → nhưng nếu giải mã chậm (time-based), AV có thể bỏ lỡ |
| **`C:\Windows\Installer\` Path** | Path này thường bị exclude khỏi AV scan vì hay có MSI cache → blind spot |
| **CustomAction Detection** | Một số EDR parse MSI CustomAction table → có thể detect nếu action type 1 (DLL call) với path không phải System32 |

### Success Criteria
- [ ] MSI install + CustomAction execute thành công, HIGH integrity
- [ ] C2 agent chạy HIGH, EDR không flag msiexec chain
- [ ] **Chain verification**: HIGH shell → T1003 offline hive dump (SAM+LSA+MSCache) thành công
- [ ] MSI cleanup (uninstall) không để lại artifact
- [ ] Pre-patch Windows 10 21H1 / Server 2019

### Expected EDR Detection Points
- **MSI install from user path** → `msiexec /i C:\Users\Public\...` có thể bị flag. Bypass: copy MSI vào `C:\Windows\Installer\` trước khi install.
- **CustomAction DLL call** → nếu EDR sandbox MSI trước khi execute → có thể detect. Bypass: dùng custom DLL load chain gián tiếp.
- **Network từ post-install process** → nếu C2 agent beacon ngay sau MSI install → timing correlation. Bypass: delay 5-10 phút trước khi beacon.

---

## Inter-Plan Chain Reference

| This Plan | Grants Privilege | Feeds Into | Rationale |
|-----------|-----------------|------------|-----------|
| Plan 1 (CVE-2024-30057) | HIGH Integrity | **T1068 Plan 1** (BYOVD) → SYSTEM → **T1003 Plan 1** (LSASS) | HIGH integrity cần để load kernel driver |
| Plan 2 (CVE-2023-21674) | HIGH Integrity | **T1055.001 Plan 1** (DLL Injection) | HIGH integrity cần để mở handle process HIGH (RuntimeBroker) |
| Plan 3 (CVE-2022-21922) | HIGH Integrity | **T1003 Plan 2** (Offline Hive Dump) | HIGH integrity đủ để đọc raw volume + export registry hives (không cần SYSTEM cho T1003.002/.004/.005) |

---

## Summary: Detection Difficulty Matrix

| Plan | CVE | Year | Stealth | EDR Detection Difficulty | Chain Output |
|------|-----|------|---------|--------------------------|-------------|
| Plan 1 | CVE-2024-30057 | 2024 | ★★★★☆ | **High** | HIGH → T1068 BYOVD → SYSTEM |
| Plan 2 | CVE-2023-21674 | 2023 | ★★★★★ | **Very High** (ALPC ít monitor) | HIGH → T1055.001 DLL Injection |
| Plan 3 | CVE-2022-21922 | 2022 | ★★★☆☆ | **Medium-High** (msiexec detect) | HIGH → T1003 Offline Hive Dump |
