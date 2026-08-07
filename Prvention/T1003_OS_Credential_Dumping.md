# T1003 — OS Credential Dumping: Evaluation Plans

> **MITRE ATT&CK**: OS Credential Dumping — 8 sub-techniques
> **EDR Assumption**: Medium-high maturity. EDR có userland hook, kernel callbacks (ObRegisterCallbacks cho LSASS handle, PsSetCreateProcessNotifyRoutineEx), ETW, AMSI, memory scanning.
> **Design principle**: Mỗi plan nhận privileges được cấp từ T1068 hoặc T1548.002, dựa trên CVE thực tế (2021-2026) có PoC. Plan chain từ PE → Cred Dump.

---

## Evaluation Plan 1: LSASS Memory Dump (T1003.001) — Indirect Syscall + Module Stomping + ETW Patching

### Receives Privileges From
| Source Technique | Privilege | Required For |
|-----------------|-----------|--------------|
| **T1068 Plan 1** (CVE-2024-26234 BYOVD) | SYSTEM | Mở LSASS handle với PROCESS_VM_READ |
| **T1068 Plan 2** (CVE-2023-28252 CLFS) | SYSTEM | Mở LSASS handle |
| **T1548.002** (any UAC bypass) | HIGH Integrity | SeDebugPrivilege enable → mở LSASS handle |

### Chain Map
```
┌──────────────────────────────────────────────────────────────┐
│ INPUT CHAIN (any of these → SYSTEM → LSASS Dump)              │
├──────────────────────────────────────────────────────────────┤
│ [T1068 Plan 1] BYOVD → SYSTEM                                 │
│ [T1068 Plan 2] CLFS Kernel PE → SYSTEM                        │
│   ▼ [NT AUTHORITY\SYSTEM]                                     │
│ [T1003 Plan 1] LSASS Dump ← (YOU ARE HERE)                    │
│   ├─ Enable SeDebugPrivilege                                  │
│   ├─ Indirect syscall NtOpenProcess → LSASS                   │
│   ├─ Module stomping: overwrite legit DLL .text in target     │
│   ├─ Reflective DLL loads C2 agent in staging process         │
│   ├─ Minidump LSASS via NtReadVirtualMemory (syscall)        │
│   └─ Exfil dump via encrypted C2                             │
│   ▼ [NTLM Hashes + Kerberos Keys Extracted]                   │
└──────────────────────────────────────────────────────────────┘
```

### Sub-techniques Leveraged
| ID | Name | Role |
|----|------|------|
| **T1003.001** | LSASS Memory | Primary — dump LSASS process memory |
| **T1106** | Native API | Indirect syscall (không qua ntdll.dll hook) cho toàn bộ operations |
| **T1027.009** | Embedded Payloads | Dump tool mã hóa ChaCha20, chỉ decrypt trong memory |
| **T1620** | Reflective Code Loading | DLL dumper load reflectively trong staging process |
| **T1055.012** | Process Hollowing | Staging process (svchost.exe) bị hollow để tránh anomalous process |
| **T1562.004** | Impair Defenses | ETW provider Microsoft-Windows-Threat-Intelligence bị patch trong target |
| **T1036.005** | Masquerading | Dump file ghi ra `C:\Windows\System32\config\software.log` (giả event log) |

### Test Scenario
1. **Tiền đề**: Attacker có SYSTEM shell (từ T1068 PE chain).
2. **Execution chain**:
   - **Bước 1 — Enable SeDebugPrivilege**:
     - `RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, ...)` → native API, không qua `AdjustTokenPrivileges` Win32.
     - SeDebugPrivilege cho phép mở handle LSASS (protected process light - PPL).
   - **Bước 2 — Create Staging Process (Hollowed)**:
     - `NtCreateUserProcess` tạo `svchost.exe -k LocalService` ở CREATE_SUSPENDED.
     - Module stomping: unmap `svchost.exe` image → allocate memory tại base cũ với PAGE_EXECUTE_READWRITE → write reflective DLL dumper → đổi thành PAGE_EXECUTE_READ.
     - DLL dumper: tự parse PE headers + resolve imports thủ công + call `ReflectiveLoader`.
   - **Bước 3 — ETW Patching**:
     - Trong staging process, patch `EtwEventWrite` → return 0 (STATUS_SUCCESS) không emit event.
     - Patch `ntdll!EtwNotificationRegister` → vô hiệu hóa Threat Intelligence provider.
   - **Bước 4 — Open LSASS Handle (Indirect Syscall)**:
     - `NtOpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, ..., LSASS_PID)` — qua indirect syscall:
       - Lấy syscall number từ clean ntdll.dll trên disk (không qua hooked DLL).
       - Build syscall stub với `syscall` instruction + `ret`.
       - Gọi trực tiếp → bypass toàn bộ userland hook.
   - **Bước 5 — Create LSASS Minidump**:
     - `NtReadVirtualMemory` (indirect syscall) → đọc toàn bộ memory regions của LSASS.
     - Parse process memory: tìm `lsass.exe` loaded modules, heap, stack.
     - Dump `MiniDumpWriteDump` thay thế: custom implementation dùng syscall để tránh hooked API.
     - Output: minidump chứa `lsass.exe` memory → chứa NTLM hashes, Kerberos keys, DPAPI master keys.
   - **Bước 6 — Exfiltration**:
     - Dump file được nén LZNT1 + mã hóa ChaCha20 key = SHA256(machine SID + current time).
     - Viết ra `C:\Windows\System32\config\software.log:lsass` (ADS - Alternate Data Stream).
     - Hoặc exfil trực tiếp qua C2 channel mà không ghi disk.

3. **Cleanup**:
   - VirtualFree staging memory trong svchost.exe
   - Close LSASS handle
   - Re-enable ETW (nếu cần)
   - Xóa ADS hoặc dump file khỏi disk

### Bypass Methodology
| Layer | How It's Bypassed |
|-------|-------------------|
| **ntdll.dll Userland Hook** | Indirect syscall: syscall stub build từ clean ntdll.dll trên disk, syscall number + stub không qua hooked functions |
| **ObRegisterCallbacks (LSASS Handle)** | Kernel callback `ObPreOperationCallback` → EDR thấy `NtOpenProcess` với target = LSASS. **Đây là điểm yếu nhất.** Bypass: dùng handle từ process khác đã có sẵn (vd: taskmgr.exe nếu debug mode) hoặc kernel driver để mở handle |
| **ETW Threat Intelligence** | Patch `EtwEventWrite` → ETW provider không emit events cho LSASS access, memory read |
| **Process Hollowing Detection** | Module stomping giữ memory region với type `Image` → EDR scan memory thấy Image type → có thể bỏ qua |
| **AMSI** | Không dùng PowerShell/.NET → AMSI không scan native C reflective DLL |
| **Dump File Signature** | Không có file header signature "PSS" (minidump) → custom dump format; output encrypted + ADS → tránh file scan |
| **LSASS Protection (PPL)** | SeDebugPrivilege enabled + indirect syscall bypass; nếu LSASS chạy với PPL → cần thêm kernel driver (T1068 BYOVD driver hoặc dùng CVE-2024-26234) |

### Success Criteria
- [ ] LSASS handle mở thành công (không bị ObRegisterCallbacks block)
- [ ] LSASS memory dump hoàn tất: NTLM hashes + Kerberos keys extracted
- [ ] EDR không detect: (a) indirect syscall LSASS access, (b) ETW patching, (c) staging process hollowing, (d) ADS dump output
- [ ] **Chain verification**: SYSTEM (từ T1068) → LSASS dump → credentials validated (có thể dùng để auth)
- [ ] Payload hoạt động trên Windows 10 22H2, Windows 11 23H2, Windows Server 2022

### Expected EDR Detection Points
- **`ObRegisterCallbacks` — LSASS handle open** → **Đây là defense quan trọng nhất.** Hầu hết EDR hiện đại đăng ký pre-callback cho `PsProcessType` → filter target = LSASS PID → block non-allowlisted processes. Nếu EDR có callback này → **detect cao.** Bypass yêu cầu: (a) process nằm trong allowlist (spoof process name/PEB), (b) dùng kernel driver để mở handle trực tiếp, hoặc (c) dùng process đã có handle LSASS (handle duplication từ legitimate process).
- **`MiniDumpWriteDump` hook** → EDR hook API này → nhưng custom implementation không gọi API này.
- **Memory dump pattern** → Nếu EDR scan memory region cho minidump signature → custom dump format bypass.
- **ETW provider disable** → EDR có thể detect nếu monitor ETW provider state → nếu thấy Threat Intelligence provider bị disabled → alert.

---

## Evaluation Plan 2: SAM + LSA Secrets + Cached Credentials via Direct Volume Access (T1003.002/.004/.005)

### Receives Privileges From
| Source Technique | Privilege | Required For |
|-----------------|-----------|--------------|
| **T1548.002 Plan 3** (CVE-2022-21922 MSI UAC) | HIGH Integrity | Đọc raw volume `\\.\C:` |
| **T1068 any plan** | SYSTEM | Đọc raw volume + registry export |

### Chain Map
```
┌──────────────────────────────────────────────────────────────┐
│ INPUT CHAIN (HIGH or SYSTEM → Offline Hive Dump)              │
├──────────────────────────────────────────────────────────────┤
│ [T1548.002 Plan 3] MSI UAC → HIGH                             │
│ [T1068 Plan 2] CLFS PE → SYSTEM                               │
│   ▼ [HIGH Integrity or SYSTEM]                                │
│ [T1003 Plan 2] SAM + LSA Secrets ← (YOU ARE HERE)             │
│   ├─ Create Volume Shadow Copy (WMI COM, not vssadmin)       │
│   ├─ Raw NTFS read to locate shadow hive files               │
│   ├─ Parse SAM/SECURITY/SYSTEM offline (custom parser)       │
│   ├─ Extract NTLM + LSA Secrets + MSCache v2                 │
│   └─ Output via ADS, encrypted                                │
│   ▼ [Local Credentials Extracted]                             │
└──────────────────────────────────────────────────────────────┘
```

### Sub-techniques Leveraged
| ID | Name | Role |
|----|------|------|
| **T1003.002** | Security Account Manager (SAM) | Target — đọc hive SAM |
| **T1003.004** | LSA Secrets | Target — đọc hive SECURITY\Policy\Secrets |
| **T1003.005** | Cached Domain Credentials | Target — đọc SECURITY\Cache (MSCache v2) |
| **T1006** | Direct Volume Access | Đọc raw NTFS volume để extract files từ shadow copy |
| **T1112** | Modify Registry | (Optional) `reg save HKLM\SAM` nếu có SYSTEM |
| **T1036.005** | Masquerading | Output file giả dạng Windows event log trong `C:\Windows\System32\winevt\Logs\` |
| **T1562.004** | Impair Defenses | (Pre-dump) Add exclusion path cho output directory |

### Test Scenario — CVE-2021-36934 Inspired (HiveNightmare / SeriousSAM) + Direct Volume Access
1. **Tiền đề**: Attacker có HIGH integrity (từ T1548.002) hoặc SYSTEM (từ T1068).
2. **Execution chain**:
   - **Bước 1 — Volume Shadow Copy Creation**:
     - **Không dùng** `vssadmin.exe` (bị monitor heavily).
     - Dùng COM interface `IWbemServices` qua WMI: `Win32_ShadowCopy.Create(Volume='C:\')`.
     - HOẶC: dùng raw NTFS read để access file trực tiếp (không cần shadow copy nếu file không bị lock).
   - **Bước 2 — Raw Volume Read (CVE-2021-36934 pattern)**:
     - Mở handle `\\.\C:` với `GENERIC_READ` (yêu cầu HIGH hoặc SYSTEM).
     - Parse NTFS MFT (Master File Table) để tìm vị trí vật lý của:
       - `C:\Windows\System32\config\SAM`
       - `C:\Windows\System32\config\SECURITY`
       - `C:\Windows\System32\config\SYSTEM`
     - Đọc trực tiếp cluster từ volume (bypass file system ACLs, bypass file lock).
   - **Bước 3 — Alternative: reg save (nếu SYSTEM)**:
     - Nếu có SYSTEM: `reg save HKLM\SAM C:\Windows\winevt\Logs\SAM.evtx` (giả event log).
     - `reg save HKLM\SECURITY C:\Windows\winevt\Logs\SECURITY.evtx`
     - `reg save HKLM\SYSTEM C:\Windows\winevt\Logs\SYSTEM.evtx`
     - Dùng `NtSaveKey` native API thay vì `RegSaveKeyExW` (Win32 hook).
   - **Bước 4 — Offline Parsing**:
     - Custom parser (không phải mimikatz, không phải secretsdump):
       - SAM parser: extract NTLM hash từ `SAM\Domains\Account\Users\{RID}\V`
       - SECURITY parser: extract LSA secrets (`NL$KM`, `DPAPI_SYSTEM`, auto-logon passwords)
       - Cache parser: extract MSCache v2 entries từ `SECURITY\Cache\{username}`
     - Parser là DLL reflective-loaded trong memory của staging process (không chạy Python/công cụ external).
   - **Bước 5 — Output**:
     - Credentials được mã hóa AES-256-GCM, key = hash(machine SID).
     - Output ghi vào ADS: `C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx:cred` (không tạo file mới).
     - Exfil qua C2 channel.

### Bypass Methodology
| Layer | How It's Bypassed |
|-------|-------------------|
| **vssadmin.exe Monitoring** | Không dùng vssadmin → dùng WMI COM interface (ít EDR monitor WMI ShadowCopy class) hoặc raw NTFS |
| **reg.exe Monitoring** | Dùng `NtSaveKey` native API (bypass `RegSaveKeyExW` hook); file path `C:\Windows\winevt\Logs\` trông legitimate |
| **File Creation Scan** | Output qua ADS → không tạo file mới trên disk; ADS không bị scan bởi hầu hết AV |
| **Raw Volume Access** | `\\.\C:` open có thể bị flag → nhưng backup software cũng dùng → phụ thuộc vào EDR heuristic |
| **Offline Parser Signature** | Custom parser → không có signature của mimikatz/secretsdump; string encrypted; reflective-loaded |
| **Event 4656 (File Access)** | Windows audit có thể ghi `4656 - A handle to an object was requested` cho SAM/SECURITY → nếu audit policy bật. Nhưng attacker có SYSTEM → có thể xóa event log |

### Success Criteria
- [ ] SAM, SECURITY, SYSTEM hives extracted (raw volume hoặc registry save)
- [ ] NTLM hashes, LSA secrets, MSCache v2 parsed thành công
- [ ] EDR không detect: (a) volume shadow copy creation, (b) raw volume access, (c) registry hive save, (d) ADS write
- [ ] **Chain verification**: HIGH/SYSTEM (từ T1548.002/T1068) → credentials validated
- [ ] Hoạt động trên Windows 10 22H2, Windows 11 23H2, Windows Server 2022

### Expected EDR Detection Points
- **Raw volume access** → `\\.\C:` handle open có thể bị detect. Một số EDR hook `NtCreateFile` với `\\.\C:` path → **có thể detect.** Bypass: dùng process trong allowlist (backup software) hoặc kernel driver.
- **Hive file access** → Nếu EDR monitor `NtOpenFile` cho `\Windows\System32\config\SAM` → **detect.** Nhưng raw volume read bypass file-level monitoring.
- **ADS write** → ít EDR monitor ADS. **Blind spot phổ biến.**
- **Event 4656** → Nếu SIEM/Sysmon có rule cho SAM/SECURITY handle access → **detect cao.** Nhưng cần audit policy bật.

---

## Evaluation Plan 3: DCSync via DRSUAPI + CVE-2022-26923 (AD CS Abuse) — T1003.006 + Full Domain Credential Theft

### Receives Privileges From
| Source Technique | Privilege | Required For |
|-----------------|-----------|--------------|
| **T1068 Plan 3** (sAMAccountName Spoof → DA) | Domain Admin equivalent | Quyền Replicate Directory Changes |
| **T1068 Plan 2** (CLFS PE) | SYSTEM on DC | Thực thi DCSync trực tiếp trên DC |

### Chain Map
```
┌──────────────────────────────────────────────────────────────────┐
│ INPUT CHAIN: DA equivalent → DCSync OR AD CS → Credential Theft   │
├──────────────────────────────────────────────────────────────────┤
│ [T1068 Plan 3] sAMAccountName → DA equivalent                      │
│   HOẶC                                                           │
│ [CVE-2022-26923] AD CS ESC1 → Certificate → DA (see below)        │
│   ▼ [Domain Admin / Replicate Directory Changes]                   │
│ [T1003 Plan 3] DCSync ← (YOU ARE HERE)                            │
│   ├─ DRSUAPI DsGetNCChanges with replication flags                │
│   ├─ Extract ALL domain credentials (NTLM + AES + history)        │
│   ├─ C2: chunked HTTPS POST, mimic Office telemetry               │
│   └─ Full domain compromise                                       │
│   ▼ [ALL Domain Credentials Extracted]                             │
└──────────────────────────────────────────────────────────────────┘
```

### CVE Reference
| Field | Detail |
|-------|--------|
| **CVE** | CVE-2022-26923 (Active Directory Certificate Services — ESC1 privilege escalation) |
| **Published** | May 2022 |
| **PoC** | Public (Certipy, Certify) |
| **Impact** | Domain User → enroll certificate with SAN → UPN of Domain Admin → DA |
| **Patch** | KB5014754 (May 2022), AD CS configuration hardening |

### Sub-techniques Leveraged
| ID | Name | Role |
|----|------|------|
| **T1003.006** | DCSync | Primary — DRSUAPI replication để lấy credentials |
| **T1649** | Steal or Forge Authentication Certificates | AD CS ESC1: enroll certificate as DA |
| **T1573.002** | Encrypted Channel: Asymmetric Cryptography | C2 traffic mã hóa RSA-4096 + AES-256-GCM |
| **T1071.001** | Web Protocols | C2 qua HTTPS port 443, mimic Microsoft 365 telemetry |
| **T1078.002** | Valid Accounts: Domain Accounts | Domain user → certificate → DA |
| **T1027** | Obfuscated Files or Information | DCSync output phân mảnh, mã hóa, gửi chunked |

### Test Scenario — Phase 1: AD CS ESC1 (if DA not yet achieved)
1. **Tiền đề bổ sung**: Nếu attacker chưa có DA, có thể dùng **CVE-2022-26923 (AD CS ESC1)**:
   - Domain user → request certificate template có `ENROLLEE_SUPPLIES_SUBJECT` flag.
   - Craft CSR với `subjectAltName` = `Administrator@domain.local` (UPN của DA).
   - AD CS cấp certificate với UPN = DA → certificate có thể dùng để xác thực Kerberos PKINIT → lấy TGT của DA.
   - TGT DA → DCSync.

2. **Phase 2 — DCSync Execution** (từ DA hoặc SYSTEM trên DC):
   - **Bước 1**: Dùng `LsarOpenPolicy` hoặc `SamrConnect` để kết nối đến DC.
   - **Bước 2**: Gọi `DsGetNCChanges(NULL, ..., DRS_GET_ANC | DRS_GET_OBJECT_SECURITY | DRS_GET_NC_SIZE)`.
   - **Bước 3**: DRSUAPI replication trả về toàn bộ Active Directory objects bao gồm:
     - `unicodePwd` → NTLM hash
     - `supplementalCredentials` → Kerberos AES keys + WDigest
     - `pwdHistory` → password history (có thể crack)
   - **Bước 4**: Parse response + extract credentials.

3. **Phase 3 — Exfiltration (Encrypted C2)**:
   - Credentials chunked thành < 4KB mỗi chunk.
   - Mã hóa: RSA public key của C2 server → AES-256-GCM session key.
   - Gửi qua HTTPS POST: User-Agent = `Microsoft Office/16.0 (Windows NT 10.0; MSA 16.0.xxxxx)`.
   - Jitter delay: 500ms-3s random giữa các chunk.
   - C2 domain: `telemetry-events.office-{RAND}.com` hoặc domain fronting qua Azure CDN.

### Bypass Methodology
| Layer | How It's Bypassed |
|-------|-------------------|
| **Network IDS/IPS** | HTTPS + double encryption (RSA + AES); certificate pinning ngăn SSL inspection; traffic trông như Office telemetry |
| **SIEM Event 4662** | Event `Directory Service Access` chỉ ghi nếu audit policy bật. Nếu attacker có SYSTEM trên DC → có thể auditpol.exe /disable. Nếu không: Event 4662 với GUID `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` có thể được ghi → SIEM correlation → **detect** |
| **AD CS Certificate Request** | Event 4886/4887 (Certificate Services) ghi certificate request. Nhưng volume cao trong enterprise CA → khó phân biệt |
| **Process trên DC** | Nếu attacker dùng GPO-deployed service (như T1003 Plan 3 cũ) → service creation event có thể flag. Bypass: dùng Cobalt Strike `execute-assembly` trong memory, không tạo process mới |
| **Kerberos TGT Request (PKINIT)** | Nếu dùng CVE-2022-26923 certificate → PKINIT request trông bình thường; nhưng TGT cho DA lần đầu từ user bình thường → anomaly |

### Success Criteria
- [ ] **Phase 1 (optional)**: AD CS ESC1 thành công → certificate DA
- [ ] **Phase 2**: DCSync hoàn tất → toàn bộ domain NTLM hashes + Kerberos keys extracted
- [ ] **Phase 3**: Exfil không bị detect bởi network sensor
- [ ] EDR không: (a) detect DCSync behavior, (b) detect C2 traffic pattern, (c) detect certificate abuse
- [ ] **Chain verification**: DA (từ T1068 Plan 3) → DCSync → credentials validated
- [ ] Event ID 4662 **không** trigger SIEM rule (nếu audit policy bật và EDR/SIEM có rule)

### Expected EDR Detection Points
- **Event 4662 (DCSync)** → **Detection quan trọng nhất.** Nếu audit policy `Directory Service Access` bật và EDR/SIEM có correlation rule → **detect cao.** Bypass: disable audit policy trước khi DCSync (cần SYSTEM).
- **AD CS ESC1** → Microsoft Defender for Identity (MDI) có alert cho certificate template abuse → **detect cao** nếu MDI deployed. Bypass: chọn template ít suspicious, request trong giờ hành chính.
- **Network traffic từ DC** → DC thường không gửi traffic đến unknown domains → nếu C2 domain mới registered, low reputation → **có thể detect.** Bypass: dùng domain fronting qua Azure CDN / Cloudflare Workers.
- **Volume-based anomaly** → DCSync replication data có thể vài MB với domain lớn → chunking nhỏ tránh volume detection.

---

## Inter-Plan Chain Reference

| This Plan | Targets | Receives From | Prerequisites | Output |
|-----------|---------|---------------|---------------|--------|
| Plan 1 | T1003.001 (LSASS) | **T1068 Plan 1** (BYOVD → SYSTEM) hoặc **T1068 Plan 2** (CLFS → SYSTEM) | SYSTEM, SeDebugPrivilege | NTLM hashes + Kerberos keys (local machine) |
| Plan 2 | T1003.002/.004/.005 | **T1548.002 Plan 3** (UAC → HIGH) hoặc **T1068** (→ SYSTEM) | HIGH or SYSTEM | NTLM + LSA Secrets + MSCache v2 (local) |
| Plan 3 | T1003.006 (DCSync) | **T1068 Plan 3** (→ DA) hoặc **CVE-2022-26923** (AD CS → DA) | Domain Admin quyền | ALL domain credentials |

---

## Summary: Detection Difficulty Matrix

| Plan | Target Sub-technique | Requires | Attack Complexity | EDR Detection Difficulty | Key Blind Spot |
|------|---------------------|----------|-------------------|--------------------------|----------------|
| Plan 1 | T1003.001 (LSASS) | SYSTEM | **High** (syscall + reflective + ETW) | **High** | ObRegisterCallbacks là chốt chặn cuối; nếu vượt được → dump tự do |
| Plan 2 | T1003.002/.004/.005 | HIGH or SYSTEM | **Medium** | **Medium-High** | Raw volume access + ADS output là blind spot phổ biến |
| Plan 3 | T1003.006 (DCSync) | Domain Admin | **Low-Medium** (DA đã có) | **Medium** | Event 4662 + SIEM là chốt chặn; nếu audit disabled → mù |
