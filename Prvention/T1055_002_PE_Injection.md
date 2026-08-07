# T1055.002 — Process Injection: Portable Executable Injection — Evaluation Plans

> **MITRE ATT&CK**: T1055.002 — PE Injection (Sub-technique of T1055: Process Injection)
> **EDR Assumption**: Medium-high maturity. EDR có kernel callbacks (PsSetCreateProcessNotifyRoutineEx, PsSetLoadImageNotifyRoutine, ObRegisterCallbacks), userland hook, ETW TI, memory scanning.
> **Design principle**: PE injection để đạt execution trong process elevated hoặc SYSTEM. Chain từ PE injection → SYSTEM context → credential dump (T1003). Dựa trên CVE thực tế + technique đã thấy in-the-wild (2021-2026).

---

## Evaluation Plan 1: Process Hollowing via CVE-2024-21338 — Windows Kernel PE + PE Injection Chain → LSASS Dump

### CVE Reference
| Field | Detail |
|-------|--------|
| **CVE** | CVE-2024-21338 (Windows Kernel Elevation of Privilege — appid.sys IOCTL) |
| **Published** | February 2024 |
| **PoC** | Public (GitHub: kernel arbitrary read/write via appid.sys) |
| **Impact** | Standard User → SYSTEM through kernel exploit |
| **Patch** | KB5034765 (Feb 2024 Patch Tuesday) |
| **In-the-wild** | Lazarus Group (Operation AppleJeus) — CVE-2024-21338 + CVE-2024-21437 chain |

### Chain Map
```
┌──────────────────────────────────────────────────────────────────────┐
│ CHAIN: Kernel PE → SYSTEM → Process Hollowing (masquerade) → T1003    │
├──────────────────────────────────────────────────────────────────────┤
│ [Standard User - NO admin required]                                   │
│ [CVE-2024-21338] appid.sys kernel arbitrary read/write               │
│   ├─ NtQuerySystemInformation → leak kernel addresses                │
│   ├─ DeviceIoControl(\\\\.\appid) → arbitrary kernel read            │
│   ├─ Find SYSTEM EPROCESS → copy token                               │
│   └─ SYSTEM token on attacker process                                │
│   ▼ [NT AUTHORITY\SYSTEM]                                             │
│ [T1055.002 Plan 1] Process Hollowing (Masqueraded PE Injection)       │
│   ├─ Create suspended svchost.exe                                     │
│   ├─ NtUnmapViewOfSection → remove legitimate image                  │
│   ├─ Allocate + write PE payload (C2 agent)                          │
│   ├─ Fix PEB.ImageBaseAddress + rebuild Ldr list                     │
│   └─ Resume thread → C2 runs as "svchost.exe"                        │
│   ▼ [C2 agent masquerading as svchost.exe (SYSTEM)]                   │
│ [T1003 Plan 1] LSASS Dump → Domain Credentials                        │
└──────────────────────────────────────────────────────────────────────┘
```

### Sub-techniques Leveraged
| ID | Name | Role |
|----|------|------|
| **T1055.002** | PE Injection | Primary |
| **T1055.012** | Process Hollowing | Hollow `svchost.exe` + replace với PE payload |
| **T1106** | Native API | `NtCreateProcessEx`, `NtUnmapViewOfSection`, `NtAllocateVirtualMemory`, `NtWriteVirtualMemory` |
| **T1036.005** | Masquerading: Match Legitimate Resource Name or Location | Process vẫn hiển thị path `C:\Windows\System32\svchost.exe` |
| **T1027.009** | Embedded Payloads | PE payload (C2 agent) nén + mã hóa trong attacker process |
| **T1134.004** | Parent PID Spoofing | PPID = services.exe |
| **T1620** | Reflective Code Loading | (Fallback nếu hollowing bị detect) |

### Test Scenario
1. **Tiền đề**: Standard User (NO admin). Sử dụng CVE-2024-21338 để lên SYSTEM trước khi hollowing.
2. **Exploit chain — Phase 1: Kernel PE (CVE-2024-21338)**:
   - **Bước 1**: Leak `ntoskrnl.exe` base + kernel pool address qua `NtQuerySystemInformation(SystemModuleInformation)`.
   - **Bước 2**: Mở handle `\\.\appid` → `DeviceIoControl` với IOCTL code craft để trigger arbitrary kernel memory read.
   - **Bước 3**: Walk `PsActiveProcessHead` linked list → tìm `System` process (PID 4) → copy `_EPROCESS.Token` address.
   - **Bước 4**: `DeviceIoControl` với IOCTL arbitrary write → overwrite attacker EPROCESS token với SYSTEM token.
   - **Bước 5**: Attacker process có SYSTEM token → `CreateProcessWithTokenW` spawn SYSTEM shell.
3. **Phase 2 — Process Hollowing (PE Injection)**:
   - **Bước 1 — Create Host Process**:
     - `NtCreateUserProcess` tạo `svchost.exe -k LocalServiceNetworkRestricted` ở `CREATE_SUSPENDED`.
     - PPID = `services.exe` (legitimate).
   - **Bước 2 — Hollow the Process**:
     - `NtQueryInformationProcess(ProcessBasicInformation)` → tìm PEB + ImageBaseAddress.
     - `NtUnmapViewOfSection(hProcess, ImageBaseAddress)` → xóa legitimate `svchost.exe` image khỏi process memory.
     - Sau unmap: process memory trống, không có executable code.
   - **Bước 3 — Inject PE Payload**:
     - `NtAllocateVirtualMemory(hProcess, &newImageBase, ..., MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)`.
       - Allocation tại **preferred base address** của PE payload (để tránh relocation phức tạp).
       - Nếu preferred base conflict với allocation khác → chọn địa chỉ khác + apply relocations.
     - Write PE headers + sections (`.text`, `.rdata`, `.data`, `.reloc`):
       - `NtWriteVirtualMemory` → copy từng section đúng RVA.
     - Fix import table: walk Ldr list của process gốc → resolve function addresses → ghi vào IAT.
     - Fix relocations nếu base khác preferred.
   - **Bước 4 — Fix PEB**:
     - `NtWriteVirtualMemory(..., &peb->ImageBaseAddress, newImageBase, ...)` → PEB trỏ đến payload.
     - **Giữ nguyên** `PEB->ProcessParameters.ImagePathName` → vẫn hiển thị `svchost.exe` path.
     - **Giữ nguyên** `PEB->ProcessParameters.CommandLine` → vẫn hiển thị command line gốc.
     - **Ldr list**: `PEB_LDR_DATA` vẫn giữ lại entries từ svchost.exe cũ → `EnumProcessModules` vẫn trả về list cũ.
   - **Bước 5 — Change Protection + Execute**:
     - `NtProtectVirtualMemory` → đổi `.text` từ RWX → RX, `.rdata` → R, `.data` → RW.
     - Set thread context: `RIP` → entry point của PE payload (`AddressOfEntryPoint + newImageBase`).
     - `NtResumeThread` → process bắt đầu chạy với PE payload (C2 agent).
   - **Bước 6 — C2 & Chain to T1003**:
     - C2 agent trong hollowed `svchost.exe` chạy SYSTEM.
     - Process trong Task Manager: `svchost.exe` (tên, PID, path, command line trông legitimate).
     - **Chain**: Từ SYSTEM context → thực hiện LSASS dump (T1003 Plan 1).

### Bypass Methodology
| Layer | How It's Bypassed |
|-------|-------------------|
| **Process Creation Detection** | Process được tạo từ file `svchost.exe` trên disk → image path trong kernel callback hợp lệ |
| **Image Unload Detection** | `NtUnmapViewOfSection` → EDR có thể detect nếu đăng ký image unload callback. **Đây là điểm yếu.** Bypass: dùng technique khác (transacted hollowing, section replacement) |
| **PEB ImageBaseAddress Mismatch** | EDR kiểm tra PEB ImageBaseAddress vs actual mapped image → có thể detect. Bypass: map payload tại **đúng** base address của svchost.exe (cần layout PE để phù hợp) |
| **Memory Protection Scan** | Sau khi write xong, đổi RWX → RX → không có RWX khi process chạy. EDR memory scan thấy RX tại `ImageBaseAddress` → trông như legitimate |
| **Module List** | `EnumProcessModules` query PEB Ldr → list modules cũ của svchost.exe. Nếu EDR force reload module list (query kernel PsLoadedModuleList) → mismatch với PEB |
| **Process Signature Verification** | Nếu EDR verify process image hash (compare memory content với file trên disk) → hash không match → **detect.** Hầu hết EDR không làm runtime hash verify vì performance |

### Success Criteria
- [ ] **Phase 1**: CVE-2024-21338 thành công → SYSTEM shell
- [ ] **Phase 2**: Process hollowing: `svchost.exe` chạy với PE payload
- [ ] C2 agent hoạt động, process hiển thị `svchost.exe` trong Task Manager
- [ ] EDR không detect: (a) image unmap, (b) PE payload injection, (c) PEB manipulation
- [ ] **Chain verification**: SYSTEM → hollowed svchost.exe → T1003 LSASS dump → credentials
- [ ] `EnumProcessModules` trả về module list cũ (hoặc rỗng, không có payload module)
- [ ] Windows 10 22H2 / Windows 11 23H2 pre-Feb-2024 patch

### Expected EDR Detection Points
- **Image unload → reload cycle** → Nếu EDR có `PsSetLoadImageNotifyRoutine` + track image unload → thấy svchost.exe image unmap + memory allocate tại base cũ → **detect cao.** Đây là cách hầu hết EDR bắt process hollowing.
- **PEB module list inconsistency** → Nếu EDR cross-check module list từ PEB vs kernel PsLoadedModuleList → thấy mismatch → **detect.**
- **`NtUnmapViewOfSection`** → API này ít được dùng bởi legitimate software → có thể bị flag. Bypass: dùng `NtFreeVirtualMemory` thay vì unmap.
- **Image hash verification** → Một số EDR tiên tiến verify hash của `.text` section với file trên disk → **detect nếu EDR làm.** Nhưng performance cost cao.

---

## Evaluation Plan 2: Process Doppelgänging + CVE-2021-42278 Fallback — PE Injection via NTFS Transaction

### CVE Reference
| Field | Detail |
|-------|--------|
| **Technique** | Process Doppelgänging (NTFS Transaction abuse) |
| **First Documented** | BlackHat 2017 (Tal Liberman); still effective on Win10 22H2 / Win11 23H2 |
| **PoC** | Public (GitHub: multiple implementations, ProcessDoppelganging, Carbonate) |
| **Impact** | Disk-less PE injection → PE payload never written to disk |
| **Pre-req** | HIGH integrity (từ T1548.002) hoặc SYSTEM |
| **Note** | NOT patched — TxF deprecated nhưng vẫn hoạt động; technique-based, not CVE-based |

### Chain Map
```
┌──────────────────────────────────────────────────────────────┐
│ CHAIN: UAC Bypass → HIGH → Doppelgänging → SYSTEM → T1003     │
├──────────────────────────────────────────────────────────────┤
│ [T1548.002 Plan 3] CVE-2022-21922 MSI UAC → HIGH             │
│   ▼ [HIGH Integrity]                                          │
│ [T1055.002 Plan 2] Process Doppelgänging                       │
│   ├─ NtCreateTransaction → NTFS transaction                  │
│   ├─ NtCreateFile (transacted) → create "ghost file"         │
│   ├─ NtCreateSection (SEC_IMAGE) → section from ghost file   │
│   ├─ NtCreateProcessEx → process with ghost image            │
│   ├─ NtRollbackTransaction → file never existed on disk      │
│   └─ ResumeThread → PE payload execute                       │
│   ▼ [C2 agent in process with no disk file]                   │
│ [T1068 Plan 3] sAMAccountName Spoof → DA → T1003 Plan 3 DCSync│
└──────────────────────────────────────────────────────────────┘
```

### Sub-techniques Leveraged
| ID | Name | Role |
|----|------|------|
| **T1055.002** | PE Injection | Primary |
| **T1055.013** | Process Doppelgänging | NTFS transaction để tạo process với ghost image |
| **T1106** | Native API | `NtCreateTransaction`, `NtCreateFile`, `NtCreateSection`, `NtCreateProcessEx` |
| **T1027.009** | Embedded Payloads | PE payload encrypted ChaCha20, decrypt trong memory trước khi write vào transaction |
| **T1036.005** | Masquerading | Ghost file path = `C:\Windows\System32\taskhostw.dll` (legitimate name) |
| **T1562.004** | Impair Defenses | Vô hiệu hóa ETW cho Process Creation + Image Load events trong transaction scope |

### Test Scenario
1. **Tiền đề**: HIGH integrity (từ T1548.002 Plan 3: CVE-2022-21922 MSI UAC bypass).
2. **Execution chain**:
   - **Bước 1 — Create NTFS Transaction**:
     - `NtCreateTransaction(&hTransaction, TRANSACTION_ALL_ACCESS, ..., TRANSACTION_DO_NOT_PROMOTE, ...)`.
     - Transaction tạo trong userland → kernel TxF manager xử lý.
   - **Bước 2 — Create Ghost File**:
     - `NtCreateFile(hTransaction, L"C:\\Windows\\System32\\taskhostw.dll", ..., FILE_OVERWRITE_IF, ...)` → tạo file trong transaction.
     - `NtWriteFile` → write PE payload (C2 agent) vào transacted file.
     - File **chỉ tồn tại trong transaction** — không visible trên disk, không scan bởi AV (AV không thấy vì file không có directory entry thực sự).
   - **Bước 3 — Create SEC_IMAGE Section**:
     - `NtCreateSection(&hSection, SECTION_ALL_ACCESS, ..., SEC_IMAGE, hTransactedFile)`.
     - Section attribute `SEC_IMAGE` → kernel xử lý file như executable image:
       - Kernel PE parser: validate PE headers, parse sections.
       - Nếu PE hợp lệ → kernel chuẩn bị image section (relocations, imports sẽ được kernel xử lý khi tạo process).
   - **Bước 4 — Create Process from Ghost Image**:
     - `NtCreateProcessEx(&hProcess, PROCESS_ALL_ACCESS, ..., hSection, ..., PS_CREATE_FLAGS_CREATE_SUSPENDED)`.
     - Process được tạo với image từ transacted file → PEB `ImagePathName` = `C:\Windows\System32\taskhostw.dll`.
     - Không cần write memory thủ công — kernel xử lý PE mapping.
   - **Bước 5 — Rollback Transaction**:
     - `NtRollbackTransaction(hTransaction)` → transacted file biến mất hoàn toàn.
     - Lúc này: process đang chạy với image từ file đã "never existed".
     - Không có artifact trên disk.
   - **Bước 6 — Create Thread + Execute**:
     - `NtCreateThreadEx(hProcess, entry_point, ...)` → tạo thread để chạy.
     - `NtResumeThread` → process chạy với PE payload.
   - **Bước 7 — Chain to Lateral Movement / Credential Dump**:
     - C2 agent trong hollowed process → có thể thực hiện AD operations.
     - **Chain**: Dùng CVE-2021-42278 (sAMAccountName spoof) → DA → DCSync (T1003 Plan 3).

### Bypass Methodology
| Layer | How It's Bypassed |
|-------|-------------------|
| **File-based AV Scan** | PE payload KHÔNG BAO GIỜ tồn tại trên disk → không scan được |
| **Process Creation Monitoring** | `PsSetCreateProcessNotifyRoutineEx` fire với `ImageFileName` = `taskhostw.dll` path → EDR thấy path legitimate, không suspicious |
| **Image File Check** | Nếu EDR kiểm tra file `C:\Windows\System32\taskhostw.dll` → **file không tồn tại** (đã bị rollback). EDR có thể flag: "process from non-existent file" → **đây là điểm yếu** |
| **NTFS Transaction Monitoring** | TxF là deprecated nhưng vẫn functional; ít EDR monitor `NtCreateTransaction` → blind spot |
| **SEC_IMAGE Section** | Section tạo từ transacted file — kernel image load callback `PsSetLoadImageNotifyRoutine` fire với transacted file path → EDR thấy image load từ path hợp lệ |
| **Memory Scan** | Process memory có type `Image` cho payload → EDR thường skip Image regions khi scan |
| **ETW Process Creation** | Event Microsoft-Windows-Kernel-Process ghi process creation với ImagePath → path hợp lệ |

### Success Criteria
- [ ] NTFS transaction tạo thành công
- [ ] Ghost file + SEC_IMAGE section → process created với image từ transaction
- [ ] Transaction rollback → không artifact trên disk
- [ ] C2 agent chạy trong process không có disk file
- [ ] EDR không detect: (a) NTFS transaction abuse, (b) process from non-existent file, (c) ghost image
- [ ] **Chain verification**: C2 → AD operations → CVE-2021-42278 → DA → T1003 DCSync
- [ ] Windows 10 22H2 / Windows 11 23H2 (NTFS volume, TxF enabled)

### Expected EDR Detection Points
- **Process from non-existent file** → Nếu EDR check file existence khi `PsSetCreateProcessNotifyRoutineEx` fire → thấy file không tồn tại → **detect cao.** Đây là primary detection cho Doppelgänging.
- **NTFS transaction** → Một số EDR có minifilter driver đăng ký `IRP_MJ_CREATE` + transaction notifications → có thể detect transacted file operations. Nhưng ít phổ biến.
- **`NtCreateTransaction`** → Có thể hook; nhưng application compatibility software (MSI, COM+) cũng dùng TxF → false positive risk.
- **Section from non-disk file** → Nếu EDR query section backing file → thấy file không có directory entry → flag. **Detection vector thứ hai.**

---

## Evaluation Plan 3: PE Injection via CVE-2024-21437 — Windows Graphics Component + Chain to T1003 via Token Theft

### CVE Reference
| Field | Detail |
|-------|--------|
| **CVE** | CVE-2024-21437 (Windows Graphics Component Elevation of Privilege — DirectComposition) |
| **Published** | March 2024 |
| **PoC** | Public (GitHub: GDI kernel pool overflow via DirectComposition object) |
| **Impact** | Standard User → SYSTEM, chain với PE injection |
| **Patch** | KB5035853 (March 2024 Patch Tuesday) |
| **In-the-wild** | Lazarus Group AppleJeus campaign (chain w/ CVE-2024-21338) |

### Chain Map
```
┌──────────────────────────────────────────────────────────────────┐
│ CHAIN: Kernel GDI PE → SYSTEM → PE Injection → T1003              │
├──────────────────────────────────────────────────────────────────┤
│ [Standard User - NO admin]                                        │
│ [CVE-2024-21437] DirectComposition GDI kernel pool overflow      │
│   ├─ Create DirectComposition device                             │
│   ├─ Spray kernel pool with bitmap objects                       │
│   ├─ Trigger pool overflow → corrupt adjacent object             │
│   ├─ Read/write primitive → overwrite token privileges           │
│   └─ SYSTEM shell                                                │
│   ▼ [NT AUTHORITY\SYSTEM]                                         │
│ [T1055.002 Plan 3] PE Injection via syscall-based remapping       │
│   ├─ Allocate memory in target process (session isolation)       │
│   ├─ Map PE payload as SEC_IMAGE section                         │
│   ├─ Hijack thread via SetThreadContext                          │
│   └─ C2 agent in legitimate process                              │
│   ▼ [C2 in existing SYSTEM process]                               │
│ [T1003 Plan 1] LSASS Dump                                        │
└──────────────────────────────────────────────────────────────────┘
```

### Sub-techniques Leveraged
| ID | Name | Role |
|----|------|------|
| **T1055.002** | PE Injection | Primary |
| **T1055.003** | Thread Execution Hijacking | `SetThreadContext` → redirect thread đến payload |
| **T1106** | Native API | `NtCreateSection`, `NtMapViewOfSection`, `NtGetContextThread`, `NtSetContextThread` |
| **T1027.007** | Dynamic API Resolution | Custom PEB hash lookup, không IAT |
| **T1562.004** | Impair Defenses | ETW thread creation provider patch |

### Test Scenario
1. **Tiền đề**: SYSTEM (từ CVE-2024-21437) hoặc HIGH integrity (từ T1548.002), target `RuntimeBroker.exe` hoặc `svchost.exe`.
2. **Execution chain**:
   - **Bước 1 — Prepare PE Payload**:
     - PE payload (C2 agent, position-independent code) được compile với `/DYNAMICBASE` + `/FIXED:NO`.
     - Resolve imports: parse target process' loaded modules từ PEB → tìm `kernel32.dll`, `ntdll.dll`, `ws2_32.dll`.
     - Apply relocations cho preferred base trong target.
   - **Bước 2 — Map PE into Target via Section**:
     - `NtCreateSection(&hSection, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, ..., PAGE_EXECUTE_READWRITE, SEC_COMMIT, ...)` → anonymous section.
     - Map vào attacker process (RW): `NtMapViewOfSection(hSection, GetCurrentProcess(), &localView, ..., PAGE_READWRITE, ...)`.
     - Write PE payload vào local view.
     - Map vào target process (RX): `NtMapViewOfSection(hSection, hTarget, &remoteView, ..., PAGE_EXECUTE_READ, ...)`.
   - **Bước 3 — Thread Hijacking (không tạo thread mới)**:
     - `NtGetContextThread(hTargetThread, &ctx)` → lấy current thread context (RIP, RSP, register state).
     - Save original context (để restore sau payload).
     - Modify context:
       - `ctx.Rip = remoteView + AddressOfEntryPoint` → redirect đến payload.
       - `ctx.Rsp -= 8` (stack pivot, nếu cần).
     - `NtSetContextThread(hTargetThread, &ctx)` → set thread context mới.
   - **Bước 4 — Signal + Return**:
     - Payload chạy trong context của thread legitimate → khởi tạo C2.
     - Payload restore original context → `NtContinue(&savedCtx)` → thread trở về normal execution.
     - Thread hijack trong suốt: thread "biến mất" trong vài ms (payload), sau đó trở lại bình thường.
   - **Bước 5 — Cleanup + Chain**:
     - `NtUnmapViewOfSection(hSelf, localView)` → cleanup local staging.
     - Remote view vẫn tồn tại → payload trong target.
     - **Chain**: Từ target process → thực hiện T1003 LSASS dump (nếu đã có SYSTEM).

### Bypass Methodology
| Layer | How It's Bypassed |
|-------|-------------------|
| **Thread Creation Detection** | Không tạo thread mới → `PsSetCreateThreadNotifyRoutine` không fire |
| **`WriteProcessMemory`** | Không dùng — map qua shared section → cross-process visibility không qua WPM |
| **RWX Memory** | Trong target: RX only. RW chỉ trong attacker process → tránh RWX detection |
| **`SetThreadContext` Hook** | Một số EDR hook `NtSetContextThread` → detect thread hijacking → **có thể detect** |
| **Module List** | Anonymous section không thêm module mới vào PEB Ldr → `EnumProcessModules` không thấy payload |
| **Thread Stack** | Stack vẫn là stack của thread legitimate → payload dùng `sub rsp, 0x800` để pivot stack riêng → không corrupt legitimate stack |
| **ETW** | Thread creation event không fire (không tạo thread); image load event không fire (không LoadLibrary) |

### Success Criteria
- [ ] PE payload mapped vào target process (qua anonymous section)
- [ ] Thread hijack thành công: thread legitimate redirect đến payload
- [ ] C2 agent chạy trong target, thread trả về bình thường sau payload
- [ ] EDR không detect: (a) section mapping, (b) SetThreadContext hijack, (c) thread context anomaly
- [ ] **Chain verification**: SYSTEM (từ CVE-2024-21437) → PE injection → thread hijack → T1003 LSASS dump
- [ ] Không crash target process
- [ ] Windows 10 22H2 / Windows 11 23H2

### Expected EDR Detection Points
- **`NtSetContextThread`** → Nếu EDR hook API này hoặc có kernel callback `PsSetCreateThreadNotifyRoutine` + thread context check → có thể detect nếu RIP trỏ đến vùng memory không phải Image. **Detection vector chính.**
- **Anonymous section mapping** → Section được tạo không từ file → EDR có thể flag "section without backing file mapped into remote process". **Detection vector.**
- **`RIP` trỏ đến non-Image region** → Nếu EDR periodically check thread RIP → thấy RIP trong vùng `MEM_MAPPED` (không phải `Image`) → flag. Bypass: dùng `SEC_IMAGE` section từ file (cần file trên disk).
- **Stack pivot detection** → Nếu EDR analyze stack trace → thấy stack frame trong non-Image memory → anomalous.

---

## Inter-Plan Chain Reference

| This Plan | Injection Method | Receives From | Grants | Feeds Into |
|-----------|-----------------|---------------|--------|------------|
| Plan 1 | Process Hollowing | **CVE-2024-21338** (kernel PE → SYSTEM) | SYSTEM C2 (masqueraded) | **T1003 Plan 1** (LSASS Dump) |
| Plan 2 | Process Doppelgänging | **T1548.002 Plan 3** (MSI UAC → HIGH) | C2 (diskless process) | **T1068 Plan 3** → DA → **T1003 Plan 3** (DCSync) |
| Plan 3 | PE Injection + Thread Hijack | **CVE-2024-21437** (GDI PE → SYSTEM) | SYSTEM C2 in legit process | **T1003 Plan 1** (LSASS Dump) |

---

## Summary: Detection Difficulty Matrix

| Plan | CVE / Technique | Year | Stealth | EDR Detection Difficulty | Key Blind Spot |
|------|----------------|------|---------|--------------------------|----------------|
| Plan 1 | CVE-2024-21338 + Process Hollowing | 2024 | ★★★☆☆ | **Medium** (hollowing well-known) | Image unload detection; PEB integrity; image hash |
| Plan 2 | Process Doppelgänging (TxF) | 2017→ | ★★★★★ | **Very High** (TxF blind spot) | File-less execution; transaction monitoring; ghost file |
| Plan 3 | CVE-2024-21437 + Thread Hijack | 2024 | ★★★★☆ | **High** | SetThreadContext hook; anonymous section mapping |
