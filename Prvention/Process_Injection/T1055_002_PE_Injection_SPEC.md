# Plan 2 — PE Injection: Technical Specification

> **Target**: T1055.002 — Portable Executable Injection
> **Technique**: Process Doppelgänging via NTFS Transaction (TxF)
> **Pre-condition**: SYSTEM or Administrator (assumed)
> **Scope**: Create a process from a PE file that NEVER existed on disk — diskless execution via NTFS transaction abuse

---

## 1. Overview

Process Doppelgänging sử dụng NTFS Transaction (TxF) để tạo một "ghost file" — file chỉ tồn tại trong transaction, chưa bao giờ được commit lên disk. PE payload được viết vào ghost file, sau đó `NtCreateSection(SEC_IMAGE)` tạo image section từ file này. Process được tạo từ section, rồi transaction được rollback — file biến mất hoàn toàn. Kết quả: process đang chạy với executable không tồn tại trên disk.

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌────────────┐
│ NTFS         │    │ Transacted   │    │ SEC_IMAGE    │    │ Create     │
│ Transaction  │───▶│ File Write   │───▶│ Section      │───▶│ Process    │
│ (TxF Create) │    │ (Ghost File) │    │ (Kernel PE)  │    │ (SUSPEND)  │
└──────────────┘    └──────────────┘    └──────────────┘    └────────────┘
                                                                    │
┌────────────┐    ┌──────────────┐    ┌──────────────┐              │
│ ADS Output │◀───│ Payload      │◀───│ Rollback     │◀─────────────┘
│ (encrypted)│    │ Executes     │    │ Transaction  │
└────────────┘    └──────────────┘    └──────────────┘
```

---

## 2. Functional Requirements

### FR-1: NTFS Transaction Setup
| ID | Requirement |
|----|-------------|
| FR-1.1 | Tạo NTFS transaction với `NtCreateTransaction` |
| FR-1.2 | Transaction handle được dùng cho tất cả file operations tiếp theo |
| FR-1.3 | Không dùng KTM (Kernel Transaction Manager) API — dùng trực tiếp NT API |

### FR-2: Ghost File Creation
| ID | Requirement |
|----|-------------|
| FR-2.1 | `NtCreateFile` với transaction handle → tạo file trong transaction |
| FR-2.2 | File path: `C:\Windows\System32\` + legitimate-looking name (masquerading) |
| FR-2.3 | `NtWriteFile` → write PE payload (C2 agent / demo payload) |
| FR-2.4 | File CHỈ tồn tại trong transaction — không visible trên disk, không AV scan |

### FR-3: Image Section + Process Creation
| ID | Requirement |
|----|-------------|
| FR-3.1 | `NtCreateSection(SEC_IMAGE)` từ transacted file handle |
| FR-3.2 | Kernel PE parser tự động validate PE headers + map sections |
| FR-3.3 | `NtCreateProcessEx` với section handle → process được tạo từ ghost image |
| FR-3.4 | Process ở trạng thái SUSPENDED (chuẩn bị cho thread creation) |
| FR-3.5 | PEB `ImagePathName` = path của ghost file (legitimate-looking) |

### FR-4: Transaction Rollback
| ID | Requirement |
|----|-------------|
| FR-4.1 | `NtRollbackTransaction` → transacted file biến mất hoàn toàn |
| FR-4.2 | Sau rollback: process vẫn chạy bình thường (kernel đã giữ reference) |
| FR-4.3 | Không artifact trên disk — file explorer + forensic tool không thấy file |

### FR-5: Payload Execution
| ID | Requirement |
|----|-------------|
| FR-5.1 | `NtCreateThreadEx` → tạo thread trong process với entry point từ PE |
| FR-5.2 | `NtResumeThread` → process + thread chạy |
| FR-5.3 | Payload: PIC entry point → resolve APIs → write success marker → exit cleanly |

### FR-6: Output
| ID | Requirement |
|----|-------------|
| FR-6.1 | Success marker được mã hóa AES-256-GCM |
| FR-6.2 | Ghi vào ADS trên file hệ thống hợp lệ |
| FR-6.3 | Ghi PID + ghost file path + timestamp + technique name |

---

## 3. Bypass Strategy

| # | EDR Layer | Detection | Bypass |
|---|-----------|-----------|--------|
| 1 | File-based AV scan | Scan file khi tạo trên disk | File chưa bao giờ tồn tại trên disk — không scan được |
| 2 | `PsSetCreateProcessNotifyRoutineEx` | Kernel callback fire với `ImageFileName` | Path legitimate (`System32\*.dll`) — không suspicious |
| 3 | Process from non-existent file | EDR check file existence sau khi process created | TxF rollback timing — check xảy ra sau khi file đã biến mất |
| 4 | `PsSetLoadImageNotifyRoutine` | Kernel image load callback | Callback fire với transacted file path — path hợp lệ |
| 5 | NTFS transaction monitoring | TxF activity detection | TxF ít được EDR monitor — blind spot phổ biến |
| 6 | `NtCreateTransaction` | Hook trên NT API | Indirect syscall — bypass userland hook |
| 7 | ETW Process Creation | Event `Microsoft-Windows-Kernel-Process` | Event ghi path hợp lệ — không anomalous |
| 8 | Memory scan (RWX) | Scan process memory sau khi tạo | Kernel PE mapping: Image type với RX → EDR skip |
| 9 | Minifilter driver | File system minifilter thấy transacted write | Minifilter receive IRP_MJ_CREATE nhưng file chưa commit |
| 10 | ETW Threat Intelligence | ETW TI provider | Patch `EtwEventWrite` → xor eax,eax; ret |

---

## 4. Data Flow

```
[Attacker Process (SYSTEM/Admin)]
    │
    ├─(1)─ InitSyscallResolver(): đọc clean ntdll.dll từ disk
    │      → extract SSN → build indirect syscall stubs
    │
    ├─(2)─ PatchEtw(): VirtualProtect + overwrite EtwEventWrite → ret 0
    │
    ├─(3)─ PreparePayload():
    │      ├─ Embed minimal PE (position-independent, ~4KB)
    │      ├─ PE has: DOS header + NT headers + .text section
    │      └─ Entry point: PIC that resolves APIs + writes marker
    │
    ├─(4)─ CreateTransaction():
    │      NtCreateTransaction(&hTx, ..., TRANSACTION_DO_NOT_PROMOTE, ...)
    │
    ├─(5)─ CreateGhostFile():
    │      ├─ NtCreateFile(hTx, "\\System32\\<masq_name>.dll", ...)
    │      ├─ NtWriteFile(hGhost, PE_payload, ...)
    │      └─ File only visible within transaction scope
    │
    ├─(6)─ CreateSectionFromGhost():
    │      NtCreateSection(&hSec, SEC_IMAGE, hGhostFile)
    │      → Kernel validates PE, maps sections internally
    │
    ├─(7)─ CreateProcess():
    │      NtCreateProcessEx(&hProc, hSec, ..., CREATE_SUSPENDED)
    │      → PEB.ImagePathName = ghost file path (legitimate)
    │
    ├─(8)─ RollbackTransaction():
    │      NtRollbackTransaction(hTx)
    │      → Ghost file vanishes — never existed on disk
    │
    ├─(9)─ ExecutePayload():
    │      ├─ NtCreateThreadEx(hProc, entryPoint, ...)
    │      ├─ NtResumeThread(hThread)
    │      └─ Payload executes in process
    │
    └─(10)- Payload actions:
           ├─ PEB walk → resolve APIs
           ├─ Write success marker to ADS
           └─ ExitProcess(0) or return cleanly
```

---

## 5. Test Cases

| TC | Scenario | Expected |
|----|----------|---------|
| TC-01 | SYSTEM, Doppelgänging tạo process từ ghost file | Process chạy, file không tồn tại trên disk |
| TC-02 | Admin, Doppelgänging với PE payload C2 demo | C2 beacon hoạt động, không file trên disk |
| TC-03 | EDR with file-system minifilter | Minifilter thấy transacted create nhưng file chưa commit |
| TC-04 | EDR with process creation monitoring | Event với path hợp lệ, không flag |
| TC-05 | EDR with TxF monitoring (nếu có) | Blind spot — TxF ít được monitor |
| TC-06 | Verify forensic artifacts | Không PE file trên disk, không USN journal entry |
| TC-07 | Check process stability | Process chạy bình thường sau rollback |
| TC-08 | Multiple concurrent Doppelgänging | Nhiều ghost processes chạy đồng thời |

---

## 6. Success Criteria

- [ ] NTFS transaction tạo thành công
- [ ] Ghost file viết PE payload thành công (trong transaction)
- [ ] `SEC_IMAGE` section tạo từ transacted file — kernel chấp nhận
- [ ] Process tạo từ ghost image — PEB path legitimate
- [ ] Transaction rollback — không artifact trên disk
- [ ] Payload executes: API resolve → ADS marker → exit
- [ ] Process list hiển thị path `System32\*.dll` (không tồn tại thật)
- [ ] EDR không detect: (a) TxF abuse, (b) diskless process, (c) ghost file
- [ ] Windows 10/11 (NTFS, TxF enabled — mặc định enabled)
