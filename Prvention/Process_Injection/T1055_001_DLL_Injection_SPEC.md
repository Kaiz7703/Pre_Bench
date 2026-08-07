# Plan 1 — DLL Injection: Technical Specification

> **Target**: T1055.001 — Dynamic-link Library Injection
> **Technique**: Module Stomping + Early Bird APC Injection
> **Pre-condition**: SYSTEM or Administrator (assumed)
> **Scope**: Inject reflective DLL payload into target process without remote thread, without LoadLibrary, without RWX memory

---

## 1. Overview

Early Bird APC Injection kết hợp Module Stomping để đưa payload DLL vào target process. Thay vì tạo remote thread (dễ bị detect bởi `PsSetCreateThreadNotifyRoutine`), kỹ thuật này queue APC vào main thread đang suspended của process mới tạo. Payload được ghi đè lên `.text` section của một legitimate DLL đã loaded (module stomping) — giữ memory trong Image region, bypass memory scan của EDR.

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌────────────┐
│ Indirect     │    │ ETW Patch    │    │ CreateProc   │    │ Module     │
│ Syscalls     │───▶│ (EtwEventWr) │───▶│ SUSPENDED    │───▶│ Stomping   │
│ (disk ntdll) │    │              │    │ (PPID spoof) │    │ (.text OW) │
└──────────────┘    └──────────────┘    └──────────────┘    └────────────┘
                                                                    │
┌────────────┐    ┌──────────────┐    ┌──────────────┐              │
│ ADS Output │◀───│ Reflective   │◀───│ APC Queue    │◀─────────────┘
│ (encrypted)│    │ DLL Execute  │    │ + Resume     │
└────────────┘    └──────────────┘    └──────────────┘
```

---

## 2. Functional Requirements

### FR-1: Process Creation & Preparation
| ID | Requirement |
|----|-------------|
| FR-1.1 | Tạo target process ở trạng thái SUSPENDED với `NtCreateUserProcess` |
| FR-1.2 | PPID spoofing: parent process = `services.exe` (PID từ snapshot) |
| FR-1.3 | Target: `RuntimeBroker.exe` — HIGH integrity, Microsoft signed, có network |
| FR-1.4 | Không sử dụng `CreateProcessW` (userland hooked) — dùng indirect syscall |

### FR-2: Module Stomping
| ID | Requirement |
|----|-------------|
| FR-2.1 | Enum loaded modules trong target process qua PEB Ldr list |
| FR-2.2 | Chọn legitimate DLL để stomp (vd: `msxml3.dll`, `comctl32.dll`) |
| FR-2.3 | Đọc `.text` section header → xác định RVA + size từ PE headers |
| FR-2.4 | `NtProtectVirtualMemory`: RW → write payload → RX (không RWX đồng thời) |
| FR-2.5 | Payload: small PIC reflective loader + embedded DLL |
| FR-2.6 | Giữ nguyên module list — `EnumProcessModules` vẫn thấy DLL cũ |

### FR-3: APC Injection (Early Bird)
| ID | Requirement |
|----|-------------|
| FR-3.1 | Xác định main thread của target process (thread đầu tiên) |
| FR-3.2 | `NtQueueApcThread`: queue APC với entry point = stomped .text address |
| FR-3.3 | Không `CreateRemoteThread` — bypass `PsSetCreateThreadNotifyRoutine` |
| FR-3.4 | `NtResumeThread` — thread resumed → APC được deliver → payload chạy |

### FR-4: Reflective DLL Payload
| ID | Requirement |
|----|-------------|
| FR-4.1 | Payload là PIC (position-independent code) — không relocation needed |
| FR-4.2 | PEB walk → resolve `kernel32.dll` → `GetProcAddress` |
| FR-4.3 | Resolve tất cả API cần thiết động (không IAT import) |
| FR-4.4 | DllMain: ghi success marker vào ADS → return TRUE |
| FR-4.5 | Không crash target process — thread trả về bình thường |

### FR-5: Output
| ID | Requirement |
|----|-------------|
| FR-5.1 | Success marker được mã hóa AES-256-GCM |
| FR-5.2 | Ghi vào ADS trên file hệ thống hợp lệ |
| FR-5.3 | Ghi PID + timestamp + technique name |

---

## 3. Bypass Strategy

| # | EDR Layer | Detection | Bypass |
|---|-----------|-----------|--------|
| 1 | `CreateRemoteThread` | Kernel callback fire cho new thread | APC queue trên thread có sẵn → không fire |
| 2 | `LoadLibraryW` hook | Userland hook thấy DLL load | Reflective loading → không gọi LoadLibrary |
| 3 | `PsSetLoadImageNotifyRoutine` | Kernel callback cho image load | Reflective loading → không image load event |
| 4 | RWX memory scan | EDR scan cho vùng Private + RWX | Payload nằm trong Image region (.text của DLL) |
| 5 | `WriteProcessMemory` | Userland hook | Indirect syscall `NtWriteVirtualMemory` |
| 6 | `NtProtectVirtualMemory` hook | Userland hook thấy RX→RW→RX cycle | Indirect syscall |
| 7 | ETW Image Load event | Event `Microsoft-Windows-Kernel-Process` | Reflective load không sinh event |
| 8 | PPID anomaly | Process tree không khớp | PPID = services.exe (legitimate parent) |
| 9 | `NtCreateUserProcess` hook | Userland hook | Indirect syscall |
| 10 | ETW Threat Intelligence | ETW TI provider | Patch `EtwEventWrite` → xor eax,eax; ret |

---

## 4. Data Flow

```
[Attacker Process (SYSTEM/Admin)]
    │
    ├─(1)─ InitSyscallResolver(): đọc clean ntdll.dll từ disk
    │      → extract SSN từ export stubs → build indirect syscall stubs
    │
    ├─(2)─ PatchEtw(): VirtualProtect + overwrite EtwEventWrite → ret 0
    │
    ├─(3)─ CreateSuspendedProcess():
    │      NtCreateUserProcess("RuntimeBroker.exe", SUSPENDED, PPID=services.exe)
    │
    ├─(4)─ ModuleStomp():
    │      ├─ Enum target PEB → Ldr → find msxml3.dll base
    │      ├─ Parse PE headers → find .text section RVA + size
    │      ├─ NtProtectVirtualMemory(.text, RW)
    │      ├─ NtWriteVirtualMemory(.text, PIC_payload)
    │      └─ NtProtectVirtualMemory(.text, RX)
    │
    ├─(5)─ EarlyBirdApc():
    │      ├─ Find main thread (first thread in target)
    │      ├─ NtQueueApcThread(mainThread, stomped_text_addr, NULL, NULL)
    │      └─ NtResumeThread(mainThread)
    │
    ├─(6)─ Payload executes in target:
    │      ├─ PEB walk → find kernel32
    │      ├─ Resolve GetProcAddress
    │      ├─ Load user32/ws2_32 (if needed)
    │      ├─ Write success marker to ADS
    │      └─ Return (thread continues normale execution)
    │
    └─(7)─ Attacker verifies: read ADS → check marker
```

---

## 5. Test Cases

| TC | Scenario | Expected |
|----|----------|---------|
| TC-01 | SYSTEM, inject vào RuntimeBroker.exe | Payload executes, ADS marker written |
| TC-02 | Admin, inject vào notepad.exe (user session) | Payload executes, process không crash |
| TC-03 | EDR with kernel callbacks enabled | Không detect CreateRemoteThread, LoadLibrary |
| TC-04 | EDR with ETW TI provider | ETW patched → không event |
| TC-05 | EDR with userland hooks on ntdll | Indirect syscall bypass hooks |
| TC-06 | EDR with memory scan (RWX detection) | Payload trong Image region → không bị scan |
| TC-07 | Verify target process stability | Process tiếp tục chạy bình thường sau injection |
| TC-08 | Check PPID in process tree | Parent = services.exe (legitimate) |

---

## 6. Success Criteria

- [ ] Process tạo SUSPENDED thành công với PPID spoofing
- [ ] Module stomping: .text section của legitimate DLL bị overwrite
- [ ] APC queued + delivered → payload reflective DLL chạy
- [ ] Payload hoàn thành: PEB resolve → ADS write → return
- [ ] Target process không crash
- [ ] Không `CreateRemoteThread`, không `LoadLibrary`, không `WriteProcessMemory`
- [ ] Không RWX memory đồng thời (RW → write → RX)
- [ ] EDR không detect injection
- [ ] Windows 10/11, Windows Server 2019/2022
