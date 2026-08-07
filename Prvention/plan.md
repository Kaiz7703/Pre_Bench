# RTCore64 BYOVD — Privilege Escalation Plan (T1068)

## Mục tiêu

Escalate từ **local admin** lên **SYSTEM** trên Windows 11 Enterprise / Windows Server 2022 bằng kỹ thuật BYOVD (Bring Your Own Vulnerable Driver), dùng driver hợp lệ có chữ ký **RTCore64.sys** (đi kèm MSI Afterburner) chứa lỗ hổng arbitrary kernel read/write.

- **Technique:** T1068 - Exploitation for Privilege Escalation
- **CVE:** CVE-2019-16098 (arbitrary R/W memory/I/O port/MSR trong RTCore64.sys), tương tự CVE-2022-22077
- **Vì sao chọn hướng này:** không phụ thuộc patch-level của Windows OS (lỗ hổng nằm trong driver bên thứ ba, không phải trong Windows), có PoC công khai, và khớp CTI thực tế — driver cùng họ (RTCore64, gdrv.sys, mhyprot2.sys, procexp.sys) từng bị BlackByte, AvosLocker, LockBit dùng để escalate + tắt EDR trước khi mã hoá, đúng theme Crimeware-as-a-Service.

## Điều kiện tiên quyết

- Đã có **local admin** trên host mục tiêu (cần quyền tạo/khởi động kernel service để load driver — đây là giới hạn chung của mọi BYOVD, không riêng driver này).
- Driver Signature Enforcement (DSE) bật bình thường — không cần bypass vì RTCore64.sys có chữ ký hợp lệ.
- Host có thể là Windows 11 Enterprise workstation hoặc Windows Server 2022.

## Thành phần cần chuẩn bị

| Thành phần | Nguồn | Ghi chú |
|---|---|---|
| `RTCore64.sys` | Driver gốc đi kèm MSI Afterburner, hoặc tra `loldrivers.io` để lấy bản có hash đã biết | Driver hợp lệ, có chữ ký Microsoft-trusted |
| Exploit binary (token stealer) | Tham khảo `0xJs/BYOVD_read_write_primitive` (GitHub) — **không copy nguyên văn**, viết lại theo logic: mở handle tới device driver → IOCTL đọc `_EPROCESS` của PID 4 (System) → tìm offset `Token` → ghi token đó vào `_EPROCESS` của process hiện tại | Cần build riêng cho lab, adapt offset theo build Windows cụ thể trong lab |

## Các bước thực thi (khung)

1. ☣️ Copy `RTCore64.sys` vào host mục tiêu (vd. `C:\Windows\Temp\RTCore64.sys`).
2. ☣️ Tạo kernel service trỏ tới driver và khởi động (load driver vào kernel):
   ```powershell
   sc.exe create RTCore64 type= kernel binPath= C:\Windows\Temp\RTCore64.sys
   sc.exe start RTCore64
   ```
3. ☣️ Chạy exploit binary: mở `\\.\RTCore64` device, dùng IOCTL đọc/ghi kernel memory để đánh cắp SYSTEM token (PID 4) và gán cho tiến trình hiện tại.
4. Xác nhận elevation: spawn `cmd.exe`/`powershell.exe` con chạy dưới token SYSTEM (`whoami` → `nt authority\system`).
5. (Cleanup) `sc.exe stop RTCore64` + `sc.exe delete RTCore64`, xoá file driver khỏi disk.

## Artifacts / dấu vết dự kiến

- File driver nằm ở đường dẫn không chuẩn (không phải `C:\Windows\System32\drivers\`) — Sysmon EventCode=6 (Driver Load) với publisher không khớp inventory driver đã cài trên host.
- Service creation kernel-mode bất thường — Security EventCode 4697 / Sysmon EventCode=6, hoặc 7045 (Service Installed).
- Token elevation bất thường: tiến trình con chạy SYSTEM mà không qua đường hợp lệ (không phải service logon, không phải `runas` từ admin đã biết).
- IOCTL calls tới device object `\\.\RTCore64` nếu có kernel/ETW driver telemetry.

## Việc cần làm tiếp

- [ ] `craft-payload` — build exploit binary thật (token-stealer qua IOCTL), xác định offset `_EPROCESS.Token` đúng cho build Windows trong lab, đặt tại `resources/payloads/T1068/` kèm `README.md`.
- [ ] Xác định path/phase cụ thể trong plan để gắn bước này (đứng sau bước nào đã có local admin).
- [ ] `write-phase` — viết Procedures + Reference Table (Detection Criteria, ACW, Calibrated/Not Calibrated) sau khi payload đã build xong.

## So sánh nhanh với các phương án T1068 khác trong `resources/`

| Hướng | Cần local admin trước? | Áp dụng Server 2022? | Cần build gì | Giới hạn chính |
|---|---|---|---|---|
| **RTCore64 BYOVD (file này)** | **Có** | Có | Driver + exploit IOCTL | Cần local admin sẵn có trước |
| `../walletservice-lpe/plan.md` (WalletService) | Không | Chưa xác nhận | 1 script PowerShell + DLL payload | Chỉ khẳng định trên Windows 11 25H2, cần pre-07/2026 patch |
| `../wer-alpc-lpe/plan.md` (WER ALPC) | Không | Có | Build C++ PoC | Setup nặng hơn WalletService, cần pre-01/2026 patch |

## Tham khảo

- [T1068 - Exploitation for Privilege Escalation | MITRE ATT&CK](https://attack.mitre.org/techniques/T1068/)
- [GitHub - hfiref0x/KDU: Kernel Driver Utility](https://github.com/hfiref0x/KDU)
- [Local Privilege Escalation through BYOVD with Kernel R/W Primitives (Medium)](https://medium.com/@s12deff/local-privilege-escalation-through-byovd-with-kernel-r-w-primitives-2e27878725a2)
- [GitHub - 0xJs/BYOVD_read_write_primitive](https://github.com/0xJs/BYOVD_read_write_primitive)
- [RTCore64.sys - CVE-2019-16098 write-up](https://seg-fault.gitbook.io/researchs/windows-security-research/exploit-development/rtcore64.sys-cve-2019-16098)
- [GitHub - grisuno/CVE-2022-22077 (RTCore64.sys)](https://github.com/grisuno/CVE-2022-22077)
- [The Vault: Unwinding RTCore](https://swapcontext.blogspot.com/2020/01/unwinding-rtcore.html)
