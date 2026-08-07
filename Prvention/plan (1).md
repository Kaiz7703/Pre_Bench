# Windows WalletService LPE — Privilege Escalation Plan (T1068)

## Mục tiêu

Escalate từ **standard user (không cần local admin trước)** lên **SYSTEM** trên Windows 11 bằng lỗ hổng logic trong WalletService (`FOLDERID_Documents` resolve khi impersonate caller, sau đó revert về LocalSystem trước khi mở `wallet.db`).

- **Technique:** T1068 - Exploitation for Privilege Escalation
- **CVE:** CVE-2026-49176 (Windows WalletService)
- **Vì sao chọn hướng này:** đây là hướng **dễ setup nhất** trong các phương án đã khảo sát cho T1068 — không cần build binary, không cần driver, không cần local admin sẵn có (khác với BYOVD RTCore64, xem `../rtcore-exploit/plan.md`). Toàn bộ exploit chỉ là 1 script PowerShell.

## Root cause

WalletService resolve `FOLDERID_Documents` trong khi đang impersonate caller (standard user), nhưng sau đó **revert về LocalSystem** trước khi mở file `<Documents>\Wallet\wallet.db`. Service chấp nhận một ESE database do user tự tạo, với persisted callback được bật — khi service (chạy SYSTEM) truy cập bảng `Cards` trong database này, nó load DLL do attacker kiểm soát dưới quyền SYSTEM.

## Điều kiện tiên quyết

- **Standard user** (không cần local admin) trên host mục tiêu.
- Host: **Windows 11 version 25H2, build 26200.8737 hoặc cũ hơn** — bản vá đã phát hành trong Patch Tuesday **07/2026**, nên host lab phải được giữ ở baseline patch-level **trước** thời điểm đó. Cần kiểm soát snapshot/image của lab để đảm bảo build chưa được vá.
- Chưa xác nhận áp dụng được cho Windows Server 2022 — PoC công khai hiện chỉ khẳng định trên Windows 11 25H2; cần verify riêng nếu muốn dùng trên server trong lab.

## Thành phần cần chuẩn bị

| Thành phần | Nguồn | Ghi chú |
|---|---|---|
| `trigger.ps1` / `run.cmd` | Tham khảo `DavidCarliez/CVE-2026-49176_LPE_POC` (GitHub) — **không copy nguyên văn**, viết lại theo logic: tạo ESE Wallet database độc hại với persisted callback, redirect Documents folder để trigger service load DLL | Cần build/adapt riêng cho lab, kiểm chứng lại trên build Windows 11 cụ thể của lab |
| DLL payload | Tự viết, chạy dưới quyền SYSTEM khi được WalletService load qua persisted callback | Payload đơn giản (vd. spawn `cmd.exe` SYSTEM) để chứng minh khai thác thành công |

## Các bước thực thi (khung)

1. Từ shell **không elevate** (standard user), chuẩn bị ESE Wallet database độc hại (persisted callback trỏ tới DLL payload) và đặt vào vị trí sẽ bị WalletService đọc khi resolve `Documents` folder.
2. ☣️ Kích hoạt WalletService xử lý database (qua trigger script) — service impersonate caller để resolve path, sau đó revert LocalSystem và mở `wallet.db` do attacker kiểm soát.
3. ☣️ WalletService (chạy SYSTEM) load DLL payload khi truy cập bảng `Cards` trong ESE database qua callback.
4. Xác nhận elevation: shell SYSTEM được spawn (`whoami` → `nt authority\system`).
5. (Cleanup) Xoá ESE database, DLL payload đã đặt tại các vị trí tạm.

## Artifacts / dấu vết dự kiến

- File ESE database bất thường trong `<Documents>\Wallet\wallet.db` không do user thao tác qua ứng dụng Wallet hợp lệ.
- Module/DLL load bất thường trong tiến trình WalletService (Sysmon EventCode=7 Image Load) — DLL nằm ngoài đường dẫn cài đặt chuẩn của WalletService.
- Tiến trình con SYSTEM được spawn từ WalletService mà không qua flow hợp lệ (Sysmon EventCode=1 Process Creation, parent = WalletService svchost).
- Truy cập bất thường vào `FOLDERID_Documents` với impersonation token đổi nhanh sang LocalSystem trong cùng call chain (nếu có ETW/ALPC telemetry chi tiết).

## Việc cần làm tiếp

- [ ] `craft-payload` — build trigger script + DLL payload thật, verify trên build Windows 11 cụ thể trong lab (pre-July 2026 patch), đặt tại `resources/payloads/T1068/` kèm `README.md`.
- [ ] Xác nhận baseline patch-level của lab image hỗ trợ CVE này (nếu image đã patch 07/2026 trở đi, phương án này không dùng được — chuyển sang `../rtcore-exploit/plan.md` hoặc `../wer-alpc-lpe/plan.md`).
- [ ] Xác định path/phase cụ thể trong plan để gắn bước này.
- [ ] `write-phase` — viết Procedures + Reference Table sau khi payload đã build xong.

## So sánh nhanh với các phương án T1068 khác trong `resources/`

| Hướng | Cần local admin trước? | Cần build gì | Giới hạn chính |
|---|---|---|---|
| `../rtcore-exploit/plan.md` (RTCore64 BYOVD) | Có | Driver + exploit IOCTL | Cần local admin sẵn có |
| **WalletService (file này)** | **Không** | 1 script PowerShell + DLL payload | Chỉ áp dụng build Windows 11 pre-07/2026 patch |
| `../wer-alpc-lpe/plan.md` (WER ALPC) | Không | Build C++ PoC | Setup nặng hơn (build từ source, hiểu ALPC message format) |

## Tham khảo

- [GitHub - DavidCarliez/CVE-2026-49176_LPE_POC](https://github.com/DavidCarliez/CVE-2026-49176_LPE_POC)
- [T1068 - Exploitation for Privilege Escalation | MITRE ATT&CK](https://attack.mitre.org/techniques/T1068/)
