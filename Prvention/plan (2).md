# Windows Error Reporting (WER) ALPC LPE — Privilege Escalation Plan (T1068)

## Mục tiêu

Escalate từ **standard user (không cần local admin trước)** lên **SYSTEM** trên Windows 10/11/Server 2019/Server 2022 bằng lỗ hổng thiếu kiểm tra quyền trong ALPC handler `SvcElevatedLaunch` (0x0D) của Windows Error Reporting service.

- **Technique:** T1068 - Exploitation for Privilege Escalation
- **CVE:**   (Windows Error Reporting ALPC)
- **Vì sao chọn hướng này:** cùng nhóm "standard user → SYSTEM, không cần driver/local admin sẵn có" như WalletService (xem `../walletservice-lpe/plan.md`), nhưng phạm vi ảnh hưởng rộng hơn — áp dụng cho cả **Windows Server 2022**, khớp trực tiếp với hạ tầng DC/File Server trong lab (`q3-plan/detect-technique-list.md` — Test Environment).

## Root cause

WER service không validate đầy đủ quyền của caller trước khi xử lý ALPC message tại method `SvcElevatedLaunch` (0x0D) trên port `\WindowsErrorReportingService`. Service duplicate handle của shared memory chứa command line do attacker kiểm soát, rồi khởi chạy `WerFault.exe` với command line đó — do WER service chạy dưới SYSTEM, tiến trình `WerFault.exe` sinh ra cũng chạy SYSTEM.

## Điều kiện tiên quyết

- **Standard user** (authenticated, không cần local admin) trên host mục tiêu.
- Host: **Windows 10, Windows 11, Windows Server 2019, hoặc Windows Server 2022** — các bản phát hành **trước tháng 01/2026** (patch đã phát hành từ thời điểm đó). Cần kiểm soát baseline patch-level của lab image.
- Build môi trường: Windows SDK + Visual Studio 2019+ (build PoC trên máy attacker/dev, không phải trên target).

## Thành phần cần chuẩn bị

| Thành phần | Nguồn | Ghi chú |
|---|---|---|
| PoC C++ (compile thành exploit binary) | Tham khảo `oxfemale/CVE-2026-20817` (GitHub) — **không copy nguyên văn**, viết lại theo logic: tạo shared memory chứa command line tuỳ ý → connect ALPC port `\WindowsErrorReportingService` → gửi message method 0x0D kèm PID, handle shared memory, độ dài command line → WER service duplicate handle và exec `WerFault.exe` với command line đó | Build bằng `cl /EHsc` (Windows SDK), cần compile trước khi đưa vào target |
| Command line payload | Tự định nghĩa — command chạy dưới SYSTEM khi `WerFault.exe` được spawn với tham số bị chèn | Payload đơn giản để chứng minh khai thác (vd. spawn `cmd.exe` SYSTEM) |

## Các bước thực thi (khung)

1. Build exploit binary trên máy dev (Windows SDK + `cl /EHsc CVE-2026-20817_PoC.cpp`), đưa binary đã compile lên target qua Ingress Tool Transfer (T1105) nếu chưa có sẵn.
2. Từ shell **không elevate** (standard user) trên target, tạo shared memory section chứa command line độc hại.
3. ☣️ Connect tới ALPC port `\WindowsErrorReportingService`, gửi message qua method `SvcElevatedLaunch` (0x0D) kèm: PID của tiến trình gọi, handle shared memory, độ dài command line.
4. ☣️ WER service duplicate handle, khởi chạy `WerFault.exe` với command line do attacker cung cấp — tiến trình chạy dưới SYSTEM.
5. Xác nhận elevation: shell SYSTEM được spawn (`whoami` → `nt authority\system`; lưu ý token có `SeDebugPrivilege`/`SeImpersonatePrivilege` nhưng **không có** `SeTcbPrivilege`).
6. (Cleanup) Đóng handle/section đã tạo, xoá exploit binary khỏi disk.

## Artifacts / dấu vết dự kiến

- `WerFault.exe` được spawn với command line bất thường (không khớp pattern crash-report chuẩn của WER) — Sysmon EventCode=1 (Process Creation), parent process là WER service (`svchost.exe -k WerSvcGroup` hoặc tương đương).
- Token của `WerFault.exe` con có `SeDebugPrivilege`/`SeImpersonatePrivilege` nhưng thiếu `SeTcbPrivilege` — điểm bất thường để phân biệt với `WerFault.exe` sinh ra hợp lệ.
- Kết nối ALPC tới port `\WindowsErrorReportingService` từ tiến trình không phải WER-related component chuẩn (nếu có ETW ALPC telemetry).
- Shared memory section được tạo/duplicate bất thường ngay trước khi `WerFault.exe` spawn.

## Việc cần làm tiếp

- [ ] `craft-payload` — build exploit binary thật từ logic PoC, verify trên build Windows Server 2022 / Windows 11 cụ thể trong lab (pre-01/2026 patch), đặt tại `resources/payloads/T1068/` kèm `README.md`.
- [ ] Xác nhận baseline patch-level của lab image (Server 2022 DC/File Server, Windows 11 workstation) hỗ trợ CVE này.
- [ ] Xác định path/phase cụ thể trong plan để gắn bước này — ưu tiên xem xét path nhắm vào Server 2022 (DC/File Server) vì đây là hướng duy nhất trong 3 phương án áp dụng được cho server.
- [ ] `write-phase` — viết Procedures + Reference Table sau khi payload đã build xong.

## So sánh nhanh với các phương án T1068 khác trong `resources/`

| Hướng | Cần local admin trước? | Áp dụng Server 2022? | Cần build gì | Giới hạn chính |
|---|---|---|---|---|
| `../rtcore-exploit/plan.md` (RTCore64 BYOVD) | Có | Có | Driver + exploit IOCTL | Cần local admin sẵn có |
| `../walletservice-lpe/plan.md` (WalletService) | Không | Chưa xác nhận | 1 script PowerShell + DLL payload | Chỉ khẳng định trên Windows 11 25H2 |
| **WER ALPC (file này)** | **Không** | **Có** | Build C++ PoC (Windows SDK/Visual Studio) | Setup nặng hơn WalletService — cần build từ source, hiểu ALPC message format |

## Tham khảo

- [GitHub - oxfemale/CVE-2026-20817](https://github.com/oxfemale/CVE-2026-20817)
- [T1068 - Exploitation for Privilege Escalation | MITRE ATT&CK](https://attack.mitre.org/techniques/T1068/)
