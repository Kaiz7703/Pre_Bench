# elevate_setup.ps1 — chạy MỘT LẦN dưới quyền admin (UAC) để đăng ký SYSTEM scheduled task
# chạy test Plan1_LSASS, đợi kết quả, rồi dọn task.
$root   = "D:\VM\kali\Pre_Bench\Prvention\OS_dump\Plan1_LSASS"
$marker = Join-Path $root "elev_marker.txt"
$outdir = Join-Path $root "output"
if (-not (Test-Path $outdir)) { New-Item -ItemType Directory -Force -Path $outdir | Out-Null }

"[START] elevated as: $(whoami) @ $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Out-File $marker -Encoding utf8

# Ghi nhận thời điểm để so khớp log mới tạo
$before = Get-Date

$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument '-NoProfile -ExecutionPolicy Bypass -File "D:\VM\kali\Pre_Bench\Prvention\OS_dump\Plan1_LSASS\test\run_test.ps1" -SkipCleanup' `
    -WorkingDirectory "D:\VM\kali\Pre_Bench\Prvention\OS_dump\Plan1_LSASS\test"

$principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask -TaskName "BenchPlan1LSASS" -Action $action -Principal $principal -Force | Out-Null
Start-ScheduledTask -TaskName "BenchPlan1LSASS"
"[TASK] BenchPlan1LSASS started @ $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Out-File $marker -Append -Encoding utf8

# Đợi tối đa 5 phút cho log test mới xuất hiện
$deadline = (Get-Date).AddMinutes(5)
$found = $false
while ((Get-Date) -lt $deadline) {
    $latest = Get-ChildItem $outdir -Filter "test_*.log" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($latest -and $latest.LastWriteTime -gt $before) {
        "[WAIT] found test log: $($latest.Name)" | Out-File $marker -Append -Encoding utf8
        $found = $true
        break
    }
    Start-Sleep -Seconds 5
}
if (-not $found) { "[WAIT] timeout — no test log appeared" | Out-File $marker -Append -Encoding utf8 }

# Đợi thêm 20s cho detect_check/cleanup chạy xong rồi xóa task
Start-Sleep -Seconds 20
Unregister-ScheduledTask -TaskName "BenchPlan1LSASS" -Confirm:$false -ErrorAction SilentlyContinue
"[END] done @ $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Out-File $marker -Append -Encoding utf8
