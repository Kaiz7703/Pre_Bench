<#
.SYNOPSIS
    Chạy một PoC leo thang đặc quyền trên VM lab và kết luận PASS/FAIL kèm bằng chứng.

.DESCRIPTION
    Script này KHÔNG tự động hoá việc khai thác — nó là cái khung đo lường.
    Nó giải quyết 3 vấn đề hay làm hỏng kết quả benchmark LPE:

      1. Chạy PoC từ prompt admin rồi kết luận "pass".  -> Script chạy payload
         hạ quyền qua Scheduled Task (-RunAsUser) và TỪ CHỐI kết luận nếu
         payload đang chạy elevated.
      2. Chạy trên VM đã vá.  -> Gate kiểm tra kernel build + ngày cài hotfix
         TRƯỚC khi chạy.
      3. Tin vào output tự khai của PoC.  -> Bằng chứng được xếp hạng theo độ
         tin cậy; output tự khai chỉ được xếp hạng WEAK.

    Script cần chạy ELEVATED để QUAN SÁT (đọc token tiến trình, đọc event log).
    Đó là lý do kiến trúc phải tách "quyền để đo" khỏi "quyền để test".

.PARAMETER Payload
    Đường dẫn tới file .exe cần kiểm tra.

.PARAMETER RunAsUser
    Tài khoản STANDARD USER để chạy payload. Bắt buộc nếu phiên hiện tại đang
    elevated, vì nếu không payload sẽ chạy dưới quyền admin và phép thử vô nghĩa.
    Tài khoản phải đang có phiên đăng nhập tương tác (LogonType Interactive).

.PARAMETER Cve
    Mã CVE để tra bảng gate. Mặc định CVE-2026-42980.

.EXAMPLE
    # Đúng cách: prompt admin, payload chạy hạ quyền xuống user 'grunt'
    .\verify-poc.ps1 -Payload 'D:\poc.exe' -RunAsUser 'grunt' -ExpectProcess cmd.exe

.EXAMPLE
    # Kiểm tra gate rồi thoát, không chạy payload
    .\verify-poc.ps1 -Payload 'D:\poc.exe' -GateOnly

.NOTES
    Cho benchmark nội bộ. Chỉ dùng trên VM lab thuộc sở hữu của bạn.

    QUAN TRỌNG — ENCODING:
    File này chứa tiếng Việt và PHẢI được lưu dưới dạng UTF-8 **có BOM**.
    Windows PowerShell 5.1 đọc file .ps1 không có BOM theo codepage ANSI của hệ
    thống, sẽ làm vỡ toàn bộ chuỗi tiếng Việt và gây lỗi parser. Nếu bạn sửa
    file bằng editor có thể làm mất BOM, hãy chạy lại lệnh sau trước khi dùng:

        $c = Get-Content -Raw .\verify-poc.ps1 -Encoding UTF8
        [IO.File]::WriteAllText((Resolve-Path .\verify-poc.ps1),
            $c, (New-Object Text.UTF8Encoding($true)))

    Kiểm tra nhanh: 3 byte đầu file phải là EF BB BF.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Payload,

    [string]$PayloadArgs = '',

    [string]$Cve = 'CVE-2026-42980',

    [string]$RunAsUser = '',

    # Tiến trình con kỳ vọng mang token SYSTEM (vd cmd.exe). Tên không cần đuôi .exe.
    [string[]]$ExpectProcess = @('cmd.exe'),

    # File artifact kỳ vọng (vd C:\poc_wer.txt)
    [string[]]$ExpectFile = @(),
    [string]$ExpectFileContains = '',

    # Chuỗi kỳ vọng trong stdout của payload (bằng chứng hạng WEAK)
    [string[]]$ExpectStdout = @(),

    [int]$ExpectExitCode = 0,
    [int]$TimeoutSec = 240,

    [string]$OutDir = '',

    [switch]$GateOnly,          # chỉ kiểm tra patch level rồi thoát
    [switch]$SkipGate,          # bỏ qua gate (chỉ dùng khi đã tự xác minh)
    [switch]$CaptureEvents,     # thu thập Sysmon/Security trong cửa sổ chạy
    [switch]$NoCleanup,         # không kill tiến trình con sau khi đo
    [switch]$ShowPayload        # hiện cửa sổ console của payload (không redirect stdout)
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

# ============================================================
# BẢNG GATE THEO CVE
# ============================================================
# FixedBuild chỉ so sánh được khi CÙNG nhánh build (26100 với 26100).
# Khác nhánh -> trả UNKNOWN và bắt người dùng xác minh tay. Đây là chủ ý:
# thà UNKNOWN còn hơn khẳng định sai rằng VM đã vá / chưa vá.
$CveGate = @{
    'CVE-2026-42980' = @{
        Title      = 'Windows kernel WMI serialization integer underflow'
        Detail     = 'nt!WmipQuerySingleMultiple + nt!WmipQueryAllDataMultiple, IOCTL 0x228130 / 0x22812C'
        FixedOn    = '2026-06-09'          # Patch Tuesday tháng 6/2026
        FixedBuild = '10.0.26100.1992'
        MinBuild   = 19041
        Requires   = @('\Device\WMIDataDevice')
        Verified   = $true                 # số liệu đã đối chiếu nguồn ngoài
    }
    'CVE-2026-20817' = @{
        Title      = 'Windows Error Reporting (WER) ALPC local privilege escalation'
        Detail     = 'WerSvc ALPC \WindowsErrorReportingService, method 0x0D (SvcElevatedLaunch)'
        FixedOn    = '2026-01-13'
        FixedBuild = ''
        MinBuild   = 0
        Requires   = @()
        Services   = @('WerSvc')
        Verified   = $false                # lấy từ plan (2).md, chưa đối chiếu nguồn ngoài
    }
    'CVE-2026-49176' = @{
        Title      = 'WalletService local privilege escalation'
        Detail     = 'WalletService'
        FixedOn    = '2026-07-14'
        FixedBuild = ''                    # plan ghi "26200.8737 hoặc cũ hơn"
        MaxBuild   = 26200
        MinBuild   = 0
        Requires   = @()
        Verified   = $false
    }
    'CVE-2019-16098' = @{
        Title      = 'RTCore64.sys arbitrary read/write (BYOVD)'
        Detail     = 'MSI RTCore64.sys IOCTL - KHÔNG phải LPE thuần, cần local admin + driver vulnerable'
        FixedOn    = ''
        FixedBuild = ''
        MinBuild   = 0
        Requires   = @()
        NeedsAdmin = $true                 # đánh dấu: không chạy được từ standard user
        Verified   = $false
    }
}

# ============================================================
# TIỆN ÍCH
# ============================================================
function Write-Head($t) { Write-Host ''; Write-Host ('=' * 68) -ForegroundColor DarkGray; Write-Host "  $t" -ForegroundColor Cyan; Write-Host ('=' * 68) -ForegroundColor DarkGray }
function Write-Ok($t)   { Write-Host "  [OK]   $t" -ForegroundColor Green }
function Write-Bad($t)  { Write-Host "  [FAIL] $t" -ForegroundColor Red }
function Write-Warn2($t){ Write-Host "  [WARN] $t" -ForegroundColor Yellow }
function Write-Info($t) { Write-Host "  [*]    $t" -ForegroundColor Gray }

function Test-IsElevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    return $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-ProcessOwnerSid {
    param([int]$ProcessId)
    try {
        $p = Get-CimInstance Win32_Process -Filter "ProcessId=$ProcessId" -ErrorAction Stop
        if (-not $p) { return $null }
        $o = Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid -ErrorAction Stop
        if ($null -ne $o -and $o.ReturnValue -eq 0) { return $o.Sid }
    } catch { }
    return $null
}

function Get-KernelVersion {
    $nt = Join-Path $env:SystemRoot 'System32\ntoskrnl.exe'
    if (-not (Test-Path -LiteralPath $nt)) { return $null }
    $vi = (Get-Item -LiteralPath $nt).VersionInfo
    return [pscustomobject]@{
        FileVersion = $vi.FileVersion
        Build       = $vi.FileBuildPart
        Revision    = $vi.FilePrivatePart
        Path        = $nt
    }
}

# ============================================================
# 1. GATE — PATCH LEVEL
# ============================================================
function Invoke-Gate {
    param([string]$CveId, [switch]$Quiet)

    $res = [ordered]@{
        Cve         = $CveId
        Verdict     = 'UNKNOWN'
        Reason      = ''
        Kernel      = $null
        RecentFixes = @()
    }

    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue
    $k  = Get-KernelVersion

    $build = $null; $rev = $null
    if ($k) { $build = $k.Build; $rev = $k.Revision }

    if (-not $Quiet) {
        # Truy cập thuộc tính có thể thiếu trên build cũ -> đọc qua biến tạm, không dùng $obj.Prop trực tiếp.
        $caption = ''; $displayVer = ''; $curBuild = ''; $ubr = ''
        if ($os) { $caption = [string]$os.Caption }
        if ($os -and $os.PSObject.Properties['LastBootUpTime']) { $boot = $os.LastBootUpTime } else { $boot = $null }
        if ($cv) {
            if ($cv.PSObject.Properties['DisplayVersion'])  { $displayVer = [string]$cv.DisplayVersion }
            if ($cv.PSObject.Properties['CurrentBuildNumber']) { $curBuild = [string]$cv.CurrentBuildNumber }
            if ($cv.PSObject.Properties['UBR'])             { $ubr = [string]$cv.UBR }
        }
        Write-Info ("OS          : {0} {1}" -f $caption, $displayVer)
        Write-Info ("Build       : {0}.{1}" -f $curBuild, $ubr)
        if ($k) { Write-Info ("Kernel      : {0}  [{1}]" -f $k.FileVersion, $k.Path) }
        else    { Write-Warn2 'Không đọc được version ntoskrnl.exe.' }
        Write-Info ("Last boot   : {0}" -f $boot)

        # Trên 25H2, ntoskrnl.exe vẫn khai nhánh 26100 dù OS là 26200 — nói rõ để
        # người vận hành không tưởng là đọc nhầm máy.
        $kParts = @()
        if ($k) { $kParts = @(([string]$k.FileVersion).Split('.')) }
        if ($curBuild -and $kParts.Count -ge 3 -and $kParts[2] -ne $curBuild) {
            Write-Info ("  (ntoskrnl khai nhánh {0}, OS khai {1} — bình thường trên 25H2; gate lấy ngày hotfix làm căn cứ chính)" -f $kParts[2], $curBuild)
        }
    }

    $res.Kernel = $k

    $g = $null
    if ($CveGate.ContainsKey($CveId)) { $g = $CveGate[$CveId] }

    if (-not $g) {
        $res.Reason = "Không có trong bảng gate — tự xác minh patch level."
        if (-not $Quiet) { Write-Warn2 $res.Reason }
        return $res
    }

    if (-not $Quiet) {
        Write-Info ("CVE         : {0} — {1}" -f $CveId, $g.Title)
        Write-Info ("Chi tiết    : {0}" -f $g.Detail)
        if (-not $g.Verified) { Write-Warn2 "Số liệu gate của CVE này CHƯA được đối chiếu nguồn ngoài (lấy từ plan)." }
    }

    # --- dịch vụ / device bắt buộc ---
    if ($g.ContainsKey('Services')) {
        foreach ($svc in $g.Services) {
            $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
            if (-not $s) { Write-Warn2 "Dịch vụ $svc không tồn tại." }
            elseif ($s.Status -ne 'Running') { Write-Warn2 "Dịch vụ $svc đang $($s.Status) — PoC cần dịch vụ chạy." }
            else { Write-Info "Dịch vụ ${svc}: Running" }
        }
    }
    if ($g.ContainsKey('Requires')) {
        foreach ($dev in $g.Requires) {
            $leaf = $dev.TrimStart('\') -replace '^Device\\', ''
            $exists = $null -ne (Get-CimInstance Win32_PnPEntity -Filter "DeviceID LIKE '%$leaf%'" -ErrorAction SilentlyContinue)
            if ($exists) { Write-Info "Device ${dev}: có mặt" }
            else { Write-Info "Device ${dev}: không thấy qua PnP (bình thường với device nội bộ kernel)" }
        }
    }
    if ($g.ContainsKey('NeedsAdmin') -and $g.NeedsAdmin) {
        Write-Warn2 "CVE này cần local admin — KHÔNG phải LPE từ standard user. Đừng ghi nhận nhầm là leo thang."
    }

    # --- hotfix gần đây ---
    $fixes = @()
    try {
        $fixes = Get-CimInstance Win32_QuickFixEngineering -ErrorAction SilentlyContinue |
                 Where-Object { $_.InstalledOn } |
                 Sort-Object InstalledOn -Descending | Select-Object -First 8
        if (-not $Quiet -and $fixes) {
            Write-Host '  Hotfix gần đây:' -ForegroundColor Gray
            foreach ($f in $fixes) { Write-Host ("    {0,-12} {1:yyyy-MM-dd}" -f $f.HotFixID, $f.InstalledOn) -ForegroundColor DarkGray }
        }
        $res.RecentFixes = $fixes | ForEach-Object { "{0} {1:yyyy-MM-dd}" -f $_.HotFixID, $_.InstalledOn }
    } catch { }

    # --- kết luận ---
    $latestFix = $null
    if ($fixes) { $latestFix = ($fixes | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn }

    if ($g.FixedOn -and $latestFix) {
        $fixedOn = [datetime]::ParseExact($g.FixedOn, 'yyyy-MM-dd', $null)
        if ($latestFix -ge $fixedOn) {
            $res.Verdict = 'LIKELY_PATCHED'
            $res.Reason  = "Cập nhật luỹ kế mới nhất cài ngày $($latestFix.ToString('yyyy-MM-dd')), sau mốc vá $($g.FixedOn)."
        }
    }

    if ($res.Verdict -eq 'UNKNOWN' -and $g.FixedBuild -and $k -and $rev) {
        $fb       = @($g.FixedBuild.Split('.'))
        $curParts = @(([string]$k.FileVersion).Split('.'))
        if ($fb.Count -ge 4 -and $curParts.Count -ge 3) {
            $famFixed = ($fb[0..2] -join '.')
            $famCur   = ($curParts[0..2] -join '.')
            if ($famCur -eq $famFixed) {
                $fbRev = 0; $curRev = 0
                [void][int]::TryParse([string]$fb[3], [ref]$fbRev)
                [void][int]::TryParse([string]$rev,   [ref]$curRev)
                if ($curRev -ge $fbRev) {
                    $res.Verdict = 'LIKELY_PATCHED'
                    $res.Reason  = "Kernel $($k.FileVersion) >= bản vá $($g.FixedBuild)."
                } else {
                    $res.Verdict = 'LIKELY_VULNERABLE'
                    $res.Reason  = "Kernel $($k.FileVersion) < bản vá $($g.FixedBuild)."
                }
            } else {
                $res.Reason = "Kernel nhánh $famCur khác nhánh bản vá $famFixed — không so sánh trực tiếp được."
            }
        } else {
            $res.Reason = "Không tách được số build từ ntoskrnl.exe."
        }
    }

    if ($res.Verdict -eq 'UNKNOWN') {
        if (-not $res.Reason) { $res.Reason = "Không đủ dữ liệu để kết luận từ xa." }
        Write-Warn2 "GATE: UNKNOWN — $($res.Reason)"
        Write-Warn2 "Hãy xác minh tay trước khi tin kết quả (VD: so build kernel với advisory của Microsoft)."
    } elseif ($res.Verdict -eq 'LIKELY_PATCHED') {
        Write-Bad "GATE: LIKELY_PATCHED — $($res.Reason)"
        Write-Warn2 "PoC gần như chắc chắn KHÔNG nổ trên VM này. Kết quả FAIL sẽ là dương tính giả của môi trường, không phải EDR bắt được."
    } else {
        Write-Ok "GATE: LIKELY_VULNERABLE — $($res.Reason)"
    }

    return $res
}

# ============================================================
# 2. CHẠY PAYLOAD
# ============================================================
function Invoke-PayloadDeElevated {
    param([string]$Path, [string]$ArgStr, [string]$User, [string]$OutFile, [int]$Limit)

    $taskName = 'PoCVerify_' + ([guid]::NewGuid().ToString('N').Substring(0, 8))
    $workDir  = Split-Path -Parent $Path

    $cmdLine = '/c ""{0}" {1} > "{2}" 2>&1"' -f $Path, $ArgStr, $OutFile

    $action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument $cmdLine -WorkingDirectory $workDir
    $principal = New-ScheduledTaskPrincipal -UserId $User -LogonType Interactive -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                    -ExecutionTimeLimit (New-TimeSpan -Seconds ($Limit + 30)) -StartWhenAvailable
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddYears(1)

    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal `
        -Settings $settings -Trigger $trigger -Force | Out-Null

    try {
        Start-ScheduledTask -TaskName $taskName
        $deadline = (Get-Date).AddSeconds($Limit)
        $state = 'Unknown'
        do {
            Start-Sleep -Milliseconds 500
            $t = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            if ($t) { $state = [string]$t.State }
        } while ((Get-Date) -lt $deadline -and $state -eq 'Running')

        $ti = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue
        $code = $null
        if ($ti) { $code = $ti.LastTaskResult }
        return [pscustomobject]@{ TaskName = $taskName; ExitCode = $code; TimedOut = ($state -eq 'Running') }
    } catch {
        return [pscustomobject]@{ TaskName = $taskName; ExitCode = $null; TimedOut = $false; Error = $_.Exception.Message }
    }
}

function Invoke-PayloadDirect {
    param([string]$Path, [string]$ArgStr, [string]$OutFile, [int]$Limit, [switch]$Show)
    $sp = @{ FilePath = $Path; PassThru = $true; WorkingDirectory = (Split-Path -Parent $Path) }
    if ($ArgStr) { $sp.ArgumentList = $ArgStr }
    if (-not $Show) {
        $sp.RedirectStandardOutput = $OutFile
        $sp.RedirectStandardError  = "$OutFile.err"
        $sp.NoNewWindow = $true
    }
    $p = Start-Process @sp
    if (-not $p.WaitForExit($Limit * 1000)) {
        return [pscustomobject]@{ Process = $p; ExitCode = $null; TimedOut = $true }
    }
    return [pscustomobject]@{ Process = $p; ExitCode = $p.ExitCode; TimedOut = $false }
}

# ============================================================
# 3. THU THẬP BẰNG CHỨNG
# ============================================================
function Get-NewSystemProcesses {
    param([datetime]$Since, [string[]]$Names)

    $wanted = @()
    foreach ($n in $Names) {
        $b = $n -replace '\.exe$', ''
        $wanted += $b.ToLower()
    }

    $found = @()
    $procs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
             Where-Object { $_.CreationDate -and $_.CreationDate -ge $Since }
    foreach ($p in $procs) {
        $base = ($p.Name -replace '\.exe$', '').ToLower()
        if ($wanted -notcontains $base) { continue }
        $sid = Get-ProcessOwnerSid -ProcessId $p.ProcessId
        $found += [pscustomobject]@{
            Name       = $p.Name
            ProcessId  = $p.ProcessId
            ParentPid  = $p.ParentProcessId
            OwnerSid   = $sid
            IsSystem   = ($sid -eq 'S-1-5-18')
            CommandLine= $p.CommandLine
            Created    = $p.CreationDate
        }
    }
    return $found
}

function Get-RecentBugCheck {
    param([datetime]$Since)
    try {
        $ev = Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 1001; StartTime = $Since } -ErrorAction Stop
        return $ev
    } catch { return @() }
}

# ============================================================
# MAIN
# ============================================================
$elevated = Test-IsElevated
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $OutDir) { $OutDir = Join-Path $env:USERPROFILE 'Desktop\poc-verify' }
if (-not (Test-Path -LiteralPath $OutDir)) { New-Item -ItemType Directory -Force -Path $OutDir | Out-Null }

$stateFile = Join-Path $OutDir 'state.json'
$runId = Get-Date -Format 'yyyyMMdd-HHmmss'
$start = Get-Date

Write-Head "verify-poc.ps1 — $runId"

# --- phát hiện lần chạy trước bị treo (nghi BSOD) ---
if (Test-Path -LiteralPath $stateFile) {
    try {
        $prev = Get-Content -LiteralPath $stateFile -Raw | ConvertFrom-Json
        if ($prev.Status -eq 'RUNNING') {
            Write-Warn2 "Lần chạy trước ($($prev.RunId)) KHÔNG kết thúc bình thường."
            Write-Warn2 "Nhiều khả năng VM đã bugcheck/BSOD giữa chừng. Kiểm tra ảnh chụp VM."
        }
    } catch { }
}
@{ RunId = $runId; Status = 'RUNNING'; Payload = $Payload; Started = $start.ToString('o') } |
    ConvertTo-Json | Set-Content -LiteralPath $stateFile -Encoding UTF8

$report = [ordered]@{
    RunId          = $runId
    Payload        = $Payload
    PayloadArgs    = $PayloadArgs
    Cve            = $Cve
    Elevated       = $elevated
    RanAsUser      = $RunAsUser
    Started        = $start.ToString('o')
    Gate           = $null
    Preflight      = [ordered]@{}
    ExitCode       = $null
    TimedOut       = $false
    Evidence       = @()
    Verdict        = 'FAIL'
    Confidence     = 'NONE'
    Notes          = @()
}

# ---------- BƯỚC 1: GATE ----------
Write-Head '1. GATE — patch level & điều kiện tiên quyết'
$gate = Invoke-Gate -CveId $Cve
$report.Gate = $gate

if ($GateOnly) {
    $report.Verdict = $gate.Verdict
    Write-Head "Kết luận gate: $($gate.Verdict)"
    @{ RunId = $runId; Status = 'DONE'; Payload = $Payload } | ConvertTo-Json |
        Set-Content -LiteralPath $stateFile -Encoding UTF8
    return
}

if ($gate.Verdict -eq 'LIKELY_PATCHED' -and -not $SkipGate) {
    Write-Bad 'Dừng: VM có vẻ đã được vá. Chạy tiếp sẽ tạo false negative.'
    Write-Info 'Dùng -SkipGate nếu bạn đã tự xác minh ngược lại.'
    $report.Notes += 'Dừng ở gate: LIKELY_PATCHED'
    $report.Verdict = 'ABORTED_PATCHED'
} else {
    if ($gate.Verdict -eq 'LIKELY_PATCHED' -and $SkipGate) {
        Write-Warn2 'BỎ QUA gate báo PATCHED theo yêu cầu (-SkipGate).'
        Write-Warn2 'Kết quả dưới đây KHÔNG dùng được cho báo cáo benchmark,'
        Write-Warn2 'trừ khi bạn đã tự xác minh VM thật sự chưa vá.'
        $report.Notes += 'Gate báo LIKELY_PATCHED nhưng bị bỏ qua bằng -SkipGate.'
    }
    if ($gate.Verdict -eq 'UNKNOWN' -and -not $SkipGate) {
        Write-Warn2 'Gate UNKNOWN — vẫn chạy tiếp nhưng kết quả chỉ có giá trị nếu bạn tự xác minh VM chưa vá.'
    }

    # ---------- BƯỚC 2: KIỂM TRA QUYỀN ----------
    Write-Head '2. Kiểm tra quyền — quyền để ĐO vs quyền để TEST'
    Write-Info "Phiên hiện tại : $($id.Name)  (elevated: $elevated)"

    if (-not (Test-Path -LiteralPath $Payload)) {
        Write-Bad "Không tìm thấy payload: $Payload"
        return
    }
    $pi = Get-Item -LiteralPath $Payload
    Write-Info ("Payload        : {0} ({1:N0} bytes, sửa {2})" -f $pi.Name, $pi.Length, $pi.LastWriteTime)
    $report.Preflight['PayloadSize'] = $pi.Length

    $useDeElevate = $false
    if ($elevated) {
        if ($RunAsUser) {
            $u = Get-LocalUser -Name $RunAsUser -ErrorAction SilentlyContinue
            if (-not $u) {
                Write-Bad "Không có local user '$RunAsUser'. Tạo trước hoặc chỉ định -RunAsUser khác."
                return
            }
            $isAdminUser = $false
            try {
                $admins = Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue |
                          Where-Object { $_.Name -like "*$RunAsUser" }
                $isAdminUser = ($null -ne $admins)
            } catch { }
            if ($isAdminUser) {
                Write-Bad "'$RunAsUser' thuộc nhóm Administrators — không phải standard user, phép thử LPE vô nghĩa."
                return
            }
            $useDeElevate = $true
            Write-Ok "Payload sẽ chạy hạ quyền xuống: $RunAsUser (RunLevel Limited)"
            $report.Preflight['RunAsUserVerified'] = $true
        } else {
            Write-Bad 'Phiên này đang ELEVATED và không có -RunAsUser.'
            Write-Warn2 'Chạy PoC LPE từ prompt admin là lỗi benchmark nghiêm trọng:'
            Write-Warn2 '  mọi tiến trình con đều là admin/SYSTEM sẵn, nên "pass" không chứng minh được gì.'
            Write-Warn2 "Khởi chạy lại:  .\verify-poc.ps1 -Payload '$Payload' -RunAsUser <standard_user>"
            $report.Verdict = 'ABORTED_NEEDS_RUNASUSER'
            $report.Notes += 'Dừng: cần -RunAsUser để hạ quyền payload.'
        }
    } else {
        Write-Warn2 'Phiên hiện tại KHÔNG elevated.'
        Write-Warn2 '  -> Không đọc được token tiến trình SYSTEM (GetOwner/Get-Process đều bị từ chối).'
        Write-Warn2 '  -> Bằng chứng mạnh nhất (owner SID) sẽ KHÔNG thu thập được.'
        Write-Warn2 '  -> Khuyến nghị: chạy script này từ prompt admin với -RunAsUser.'
        $report.Preflight['ObservationLimited'] = $true
        $report.Notes += 'Chạy non-elevated: bằng chứng bị giới hạn.'
    }

    # ---------- BƯỚC 3: CHẠY ----------
    if ($report.Verdict -ne 'ABORTED_NEEDS_RUNASUSER') {
        Write-Head '3. Chạy payload'
        $stdoutFile = Join-Path $OutDir "$runId.stdout.txt"
        $runStart = Get-Date

        if ($useDeElevate) {
            Write-Info "Qua Scheduled Task, tài khoản $RunAsUser, không elevated."
            $r = Invoke-PayloadDeElevated -Path $Payload -ArgStr $PayloadArgs -User $RunAsUser -OutFile $stdoutFile -Limit $TimeoutSec
            Write-Info "Task: $($r.TaskName)"
            $report.ExitCode = $r.ExitCode
            $report.TimedOut = $r.TimedOut
        } else {
            Write-Info 'Chạy trực tiếp trong phiên hiện tại.'
            $r = Invoke-PayloadDirect -Path $Payload -ArgStr $PayloadArgs -OutFile $stdoutFile -Limit $TimeoutSec -Show:$ShowPayload
            $report.ExitCode = $r.ExitCode
            $report.TimedOut = $r.TimedOut
        }

        if ($report.TimedOut) { Write-Warn2 "Payload vượt quá ${TimeoutSec}s — có thể đang treo." }
        if ($null -ne $report.ExitCode) { Write-Info ("Exit code      : {0}" -f $report.ExitCode) }

        $stdoutText = ''
        if (Test-Path -LiteralPath $stdoutFile) {
            $stdoutText = Get-Content -LiteralPath $stdoutFile -Raw -ErrorAction SilentlyContinue
            if ($stdoutText) {
                Write-Host '  --- stdout payload (40 dòng cuối) ---' -ForegroundColor DarkGray
                ($stdoutText -split "`r?`n" | Where-Object { $_ -ne '' } | Select-Object -Last 40) |
                    ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
                Write-Host '  -------------------------------------' -ForegroundColor DarkGray
            }
        }
        $report.Preflight['StdoutFile'] = $stdoutFile

        Start-Sleep -Seconds 2

        # ---------- BƯỚC 4: BẰNG CHỨNG ----------
        Write-Head '4. Thu thập bằng chứng'
        $evidence = @()

        # --- Tier 1: tiến trình con mang token SYSTEM (cần elevated để đo) ---
        if ($elevated) {
            $sysProcs = Get-NewSystemProcesses -Since $runStart -Names $ExpectProcess
            $hit = $sysProcs | Where-Object { $_.IsSystem }
            if ($hit) {
                foreach ($h in $hit) {
                    Write-Ok ("TIER1 tiến trình SYSTEM mới: {0} (PID {1}, parent {2})" -f $h.Name, $h.ProcessId, $h.ParentPid)
                    $evidence += [pscustomobject]@{ Tier = 1; Kind = 'ChildProcessSystemToken'; Detail = "$($h.Name) PID=$($h.ProcessId) parent=$($h.ParentPid) sid=$($h.OwnerSid) cmd=$($h.CommandLine)" }
                }
            } else {
                if ($sysProcs.Count -gt 0) {
                    Write-Warn2 'Có tiến trình trùng tên nhưng KHÔNG mang token SYSTEM:'
                    foreach ($h in $sysProcs) { Write-Host "       $($h.Name) PID=$($h.ProcessId) sid=$($h.OwnerSid)" -ForegroundColor DarkYellow }
                    Write-Warn2 'Đây là dấu hiệu PoC chạy nhưng KHÔNG leo thang được.'
                } else {
                    Write-Warn2 "Không thấy tiến trình mới nào tên [$($ExpectProcess -join ', ')]."
                }
            }
            if (-not $NoCleanup -and $hit) { $report.Preflight['SpawnedPids'] = @($hit | ForEach-Object { $_.ProcessId }) }
        } else {
            Write-Warn2 'Bỏ qua TIER1 (cần quyền elevated để đọc token tiến trình khác).'
        }

        # --- Tier 2: file artifact ---
        foreach ($f in $ExpectFile) {
            if (Test-Path -LiteralPath $f) {
                $content = Get-Content -LiteralPath $f -Raw -ErrorAction SilentlyContinue
                if ($ExpectFileContains) {
                    if ($content -match [regex]::Escape($ExpectFileContains)) {
                        Write-Ok "TIER2 $f tồn tại và chứa '$ExpectFileContains'"
                        $evidence += [pscustomobject]@{ Tier = 2; Kind = 'ArtifactFile'; Detail = "$f chứa '$ExpectFileContains'" }
                    } else {
                        Write-Warn2 "$f tồn tại nhưng KHÔNG chứa '$ExpectFileContains'"
                    }
                } else {
                    Write-Ok "TIER2 $f tồn tại"
                    $evidence += [pscustomobject]@{ Tier = 2; Kind = 'ArtifactFile'; Detail = "$f tồn tại" }
                }
                $report.Preflight["File_$f"] = ($content -replace "`r?`n", ' | ')
            } else {
                Write-Warn2 "Không thấy file kỳ vọng: $f"
            }
        }

        # --- Tier 3: stdout tự khai (WEAK) ---
        foreach ($s in $ExpectStdout) {
            if ($stdoutText -and ($stdoutText -match [regex]::Escape($s))) {
                Write-Warn2 "TIER3 (WEAK) stdout chứa '$s' — đây là lời khai của chính PoC, không phải bằng chứng độc lập."
                $evidence += [pscustomobject]@{ Tier = 3; Kind = 'SelfReportedStdout'; Detail = "stdout chứa '$s'" }
            }
        }
        if ($null -ne $report.ExitCode -and $report.ExitCode -eq $ExpectExitCode -and $ExpectExitCode -ne 0) {
            Write-Warn2 "TIER3 (WEAK) exit code $($report.ExitCode) khớp kỳ vọng."
            $evidence += [pscustomobject]@{ Tier = 3; Kind = 'ExitCode'; Detail = "exit=$($report.ExitCode)" }
        }

        $report.Evidence = $evidence

        # ---------- KẾT LUẬN ----------
        $tiers = @($evidence | ForEach-Object { $_.Tier })
        if ($tiers -contains 1) { $report.Verdict = 'PASS'; $report.Confidence = 'HIGH' }
        elseif ($tiers -contains 2) { $report.Verdict = 'PASS'; $report.Confidence = 'MEDIUM' }
        elseif ($tiers -contains 3) { $report.Verdict = 'INCONCLUSIVE'; $report.Confidence = 'WEAK' }
        else { $report.Verdict = 'FAIL'; $report.Confidence = 'NONE' }

        # ---------- BUGCHECK ----------
        $bc = Get-RecentBugCheck -Since $runStart
        if ($bc) {
            Write-Bad 'Phát hiện BugCheck trong lúc chạy — kernel exploit gây crash!'
            $report.Notes += ('BugCheck: ' + (@($bc) | ForEach-Object { $_.Message -split "`r?`n" | Select-Object -First 1 }) -join '; ')
        } else {
            Write-Ok 'Không có BugCheck trong cửa sổ chạy.'
        }

        # ---------- EVENT LOG ----------
        if ($CaptureEvents -and $elevated) {
            Write-Head '5. Event log trong cửa sổ chạy'
            $logs = @(
                @{ Name = 'Sysmon EID 1 (ProcessCreate)';    Log = 'Microsoft-Windows-Sysmon/Operational'; Ids = @(1) },
                @{ Name = 'Sysmon EID 17/18 (Pipe)';         Log = 'Microsoft-Windows-Sysmon/Operational'; Ids = @(17, 18) },
                @{ Name = 'Security EID 4688 (Process)';     Log = 'Security'; Ids = @(4688) }
            )
            $report.Preflight['Events'] = [ordered]@{}
            foreach ($l in $logs) {
                try {
                    $ev = Get-WinEvent -FilterHashtable @{ LogName = $l.Log; Id = $l.Ids; StartTime = $runStart } -ErrorAction Stop
                    $report.Preflight['Events'][$l.Name] = @($ev).Count
                    if (@($ev).Count -gt 0) { Write-Ok ("{0}: {1} sự kiện" -f $l.Name, @($ev).Count) }
                    else { Write-Info ("{0}: 0 sự kiện" -f $l.Name) }
                } catch {
                    $report.Preflight['Events'][$l.Name] = 'unavailable'
                    Write-Info ("{0}: không đọc được log" -f $l.Name)
                }
            }
        }

        # ---------- CLEANUP ----------
        if (-not $NoCleanup -and $report.Preflight.Contains('SpawnedPids')) {
            Write-Head '6. Dọn dẹp'
            foreach ($pid in $report.Preflight['SpawnedPids']) {
                try { Stop-Process -Id $pid -Force -ErrorAction Stop; Write-Info "Đã kill PID $pid" } catch { }
            }
        }
    }
}

# ---------- XUẤT BÁO CÁO ----------
$report['Finished'] = (Get-Date).ToString('o')
$jsonPath = Join-Path $OutDir "$runId.result.json"
$mdPath   = Join-Path $OutDir "$runId.result.md"
$report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $jsonPath -Encoding UTF8

$color = 'Red'
if ($report.Verdict -eq 'PASS') { $color = 'Green' }
elseif ($report.Verdict -eq 'INCONCLUSIVE') { $color = 'Yellow' }

Write-Head 'KẾT LUẬN'
Write-Host ("  {0}" -f $report.Verdict) -ForegroundColor $color
Write-Host ("  Độ tin cậy: {0}" -f $report.Confidence) -ForegroundColor $color
if ($report.Verdict -eq 'FAIL') {
    Write-Host '  Lưu ý: FAIL chỉ có nghĩa nếu gate cho thấy VM CHƯA vá.' -ForegroundColor Yellow
    Write-Host '         Nếu gate UNKNOWN/PATCHED thì đây là dương tính giả của môi trường,' -ForegroundColor Yellow
    Write-Host '         KHÔNG phải bằng chứng EDR chặn được.' -ForegroundColor Yellow
}
Write-Info "JSON: $jsonPath"

$kernelVer = 'unknown'
if ($report.Gate -and $report.Gate.Kernel) { $kernelVer = [string]$report.Gate.Kernel.FileVersion }
$ranAs = $id.Name + ' (không hạ quyền)'
if ($RunAsUser) { $ranAs = $RunAsUser }

$md = @()
$md += "# Kết quả kiểm tra PoC — $runId"
$md += ''
$md += "| Trường | Giá trị |"
$md += "|---|---|"
$md += "| Payload | ``$Payload`` |"
$md += "| CVE | $Cve |"
$md += "| Gate | $($report.Gate.Verdict) — $($report.Gate.Reason) |"
$md += "| Kernel | $kernelVer |"
$md += "| Chạy dưới tài khoản | $ranAs |"
$md += "| Exit code | $($report.ExitCode) |"
$md += "| **Kết luận** | **$($report.Verdict)** ($($report.Confidence)) |"
$md += ''
$md += '## Bằng chứng'
$md += ''
if (@($report.Evidence).Count -eq 0) { $md += '*Không thu được bằng chứng nào.*' }
else {
    $md += "| Tier | Loại | Chi tiết |"
    $md += "|---|---|---|"
    foreach ($e in $report.Evidence) { $md += "| $($e.Tier) | $($e.Kind) | $($e.Detail) |" }
}
$md += ''
if (@($report.Notes).Count -gt 0) {
    $md += '## Ghi chú'
    $md += ''
    foreach ($n in $report.Notes) { $md += "- $n" }
    $md += ''
}
$md += '> Tier 1 = bằng chứng độc lập mạnh nhất (token SYSTEM quan sát từ ngoài).'
$md += '> Tier 3 = lời khai của chính PoC — KHÔNG dùng để kết luận trong báo cáo benchmark.'
$md | Set-Content -LiteralPath $mdPath -Encoding UTF8
Write-Info "Markdown: $mdPath"

@{ RunId = $runId; Status = 'DONE'; Payload = $Payload; Verdict = $report.Verdict } |
    ConvertTo-Json | Set-Content -LiteralPath $stateFile -Encoding UTF8
