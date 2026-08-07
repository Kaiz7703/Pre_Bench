# run_test.ps1 — Plan 1 DLL Injection test runner
# Run as Administrator or SYSTEM
param(
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"
$PlanDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ExePath = Join-Path $PlanDir "..\DLLInjection.exe"

Write-Host "=== Plan 1: DLL Injection Test (T1055.001) ===" -ForegroundColor Cyan
Write-Host "Technique: Module Stomping + Early Bird APC Injection`n"

# Build if needed
if (-not $SkipBuild -and -not (Test-Path $ExePath)) {
    Write-Host "[*] Building..." -ForegroundColor Yellow
    Push-Location $PlanDir
    & cmd /c "build.bat"
    Pop-Location
    if (-not (Test-Path $ExePath)) {
        Write-Host "[ERR] Build failed" -ForegroundColor Red
        exit 1
    }
}

# Check privilege
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[WARN] Not running as Administrator — injection may fail" -ForegroundColor Yellow
}

# Run the tool
Write-Host "[*] Running DLLInjection.exe..." -ForegroundColor Yellow
$result = & $ExePath 2>&1
$exitCode = $LASTEXITCODE
Write-Host $result

# Check results
Write-Host "`n[*] Verifying results..." -ForegroundColor Yellow

# Check ADS
$adsFiles = @(
    "C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx",
    "C:\Windows\System32\winevt\Logs\Application.evtx"
)

$foundAds = $false
foreach ($f in $adsFiles) {
    try {
        $stream = Get-Item $f -Stream DLLINJ -ErrorAction Stop
        if ($stream) {
            Write-Host "[+] ADS found: $f`:DLLINJ" -ForegroundColor Green
            $content = Get-Content $f -Stream DLLINJ -Raw
            Write-Host "    Content: $content"
            $foundAds = $true
            break
        }
    } catch {}
}

if (-not $foundAds) {
    Write-Host "[-] ADS not found (may be on alternate target)" -ForegroundColor Yellow
}

Write-Host "`n=== Test Complete (exit code: $exitCode) ===" -ForegroundColor Cyan
