# run_test.ps1 — Plan 2 PE Injection test runner
param([switch]$SkipBuild)

$ErrorActionPreference = "Stop"
$PlanDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ExePath = Join-Path $PlanDir "..\PEInjection.exe"

Write-Host "=== Plan 2: PE Injection Test (T1055.002) ===" -ForegroundColor Cyan
Write-Host "Technique: Process Doppelganging via NTFS Transaction`n"

if (-not $SkipBuild -and -not (Test-Path $ExePath)) {
    Write-Host "[*] Building..." -ForegroundColor Yellow
    Push-Location $PlanDir
    & cmd /c "build.bat"
    Pop-Location
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[WARN] Not running as Administrator" -ForegroundColor Yellow
}

# Run
Write-Host "[*] Running PEInjection.exe..." -ForegroundColor Yellow
$result = & $ExePath 2>&1
$exitCode = $LASTEXITCODE
Write-Host $result

# Verify
Write-Host "`n[*] Verifying results..." -ForegroundColor Yellow

# Check ghost file does NOT exist
$ghostPath = "C:\Windows\System32\Tasks.dll"
if (Test-Path $ghostPath) {
    Write-Host "[!] Ghost file EXISTS on disk: $ghostPath" -ForegroundColor Red
    Write-Host "    Doppelganging may have failed (TxF might have committed)"
} else {
    Write-Host "[+] Ghost file does NOT exist on disk: $ghostPath" -ForegroundColor Green
}

# Check ADS
$adsFiles = @(
    "C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx",
    "C:\Windows\System32\winevt\Logs\Application.evtx"
)
foreach ($f in $adsFiles) {
    try {
        $stream = Get-Item $f -Stream PEINJ -ErrorAction Stop
        if ($stream) {
            Write-Host "[+] ADS found: $f`:PEINJ" -ForegroundColor Green
            $content = Get-Content $f -Stream PEINJ -Raw
            Write-Host "    Content: $content"
            break
        }
    } catch {}
}

# Check TxF status
Write-Host "`n[*] Checking TxF status..." -ForegroundColor Yellow
$txfStatus = & fsutil behavior query TxF 2>&1
Write-Host "    $txfStatus"

Write-Host "`n=== Test Complete (exit code: $exitCode) ===" -ForegroundColor Cyan
