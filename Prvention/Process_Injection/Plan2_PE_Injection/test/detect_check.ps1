# detect_check.ps1 — EDR detection verification for PE Injection (Doppelganging)
Write-Host "=== EDR Detection Check: PE Injection (T1055.002) ===" -ForegroundColor Cyan

$checks = @()

# Check 1: Sysmon Event ID 1 (Process Creation)
Write-Host "`n[1] Sysmon Event 1 — Process Creation..." -ForegroundColor Yellow
$evt1 = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=1]]" -MaxEvents 50 -ErrorAction SilentlyContinue |
    Where-Object { $_.TimeCreated -gt (Get-Date).AddMinutes(-5) }
if ($evt1) {
    $ghostProcs = $evt1 | Where-Object { $_.Message -match "Tasks\.dll" }
    if ($ghostProcs) {
        Write-Host "    [i] Ghost process creation event seen (expected)"
        Write-Host "    Image: Tasks.dll — legitimate-looking path"
        Write-Host "    [!] Check if EDR flagged this event" -ForegroundColor Yellow
        $checks += "Event1:GhostProcessCreation"
    }
}

# Check 2: Sysmon Event 11 (File Creation)
Write-Host "[2] Sysmon Event 11 — File Creation..." -ForegroundColor Yellow
$evt11 = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=11]]" -MaxEvents 50 -ErrorAction SilentlyContinue |
    Where-Object { $_.TimeCreated -gt (Get-Date).AddMinutes(-5) }
if ($evt11) {
    $ghostFiles = $evt11 | Where-Object { $_.Message -match "Tasks\.dll|PEInjection" }
    if ($ghostFiles) {
        Write-Host "    [!] Ghost file creation detected on disk" -ForegroundColor Red
        $checks += "Event11:GhostFileCreation"
    } else {
        Write-Host "    [+] No ghost file creation events" -ForegroundColor Green
    }
}

# Check 3: NTFS Transaction events
Write-Host "[3] NTFS Transaction events..." -ForegroundColor Yellow
$txfEvts = Get-WinEvent -LogName "System" -MaxEvents 100 -ErrorAction SilentlyContinue |
    Where-Object { $_.TimeCreated -gt (Get-Date).AddMinutes(-5) -and $_.Id -in @(134, 135, 136, 137) }
if ($txfEvts) {
    Write-Host "    [!] NTFS transaction events found (KTM)" -ForegroundColor Red
    $checks += "KTM:TransactionEvents"
} else {
    Write-Host "    [+] No NTFS transaction events" -ForegroundColor Green
}

# Check 4: AppLocker / WDAC
Write-Host "[4] AppLocker / WDAC..." -ForegroundColor Yellow
$appLocker = Get-WinEvent -LogName "Microsoft-Windows-AppLocker/EXE and DLL" -MaxEvents 10 -ErrorAction SilentlyContinue |
    Where-Object { $_.TimeCreated -gt (Get-Date).AddMinutes(-5) }
if ($appLocker) {
    Write-Host "    [!] AppLocker events found" -ForegroundColor Red
    $checks += "AppLocker:Events"
} else {
    Write-Host "    [+] No AppLocker events" -ForegroundColor Green
}

# Check 5: Defender
Write-Host "[5] Windows Defender..." -ForegroundColor Yellow
try {
    $mpThreats = Get-MpThreatDetection -ErrorAction Stop |
        Where-Object { $_.InitialDetectionTime -gt (Get-Date).AddMinutes(-5) }
    if ($mpThreats) {
        Write-Host "    [!] Recent Defender detections!" -ForegroundColor Red
        $checks += "Defender:ThreatDetected"
    } else {
        Write-Host "    [+] No recent Defender detections" -ForegroundColor Green
    }
} catch {
    Write-Host "    [i] Defender not available" -ForegroundColor Gray
}

# Summary
Write-Host "`n=== Summary ===" -ForegroundColor Cyan
if ($checks.Count -eq 0) {
    Write-Host "[+] EDR bypass successful — no detection events found" -ForegroundColor Green
} elseif ($checks.Count -eq 1 -and $checks[0] -match "GhostProcessCreation") {
    Write-Host "[~] Process creation event seen but with legitimate path — likely not flagged" -ForegroundColor Yellow
} else {
    Write-Host "[-] Potential detection vectors: $($checks -join ', ')" -ForegroundColor Red
}
