# detect_check.ps1 — EDR detection verification for DLL Injection
Write-Host "=== EDR Detection Check: DLL Injection (T1055.001) ===" -ForegroundColor Cyan

$checks = @()

# Check 1: Sysmon Event ID 8 (CreateRemoteThread)
Write-Host "`n[1] Sysmon Event 8 — CreateRemoteThread..." -ForegroundColor Yellow
$evt8 = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=8]]" -MaxEvents 50 -ErrorAction SilentlyContinue |
    Where-Object { $_.TimeCreated -gt (Get-Date).AddMinutes(-5) }
if ($evt8) {
    Write-Host "    [!] Recent CreateRemoteThread events found" -ForegroundColor Red
    $checks += "Event8:CreateRemoteThread"
} else {
    Write-Host "    [+] No CreateRemoteThread events" -ForegroundColor Green
}

# Check 2: Sysmon Event ID 7 (Image Loaded - DLL)
Write-Host "[2] Sysmon Event 7 — Image Load..." -ForegroundColor Yellow
$evt7 = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=7]]" -MaxEvents 50 -ErrorAction SilentlyContinue |
    Where-Object { $_.TimeCreated -gt (Get-Date).AddMinutes(-5) }
if ($evt7) {
    Write-Host "    [i] $($evt7.Count) image load events in last 5 min"
    $suspicious = $evt7 | Where-Object { $_.Message -match "RuntimeBroker|DLLInjection" }
    if ($suspicious) {
        Write-Host "    [!] Suspicious image load in target process" -ForegroundColor Red
        $checks += "Event7:SuspiciousImageLoad"
    }
} else {
    Write-Host "    [+] No image load events" -ForegroundColor Green
}

# Check 3: Windows Defender / Antivirus
Write-Host "[3] Windows Defender detection..." -ForegroundColor Yellow
try {
    $mpThreats = Get-MpThreatDetection -ErrorAction Stop |
        Where-Object { $_.InitialDetectionTime -gt (Get-Date).AddMinutes(-5) }
    if ($mpThreats) {
        Write-Host "    [!] Recent Defender detections!" -ForegroundColor Red
        $mpThreats | Format-List ThreatName, Resources
        $checks += "Defender:ThreatDetected"
    } else {
        Write-Host "    [+] No recent Defender detections" -ForegroundColor Green
    }
} catch {
    Write-Host "    [i] Defender not available or not running" -ForegroundColor Gray
}

# Check 4: ETW Provider events
Write-Host "[4] ETW Threat Intelligence..." -ForegroundColor Yellow
$etwTi = Get-WinEvent -LogName "Microsoft-Windows-Threat-Intelligence/Operational" -MaxEvents 10 -ErrorAction SilentlyContinue |
    Where-Object { $_.TimeCreated -gt (Get-Date).AddMinutes(-5) }
if ($etwTi) {
    Write-Host "    [!] ETW TI events found" -ForegroundColor Red
    $checks += "ETW:ThreatIntelligence"
} else {
    Write-Host "    [+] No ETW TI events" -ForegroundColor Green
}

# Summary
Write-Host "`n=== Summary ===" -ForegroundColor Cyan
if ($checks.Count -eq 0) {
    Write-Host "[+] EDR bypass successful — no detection events found" -ForegroundColor Green
} else {
    Write-Host "[-] Potential detection vectors: $($checks -join ', ')" -ForegroundColor Red
    Write-Host "    Review each vector for false positive vs true detection"
}
