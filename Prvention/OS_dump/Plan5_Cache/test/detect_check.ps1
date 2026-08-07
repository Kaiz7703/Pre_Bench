# detect_check.ps1 — EDR detection check for cached credential extraction
# Checks for alerts from multi-source credential access
param([int]$LookbackMinutes = 10)

Write-Host "  === EDR Detection Check (Cached Credential Dump) ==="

$startTime = (Get-Date).AddMinutes(-$LookbackMinutes)
$detections = 0

# ─── Security Events ───
Write-Host "  [*] Checking Security event log..."
$secEvents = Get-WinEvent -LogName Security -MaxEvents 200 -EA SilentlyContinue |
    Where-Object { $_.TimeCreated -gt $startTime }

if ($secEvents) {
    # Event 4663 — Object Access (SECURITY hive, LSASS, browser DBs)
    $e4663 = $secEvents | Where-Object { $_.Id -eq 4663 }
    if ($e4663) {
        Write-Host "  [!] Event 4663 (Object Access): $($e4663.Count) events" -ForegroundColor Yellow
        $detections++
    }

    # Event 4656 — Handle Requested (LSASS)
    $e4656 = $secEvents | Where-Object { $_.Id -eq 4656 }
    $lsassEvents = $e4656 | Where-Object { $_.Message -match "lsass" }
    if ($lsassEvents) {
        Write-Host "  [!] Event 4656 (LSASS Handle): $($lsassEvents.Count) events" -ForegroundColor Yellow
        $detections++
    }

    # Event 4688 — Process Creation
    $e4688 = $secEvents | Where-Object { $_.Id -eq 4688 }
    $cacheProc = $e4688 | Where-Object { $_.Message -match "CacheDump" }
    if ($cacheProc) {
        Write-Host "  [!] Event 4688 (CacheDump.exe): $($cacheProc.Count) events" -ForegroundColor Red
        $detections++
    }

    # Event 5156 — Network Connection (Wi-Fi netsh)
    $e5156 = $secEvents | Where-Object { $_.Id -eq 5156 }
    if ($e5156) {
        Write-Host "  [i] Event 5156 (Network): $($e5156.Count) events" -ForegroundColor DarkGray
    }
}

# ─── Sysmon Events ───
$sysmonLog = "Microsoft-Windows-Sysmon/Operational"
try {
    $sysmonEvents = Get-WinEvent -LogName $sysmonLog -MaxEvents 200 -EA SilentlyContinue |
        Where-Object { $_.TimeCreated -gt $startTime }

    if ($sysmonEvents) {
        # Event 10 — Process Access (LSASS)
        $e10 = $sysmonEvents | Where-Object { $_.Id -eq 10 }
        $lsassAccess = $e10 | Where-Object { $_.Message -match "lsass" }
        if ($lsassAccess) {
            Write-Host "  [!] Sysmon Event 10 (LSASS Access): $($lsassAccess.Count) events" -ForegroundColor Red
            $detections++
        }

        # Event 11 — File Create
        $e11 = $sysmonEvents | Where-Object { $_.Id -eq 11 }
        $credFiles = $e11 | Where-Object {
            $_.Message -match "Credentials" -or $_.Message -match "Login Data" -or
            $_.Message -match "logins.json"
        }
        if ($credFiles) {
            Write-Host "  [!] Sysmon Event 11 (Credential File Access): $($credFiles.Count)" -ForegroundColor Red
            $detections++
        }

        # Event 1 — Process Creation (netsh, cmdkey)
        $e1 = $sysmonEvents | Where-Object { $_.Id -eq 1 }
        $suspProc = $e1 | Where-Object {
            $_.Message -match "netsh.*wlan" -or $_.Message -match "cmdkey"
        }
        if ($suspProc) {
            Write-Host "  [i] Sysmon Event 1 (netsh/cmdkey): $($suspProc.Count)" -ForegroundColor DarkGray
        }
    }
} catch {
    Write-Host "  [i] Sysmon log not available" -ForegroundColor DarkGray
}

# ─── Defender ───
Write-Host "  [*] Checking Defender events..."
$defenderLog = "Microsoft-Windows-Windows Defender/Operational"
try {
    $defEvents = Get-WinEvent -LogName $defenderLog -MaxEvents 50 -EA SilentlyContinue |
        Where-Object { $_.TimeCreated -gt $startTime }
    if ($defEvents) {
        $malware = $defEvents | Where-Object { $_.Id -in @(1116, 1117, 1118, 1119) }
        if ($malware) {
            Write-Host "  [!] Defender malware detection: $($malware.Count)" -ForegroundColor Red
            $detections++
        }
    }
} catch {
    Write-Host "  [i] Defender log not available" -ForegroundColor DarkGray
}

# ─── Summary ───
Write-Host ""
if ($detections -eq 0) {
    Write-Host "  [+] No EDR detections found (clean run)" -ForegroundColor Green
} else {
    Write-Host "  [!] Total detection categories: $detections" -ForegroundColor Yellow
}
Write-Host "  === End Detection Check ==="
