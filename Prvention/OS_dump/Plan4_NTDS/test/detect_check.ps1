# detect_check.ps1 — EDR detection check for NTDS dump operations
# Checks for alerts triggered by NTDS.dit access, VSS usage, raw volume reads

param(
    [int]$LookbackMinutes = 10
)

Write-Host "  === EDR Detection Check (NTDS Dump) ==="

$startTime = (Get-Date).AddMinutes(-$LookbackMinutes)
$detections = 0

# ─── Security Event Log ───
Write-Host "  [*] Checking Security event log..."
$secEvents = Get-WinEvent -LogName Security -MaxEvents 200 -EA SilentlyContinue |
    Where-Object { $_.TimeCreated -gt $startTime }

if ($secEvents) {
    # Event 4663 — Object Access (NTDS.dit)
    $e4663 = $secEvents | Where-Object { $_.Id -eq 4663 }
    if ($e4663) {
        Write-Host "  [!] Event 4663 (Object Access): $($e4663.Count) events" -ForegroundColor Yellow
        $detections++
    }

    # Event 4656 — Handle Requested
    $e4656 = $secEvents | Where-Object { $_.Id -eq 4656 }
    if ($e4656) {
        Write-Host "  [!] Event 4656 (Handle Requested): $($e4656.Count) events" -ForegroundColor Yellow
        $detections++
    }

    # Event 4662 — Directory Service Operation (DCSync-like)
    $e4662 = $secEvents | Where-Object { $_.Id -eq 4662 }
    if ($e4662) {
        Write-Host "  [!] Event 4662 (Directory Service Operation): $($e4662.Count) events" -ForegroundColor Red
        $detections++
    }
}

# ─── Sysmon Events ───
$sysmonLog = "Microsoft-Windows-Sysmon/Operational"
try {
    $sysmonEvents = Get-WinEvent -LogName $sysmonLog -MaxEvents 200 -EA SilentlyContinue |
        Where-Object { $_.TimeCreated -gt $startTime }

    if ($sysmonEvents) {
        # Event 1 — Process Creation
        $e1 = $sysmonEvents | Where-Object { $_.Id -eq 1 }
        # Check for NTDSDump.exe
        $ntdsProc = $e1 | Where-Object {
            $_.Message -match "NTDSDump" -or $_.Message -match "ntdsutil"
        }
        if ($ntdsProc) {
            Write-Host "  [!] Sysmon Event 1 (NTDSDump.exe created): $($ntdsProc.Count) events" -ForegroundColor Red
            $detections++
        }

        # Event 11 — File Create
        $e11 = $sysmonEvents | Where-Object { $_.Id -eq 11 }
        $ntdsFileCreate = $e11 | Where-Object {
            $_.Message -match "ntds.dit" -or $_.Message -match "NTDS"
        }
        if ($ntdsFileCreate) {
            Write-Host "  [!] Sysmon Event 11 (NTDS.dit file created): $($ntdsFileCreate.Count) events" -ForegroundColor Red
            $detections++
        }

        # Event 9 — Raw Access Read (volume read)
        $e9 = $sysmonEvents | Where-Object { $_.Id -eq 9 }
        if ($e9) {
            Write-Host "  [!] Sysmon Event 9 (Raw Access Read): $($e9.Count) events" -ForegroundColor Yellow
            $detections++
        }
    }
} catch {
    Write-Host "  [i] Sysmon log not available" -ForegroundColor DarkGray
}

# ─── Windows Defender ───
Write-Host "  [*] Checking Defender operational events..."
$defenderLog = "Microsoft-Windows-Windows Defender/Operational"
try {
    $defEvents = Get-WinEvent -LogName $defenderLog -MaxEvents 50 -EA SilentlyContinue |
        Where-Object { $_.TimeCreated -gt $startTime }

    if ($defEvents) {
        $malware = $defEvents | Where-Object { $_.Id -in @(1116, 1117, 1118, 1119) }
        if ($malware) {
            Write-Host "  [!] Windows Defender malware detection: $($malware.Count) events" -ForegroundColor Red
            $detections++
        }
    }
} catch {
    Write-Host "  [i] Defender log not available" -ForegroundColor DarkGray
}

# ─── Application EDR ───
Write-Host "  [*] Checking application EDR logs..."

$edrSources = @(
    "CrowdStrike",
    "Carbon Black",
    "SentinelOne",
    "Microsoft Defender for Endpoint",
    "Trend Micro",
    "Symantec Endpoint Protection",
    "McAfee Endpoint Security"
)

Get-WinEvent -LogName Application -MaxEvents 100 -EA SilentlyContinue |
    Where-Object { $_.TimeCreated -gt $startTime } |
    ForEach-Object {
        foreach ($src in $edrSources) {
            if ($_.ProviderName -match $src -or $_.Message -match $src) {
                Write-Host "  [!] $src event detected: Event $($_.Id)" -ForegroundColor Yellow
                $detections++
            }
        }
    }

# ─── VSS Events ───
Write-Host "  [*] Checking VSS/Volume Shadow Copy events..."
try {
    $sysEvents = Get-WinEvent -LogName System -MaxEvents 200 -EA SilentlyContinue |
        Where-Object { $_.TimeCreated -gt $startTime }

    $vssEvents = $sysEvents | Where-Object { $_.Id -in @(8222, 2001, 2005, 2006, 33, 98) }
    if ($vssEvents) {
        Write-Host "  [!] VSS-related events: $($vssEvents.Count) events" -ForegroundColor Yellow
        $vssEvents | Select-Object Id, TimeCreated -First 3 |
            ForEach-Object { Write-Host "      Event $($_.Id) @ $($_.TimeCreated)" -ForegroundColor DarkGray }
        $detections++
    }
} catch {
    Write-Host "  [i] System log not available" -ForegroundColor DarkGray
}

# ─── Summary ───
Write-Host ""
if ($detections -eq 0) {
    Write-Host "  [+] No EDR detections found (clean run)" -ForegroundColor Green
} else {
    Write-Host "  [!] Total detection categories: $detections" -ForegroundColor Yellow
}
Write-Host "  === End Detection Check ==="
