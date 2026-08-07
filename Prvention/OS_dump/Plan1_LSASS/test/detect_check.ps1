# detect_check.ps1 — Check for EDR alerts after LSASS dump operation
param(
    [int]$MinutesBack = 10,
    [switch]$Detailed
)

$cutoff = (Get-Date).AddMinutes(-$MinutesBack)
$alertsFound = 0

Write-Host "[*] Checking for EDR alerts (last ${MinutesBack} min)..." -ForegroundColor Cyan

# ─── Windows Security Event Log ───
Write-Host "`n--- Security Event Log ---" -ForegroundColor Yellow

# Event IDs to watch
# 4663: Object access (SAM/SECURITY access)
# 4656: Handle to object requested
# 4688: Process creation
# 5156: Windows Filtering Platform (network)
# 10:   Sysmon: ProcessAccess (LSASS access)
# 11:   Sysmon: FileCreate
# 8:    Sysmon: CreateRemoteThread

$watchEvents = @(4663, 4656, 4688, 5156)

try {
    $events = Get-WinEvent -LogName Security -MaxEvents 200 -ErrorAction Stop |
        Where-Object { $_.TimeCreated -gt $cutoff -and $_.Id -in $watchEvents }

    if ($events) {
        $grouped = $events | Group-Object Id
        foreach ($g in $grouped) {
            $name = switch ($g.Name) {
                4663 { "Object Access" }
                4656 { "Handle Request" }
                4688 { "Process Create" }
                5156 { "WFP Network" }
                default { "Unknown" }
            }
            Write-Host "  Event $($g.Name) ($name): $($g.Count) instances" -ForegroundColor Yellow
            $alertsFound += $g.Count
        }
    } else {
        Write-Host "  No suspicious security events found" -ForegroundColor Green
    }
} catch {
    Write-Host "  Security log not accessible" -ForegroundColor DarkYellow
}

# ─── Sysmon Event Log ───
Write-Host "`n--- Sysmon Event Log ---" -ForegroundColor Yellow

try {
    $sysmonEvents = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 100 -ErrorAction Stop |
        Where-Object { $_.TimeCreated -gt $cutoff }

    if ($sysmonEvents) {
        $grouped = $sysmonEvents | Group-Object Id
        foreach ($g in $grouped) {
            $name = switch ($g.Name) {
                10  { "ProcessAccess (LSASS)" }
                8   { "CreateRemoteThread" }
                11  { "FileCreate" }
                7   { "ImageLoad" }
                1   { "ProcessCreate" }
                3   { "NetworkConnect" }
                default { "Unknown" }
            }
            Write-Host "  Sysmon Event $($g.Name) ($name): $($g.Count) instances" -ForegroundColor Yellow
            $alertsFound += $g.Count

            if ($Detailed -and $g.Name -eq 10) {
                # Show LSASS access details
                foreach ($evt in $g.Group) {
                    $xml = [xml]$evt.ToXml()
                    $data = $xml.Event.EventData.Data
                    $srcProc = ($data | Where-Object { $_.Name -eq 'SourceImage' }).'#text'
                    $targetProc = ($data | Where-Object { $_.Name -eq 'TargetImage' }).'#text'
                    if ($targetProc -match 'lsass') {
                        Write-Host "    LSASS ACCESS: $srcProc -> $targetProc" -ForegroundColor Red
                    }
                }
            }
        }
    } else {
        Write-Host "  No Sysmon events found" -ForegroundColor Green
    }
} catch {
    Write-Host "  Sysmon log not found or not accessible" -ForegroundColor DarkYellow
}

# ─── Application Event Log (EDR-specific) ───
Write-Host "`n--- Application Event Log (EDR) ---" -ForegroundColor Yellow

$edrSources = @("Microsoft Defender Antivirus", "Windows Defender",
    "CrowdStrike", "Carbon Black", "SentinelOne", "Cybereason")

try {
    $appEvents = Get-WinEvent -LogName Application -MaxEvents 100 -ErrorAction Stop |
        Where-Object { $_.TimeCreated -gt $cutoff -and $_.ProviderName -in $edrSources }

    if ($appEvents) {
        foreach ($evt in $appEvents) {
            Write-Host "  $($evt.ProviderName): ID=$($evt.Id) Level=$($evt.LevelDisplayName)" -ForegroundColor Red
            $alertsFound++
        }
    } else {
        Write-Host "  No EDR-specific application events" -ForegroundColor Green
    }
} catch {
    Write-Host "  Application log not accessible" -ForegroundColor DarkYellow
}

# ─── Check Process Artifacts ───
Write-Host "`n--- Process Artifacts ---" -ForegroundColor Yellow

$suspiciousProcs = @("svchost.exe -k LocalService")
$foundProcs = Get-Process | Where-Object { $_.ProcessName -eq "svchost" } |
    Select-Object Id, ProcessName, StartTime

# Check for strange svchost instances
$svchostCount = ($foundProcs | Measure-Object).Count
Write-Host "  Running svchost.exe instances: $svchostCount" -ForegroundColor $(
    if ($svchostCount -gt 80) { "Yellow" } else { "Green" }
)

# ─── Summary ───
Write-Host "`n============================================" -ForegroundColor Cyan
if ($alertsFound -eq 0) {
    Write-Host "  RESULT: NO EDR alerts detected" -ForegroundColor Green
} else {
    Write-Host "  RESULT: $alertsFound potential alerts detected" -ForegroundColor Red
    Write-Host "  NOTE: Review events above for false positives" -ForegroundColor Yellow
}
Write-Host "============================================" -ForegroundColor Cyan

exit $alertsFound
