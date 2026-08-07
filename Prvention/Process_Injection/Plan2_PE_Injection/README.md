# Plan 2 — PE Injection (T1055.002)

**Technique**: Process Doppelgänging via NTFS Transaction (TxF)
**Pre-condition**: SYSTEM or Administrator
**Ghost file**: C:\Windows\System32\Tasks.dll (masquerading)

## Quick Start

```powershell
# Run as Administrator or SYSTEM
.\PEInjection.exe
```

## Attack Chain

1. **InitSyscallResolver()** — Read clean ntdll.dll from disk, extract SSN, build indirect syscall stubs
2. **PatchEtw()** — Overwrite `EtwEventWrite` with `xor eax,eax; ret`
3. **ReadPayloadExe()** — Read legitimate signed EXE from System32 as payload template
4. **CreateTransaction()** — `NtCreateTransaction` (NTFS TxF)
5. **CreateGhostFile()** — `NtCreateFile` within transaction → file only visible in TxF scope
6. **WriteGhostFile()** — `NtWriteFile` → PE payload in transacted file
7. **CreateGhostSection()** — `NtCreateSection(SEC_IMAGE)` → kernel parses PE, maps sections
8. **CreateProcessFromSection()** — `NtCreateProcessEx` + `NtCreateThreadEx` → process from ghost image
9. **RollbackAndCleanup()** — `NtRollbackTransaction` → ghost file vanishes (never existed)
10. **Resume** → process executes with no backing file on disk

## Bypass Layers

| Layer | Technique |
|-------|-----------|
| File-based AV scan | PE never existed on disk → nothing to scan |
| `PsSetCreateProcessNotifyRoutineEx` | ImageFileName = System32\Tasks.dll (legitimate path) |
| Process from non-existent file | TxF rollback after process creation — file vanished |
| `PsSetLoadImageNotifyRoutine` | SEC_IMAGE from transacted file — path looks legitimate |
| NTFS transaction monitoring | TxF blind spot — deprecated but functional, few EDR monitor |
| Userland hooks | Indirect syscalls for all sensitive operations |
| ETW Process Creation | Event fires with legitimate image path |
| Memory scan (RWX) | Kernel PE mapping → Image type with RX — EDR skips |
| Minifilter detection | File operations scoped to transaction — not committed |
| USN Journal / forensics | No journal entry for uncommitted transaction |

## Output

- Success marker written to ADS: `C:\Windows\System32\winevt\Logs\...\Sysmon*.evtx:PEINJ`
- Ghost file path + PID + timestamp recorded
- Verification: `GetFileAttributes(ghostPath)` returns INVALID (file doesn't exist)

## Detection Check

```powershell
# Verify ghost file doesn't exist on disk
Test-Path "C:\Windows\System32\Tasks.dll"

# Check for ADS output  
Get-Item "C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx" -Stream PEINJ -ErrorAction SilentlyContinue

# Check EDR logs
.\test\detect_check.ps1

# Check TxF status
fsutil behavior query TxF
```

## Build

```batch
build.bat
# Requires: Visual Studio 2022 + Windows SDK 10.0.26100.0
```

## Notes

- Requires NTFS volume with TxF enabled (default on Windows 10/11)
- Ghost file path `C:\Windows\System32\Tasks.dll` chosen for masquerading
- Payload is a legitimate signed Microsoft EXE (hostname.exe/whoami.exe)
- The technique is the benchmark — payload action is benign
- Process runs normally after transaction rollback (kernel holds references)
