# Plan 1 — DLL Injection (T1055.001)

**Technique**: Module Stomping + Early Bird APC Injection
**Pre-condition**: SYSTEM or Administrator
**Target process**: RuntimeBroker.exe (Microsoft signed, HIGH integrity)

## Quick Start

```powershell
# Run as Administrator or SYSTEM
.\DLLInjection.exe
```

## Attack Chain

1. **InitSyscallResolver()** — Read clean ntdll.dll from disk, extract SSN, build indirect syscall stubs (RW→RX)
2. **PatchEtw()** — Overwrite `EtwEventWrite` with `xor eax,eax; ret`
3. **CreateSuspendedTarget()** — `NtCreateUserProcess` (SUSPENDED) with PPID=services.exe
4. **ModuleStomp()** — Find msxml3.dll in target PEB → overwrite .text section with PIC payload
5. **EarlyBirdApc()** — `NtQueueApcThread` + `NtResumeThread` → APC fires on resume

## Bypass Layers

| Layer | Technique |
|-------|-----------|
| Userland hooks | Indirect syscalls (clean disk ntdll → SSN → custom stubs) |
| ETW | `EtwEventWrite` → xor eax,eax; ret |
| CreateRemoteThread | APC on existing thread (no new thread callback) |
| LoadLibrary detection | Reflective PIC loading (no image load callback) |
| RWX memory scan | RW → write payload → RX (no simultaneous RWX) |
| Memory type scan | Payload in Image region (.text stomp) — EDR skips |
| PPID anomaly | Parent = services.exe |
| Process creation hook | `NtCreateUserProcess` via indirect syscall |

## Output

- Success marker written to ADS: `C:\Windows\System32\winevt\Logs\...\Sysmon*.evtx:DLLINJ`
- Encrypted with AES-256-GCM (key derived from machine name)

## Detection Check

```powershell
# Check for ADS output
Get-Item "C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx" -Stream DLLINJ -ErrorAction SilentlyContinue

# Check EDR logs
.\test\detect_check.ps1
```

## Build

```batch
build.bat
# Requires: Visual Studio 2022 + Windows SDK 10.0.26100.0
```

## Notes

- Module stomping targets msxml3.dll (loaded in most processes)
- Fallback to allocated memory injection if target DLL not found
- Target process continues normal execution after payload
- No file dropped on disk (except the .exe itself)
