@echo off
REM build.bat — Plan 2: PE Injection (Process Doppelganging via TxF)
REM Requires: Visual Studio 2022 Community + Windows SDK 10.0.26100.0

call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERR] vcvars64.bat not found — check VS2022 install path
    exit /b 1
)

set CFLAGS=/nologo /O2 /MT /GS- /GL /W3 /WX- /Z7 ^
           /D "WIN32_LEAN_AND_MEAN" /D "NDEBUG" /D "_CONSOLE"

echo [*] Building PEInjection.exe (Plan 2 — T1055.002)...

cl.exe %CFLAGS% /Fe"PEInjection.exe" ^
    main.c ^
    ..\shared\syscall_resolver.c ^
    ..\shared\sha256.c ^
    ..\shared\aes256_gcm.c ^
    ..\shared\ads_writer.c ^
    /link /NOLOGO /OPT:REF /OPT:ICF /DYNAMICBASE /NXCOMPAT ^
    kernel32.lib ntdll.lib advapi32.lib crypt32.lib

if %ERRORLEVEL% EQU 0 (
    echo [OK] Build complete: PEInjection.exe
    dir PEInjection.exe 2>nul
) else (
    echo [ERR] Build failed
    exit /b 1
)
