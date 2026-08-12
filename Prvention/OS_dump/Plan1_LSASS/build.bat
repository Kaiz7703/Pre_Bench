@echo off
REM Plan 1 — LSASS Dump (T1003.001) — uses shared library
set VSPATH=C:\Program Files\Microsoft Visual Studio\2022
if exist "%VSPATH%\Community\VC\Auxiliary\Build\vcvars64.bat" (call "%VSPATH%\Community\VC\Auxiliary\Build\vcvars64.bat" & goto :build)
if exist "%VSPATH%\Professional\VC\Auxiliary\Build\vcvars64.bat" (call "%VSPATH%\Professional\VC\Auxiliary\Build\vcvars64.bat" & goto :build)
if exist "%VSPATH%\Enterprise\VC\Auxiliary\Build\vcvars64.bat" (call "%VSPATH%\Enterprise\VC\Auxiliary\Build\vcvars64.bat" & goto :build)
echo VS2022 not found & pause & exit /b 1

:build
cl.exe /nologo /O2 /MT /GS- /Fe"LSASSDump.exe" main.c ^
    ..\shared\syscall_resolver.c ..\shared\ads_writer.c ^
    ..\shared\sha256.c ..\shared\aes256_gcm.c ^
    /link /NOLOGO /OPT:REF kernel32.lib ntdll.lib advapi32.lib crypt32.lib
if %ERRORLEVEL% NEQ 0 (echo Build FAILED & pause & exit /b 1)
echo Build SUCCESS: LSASSDump.exe
pause
