@echo off
REM Plan 2 — SAM+LSA+MSCache Dump (T1003.002/004/005)
set VSPATH=C:\Program Files\Microsoft Visual Studio\2022
if exist "%VSPATH%\Community\VC\Auxiliary\Build\vcvars64.bat" (call "%VSPATH%\Community\VC\Auxiliary\Build\vcvars64.bat" & goto :build)
if exist "%VSPATH%\Professional\VC\Auxiliary\Build\vcvars64.bat" (call "%VSPATH%\Professional\VC\Auxiliary\Build\vcvars64.bat" & goto :build)
if exist "%VSPATH%\Enterprise\VC\Auxiliary\Build\vcvars64.bat" (call "%VSPATH%\Enterprise\VC\Auxiliary\Build\vcvars64.bat" & goto :build)
echo VS2022 not found & pause & exit /b 1

:build
cl.exe /nologo /O2 /MT /GS- /Fe"SAMLSAExtract.exe" main.c ^
    ..\shared\ntfs_raw.c ..\shared\mft_parser.c ..\shared\hive_extractor.c ^
    ..\shared\ads_writer.c ..\shared\sha256.c ..\shared\md5.c ..\shared\rc4.c ^
    ..\shared\aes256_gcm.c ^
    /link /NOLOGO /OPT:REF kernel32.lib ntdll.lib advapi32.lib crypt32.lib
if %ERRORLEVEL% NEQ 0 (echo Build FAILED & pause & exit /b 1)
echo Build SUCCESS: SAMLSAExtract.exe
pause
