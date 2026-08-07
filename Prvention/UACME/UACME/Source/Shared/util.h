/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017 - 2026
*
*  TITLE:       UTIL.H
*
*  VERSION:     3.71
*
*  DATE:        23 Jul 2026
*
*  Global support routines header file shared between payload dlls.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

typedef BOOL(WINAPI* PFNCREATEPROCESSW)(
    _In_opt_ LPCWSTR lpApplicationName,
    _Inout_opt_ LPWSTR lpCommandLine,
    _In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
    _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
    _In_ BOOL bInheritHandles,
    _In_ DWORD dwCreationFlags,
    _In_opt_ LPVOID lpEnvironment,
    _In_opt_ LPCWSTR lpCurrentDirectory,
    _In_ LPSTARTUPINFOW lpStartupInfo,
    _Out_ LPPROCESS_INFORMATION lpProcessInformation);

typedef BOOL(WINAPI* PFNCREATEPROCESSASUSERW)(
    _In_opt_ HANDLE hToken,
    _In_opt_ LPCWSTR lpApplicationName,
    _Inout_opt_ LPWSTR lpCommandLine,
    _In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
    _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
    _In_ BOOL bInheritHandles,
    _In_ DWORD dwCreationFlags,
    _In_opt_ LPVOID lpEnvironment,
    _In_opt_ LPCWSTR lpCurrentDirectory,
    _In_ LPSTARTUPINFOW lpStartupInfo,
    _Out_ LPPROCESS_INFORMATION lpProcessInformation);

typedef struct _OPLOCK_FILE_CONTEXT {
    DWORD Length;
    HANDLE FileHandle;
    OVERLAPPED Overlapped;
} OPLOCK_FILE_CONTEXT, * POPLOCK_FILE_CONTEXT;

VOID ucmBinTextEncode(
    _In_ unsigned __int64 x,
    _Inout_ wchar_t* s);

VOID ucmGenerateSharedObjectName(
    _In_ WORD ObjectId,
    _Inout_ LPWSTR lpBuffer);

BOOLEAN ucmPrivilegeEnabled(
    _In_ HANDLE hToken,
    _In_ ULONG Privilege);

NTSTATUS ucmCreateSyncMutant(
    _Out_ PHANDLE phMutant);

BOOLEAN ucmIsProcess32bit(
    _In_ HANDLE hProcess);

DWORD ucmGetHashForString(
    _In_ char* s);

LPVOID ucmGetProcedureAddressByHash(
    _In_ PVOID ImageBase,
    _In_ DWORD ProcedureHash);

VOID ucmGetStartupInfo(
    _In_ LPSTARTUPINFOW lpStartupInfo);

DWORD ucmExpandEnvironmentStrings(
    _In_ LPCWSTR lpSrc,
    _Out_writes_to_opt_(nSize, return) LPWSTR lpDst,
    _In_ DWORD nSize);

PVOID ucmGetSystemInfo(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass);

BOOL ucmLaunchPayload(
    _In_opt_ LPWSTR pszPayload,
    _In_opt_ DWORD cbPayload);

BOOL ucmLaunchPayloadEx(
    _In_ PFNCREATEPROCESSW pCreateProcess,
    _In_opt_ LPWSTR pszPayload,
    _In_opt_ DWORD cbPayload);

BOOL ucmLaunchPayload2(
    _In_ PFNCREATEPROCESSASUSERW pCreateProcessAsUser,
    _In_ BOOL bIsLocalSystem,
    _In_ ULONG SessionId,
    _In_opt_ LPWSTR pszPayload,
    _In_opt_ DWORD cbPayload);

BOOL ucmLaunchPayload3(
    _In_ UCM_METHOD ucmMethod,
    _In_opt_ LPWSTR pszPayload,
    _In_opt_ DWORD cbPayload,
    _In_ LPWSTR pszOpLockFile,
    _In_ LPWSTR pszTask);

LPWSTR ucmQueryRuntimeInfo(
    _In_ BOOL ReturnData);

BOOLEAN ucmDestroyRuntimeInfo(
    _In_ LPWSTR RuntimeInfo);

BOOL ucmIsUserWinstaInteractive(
    VOID);

NTSTATUS ucmIsUserHasInteractiveSid(
    _In_ HANDLE hToken,
    _Out_ PBOOL pbInteractiveSid);

NTSTATUS ucmIsLocalSystem(
    _Out_ PBOOL pbResult);

HANDLE ucmOpenAkagiNamespace(
    VOID);

_Success_(return == TRUE)
BOOL ucmReadSharedParameters(
    _Out_ UACME_PARAM_BLOCK * SharedParameters);

VOID ucmSetCompletion(
    _In_ LPWSTR lpEvent);

BOOL ucmGetProcessElevationType(
    _In_opt_ HANDLE ProcessHandle,
    _Out_ TOKEN_ELEVATION_TYPE * lpType);

NTSTATUS ucmIsProcessElevated(
    _In_ ULONG ProcessId,
    _Out_ PBOOL Elevated);

PLARGE_INTEGER ucmFormatTimeOut(
    _Out_ PLARGE_INTEGER TimeOut,
    _In_ DWORD Milliseconds);

VOID ucmSleep(
    _In_ DWORD Miliseconds);

BOOL ucmQueryEnvironmentVariable(
    _In_ LPCWSTR Name,
    _Out_ LPWSTR Buffer,
    _In_ ULONG BufferLength);

BOOL ucmSetEnvironmentVariable(
    _In_ LPCWSTR lpName,
    _In_ LPCWSTR lpValue);

BOOL ucmOpLockFile(
    _In_ LPCWSTR FileName,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ DWORD ShareMode,
    _In_ BOOL Exclusive,
    _In_ POPLOCK_FILE_CONTEXT ofc);

BOOL ucmReleaseOpLock(
    _In_ POPLOCK_FILE_CONTEXT ofc);

BOOL ucmWaitForOpLock(
    _In_ POPLOCK_FILE_CONTEXT ofc,
    _In_ DWORD timeout);

VOID ucmHideMainWindow(
    VOID);

BOOL ucmCheckUIAccessPermissions(
    VOID);

HANDLE ucmCallGetProcessHandleFromHwnd(
    _In_ HWND hwnd);

BOOL ucmCreateProcessWithParent(
    _In_ LPWSTR lpCommandLine,
    _In_ HANDLE hParent,
    _In_ DWORD dwFlags,
    _In_ WORD wShow,
    _In_ PROCESS_INFORMATION * pi);

HANDLE ucmGetHwndFullProcessHandle(
    _In_ HWND hwnd);

HANDLE ucmFindFirstElevatedProcessHandle(
    VOID);

BOOL ucmStartLockedElevatedProcess(
    _In_ LPCWSTR OplockFile,
    _In_ LPCWSTR TaskName,
    _In_ POPLOCK_FILE_CONTEXT ofc);

BOOL ucmRunScheduledTask(
    _In_ LPCWSTR TaskName);

BOOL ucmHideMmc();

VOID ucmLogMessage(
    _In_ LPCWSTR FileName,
    _In_ LPCWSTR Message);

#ifdef _DEBUG
#define ucmLogDbgMsg(Message) ucmLogMessage(TEXT("ucmtrace.log"), Message)
#else
#define ucmLogDbgMsg(Message) 
#endif
