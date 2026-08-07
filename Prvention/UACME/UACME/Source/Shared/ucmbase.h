/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018 - 2026
*
*  TITLE:       UCMBASE.H
*
*  VERSION:     3.71
*
*  DATE:        23 July 2026
*
*  Base UACMe definitions.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

//
// Base client-server structure shared between units.
//
typedef struct _UACME_PARAM_BLOCK {
    ULONG Crc32;
    union {
        ULONG Flags;
        struct {
            ULONG MethodId : 16;
            ULONG QueryRuntimeInformation : 1; //FubukiDefaultPayload use only.
            ULONG ParentIsMMC : 1;
            ULONG Reserved : 14;
        };
    };
    ULONG SessionId;
    WCHAR szParameter[MAX_PATH + 1];
    WCHAR szSignalObject[MAX_PATH + 1];
    WCHAR szOptionalParameter1[MAX_PATH + 1];
    WCHAR szOptionalParameter2[MAX_PATH + 1];
} UACME_PARAM_BLOCK, * PUACME_PARAM_BLOCK;


typedef enum _UCM_METHOD {
    UacMethodTest = 0,          //+
    UacMethodSysprep1 = 1,
    UacMethodSysprep2,
    UacMethodOobe,
    UacMethodRedirectExe,
    UacMethodSimda,
    UacMethodCarberp1,
    UacMethodCarberp2,
    UacMethodTilon,
    UacMethodAVrf,
    UacMethodWinsat,
    UacMethodShimPatch,
    UacMethodSysprep3,
    UacMethodMMC1,
    UacMethodSirefef,
    UacMethodGeneric,
    UacMethodGWX,
    UacMethodSysprep4,
    UacMethodManifest,
    UacMethodInetMgr,
    UacMethodMMC2,
    UacMethodSXS,
    UacMethodSXSConsent,
    UacMethodDISM,              //+
    UacMethodComet,
    UacMethodEnigma0x3,
    UacMethodEnigma0x3_2,
    UacMethodExpLife,
    UacMethodSandworm,
    UacMethodEnigma0x3_3,
    UacMethodWow64Logger,
    UacMethodEnigma0x3_4,
    UacMethodUiAccess,          //+
    UacMethodMsSettings,        //+
    UacMethodDiskSilentCleanup, //+
    UacMethodTokenMod,
    UacMethodJunction,
    UacMethodSXSDccw,
    UacMethodHakril,            //+
    UacMethodCorProfiler,       //+
    UacMethodCOMHandlers,
    UacMethodCMLuaUtil,         //+
    UacMethodFwCplLua,
    UacMethodDccwCOM,           //+
    UacMethodVolatileEnv,
    UacMethodSluiHijack,
    UacMethodBitlockerRC,
    UacMethodCOMHandlers2,
    UacMethodSPPLUAObject,
    UacMethodCreateNewLink,
    UacMethodDateTimeWriter,
    UacMethodAcCplAdmin,
    UacMethodDirectoryMock,
    UacMethodShellSdclt,        //+
    UacMethodEgre55,
    UacMethodTokenModUiAccess,  //+
    UacMethodShellWSReset,
    UacMethodSysprep5,
    UacMethodEditionUpgradeMgr,
    UacMethodDebugObject,       //+
    UacMethodGlupteba,
    UacMethodShellChangePk,     //+
    UacMethodMsSettings2,       //+
    UacMethodNICPoison,         //+
    UacMethodIeAddOnInstall,    //+
    UacMethodWscActionProtocol,
    UacMethodFwCplLua2,
    UacMethodMsSettingsProtocol,//+
    UacMethodMsStoreProtocol,   //+
    UacMethodPca,
    UacMethodCurVer,            //+
    UacMethodNICPoison2,        //+
    UacMethodMsdt,              //+
    UacMethodDotNetSerial,
    UacMethodVFServerTaskSched, //+
    UacMethodVFServerDiagProf,  //+
    UacMethodIscsiCpl,          //+
    UacMethodAtlHijack,         //+
    UacMethodSspiDatagram,
    UacMethodTokenModUiAccess2,
    UacMethodRequestTrace,      //+
    UacMethodQuickAssist,       //+
    UacMethodCleanMgrAdmin,     //+
    UacMethodUnifiedConsent,    //+
    UacMethodTabTip,            //+
    UacMethodNarrator,          //+
    UacMethodMax,
    UacMethodInvalid = 0xFFFF
} UCM_METHOD;
