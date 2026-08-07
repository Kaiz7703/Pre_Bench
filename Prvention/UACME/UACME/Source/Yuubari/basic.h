#/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2026
*
*  TITLE:       BASIC.H
*
*  VERSION:     1.62
*
*  DATE:        21 May 2026
*
*  Header file for the basic UAC info scan.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

typedef struct _UAC_BASIC_DATA {
    LPWSTR Name;
    DWORD Value;
    BOOL ThreatAsBool;
    BOOL ThreatAsToggle;
} UAC_BASIC_DATA, *PUAC_BASIC_DATA;

VOID ScanBasicUacData(
    _In_ OUTPUTCALLBACK OutputCallback);
