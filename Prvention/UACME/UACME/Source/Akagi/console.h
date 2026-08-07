/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2022 - 2026
*
*  TITLE:       CONSOLE.H
*
*  VERSION:     3.71
*
*  DATE:        21 Jul 2026
*
*  Debug console header file.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

VOID ConsoleInit(
    VOID);

VOID ConsoleRelease(
    VOID);

VOID ConsolePrintStatus(
    _In_ LPCWSTR Message,
    _In_ NTSTATUS Status);

VOID ConsolePrint(
    _In_ LPCWSTR Message);

VOID ConsolePrintValueUlong(
    _In_ LPCWSTR Message,
    _In_ ULONG Value,
    _In_ BOOL Hexademical);

VOID ConsolePrintText(
    _In_ LPCWSTR Message,
    _In_ LPCWSTR Text);

#ifdef _UCM_CONSOLE
#define ucmConsoleInit ConsoleInit
#define ucmConsoleRelease ConsoleRelease
#define ucmConsolePrintStatus ConsolePrintStatus
#define ucmConsolePrint ConsolePrint
#define ucmConsolePrintText ConsolePrintText
#define ucmConsolePrintValueUlong ConsolePrintValueUlong
#else
#define ucmConsoleInit()
#define ucmConsoleRelease()
#define ucmConsolePrintStatus(Message, Status)
#define ucmConsolePrint(Message)
#define ucmConsolePrintText(Message, Text)
#define ucmConsolePrintValueUlong(Message, Value, Hexademical)
#endif
