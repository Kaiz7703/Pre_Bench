/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2026
*
*  TITLE:       METHODS.H
*
*  VERSION:     3.71
*
*  DATE:        23 Jul 2026
*
*  Prototypes and definitions for UAC bypass methods table.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

typedef struct _UCM_METHOD_AVAILABILITY {
    ULONG MinumumWindowsBuildRequired;             //if the current build less this value this method is not working here
    ULONG MinimumExpectedFixedWindowsBuild;        //if the current build equal or greater this value this method is not working here or fixed
} UCM_METHOD_AVAILABILITY;

typedef struct tagUCM_ARGS_BLOCK {
    UCM_METHOD Method;
    PVOID PayloadCode;
    ULONG PayloadSize;
} UCM_ARGS_BLOCK, *PUCM_ARGS_BLOCK;

typedef NTSTATUS(CALLBACK *PUCM_API_ROUTINE)(
    _In_ PUCM_ARGS_BLOCK Parameter
    );
                  
#define UCM_API(n) NTSTATUS CALLBACK n(     \
    _In_ PUCM_ARGS_BLOCK Parameter)  

typedef struct _UCM_API_DISPATCH_ENTRY {
    UCM_METHOD MethodId;
    PUCM_API_ROUTINE Routine;               //method to execute
    UCM_METHOD_AVAILABILITY Availability;   //min and max supported Windows builds
    ULONG PayloadResourceId;                //which payload dll must be used
    BOOL Win32OrWow64Required;
    BOOL DisallowWow64;
    BOOL SetParameters;                     //need shared parameters to be set
} UCM_API_DISPATCH_ENTRY, *PUCM_API_DISPATCH_ENTRY;

#include "elvint.h"
#include "routines.h"
#include "comsup.h"
#include "tests\test.h"

NTSTATUS MethodsManagerCall(
    _In_ UCM_METHOD Method);
