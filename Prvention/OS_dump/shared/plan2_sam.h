// plan2_sam.h — Shared SAM/LSA/MSCache credential parsing (offline hives)
// Modern Win10 1709+ scheme, mirrors impacket secretsdump (getBootKey / getHBootKey / __decryptHash)
#pragma once
#include "common.h"

BOOL Plan2ExtractSysKey(HIVE_DATA* sys, BYTE bootKey[16]);
BOOL Plan2GetHashedBootKey(HIVE_DATA* sam, const BYTE bootKey[16], BYTE hbk[48]);
DWORD Plan2ParseSAM(HIVE_DATA* sam, const BYTE bootKey[16], NTLM_CRED** out);
DWORD Plan2ParseMSCache(HIVE_DATA* sec, WCHAR*** names, WCHAR*** domains, PBYTE** hashes);
