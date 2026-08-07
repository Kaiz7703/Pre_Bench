# Plan 5 — Cached Domain Credentials: Technical Specification

> **Target**: T1003.005 — Cached Domain Credentials (chuyên sâu)
> **Pre-condition**: SYSTEM privilege (assumed)
> **Scope**: Multi-source cached credential extraction — MSCache v2 + Kerberos Tickets + DPAPI Vault + RDP/Browser Cache

---

## 1. Overview

Trích xuất toàn bộ cached domain credentials từ nhiều nguồn trên Windows workstation/server, bao gồm MSCache v2 (SECURITY hive), Kerberos ticket cache (LSA memory), DPAPI Credential Vault, RDP saved credentials, và browser password stores. Phương pháp hybrid: kết hợp offline hive parsing + memory reading + file system enumeration.

```
┌────────────────┐    ┌────────────────┐    ┌────────────────┐
│ SECURITY Hive  │    │ LSA Memory      │    │ DPAPI Vault     │
│ MSCache v2     │    │ Kerberos TGT    │    │ Credential Mgr  │
│ (Plan 2 method)│    │ Session Keys    │    │ Web/App creds   │
└───────┬────────┘    └───────┬────────┘    └───────┬────────┘
        │                     │                     │
        └─────────────────────┼─────────────────────┘
                              │
                    ┌─────────▼─────────┐
                    │ Encrypted Output   │
                    │ (AES-256-GCM + ADS)│
                    └───────────────────┘
```

---

## 2. Functional Requirements

### FR-1: MSCache v2 (SECURITY\Cache)
| ID | Requirement |
|----|-------------|
| FR-1.1 | Đọc SECURITY hive (raw NTFS hoặc NtSaveKey fallback) |
| FR-1.2 | Enumerate tất cả `NL$1` đến `NL$N` values trong `SECURITY\Cache` |
| FR-1.3 | Parse MSCache v2 entry structure: 96-byte header + username + domain + DCC hash |
| FR-1.4 | Output format: `$DCC2$10240#username#domain#hash_hex` (hashcat mode 2100) |
| FR-1.5 | Xác định iteration count (mặc định 10240, có thể khác trên Win11) |

### FR-2: Kerberos Ticket Cache (LSA Memory)
| ID | Requirement |
|----|-------------|
| FR-2.1 | Đọc LSASS memory (indirect syscall, như Plan 1) |
| FR-2.2 | Scan memory cho Kerberos ticket structures (`KERB_TICKET_CACHE_ENTRY`) |
| FR-2.3 | Extract TGT (Ticket Granting Ticket) — session key + PAC data |
| FR-2.4 | Extract TGS (Ticket Granting Service) — service session keys |
| FR-2.5 | Decode PAC (Privilege Attribute Certificate) → group memberships |
| FR-2.6 | Output: ticket bytes (có thể reuse cho Pass-the-Ticket) |

### FR-3: DPAPI Credential Vault
| ID | Requirement |
|----|-------------|
| FR-3.1 | Enumerate `%APPDATA%\Microsoft\Credentials\*` → DPAPI blob files |
| FR-3.2 | Enumerate `%APPDATA%\Microsoft\Protect\{SID}\*` → DPAPI master keys |
| FR-3.3 | Giải mã DPAPI master key sử dụng DPAPI_SYSTEM backup key (từ LSA Secrets) |
| FR-3.4 | Giải mã credential blobs → plaintext passwords |
| FR-3.5 | Hỗ trợ cả user context DPAPI + machine context DPAPI |

### FR-4: RDP Saved Credentials
| ID | Requirement |
|----|-------------|
| FR-4.1 | Đọc `HKCU\Software\Microsoft\Terminal Server Client\Servers\*` |
| FR-4.2 | Extract `UserNameHint` và encrypted password |
| FR-4.3 | Decrypt RDP password với CryptUnprotectData (current user context) |
| FR-4.4 | Enumerate tất cả user profiles → extract RDP creds từ mỗi SID |

### FR-5: Browser & App Password Stores
| ID | Requirement |
|----|-------------|
| FR-5.1 | Chrome/Edge: `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data` |
| FR-5.2 | Firefox: `%APPDATA%\Mozilla\Firefox\Profiles\*\logins.json` + key4.db |
| FR-5.3 | Wi-Fi profiles: `netsh wlan export profile` → XML → PSK |
| FR-5.4 | Outlook/Exchange saved credentials (Credential Manager) |

### FR-6: Output & Stealth
| ID | Requirement |
|----|-------------|
| FR-6.1 | Tất cả output được mã hóa AES-256-GCM |
| FR-6.2 | Ghi vào ADS trên file hệ thống |
| FR-6.3 | Không ghi file tạm ra disk |
| FR-6.4 | Hỗ trợ output JSON với full metadata (source, timestamp, user context) |

---

## 3. Cached Credential Sources Detail

### 3.1 MSCache v2 (SECURITY\Cache)

```
Registry Path: SECURITY\Cache\NL$1, NL$2, ...

MSCache v2 Entry Structure:
┌────────────────────────────────────────────┐
│ [0x00] 16 bytes: Username hash (MD4)       │
│ [0x10] 16 bytes: Unknown                    │
│ [0x20] 16 bytes: Unknown                    │
│ [0x30] 16 bytes: Unknown                    │
│ [0x40] 16 bytes: Unknown                    │
│ [0x50] 16 bytes: Unknown                    │
│ [0x60] 16 bytes: DCC Hash                   │
├────────────────────────────────────────────┤
│ Username (Unicode, null-terminated)         │
│ Domain (Unicode, null-terminated)           │
│ Iteration count: embedded in hash           │
└────────────────────────────────────────────┘

Hashcat format: $DCC2$10240#username#domain#hash_hex
Mode: 2100

Windows 10/11 default iterations: 10240
Windows Server 2016+: 10240

Note: MSCache v2 KHÔNG chứa timestamp hay account status.
Tất cả cached users đều valid — họ đã từng login thành công.
```

### 3.2 Kerberos Ticket Cache

```
LSA Memory Structures (lsasrv.dll + kerberos.dll):

KERB_TICKET_CACHE_ENTRY:
├─ ClientName:       username@REALM
├─ ServerName:       krbtgt/REALM (TGT) or service/host (TGS)
├─ SessionKey:       AES256/AES128/RC4 session key
├─ TicketData:       ASN.1 encoded KERB_TICKET
├─ PAC_DATA:         Privilege Attribute Certificate
│   ├─ UserSID
│   ├─ GroupMemberships
│   └─ UserAccountControl flags
└─ ExpirationTime:   FILETIME

Extract → save as .kirbi file → reuse via Rubeus or mimikatz kerberos::ptt
```

### 3.3 DPAPI Vault Format

```
Location: %APPDATA%\Microsoft\Credentials\{GUID}
          %APPDATA%\Microsoft\Protect\{SID}\{GUID}

Each blob:
┌────────────────────────────────────────────┐
│ GUID (16 bytes): credential ID              │
│ Flags (4 bytes): type flags                 │
│ Size (4 bytes): blob size                   │
│ Algorithm (4 bytes): encryption algorithm   │
│ Encrypted Data: AES-256/3DES encrypted      │
│ HMAC (32 bytes): integrity check            │
└────────────────────────────────────────────┘

Decryption requires:
1. DPAPI master key (from Protect\{SID}\{GUID})
2. Master key decrypted with:
   a. User password (if user context)
   b. DPAPI_SYSTEM backup key (if machine context, from LSA Secrets)
   c. Domain backup key (if domain context, from AD)
```

---

## 4. Data Flow

```
[SYSTEM Shell]
    │
    ├─ Phase 1: Offline Hive (Plan 2 method)
    │   └─ SECURITY\Cache → MSCache v2 entries → $DCC2$ hashes
    │
    ├─ Phase 2: LSASS Memory (Plan 1 method)
    │   ├─ kerberos.dll memory → Kerberos ticket cache → TGT/TGS
    │   └─ lsasrv.dll memory → service tickets → session keys
    │
    ├─ Phase 3: DPAPI Vault (File System)
    │   ├─ Enumerate user profiles → %APPDATA%\Microsoft\Credentials
    │   ├─ Enumerate master keys → %APPDATA%\Microsoft\Protect
    │   ├─ Decrypt master keys với DPAPI_SYSTEM (từ Phase 1 LSA Secrets)
    │   └─ Decrypt credential blobs → plaintext
    │
    ├─ Phase 4: Browser/App Cache
    │   ├─ Chrome/Edge → SQLite Login Data → decrypt với DPAPI
    │   ├─ Firefox → key4.db + logins.json → decrypt
    │   ├─ Wi-Fi → netsh wlan export (XML parse)
    │   └─ RDP → registry scan + CryptUnprotectData
    │
    └─ Phase 5: Serialize → AES-256-GCM encrypt → ADS
```

---

## 5. Bypass Strategy

| # | Source | Detection Vector | Bypass |
|---|--------|-----------------|--------|
| 1 | MSCache v2 | `NtOpenKey(SECURITY)` hook | Raw NTFS (Plan 2 method) |
| 2 | Kerberos TGT | LSASS handle open | Handle dup từ legitimate process (Plan 1 method) |
| 3 | DPAPI Vault | File read on Credentials folder | Indirect syscall + path masquerading |
| 4 | Chrome Login Data | SQLite file open on browser profile | Copy to memory via indirect syscall, parse in-memory |
| 5 | RDP Registry | `RegQueryValueExW` hook | Registry hive offline parse (raw NTFS) |
| 6 | All output | New file creation | ADS + encryption, không file mới |

---

## 6. Test Cases

| TC | Scenario | Expected |
|----|----------|---------|
| TC-01 | Domain-joined workstation, 3 cached users | 3 MSCache v2 entries |
| TC-02 | User đã login với Kerberos | TGT + TGS trong LSA memory |
| TC-03 | Chrome lưu password cho 5 sites | 5 DPAPI-encrypted credentials |
| TC-04 | RDP connection đã lưu | Username + decrypted password |
| TC-05 | Multi-user workstation (3 profiles) | Credentials từ tất cả profiles |
| TC-06 | Wi-Fi WPA2-PSK đã kết nối | PSK từ wireless profiles |
| TC-07 | No internet (offline machine) | MSCache v2 + DPAPI vẫn extract được |
| TC-08 | EDR with credential Guard enabled | MSCache v2 vẫn OK (offline); LSASS bị chặn |

---

## 7. Success Criteria

- [ ] MSCache v2: Tất cả cached domain logins được extract
- [ ] Kerberos: TGT + TGS tickets được extract (nếu LSASS accessible)
- [ ] DPAPI Vault: Tất cả credential manager entries được giải mã
- [ ] Browser: Chrome/Edge/Firefox saved passwords (nếu tồn tại)
- [ ] RDP: Saved RDP credentials với username + password
- [ ] Wi-Fi: PSK từ wireless profiles
- [ ] Output format: JSON với source tagging cho mỗi credential
- [ ] Không file mới trên disk
- [ ] Không EDR alerts
