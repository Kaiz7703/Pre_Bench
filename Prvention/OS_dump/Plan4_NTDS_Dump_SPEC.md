# Plan 4 — NTDS.dit Dump: Technical Specification

> **Target**: T1003.003 — NTDS.dit (Active Directory Database)
> **Pre-condition**: SYSTEM trên Domain Controller (assumed)
> **Scope**: Dump + offline parse NTDS.dit — không VSS, không file API

---

## 1. Overview

Trích xuất toàn bộ domain credentials từ file NTDS.dit trên Domain Controller thông qua raw NTFS volume read, bypass qua file locks của LSASS. Sau đó offline parse NTDS database (ESE format) để lấy NTLM hashes, Kerberos keys, và password history cho tất cả domain users, computers, và trust accounts.

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌────────────┐
│ Raw NTFS     │    │ NTDS.dit     │    │ ESE Database │    │ Encrypted  │
│ Volume Read  │───▶│ Extraction   │───▶│ Parser       │───▶│ ADS Output │
│ (\\.\C:)     │    │ (MFT→Clusters)│   │ (Tables+Rows) │    │            │
└──────────────┘    └──────────────┘    └──────────────┘    └────────────┘
```

---

## 2. Functional Requirements

### FR-1: NTDS.dit File Access
| ID | Requirement |
|----|-------------|
| FR-1.1 | Locate NTDS.dit path từ registry (`HKLM\SYSTEM\...\NTDS\DSA Working Directory`) |
| FR-1.2 | Đọc NTDS.dit thông qua raw NTFS volume (giống Plan 2) — bypass file lock của LSASS |
| FR-1.3 | Không sử dụng VSS (Volume Shadow Copy) — tránh detection |
| FR-1.4 | Không sử dụng `CreateFileW(NTDS.dit)` — bị chặn bởi LSASS exclusive lock |
| FR-1.5 | Fallback: NTDSUtil snapshot nếu raw NTFS không khả dụng |

### FR-2: ESE Database Parsing
| ID | Requirement |
|----|-------------|
| FR-2.1 | Parse ESE (Extensible Storage Engine) header — xác định page size, version |
| FR-2.2 | Walk ESE table hierarchy: MSysObjects → datatable → link_table |
| FR-2.3 | Parse datatable rows: extract user/computer/trust objects |
| FR-2.4 | Decode each column: `ATTm590045` (NTLM hash), `ATTr589970` (SID), `ATTj589832` (username) |
| FR-2.5 | Extract `supplementalCredentials` column → Kerberos keys (AES256, AES128, DES, RC4) |
| FR-2.6 | Extract `pwdHistory` column → password history hashes |
| FR-2.7 | Extract `unicodePwd` column → NTLM hash (16 bytes, không cần decrypt thêm) |
| FR-2.8 | Handle large NTDS.dit files (>1GB, domain có 10K+ users) |

### FR-3: Offline Decryption
| ID | Requirement |
|----|-------------|
| FR-3.1 | Đọc SYSTEM hive (raw NTFS) để lấy SysKey |
| FR-3.2 | Decrypt encrypted columns trong NTDS.dit sử dụng SysKey + RID |
| FR-3.3 | Đọc boot key / SysKey từ SYSTEM\CurrentControlSet\Control\Lsa |
| FR-3.4 | Xử lý NTDS.dit được mã hóa (Windows Server 2019+ với encryption enabled) |

### FR-4: Output
| ID | Requirement |
|----|-------------|
| FR-4.1 | Output format: per-user NTLM hash + Kerberos keys + history |
| FR-4.2 | Mã hóa AES-256-GCM trước khi ghi |
| FR-4.3 | Ghi vào ADS trên file hệ thống hợp lệ |
| FR-4.4 | Hỗ trợ output JSON và binary format |

---

## 3. ESE Database Format

### 3.1 ESE Header (Page 0)

```
Offset  Size  Field
0x0000   4    Checksum
0x0004  28    Signature (usually "EFCDAB89" at 0x0040)
0x0020   4    Database magic number
0x0040   4    Page size (e.g., 8192 or 32768)
0x0070   4    Shadowing flag
0x0148   4    Database state (2 = clean shutdown, 6 = dirty)
```

### 3.2 ESE Page Structure

```
Mỗi page:
┌──────────────────────────────────────────┐
│ Page Header (40 bytes)                    │
│  ├─ Checksum (8 bytes)                    │
│  ├─ Page Number (4 bytes)                 │
│  ├─ Last Modification Time (8 bytes)      │
│  └─ Page Type (4 bytes):                  │
│       0x00 = Data (Leaf)                  │
│       0x02 = Root                         │
│       0x03 = Branch                       │
│       0x07 = Space Tree                    │
├──────────────────────────────────────────┤
│ Page Data                                 │
│  ├─ Tags array (cuối page → ngược lên)    │
│  │   Mỗi tag: [offset:2B][size:2B][flag]  │
│  └─ Nodes (từ đầu page → xuống)           │
│      Mỗi node: key data | value data      │
└──────────────────────────────────────────┘
```

### 3.3 NTDS Table Structure

```
datatable (bảng chính chứa AD objects):
├─ ATTj589832: sAMAccountName
├─ ATTj589918: userPrincipalName
├─ ATTr589970: objectSid
├─ ATTm590045: unicodePwd (NTLM hash)
├─ ATTk589826: supplementalCredentials
├─ ATTk589914: pwdHistory
├─ ATTj589876: userAccountControl
├─ ATTj589922: adminCount
├─ ATTj590126: lastLogonTimestamp
└─ ATTj590087: memberOf (link_table reference)

link_table (bảng quan hệ group membership):
├─ ATTj589849: backlink_dnt (DN của object)
└─ ATTj589918: link_dnt (DN của group)
```

---

## 4. Data Flow

```
[SYSTEM trên DC]
    │
    ├─(1)─ Đọc registry → tìm path NTDS.dit
    │      (HKLM\SYSTEM\...\Services\NTDS\Parameters)
    │
    ├─(2)─ Raw NTFS: mở \\.\C: → parse $Boot → walk MFT
    │      → tìm NTDS.dit → extract $DATA DataRuns
    │      → đọc clusters → reconstruct file in-memory
    │
    ├─(3)─ Đọc SYSTEM hive → extract SysKey
    │
    ├─(4)─ Parse ESE database:
    │      ┌─ Page 0: header → page size, DB state
    │      ├─ MSysObjects table → find datatable
    │      ├─ Walk datatable pages:
    │      │   ├─ Data pages → rows → columns
    │      │   │   ├─ ATTm590045 → NTLM hash (decrypt nếu cần)
    │      │   │   ├─ ATTk589826 → KERB_STORED_CREDENTIAL → Kerberos keys
    │      │   │   ├─ ATTr589970 → SID → RID
    │      │   │   └─ ATTj589832 → sAMAccountName
    │      │   └─ Long Value pages → supplementalCredentials > page size
    │      └─ link_table → resolve group memberships
    │
    ├─(5)─ Serialize → JSON/binary
    │
    └─(6)─ AES-256-GCM encrypt → Base64 → ADS write
```

---

## 5. Bypass Strategy

| # | EDR Layer | Detection | Bypass |
|---|-----------|-----------|--------|
| 1 | `CreateFileW(NTDS.dit)` | ACCESS_DENIED do LSASS lock | Raw NTFS — không gọi file API đến NTDS path |
| 2 | VSS snapshot creation | Event ID 8222 (VSS), Event 98 (ntdsutil) | Không dùng VSS |
| 3 | ESE database open | Minifilter thấy file mở NTDS.dit | Parse offline trong memory, không mở file |
| 4 | Volume Shadow Copy detection | Event ID 2001 (VSS writer) | Không liên quan VSS |
| 5 | File creation scan | File dump NTDS.dit mới xuất hiện | In-memory only + ADS output |
| 6 | Process creation (ntdsutil.exe) | Process creation event | Không gọi ntdsutil hay bất kỳ external tool nào |
| 7 | Large data read from disk | Volume-level I/O anomaly | Đọc từng cluster, phân tán thời gian (jitter giữa các read) |
| 8 | Event 4663 (Object Access) | Audit policy trên NTDS.dit path | Raw volume bypass SACL |

---

## 6. Test Cases

| TC | Scenario | Expected |
|----|----------|---------|
| TC-01 | SYSTEM trên DC, raw NTFS | NTDS.dit extracted + parsed |
| TC-02 | Windows Server 2019 DC, 50 domain users | Tất cả 50 user hashes extracted |
| TC-03 | Windows Server 2022 DC, NTDS encryption enabled | Decrypt thành công |
| TC-04 | Large domain (5000+ users), NTDS > 1GB | Parse thành công, memory < 500MB |
| TC-05 | EDR with VSS monitoring | Không alert (không dùng VSS) |
| TC-06 | EDR with file access monitoring | Không alert (raw NTFS bypass) |
| TC-07 | Verify hashes với DCSync | Hashes khớp 100% |
| TC-08 | Multi-DC environment | Mỗi DC dump riêng, so sánh consistency |

---

## 7. Success Criteria

- [ ] NTDS.dit extracted hoàn toàn từ raw NTFS (không file API)
- [ ] ESE database parsed: datatable + link_table
- [ ] Tất cả domain user NTLM hashes extracted
- [ ] Tất cả Kerberos keys (AES256, AES128, DES, RC4) extracted
- [ ] Password history extracted
- [ ] Computer account credentials extracted
- [ ] Trust account credentials extracted (nếu có)
- [ ] Group memberships resolved
- [ ] Không VSS, không ntdsutil, không file API
- [ ] Output encrypted + ADS (không plaintext trên disk)
- [ ] Không EDR alerts
