# Technique Detection/Prevention Coverage — Q3 2026

Extracted from `technique_detection_Q3_2024.xlsx`.

## Sheet: Detection

Split by "Khả năng phủ telemetry Q3 -2026" flag (1 = covered, 0 = not covered). STT preserves original row order from the source sheet.

### Covered (flag = 1) — 29 techniques

| STT | Technique/Sub-technique ID | Technique/Sub-technique Name | Years | Frequency |
|---|---|---|---|---|
| 1 | T1018 | Remote System Discovery | 2023, 2024, 2025, 2026 | 4 |
| 2 | T1059.001 | Command and Scripting Interpreter: PowerShell | 2023, 2024, 2025, 2026 | 4 |
| 3 | T1033 | System Owner/User Discovery | 2023, 2024, 2025, 2026 | 4 |
| 4 | T1070.004 | Indicator Removal: File Deletion | 2023, 2024, 2025, 2026 | 4 |
| 5 | T1041 | Exfiltration Over C2 Channel | 2023, 2024, 2025, 2026 | 4 |
| 6 | T1082 | System Information Discovery | 2023, 2024, 2025, 2026 | 4 |
| 7 | T1021.002 | Remote Services: SMB/Windows Admin Shares | 2023, 2024, 2025, 2026 | 4 |
| 8 | T1083 | File and Directory Discovery | 2023, 2024, 2025, 2026 | 4 |
| 9 | T1105 | Ingress Tool Transfer | 2023, 2024, 2025, 2026 | 4 |
| 10 | T1059.003 | Command and Scripting Interpreter: Windows Command Shell | 2023, 2024, 2025, 2026 | 4 |
| 12 | T1069.002 | Permission Groups Discovery: Domain Groups | 2023, 2024, 2025, 2026 | 4 |
| 13 | T1569.002 | System Services: Service Execution | 2023, 2024, 2025, 2026 | 4 |
| 14 | T1078.002 | Valid Accounts: Domain Accounts | 2023, 2024, 2025, 2026 | 4 |
| 15 | T1543.003 | Create or Modify System Process: Windows Service | 2023, 2024, 2025, 2026 | 4 |
| 16 | T1021.004 | Remote Services: SSH | 2023, 2024, 2025, 2026 | 4 |
| 17 | T1570 | Lateral Tool Transfer | 2023, 2024, 2025, 2026 | 4 |
| 18 | T1573.002 | Encrypted Channel: Asymmetric Cryptography | 2023, 2024, 2025, 2026 | 4 |
| 21 | T1057 | Process Discovery | 2023, 2024, 2026 | 3 |
| 24 | T1047 | Windows Management Instrumentation | 2023, 2024, 2026 | 3 |
| 25 | T1112 | Modify Registry | 2023, 2024, 2026 | 3 |
| 28 | T1119 | Automated Collection | 2023, 2024, 2026 | 3 |
| 29 | T1204.002 | User Execution: Malicious File | 2023, 2025, 2026 | 3 |
| 30 | T1007 | System Service Discovery | 2023, 2024, 2026 | 3 |
| 32 | T1087.002 | Account Discovery: Domain Account | 2023, 2025, 2026 | 3 |
| 35 | T1562.004 | Impair Defenses: Disable or Modify System Firewall | 2024, 2025, 2026 | 3 |
| 38 | T1069.001 | Permission Groups Discovery: Local Groups | 2023, 2024, 2026 | 3 |
| 43 | T1003.001 | OS Credential Dumping: LSASS Memory | 2023, 2026 | 2 |
| 44 | T1006 | Direct Volume Access | 2025, 2026 | 2 |
| 45 | T1003.003 | OS Credential Dumping: NTDS | 2025 | 1 |

### Not covered (flag = 0) — 16 techniques

| STT | Technique/Sub-technique ID | Technique/Sub-technique Name | Years | Frequency |
|---|---|---|---|---|
| 11 | T1071.001 | Application Layer Protocol: Web Protocols | 2023, 2024, 2025, 2026 | 4 |
| 19 | T1053.005 | Scheduled Task/Job: Scheduled Task | 2023, 2025, 2026 | 3 |
| 20 | T1133 | External Remote Services | 2024, 2025, 2026 | 3 |
| 22 | T1016 | System Network Configuration Discovery | 2023, 2024, 2025 | 3 |
| 23 | T1027 | Obfuscated Files or Information | 2023, 2024, 2026 | 3 |
| 26 | T1140 | Deobfuscate/Decode Files or Information | 2023, 2025, 2026 | 3 |
| 27 | T1036.005 | Masquerading: Match Legitimate Resource Name or Location | 2023, 2024, 2026 | 3 |
| 31 | T1204.001 | User Execution: Malicious Link | 2023, 2025, 2026 | 3 |
| 33 | T1135 | Network Share Discovery | 2023, 2024, 2026 | 3 |
| 34 | T1106 | Native API | 2023, 2025, 2026 | 3 |
| 36 | T1027.009 | Obfuscated Files or Information: Embedded Payloads | 2024, 2025, 2026 | 3 |
| 37 | T1059.004 | Command and Scripting Interpreter: Unix Shell | 2023, 2024, 2025 | 3 |
| 39 | T1027.007 | Obfuscated Files or Information: Dynamic API Resolution | 2024, 2025, 2026 | 3 |
| 40 | T1489 | Service Stop | 2023, 2024, 2026 | 3 |
| 41 | T1620 | Reflective Code Loading | 2024, 2025, 2026 | 3 |
| 42 | T1622 | Debugger Evasion | 2024, 2025, 2026 | 3 |

## Sheet: Prevention

| STT | Technique/Sub-technique ID | Technique/Sub-technique Name | Years | Frequency | Khả năng prevent Q3 -2026 |
|---|---|---|---|---|---|
| 1 | T1003 | OS Credential Dumping | | | Sub-technique (8) |
| 2 | T1068 | Exploitation for Privilege Escalation | | | Technique (1) |
| 3 | T1548.002 | Abuse Elevation Control Mechanism: Bypass User Account Control | | | Sub-technique (1) |
| 4 | T1055.1 | Process Injection: Dynamic-link Library Injection | | | Sub-technique (1) |
| 5 | T1055.2 | Process Injection: Portable Executable Injection | | | Sub-technique (1) |
