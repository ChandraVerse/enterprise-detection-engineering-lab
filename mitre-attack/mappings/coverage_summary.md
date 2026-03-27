# MITRE ATT&CK Coverage Summary

**Lab**: Enterprise Detection Engineering Lab  
**ATT&CK Version**: v14  
**Author**: Chandra Sekhar Chakraborty  
**Last Updated**: 2026-01-15

---

## Coverage by Tactic

| Tactic | ID | Techniques Detected | Detection Rate |
|--------|----|---------------------|----------------|
| Initial Access | TA0001 | T1566 (Phishing - Sysmon email attach) | Partial |
| Execution | TA0002 | T1047, T1059.001, T1059.003 | Full |
| Persistence | TA0003 | T1053.005, T1547.001 | Full |
| Privilege Escalation | TA0004 | T1078, T1134 | Partial |
| Defense Evasion | TA0005 | T1027.010, T1140, T1218 | Full |
| Credential Access | TA0006 | T1003.001, T1550.002 | Full |
| Discovery | TA0007 | T1087.001, T1069, T1082 | Full |
| Lateral Movement | TA0008 | T1021.002, T1550.002 | Full |
| Collection | TA0009 | — | Planned |
| Exfiltration | TA0010 | — | Planned |

---

## Validated Techniques (10)

| Technique ID | Name | Rule | Test Method | Status |
|-------------|------|------|------------|--------|
| T1003.001 | LSASS Memory | Mimikatz LSASS Dump | Atomic T1003.001-1 | ✅ Validated |
| T1027.010 | Command Obfuscation | PowerShell Obfuscation | Invoke-Obfuscation | ✅ Validated |
| T1021.002 | SMB/Windows Admin Shares | PsExec Lateral Movement | Atomic T1021.002-1 | ✅ Validated |
| T1047 | WMI | WMI Process Spawn | Atomic T1047-1 | ✅ Validated |
| T1053.005 | Scheduled Task | Scheduled Task Persistence | Atomic T1053.005-1 | ✅ Validated |
| T1547.001 | Registry Run Keys | Registry Run Key | Atomic T1547.001-1 | ✅ Validated |
| T1087.001 | Local Account Discovery | Net User Enum | Atomic T1087.001-1 | ✅ Validated |
| T1550.002 | Pass the Hash | Pass-the-Hash NTLM | Mimikatz sekurlsa::pth | ✅ Validated |
| T1140 | Deobfuscate/Decode | Encoded Command | Manual simulation | ✅ Validated |
| T1218 | System Binary Proxy Exec | Certutil LOLBAS | Atomic T1218-14 | ✅ Validated |

---

## Loading Navigator Layer

Import `navigator/coverage_layer.json` into [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) to visualize coverage.

Steps:
1. Open ATT&CK Navigator
2. Click **Open Existing Layer**
3. Select **Upload from local** and choose `coverage_layer.json`
4. Red cells = fully validated detection rules in this lab
