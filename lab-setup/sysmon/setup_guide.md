# Sysmon Setup Guide

**Author**: Chandra Sekhar Chakraborty  
**Sysmon Version**: v15.0+

---

## Installation

```powershell
# Download Sysmon from Sysinternals
Invoke-WebRequest -Uri https://live.sysinternals.com/Sysmon64.exe -OutFile C:\Tools\Sysmon64.exe

# Install with lab config
C:\Tools\Sysmon64.exe -accepteula -i C:\Tools\sysmon_config.xml

# Verify service
Get-Service Sysmon64 | Select-Object Status, StartType

# View events
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 20
```

## Updating Configuration

```powershell
# Update config without reinstalling
C:\Tools\Sysmon64.exe -c C:\Tools\sysmon_config.xml

# Check current config
C:\Tools\Sysmon64.exe -c
```

## Key Event IDs

| Event ID | Event Type | Detection Use |
|----------|-----------|--------------|
| 1 | Process Create | Command-line analysis, LOLBAS, obfuscation |
| 3 | Network Connect | C2 beaconing, lateral movement |
| 7 | Image Load | DLL injection, unsigned DLLs |
| 8 | CreateRemoteThread | Process injection |
| 10 | Process Access | LSASS credential dumping |
| 11 | File Create | Dropper, persistence files |
| 12/13/14 | Registry Events | Run key persistence |
| 17/18 | Pipe Events | Named pipe lateral movement |
| 22 | DNS Query | Domain fronting, C2 DNS |

## Forwarding to Elastic

Install Elastic Agent on Windows endpoints, assign the **Windows Integration** policy in Fleet. Sysmon events are automatically collected via `Microsoft-Windows-Sysmon/Operational` event channel.
