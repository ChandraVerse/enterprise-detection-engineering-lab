# Windows Server / Active Directory Lab Setup

**Author**: Chandra Sekhar Chakraborty  
**OS**: Windows Server 2019 / 2022

---

## Lab Topology

```
┌─────────────────────────────────────────────────────────┐
│                  Host Machine (Hypervisor)               │
│  VMware Workstation / VirtualBox / Hyper-V              │
│                                                         │
│  ┌───────────────────┐    ┌──────────────────────┐      │
│  │  DC01 (AD DS)     │    │  WRK01 (Workstation) │      │
│  │  Windows Srv 2019 │    │  Windows 10 / 11     │      │
│  │  IP: 10.10.10.10  │◄──►│  IP: 10.10.10.20     │      │
│  │  Domain: lab.local│    │  Joined: lab.local   │      │
│  └───────────────────┘    └──────────────────────┘      │
│                                                         │
│  ┌───────────────────────────────────────────────────┐  │
│  │  SIEM Server (Ubuntu 22.04)                       │  │
│  │  Elastic Stack 8.x | IP: 10.10.10.5               │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

## 1. Domain Controller Setup

```powershell
# Rename and set static IP
Rename-Computer -NewName "DC01" -Restart
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 10.10.10.10 -PrefixLength 24 -DefaultGateway 10.10.10.1
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 127.0.0.1

# Install AD DS
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

# Promote to Domain Controller
Install-ADDSForest `
  -DomainName "lab.local" `
  -DomainNetbiosName "LAB" `
  -SafeModeAdministratorPassword (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force) `
  -InstallDns `
  -Force
```

## 2. Create Lab Users and Groups

```powershell
# Create OUs
New-ADOrganizationalUnit -Name "Lab Users" -Path "DC=lab,DC=local"
New-ADOrganizationalUnit -Name "Lab Workstations" -Path "DC=lab,DC=local"

# Create standard user
New-ADUser -Name "John Smith" -SamAccountName "jsmith" `
  -UserPrincipalName "jsmith@lab.local" `
  -AccountPassword (ConvertTo-SecureString "User@1234!" -AsPlainText -Force) `
  -Path "OU=Lab Users,DC=lab,DC=local" `
  -Enabled $true

# Create service account (for Pass-the-Hash simulation)
New-ADUser -Name "svc-backup" -SamAccountName "svc-backup" `
  -AccountPassword (ConvertTo-SecureString "Backup@1234!" -AsPlainText -Force) `
  -Path "OU=Lab Users,DC=lab,DC=local" `
  -Enabled $true

# Add user to Domain Admins (for escalation simulation)
Add-ADGroupMember -Identity "Domain Admins" -Members "jsmith"
```

## 3. Audit Policy Configuration

```powershell
# Enable advanced audit policies (required for Security Event 4624, 4625, 4688)
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /category:"Account Logon" /success:enable /failure:enable
auditpol /set /category:"Process Creation" /success:enable
auditpol /set /category:"Privilege Use" /success:enable /failure:enable
auditpol /set /category:"Object Access" /success:enable /failure:enable

# Enable command-line logging in process creation events
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
  /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

## 4. Deploy Elastic Agent on Windows

```powershell
# Download agent (use version matching your Fleet Server)
Invoke-WebRequest -Uri https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-8.12.0-windows-x86_64.zip -OutFile C:\agent.zip
Expand-Archive C:\agent.zip -DestinationPath C:\elastic-agent

# Enroll with Fleet
cd C:\elastic-agent\elastic-agent-8.12.0-windows-x86_64\
.\elastic-agent.exe install --url=https://10.10.10.5:8220 --enrollment-token=<token> --insecure
```

## 5. Disable Defender (Lab Only)

```powershell
# WARNING: Only disable in isolated lab environment
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableIOAVProtection $true
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" `
  -Name DisableAntiSpyware -Value 1 -PropertyType DWORD -Force
```
