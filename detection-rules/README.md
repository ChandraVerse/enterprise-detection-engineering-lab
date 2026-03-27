# Detection Rules

This directory contains all detection rules for the Enterprise Detection Engineering Lab, organized by query language.

## Directory Layout

```
detection-rules/
├── sigma/    # Vendor-agnostic Sigma rules (source of truth)
├── kql/      # Elastic KQL / EQL translations
└── spl/      # Splunk SPL translations
```

## Rule Inventory

| # | Rule | MITRE Technique | Severity | Sigma | KQL | SPL |
|---|------|----------------|----------|-------|-----|-----|
| 1 | Mimikatz LSASS Dump | T1003.001 | Critical | ✅ | ✅ | ✅ |
| 2 | PowerShell Obfuscation | T1027.010 | High | ✅ | ✅ | ✅ |
| 3 | PsExec Lateral Movement | T1021.002 | High | ✅ | ✅ | ✅ |
| 4 | WMI Process Spawn | T1047 | High | ✅ | ✅ | ✅ |
| 5 | Scheduled Task Persistence | T1053.005 | Medium | ✅ | ✅ | ✅ |
| 6 | Registry Run Key | T1547.001 | Medium | ✅ | ✅ | ✅ |
| 7 | Net User Enumeration | T1087.001 | Low | ✅ | ✅ | ✅ |
| 8 | Pass-the-Hash | T1550.002 | High | ✅ | ✅ | ✅ |
| 9 | Encoded Command Execution | T1140 | High | ✅ | ✅ | ✅ |
| 10 | Certutil LOLBAS Abuse | T1218 | High | ✅ | ✅ | ✅ |

## Sigma Conversion

Rules are converted using `sigma-cli`:

```bash
# Install sigma-cli
pip install sigma-cli
pip install pysigma-backend-elasticsearch
pip install pysigma-backend-splunk

# Convert single rule
sigma convert -t lucene detection-rules/sigma/credential_access_mimikatz_lsass.yml

# Batch convert all rules to KQL
sigma convert -t lucene -p ecs_windows detection-rules/sigma/*.yml

# Batch convert all rules to SPL
sigma convert -t splunk detection-rules/sigma/*.yml
```

## Rule Format

Each Sigma rule includes:
- **title**: Human-readable rule name
- **id**: Unique UUIDv4 identifier
- **status**: `production` / `test` / `experimental`
- **description**: Detailed detection rationale
- **references**: ATT&CK URLs and tool documentation
- **tags**: ATT&CK tactic and technique tags
- **logsource**: Log source specification
- **detection**: Selection conditions and filters
- **falsepositives**: Known benign triggers
- **level**: `critical` / `high` / `medium` / `low`
