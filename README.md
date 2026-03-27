# Enterprise Detection Engineering Lab

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![SIEM](https://img.shields.io/badge/SIEM-Elastic%20Stack-005571?logo=elastic)
![ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK%20v14-red)
![Language](https://img.shields.io/badge/Python-3.10%2B-yellow?logo=python)
![Rules](https://img.shields.io/badge/Detection%20Rules-10%2B-brightgreen)
![Team](https://img.shields.io/badge/Team-Blue%20Team-blue)

> A production-grade Elastic SIEM detection engineering lab featuring Sysmon telemetry, 10+ Sigma rules converted to KQL and SPL, full MITRE ATT&CK v14 mapping, and adversary simulation via Atomic Red Team.


---

## Detection Screenshots

### Elastic SIEM SOC Dashboard
![Elastic SIEM SOC Dashboard](docs/screenshots/siem_dashboard_detection.png)
*Kibana detection dashboard showing critical alerts for T1003.001 and T1027.010, MITRE ATT&CK heatmap, alert volume timeline, and threat intelligence feeds.*

### LSASS Credential Dump — Real-Time Detection
![LSASS Credential Dump Detection](docs/screenshots/lsass_credential_dump_detection.png)
*Sysmon Event ID 10 firing as mimikatz.exe attempts LSASS memory access with GrantedAccess 0x1410 — detection rule intercepts and alerts in real time.*

### Lateral Movement Attack Chain
![Lateral Movement Attack Chain](docs/screenshots/lateral_movement_attack_chain.png)
*Full adversary kill chain: phishing initial access → PsExec lateral movement (T1021.002) → Pass-the-Hash (T1550.002) targeting the Domain Controller — each step blocked by detection rules.*

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Detection Rules](#detection-rules)
- [MITRE ATT&CK Coverage](#mitre-attck-coverage)
- [Adversary Simulation](#adversary-simulation)
- [Automation](#automation)
- [Lab Setup](#lab-setup)
- [Dashboards](#dashboards)
- [Project Structure](#project-structure)
- [Author](#author)

---

## Overview

This lab replicates a production Security Operations Center (SOC) detection engineering environment. It demonstrates the full detection lifecycle:

1. **Telemetry Collection** — Sysmon deployed on Windows endpoints with a hardened configuration capturing process creation, network connections, registry modifications, and file events.
2. **SIEM Deployment** — Elastic Stack (Elasticsearch + Kibana + Fleet) ingesting Sysmon logs via Elastic Agent.
3. **Detection Rule Authoring** — 10+ detection rules written in vendor-agnostic **Sigma** format, then transpiled to **KQL** (Elastic) and **SPL** (Splunk) using `sigma-cli`.
4. **MITRE ATT&CK Mapping** — Every rule mapped to ATT&CK Tactics, Techniques, and Sub-techniques with a Navigator layer export.
5. **Adversary Simulation** — Attack techniques executed with **Atomic Red Team** to validate rule efficacy and measure detection coverage.
6. **Automation** — Python scripts automate rule deployment, alert enrichment, and PDF report generation.

### Key Highlights

| Metric | Value |
|--------|-------|
| Detection Rules | 10+ |
| ATT&CK Tactics Covered | Credential Access, Execution, Defense Evasion, Lateral Movement, Discovery |
| Sigma Rules Converted | KQL + SPL |
| Adversary Techniques Simulated | 15+ |
| Automation Scripts | 5+ |
| SIEM Platform | Elastic Stack 8.x |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        ATTACK SURFACE                           │
│  Windows Server 2019 (AD DS) + Windows 10 Endpoints            │
│  Atomic Red Team Simulations                                     │
└──────────────────────────┬──────────────────────────────────────┘
                           │ Sysmon Events (XML → JSON)
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                     ELASTIC AGENT / FLEET                       │
│  Winlogbeat / Elastic Agent → Logstash Pipeline                 │
└──────────────────────────┬──────────────────────────────────────┘
                           │ Normalized ECS Logs
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│              ELASTIC SIEM (Elasticsearch + Kibana)              │
│  ┌─────────────────┐   ┌──────────────────┐   ┌─────────────┐  │
│  │  Detection Rules │   │  Security Alerts  │   │  Dashboards │  │
│  │  (KQL / EQL)    │   │  (Cases / Triaging)│   │  (Grafana)  │  │
│  └─────────────────┘   └──────────────────┘   └─────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                    PYTHON AUTOMATION                            │
│  Alert Enrichment | IOC Lookup | PDF Report Generation          │
└─────────────────────────────────────────────────────────────────┘
```

See [`docs/architecture/`](docs/architecture/) for detailed diagrams.

---

## Detection Rules

Rules are written in **Sigma** (vendor-agnostic) and converted to platform-specific query languages.

| Rule Name | Tactic | Technique | Sigma | KQL | SPL |
|-----------|--------|-----------|-------|-----|-----|
| Mimikatz LSASS Dump | Credential Access | T1003.001 | [📄](detection-rules/sigma/credential_access_mimikatz_lsass.yml) | [📄](detection-rules/kql/credential_access_mimikatz_lsass.kql) | [📄](detection-rules/spl/credential_access_mimikatz_lsass.spl) |
| PowerShell Obfuscated Execution | Defense Evasion | T1027.010 | [📄](detection-rules/sigma/defense_evasion_powershell_obfuscation.yml) | [📄](detection-rules/kql/defense_evasion_powershell_obfuscation.kql) | [📄](detection-rules/spl/defense_evasion_powershell_obfuscation.spl) |
| PsExec Lateral Movement | Lateral Movement | T1021.002 | [📄](detection-rules/sigma/lateral_movement_psexec.yml) | [📄](detection-rules/kql/lateral_movement_psexec.kql) | [📄](detection-rules/spl/lateral_movement_psexec.spl) |
| WMI Execution | Execution | T1047 | [📄](detection-rules/sigma/execution_wmi_process_spawn.yml) | [📄](detection-rules/kql/execution_wmi_process_spawn.kql) | [📄](detection-rules/spl/execution_wmi_process_spawn.spl) |
| Scheduled Task Creation | Persistence | T1053.005 | [📄](detection-rules/sigma/persistence_scheduled_task.yml) | [📄](detection-rules/kql/persistence_scheduled_task.kql) | [📄](detection-rules/spl/persistence_scheduled_task.spl) |
| Registry Run Key Modification | Persistence | T1547.001 | [📄](detection-rules/sigma/persistence_registry_run_key.yml) | [📄](detection-rules/kql/persistence_registry_run_key.kql) | [📄](detection-rules/spl/persistence_registry_run_key.spl) |
| Net User Discovery | Discovery | T1087.001 | [📄](detection-rules/sigma/discovery_net_user_enum.yml) | [📄](detection-rules/kql/discovery_net_user_enum.kql) | [📄](detection-rules/spl/discovery_net_user_enum.spl) |
| Pass-the-Hash Detection | Lateral Movement | T1550.002 | [📄](detection-rules/sigma/lateral_movement_pass_the_hash.yml) | [📄](detection-rules/kql/lateral_movement_pass_the_hash.kql) | [📄](detection-rules/spl/lateral_movement_pass_the_hash.spl) |
| Encoded Command Execution | Defense Evasion | T1140 | [📄](detection-rules/sigma/defense_evasion_encoded_command.yml) | [📄](detection-rules/kql/defense_evasion_encoded_command.kql) | [📄](detection-rules/spl/defense_evasion_encoded_command.spl) |
| LOLBAS Execution via Certutil | Defense Evasion | T1218 | [📄](detection-rules/sigma/defense_evasion_certutil_lolbas.yml) | [📄](detection-rules/kql/defense_evasion_certutil_lolbas.kql) | [📄](detection-rules/spl/defense_evasion_certutil_lolbas.spl) |

### Rule Authoring Methodology

1. Identify adversary technique from MITRE ATT&CK
2. Simulate technique with Atomic Red Team
3. Analyze Sysmon events in Kibana Discover
4. Author Sigma rule targeting unique behavioral indicators
5. Convert with `sigma-cli` → KQL and SPL
6. Back-test against historical telemetry
7. Set severity, false-positive notes, and schedule threshold

---

## MITRE ATT&CK Coverage

![ATT&CK Navigator](mitre-attack/navigator/coverage_layer.png)

Full coverage mapping: [`mitre-attack/mappings/`](mitre-attack/mappings/)

| Tactic | Techniques Covered |
|--------|--------------------|
| Initial Access | T1566 (Phishing) |
| Execution | T1047, T1059.001, T1059.003 |
| Persistence | T1053.005, T1547.001 |
| Privilege Escalation | T1078, T1134 |
| Defense Evasion | T1027.010, T1140, T1218 |
| Credential Access | T1003.001, T1550.002 |
| Discovery | T1087.001, T1069, T1082 |
| Lateral Movement | T1021.002, T1550.002 |

---

## Adversary Simulation

Adversary techniques are simulated using [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) to validate detection coverage.

### Validated Scenarios

| Scenario | Techniques | Status |
|----------|-----------|--------|
| Credential Dumping | T1003.001 | ✅ Detected |
| Obfuscated Script Execution | T1027.010, T1140 | ✅ Detected |
| Lateral Movement via PsExec | T1021.002 | ✅ Detected |
| Pass-the-Hash | T1550.002 | ✅ Detected |
| WMI Process Execution | T1047 | ✅ Detected |
| Scheduled Task Persistence | T1053.005 | ✅ Detected |
| Registry Run Key | T1547.001 | ✅ Detected |

See [`adversary-simulation/scenarios/`](adversary-simulation/scenarios/) for step-by-step playbooks.

---

## Automation

Python automation scripts for operational efficiency:

| Script | Purpose |
|--------|---------|
| [`rule_deployer.py`](automation/scripts/rule_deployer.py) | Deploy Sigma rules to Elastic via API |
| [`alert_enricher.py`](automation/scripts/alert_enricher.py) | Enrich alerts with VirusTotal + AbuseIPDB |
| [`report_generator.py`](automation/scripts/report_generator.py) | Auto-generate PDF incident reports |
| [`sigma_converter.py`](automation/scripts/sigma_converter.py) | Batch-convert Sigma rules to KQL/SPL |
| [`coverage_analyzer.py`](automation/scripts/coverage_analyzer.py) | Analyze ATT&CK coverage gaps |

---

## Lab Setup

> Full setup guides in [`lab-setup/`](lab-setup/)

### Prerequisites

- **Host Machine**: 16 GB RAM, 4 cores (or cloud VM equivalent)
- **Elastic Stack**: 8.x (Elasticsearch + Kibana + Fleet)
- **Windows Server 2019**: For Active Directory + endpoints
- **Sysmon**: v15+ with SwiftOnSecurity config
- **Python**: 3.10+
- **sigma-cli**: Latest

### Quick Start

```bash
# Clone this repository
git clone https://github.com/ChandraVerse/enterprise-detection-engineering-lab.git
cd enterprise-detection-engineering-lab

# Install Python dependencies
pip install -r requirements.txt

# Deploy detection rules to Elastic
python automation/scripts/rule_deployer.py --config lab-setup/elastic/config.yml

# Run Atomic Red Team scenario
Invoke-AtomicTest T1003.001 -TestGuids <guid>
```

---

## Dashboards

Kibana Security dashboards tracking:
- Alert volume by tactic over time
- Top attacked assets
- Rule hit rate and false positive ratio
- Mean Time to Detect (MTTD)

See [`dashboards/`](dashboards/) for exported Kibana dashboard JSON.

---

## Project Structure

```
enterprise-detection-engineering-lab/
├── detection-rules/
│   ├── sigma/          # Vendor-agnostic Sigma rules (.yml)
│   ├── kql/            # Elastic KQL / EQL queries
│   └── spl/            # Splunk SPL searches
├── mitre-attack/
│   ├── mappings/       # Per-rule ATT&CK technique mappings (JSON/CSV)
│   └── navigator/      # ATT&CK Navigator layer exports
├── automation/
│   ├── scripts/        # Python automation scripts
│   └── reports/        # Sample generated PDF reports
├── lab-setup/
│   ├── elastic/        # Elastic Stack deployment configs
│   ├── sysmon/         # Sysmon XML configs
│   └── windows-server/ # AD DS and endpoint setup guides
├── adversary-simulation/
│   ├── atomic-red-team/ # ART test configs and results
│   └── scenarios/      # Full attack scenario playbooks
├── dashboards/         # Kibana dashboard exports (JSON)
├── docs/
│   ├── architecture/   # Architecture diagrams
│   └── screenshots/    # Lab screenshots and evidence
├── requirements.txt
├── CONTRIBUTING.md
├── LICENSE
└── README.md
```

---

## Author

**Chandra Sekhar Chakraborty**  
Cybersecurity Analyst | SOC Analyst | Detection Engineer  
📍 Kolkata, West Bengal, India  
🔗 [LinkedIn](https://linkedin.com) | [GitHub](https://github.com/ChandraVerse) | [Portfolio](#)

---

> *"Detection engineering is not about collecting logs — it's about building hypotheses, simulating threats, and closing the gap between attacker behavior and defender visibility."*
