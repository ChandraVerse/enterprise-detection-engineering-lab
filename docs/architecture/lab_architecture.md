# Lab Architecture

**Author**: Chandra Sekhar Chakraborty  
**Version**: 1.0

---

## Overview

The Enterprise Detection Engineering Lab is a self-contained blue-team environment
designed to mirror production SOC infrastructure at reduced scale.

## Component Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         ENTERPRISE DETECTION LAB                        │
│                                                                         │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                     ATTACK SIMULATION LAYER                      │  │
│  │                                                                  │  │
│  │   ┌─────────────────┐        ┌──────────────────────────────┐  │  │
│  │   │  DC01            │        │  WRK01                       │  │  │
│  │   │  Windows Srv 2019│        │  Windows 10 Enterprise       │  │  │
│  │   │  AD DS + DNS     │        │  Joined: lab.local           │  │  │
│  │   │  10.10.10.10     │◄──────►│  10.10.10.20                │  │  │
│  │   │                  │        │                              │  │  │
│  │   │  [Sysmon v15]    │        │  [Sysmon v15]               │  │  │
│  │   │  [Elastic Agent] │        │  [Elastic Agent]            │  │  │
│  │   └─────────────────┘        └──────────────────────────────┘  │  │
│  │             │                              │                     │  │
│  │             │   Atomic Red Team / Mimikatz / Impacket           │  │
│  └─────────────┼──────────────────────────────┼────────────────────┘  │
│                │    Sysmon + Windows Events    │                        │
│                └──────────────┬───────────────┘                        │
│                               ▼                                        │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                        DETECTION LAYER                           │  │
│  │                                                                  │  │
│  │   ┌──────────────────────────────────────────────────────────┐  │  │
│  │   │  ELASTIC STACK 8.x (Ubuntu 22.04 | 10.10.10.5)          │  │  │
│  │   │                                                          │  │  │
│  │   │  Fleet Server ──► Elasticsearch ──► Kibana Security     │  │  │
│  │   │                        │                                │  │  │
│  │   │           ┌────────────┴──────────────┐                 │  │  │
│  │   │           │   Detection Engine (KQL)  │                 │  │  │
│  │   │           │   10+ Production Rules    │                 │  │  │
│  │   │           │   Sigma → KQL → Alerts    │                 │  │  │
│  │   │           └────────────┬──────────────┘                 │  │  │
│  │   └───────────────────────┼──────────────────────────────────┘  │  │
│  └───────────────────────────┼──────────────────────────────────────┘  │
│                              ▼                                          │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                      AUTOMATION LAYER                            │  │
│  │                                                                  │  │
│  │   Python Pipeline:                                               │  │
│  │   Alerts → alert_enricher.py (VT/AbuseIPDB/Shodan)             │  │
│  │         → report_generator.py (NIST 800-61 PDF)                │  │
│  │         → coverage_analyzer.py (ATT&CK gap report)             │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

## Data Flow

1. **Adversary Simulates Technique** → Atomic Red Team / Manual
2. **Sysmon Captures Event** → Writes to Windows Event Log
3. **Elastic Agent Ships Event** → Fleet Server → Elasticsearch
4. **Detection Rule Evaluates** → KQL / EQL rule fires alert
5. **Alert Enriched** → Python enricher queries VT/AbuseIPDB/Shodan
6. **Report Generated** → NIST 800-61 PDF with findings + remediation

## Network Segmentation

All VMs communicate over an isolated **host-only** or **internal** network adapter.
No VM has internet access by default — internet access is granted temporarily only
for tool downloads and is immediately revoked before attack simulation.
