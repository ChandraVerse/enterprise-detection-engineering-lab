---
name: False Positive Report
about: Report a false positive in an existing detection rule
title: '[FP] <rule_name> - <software_or_activity>'
labels: 'false-positive, bug'
assignees: ''
---

## Rule Affected

**Rule name**: e.g., credential_access_mimikatz_lsass  
**Rule file**: detection-rules/sigma/xxx.yml

## Environment

- **OS Version**: e.g., Windows 10 22H2
- **Software triggering FP**: e.g., SentinelOne agent
- **User context**: e.g., SYSTEM / domain user

## Raw Event

Paste the raw Sysmon XML or Windows event log here.

## Suggested Fix

Proposed filter condition to add to the Sigma rule.
