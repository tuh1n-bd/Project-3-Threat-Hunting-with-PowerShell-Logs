# Project-3-Threat-Hunting-with-PowerShell-Logs

## 1) Project Overview
This project focuses on threat hunting with PowerShell logs in Splunk, simulating real-world attack patterns such as encoded commands, credential dumping (Mimikatz), and malicious downloads. The dataset (powershell_attack_dataset.csv) contains both benign and malicious PowerShell events, making it ideal for practicing detection engineering and SOC workflows.

Key features:

Detection queries for suspicious PowerShell activity (-enc, -nop, Invoke-Expression, etc.)

MITRE ATT&CK mapping (e.g., T1059.001 – PowerShell, T1003 – Credential Dumping)

Dashboards and alerts for SOC monitoring

End-to-end walkthrough for Splunk Power User & SOC Analyst skill building

## 2) Dataset Prep

You’ll need fields like:

EventCode or EventID (4104 = Script Block Logging, 4688 = Process Creation)
CommandLine (actual PS command executed)
Account_Name
ComputerName
_time

If not already extracted, create a field alias so CommandLine always exists.

## MITRE ATT&CK
- T1059.001 — PowerShell Execution
- T1140 — Decode/Deobfuscate Files or Information
- T1086 — Script Execution
- T1003 — Credential Dumping

## 3) Core Detection SPLs
1. Encoded PowerShell (`-enc`)
2. Suspicious Flags (`-nop`, `-w hidden`, `-noni`)
3. Remote File Downloads (`Invoke-WebRequest`, `Net.WebClient`)
4. Credential Dumping (`Mimikatz`)
5. Rare Commands (threat hunting baseline)

A) Detect Base64-encoded PowerShell (very common in attacks)

index="sim1" sourcetype="mitre_logs" (EventID=4104 OR EventID=4688) CommandLine="*powershell*"
| eval has_base64=if(match(CommandLine,"-enc|encode|frombase64string"),1,0)
| where has_base64=1
| table _time, Account_Name, ComputerName, CommandLine, Source_IP

👉Detects obfuscation/encoded commands.

B) Detect suspicious PowerShell flags

index="sim1" sourcetype="mitre_logs" CommandLine="*powershell*"
| eval suspicious_flags=if(match(CommandLine,"-nop|-w hidden|-noni|-executionpolicy bypass"),1,0)
| where suspicious_flags=1
| table _time, Account_Name, ComputerName, CommandLine


👉 Flags: -nop (no profile), -w hidden, -noni (no interaction).

C) Detect PowerShell downloading remote files

index="sim1" sourcetype="mitre_logs" CommandLine="*powershell*"
| where like(CommandLine,"%Invoke-WebRequest%") OR like(CommandLine,"%IWR%") OR like(CommandLine,"%Net.WebClient%")
| table _time, Account_Name, ComputerName, Source_IP, CommandLine


👉 Common in malware initial access.

D) Detect credential dumping tools (Mimikatz, Invoke-Mimikatz)

index="sim1" sourcetype="mitre_logs" CommandLine="*powershell*"
| where like(CommandLine,"%mimikatz%") OR like(CommandLine,"%Invoke-Mimikatz%")
| table _time, Account_Name, ComputerName, CommandLine


👉 Credential dumping from memory.

E) Hunt all unusual PowerShell commands (baseline approach)

index="sim1" sourcetype="mitre_logs" CommandLine="*powershell*"
| stats count by CommandLine
| sort - count
| head 20

👉 Find the top 20 PowerShell commands. Hunting = compare normal admin commands vs rare ones.

## 4) Dashboard Panels

Build a Threat Hunting: PowerShell Dashboard with panels:

- KPIs (total executions, suspicious executions)
- Top Accounts & Hosts
- Rare PowerShell commands
- Suspicious flags and encoded commands

1. KPI — Total PowerShell executions (last 24h)

index="sim1" sourcetype="mitre_logs" CommandLine="*powershell*" earliest=-24h
| stats count AS total_ps_exec

2. Timechart — PowerShell executions over time

index="sim1" sourcetype="mitre_logs" CommandLine="*powershell*" earliest=-7d
| timechart span=1h count

3. Suspicious flags detected

index="sim1" sourcetype="mitre_logs" CommandLine="*powershell*"
| eval suspicious_flags=if(match(CommandLine,"-nop|-w hidden|-noni|-executionpolicy bypass"),1,0)
| where suspicious_flags=1
| table _time, Account_Name, ComputerName, CommandLine

4. Base64-encoded PS executions

index="sim1" sourcetype="mitre_logs" (EventID=4104 OR EventID=4688) CommandLine="*powershell*"
| eval has_base64=if(match(CommandLine,"-enc|encode|frombase64string"),1,0)
| where has_base64=1
| table _time, Account_Name, ComputerName, CommandLine, Source_IP

5. Top Accounts running PowerShell

index="sim1" sourcetype="mitre_logs" CommandLine="*powershell*"
| stats count by Account_Name
| sort - count

6. Top Hosts running PowerShell

index="sim1" sourcetype="mitre_logs" CommandLine="*powershell*"
| stats count by ComputerName
| sort - count

7. Rare PowerShell commands

index="ps_data" sourcetype="csv" CommandLine="*powershell*"
| rare CommandLine
| sort - count
| head 20 













## Alerts
- Encoded PowerShell Command — High
- Suspicious PowerShell Flags — Medium
- Credential Dumping (Mimikatz) — High

## Playbook
See `playbook.md` for SOC triage workflow.

