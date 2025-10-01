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

```
index="sim1" sourcetype="mitre_logs" (EventID=4104 OR EventID=4688) CommandLine="*powershell*"
| eval has_base64=if(match(CommandLine,"-enc|encode|frombase64string"),1,0)
| where has_base64=1
| table _time, Account_Name, ComputerName, CommandLine, Source_IP
```




👉Detects obfuscation/encoded commands.
-----------------
B) Detect suspicious PowerShell flags


```
index="sim1" sourcetype="mitre_logs" CommandLine="*powershell*"
| eval suspicious_flags=if(match(CommandLine,"-nop|-w hidden|-noni|-executionpolicy bypass"),1,0)
| where suspicious_flags=1
| table _time, Account_Name, ComputerName, CommandLine`
```

👉 Flags: -nop (no profile), -w hidden, -noni (no interaction).

C) Detect PowerShell downloading remote files

```
index="sim1" sourcetype="mitre_logs" CommandLine="*powershell*"
| where like(CommandLine,"%Invoke-WebRequest%") OR like(CommandLine,"%IWR%") OR like(CommandLine,"%Net.WebClient%")
| table _time, Account_Name, ComputerName, Source_IP, CommandLine
```

👉 Common in malware initial access.

D) Detect credential dumping tools (Mimikatz, Invoke-Mimikatz)

```
index="sim1" sourcetype="mitre_logs" CommandLine="*powershell*"
| where like(CommandLine,"%mimikatz%") OR like(CommandLine,"%Invoke-Mimikatz%")
| table _time, Account_Name, ComputerName, CommandLine
```

👉 Credential dumping from memory.

E) Hunt all unusual PowerShell commands (baseline approach)

```
index="sim1" sourcetype="mitre_logs" CommandLine="*powershell*"
| stats count by CommandLine
| sort - count
| head 20
```

👉 Find the top 20 PowerShell commands. Hunting = compare normal admin commands vs rare ones.

## 4) Dashboard Panels

Build a Threat Hunting: PowerShell Dashboard with panels:

- KPIs (total executions, suspicious executions)
- Top Accounts & Hosts
- Rare PowerShell commands
- Suspicious flags and encoded commands

1. KPI — Total PowerShell executions (last 24h)
   ---

```
index="sim1" sourcetype="mitre_logs" CommandLine="*powershell*" earliest=-24h
| stats count AS total_ps_exec
```

[<img src="https://github.com/tuh1n-bd/files/blob/main/1.%20KPI%20%E2%80%94%20Total%20PowerShell%20executions%20(last%2024h)%20-%20Copy.png" />](https://github.com/tuh1n-bd/files/blob/main/1.%20KPI%20%E2%80%94%20Total%20PowerShell%20executions%20(last%2024h)%20-%20Copy.png)



2. Timechart — PowerShell executions over time
   ---

```
index="sim1" sourcetype="mitre_logs" CommandLine="*powershell*" earliest=-7d
| timechart span=1h count
```


<img width="1178" height="707" alt="2  Timechart — PowerShell executions over time" src="https://github.com/user-attachments/assets/f0aa19cd-2805-4489-b9ef-b3c6c70915b8" />

------

3. Suspicious flags detected
   ---

```
index="sim1" sourcetype="mitre_logs" CommandLine="*powershell*"
| eval suspicious_flags=if(match(CommandLine,"-nop|-w hidden|-noni|-executionpolicy bypass"),1,0)
| where suspicious_flags=1
| table _time, Account_Name, ComputerName, CommandLine
```

<img width="1184" height="922" alt="3 suspicious PowerShell flags" src="https://github.com/user-attachments/assets/c59a4a2a-50b5-42b2-8506-a39d04f149f2" />

---------------------------

4. Base64-encoded PS executions
   -------
   
```
index="sim1" sourcetype="mitre_logs" (EventID=4104 OR EventID=4688) CommandLine="*powershell*"
| eval has_base64=if(match(CommandLine,"-enc|encode|frombase64string"),1,0)
| where has_base64=1
| table _time, Account_Name, ComputerName, CommandLine, Source_IP
```

<img width="1187" height="923" alt="4  Base64-encoded PS executions" src="https://github.com/user-attachments/assets/d6eb1860-309e-48f8-93ff-286179698be1" />

-----

5. Top Accounts running PowerShell
   --------
```
index="sim1" sourcetype="mitre_logs" CommandLine="*powershell*"
| stats count by Account_Name
| sort - count
```

<img width="1178" height="765" alt="5  Top Accounts running PowerShell" src="https://github.com/user-attachments/assets/acffed9f-19de-4175-9860-33d5dcb8f5e1" />



6. Top Hosts running PowerShell
   -----
```
index="sim1" sourcetype="mitre_logs" CommandLine="*powershell*"
| stats count by ComputerName
| sort - count
```

<img width="1181" height="782" alt="6  Top Hosts running PowerShell" src="https://github.com/user-attachments/assets/039d0f28-b486-4891-866f-21a137256805" />

--------------

7. Rare PowerShell commands
   -----
```
index="ps_data" sourcetype="csv" CommandLine="*powershell*"
| rare CommandLine
| sort - count
| head 20
```

<img width="1186" height="914" alt="7  Rare PowerShell commands" src="https://github.com/user-attachments/assets/bb80f299-d0b7-4cae-ac91-9d6bb0b88bb3" />

------

## 5) Alerts (Saved Searches)

1. Alert: Encoded PowerShell Command
SPL A
Runs every 5m, severity = High

2. Alert: Suspicious PowerShell Flags
SPL B
Runs every 10m, severity = Medium

3. Alert: Credential Dumping (Mimikatz)
SPL D
High severity, immediate escalation

## 6) SOC L1 Triage Playbook

When an alert fires:

1. Check CommandLine: Does it include -enc, Invoke-WebRequest, Mimikatz?

2. Check user account: Is it a service account, admin, or end-user?

3. Check host: Is this a server, workstation, or domain controller?

4. Pivot:

-  Search index=ps_data sourcetype=csv by Account_Name or ComputerName to see what else happened.

-  Look for EventID 4688 (process creation) to see child processes.

5. Correlate: Was this followed by credential dumping, lateral movement, or persistence?

6. Contain if malicious: Disable account, isolate host.

7. Document: Add to case with screenshots and SPL used.


-------------------------------------------



