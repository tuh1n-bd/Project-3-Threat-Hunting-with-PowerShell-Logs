[threat_hunting_powershell_dashboard-2025-10-01.pdf](https://github.com/user-attachments/files/22641401/threat_hunting_powershell_dashboard-2025-10-01.pdf)[powershell_hunting.xml.txt](https://github.com/user-attachments/files/22641036/powershell_hunting.xml.txt)# Project-3-Threat-Hunting-with-PowerShell-Logs

## 1) Project Overview
This project focuses on threat hunting with PowerShell logs in Splunk, simulating real-world attack patterns such as encoded commands, credential dumping (Mimikatz), and malicious downloads. The dataset (powershell_attack_dataset.csv) contains both benign and malicious PowerShell events, making it ideal for practicing detection engineering and SOC workflows.

Key features:

Detection queries for suspicious PowerShell activity (-enc, -nop, Invoke-Expression, etc.)

MITRE ATT&CK mapping (e.g., T1059.001 – PowerShell, T1003 – Credential Dumping)

Dashboards and alerts for SOC monitoring

End-to-end walkthrough for Splunk Power User & SOC Analyst skill building

## 2) Dataset Prep & Ingestion

**Required fields (recommended):**
- `timestamp` (or `_time` parsed)
- `EventID` / `EventCode`
- `Account_Name`
- `ComputerName`
- `Source_IP`
- `ParentImage`
- `ProcessName`
- `CommandLine`

**Ingest CSV into Splunk (UI steps):**
1. Splunk Web → Settings → Add Data → Upload.  
2. Select `powershell_attack_dataset.csv`.  
3. Set **Source type** to `csv` (or create a custom `powershell_logs` sourcetype).  
4. Set **Index** to `ps_data` (create index if needed).  
5. Finish and verify ingestion:
     
   ```
   index=ps_data sourcetype=csv | head 20
   ```
   
Field extraction tip (if CommandLine not parsed):

```
| rex field=_raw "CommandLine=(?<CommandLine>\".*?\"|\S+)"
```

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
index="ps_data" sourcetype="csv" (EventID=4104 OR EventID=4688) CommandLine="*powershell*"
| eval has_base64=if(match(CommandLine,"-enc|encode|frombase64string"),1,0)
| where has_base64=1
| table _time, Account_Name, ComputerName, CommandLine, Source_IP
```




👉Detects obfuscation/encoded commands.
-----------------
B) Detect suspicious PowerShell flags


```
index="ps_data" sourcetype="csv" CommandLine="*powershell*"
| eval suspicious_flags=if(match(CommandLine,"-nop|-w hidden|-noni|-executionpolicy bypass"),1,0)
| where suspicious_flags=1
| table _time, Account_Name, ComputerName, CommandLine`
```

👉 Flags: -nop (no profile), -w hidden, -noni (no interaction).

C) Detect PowerShell downloading remote files

```
index="ps_data" sourcetype="csv" CommandLine="*powershell*"
| where like(CommandLine,"%Invoke-WebRequest%") OR like(CommandLine,"%IWR%") OR like(CommandLine,"%Net.WebClient%")
| table _time, Account_Name, ComputerName, Source_IP, CommandLine
```

👉 Common in malware initial access.

D) Detect credential dumping tools (Mimikatz, Invoke-Mimikatz)

```
index="ps_data" sourcetype="csv" CommandLine="*powershell*"
| where like(CommandLine,"%mimikatz%") OR like(CommandLine,"%Invoke-Mimikatz%")
| table _time, Account_Name, ComputerName, CommandLine
```

👉 Credential dumping from memory.

E) Hunt all unusual PowerShell commands (baseline approach)

```
index="ps_data" sourcetype="csv" CommandLine="*powershell*"
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
index="ps_data" sourcetype="csv" CommandLine="*powershell*" earliest=-24h
| stats count AS total_ps_exec
```

[<img src="https://github.com/tuh1n-bd/files/blob/main/1.%20KPI%20%E2%80%94%20Total%20PowerShell%20executions%20(last%2024h)%20-%20Copy.png" />](https://github.com/tuh1n-bd/files/blob/main/1.%20KPI%20%E2%80%94%20Total%20PowerShell%20executions%20(last%2024h)%20-%20Copy.png)



2. Timechart — PowerShell executions over time
   ---

```
index="ps_data" sourcetype="csv" CommandLine="*powershell*" earliest=-7d
| timechart span=1h count
```


[<img width="1178" height="707" alt="2  Timechart — PowerShell executions over time" src="https://github.com/user-attachments/assets/f0aa19cd-2805-4489-b9ef-b3c6c70915b8" />](https://github.com/tuh1n-bd/files/blob/main/2.%20Timechart%20%E2%80%94%20PowerShell%20executions%20over%20time.png)

------

3. Suspicious flags detected
   ---

```
index="ps_data" sourcetype="csv" CommandLine="*powershell*"
| eval Account_Nmae="user***", Source_IP="1.2.3.x"
| eval suspicious_flags=if(match(CommandLine,"-nop|-w hidden|-noni|-executionpolicy bypass"),1,0)
| where suspicious_flags=1
| table _time, Account_Name, ComputerName, CommandLine
```


<img width="1187" height="924" alt="3  suspicious-new" src="https://github.com/user-attachments/assets/66f6a5ef-b31a-491e-95a3-f97112930378" />


4. Base64-encoded PS executions
   -------
   
```
index="ps_data" sourcetype="csv" (EventID=4104 OR EventID=4688) CommandLine="*powershell*"
| eval Account_Nmae="user***", Source_IP="1.2.3.x"
| eval has_base64=if(match(CommandLine,"-enc|encode|frombase64string"),1,0)
| where has_base64=1
| table _time, Account_Name, ComputerName, CommandLine, Source_IP
```

<img width="1189" height="923" alt="4  base64-new" src="https://github.com/user-attachments/assets/00485e8a-2a8c-40e8-a14d-b7e64f8d80c0" />

-----

5. Top Accounts running PowerShell
   --------
```
index="ps_data" sourcetype="csv" CommandLine="*powershell*"
| stats count by Account_Name
| sort - count
```

[<img width="1178" height="765" alt="5  Top Accounts running PowerShell" src="https://github.com/user-attachments/assets/acffed9f-19de-4175-9860-33d5dcb8f5e1" />](https://github.com/tuh1n-bd/files/blob/main/5.%20Top%20Accounts%20running%20PowerShell.png)



6. Top Hosts running PowerShell
   -----
   
```
index="ps_data" sourcetype="csv" CommandLine="*powershell*"
| stats count by ComputerName
| sort - count
```


<img width="1181" height="782" alt="6  Top Hosts running PowerShell" src="https://github.com/user-attachments/assets/0950bbcd-12c5-4b4f-ad7a-41579e1b0f72" />




7. Rare PowerShell commands
   ----
   
```
index="ps_data" sourcetype="csv" CommandLine="*powershell*"
| rare CommandLine
| sort - count
| head 20
```

[<img width="1186" height="914" alt="7  Rare PowerShell commands" src="https://github.com/user-attachments/assets/bb80f299-d0b7-4cae-ac91-9d6bb0b88bb3" />](https://github.com/tuh1n-bd/files/blob/main/7.%20Rare%20PowerShell%20commands.png)

------
## 5) powershell_hunting.xml

<img width="1145" height="925" alt="dashboard1" src="https://github.com/user-attachments/assets/f0a69be9-3c2e-43e3-830e-b738aadca2b5" />

<img width="1142" height="750" alt="dashboard2" src="https://github.com/user-attachments/assets/b8f0a7d6-d8b3-4ba0-a195-d5289a61b40c" />

<img width="1143" height="773" alt="dashboard3" src="https://github.com/user-attachments/assets/893c77e1-7ce9-4a45-915d-b541a292d1e8" />

<img width="1144" height="908" alt="dashboard4" src="https://github.com/user-attachments/assets/5895fd03-749f-49c4-b91e-b3681f32ce19" />



----------------------------------------------



## 6) Alerts (Saved Searches)

1. Alert: Encoded PowerShell Command
SPL A
Runs every 5m, severity = High

2. Alert: Suspicious PowerShell Flags
SPL B
Runs every 10m, severity = Medium

3. Alert: Credential Dumping (Mimikatz)
SPL D
High severity, immediate escalation

## 7) SOC L1 Triage Playbook (quick checklist)

When an alert fires (e.g., Encoded PS or Mimikatz):

Acknowledge the alert in your ticketing tool.

Identify scope: Account_Name, ComputerName, Source_IP, EventIDs.

Examine the CommandLine: look for IEX, IWR, -enc, mimikatz.

Pivot: search other events for the same Account_Name / ComputerName within ±30 minutes.

```
index=ps_data sourcetype=csv (Account_Name="victim" OR ComputerName="HOST-WS1") earliest=-30m latest=+30m
```

Check parent/child processes: look for EventID 4688 event(s) and examine ParentImage/ProcessName.

Enrich: IP reputation (threat_intel lookup), domain extraction from URLs.

Contain & escalate: If confirmed malicious (mimikatz or remote payload execution) — isolate host, disable account, escalate to L2.

Document: Timeline, IoCs (IPs, URLs, filenames), commands observed, recommended remediation.

Close or follow-up: add remediation notes & add signature to playbook if false positive.

## 8) Testing & verification steps (recommended)

Upload powershell_attack_dataset.csv to Splunk (index=ps_data, sourcetype=csv).

Verify ingestion:

index=ps_data sourcetype=csv | head 20


Run Encoded detection SPL — you should see base64/enc items.

Run Suspicious flags SPL — you should see flagged items.

Run Mimikatz SPL — confirm the mimikatz rows appear.

For alert testing, create a small powershell_attack_test.csv with ~20 rows focusing on malicious examples and ingest it. Run saved searches manually and confirm alerts trigger.

Mask PII when capturing screenshots (see README notes below).

## 9) Repo structure 
PowerShell-ThreatHunting-Splunk/
├─ README.md
├─ detections.spl           # All SPLs consolidated (copy/paste ready)
├─ savedsearches.conf.example
├─ dashboard/
│  ├─ powershell_hunting.xml
│  └─ screenshots/
├─ sample_data/
│  ├─ powershell_attack_dataset.csv
│  └─ powershell_attack_test.csv
├─ playbook.md
├─ TESTING.md
└─ LICENSE

## 10) Notes, tuning & next steps

Performance: Avoid transaction at scale. Prefer stats / streamstats and narrow searches with index/sourcetype.

Suppression & throttling: Use alert.suppress in saved searches to avoid noise.

False positives: Add allowlists (trusted admin hosts / service accounts) as part of tuning.

Next steps: Add threat intel lookup, automated enrichment, and a correlation search for "suspicious PS → lateral movement".
