## SOC L1 Triage Playbook

When an alert fires:
---
Check CommandLine: Does it include -enc, Invoke-WebRequest, Mimikatz?

Check user account: Is it a service account, admin, or end-user?

Check host: Is this a server, workstation, or domain controller?

Pivot:

Search index=ps_data sourcetype=csv by Account_Name or ComputerName to see what else happened.

Look for EventID 4688 (process creation) to see child processes.

Correlate: Was this followed by credential dumping, lateral movement, or persistence?

Contain if malicious: Disable account, isolate host.

Document: Add to case with screenshots and SPL used.
