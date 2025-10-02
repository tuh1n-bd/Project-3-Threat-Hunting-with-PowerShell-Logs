##SOC triage playbook (what an L1 should do when alert fires)

When BF_SuccessAfterFailures alert fires:

1. Acknowledge alert in ticketing system.

2. Identify scope: Which Account_Name, Source_IP, Host? (use event fields)

3. Check for success after failures: Confirm EventID 4624 after many 4625s.

4. Lookup IP reputation: query threat_intel lookup or run enrichment.

5. Check location/time: iplocation Source_IP and check if login times conflict with user’s usual activity.

6. Look for lateral movement: search for unusual process creations (4688) from the host.

7. Verify MFA status / password reset: communicate with identity team — recommend password reset & MFA enforcement if suspicious.

8. Containment if confirmed: disable account, isolate host, escalate to L2.

9. Document findings: in ticket: timeline, query used, IOC list (Source_IPs), recommended remediation.

10. Add suppression rule if false positives repeat
