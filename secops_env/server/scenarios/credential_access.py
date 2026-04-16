"""Active Directory and credential access scenario templates for SecOps Alert Router.

Six scenarios covering Kerberos abuse and Windows credential attacks:
  2 benign (authorized SPN registration, AD health monitoring)
  4 true threats (Kerberoasting, AS-REP roasting, DCSync, Pass-the-Hash)

MITRE ATT&CK coverage:
  T1558.003  Steal or Forge Kerberos Tickets: Kerberoasting
  T1558.004  Steal or Forge Kerberos Tickets: AS-REP Roasting
  T1003.006  OS Credential Dumping: DCSync
  T1550.002  Use Alternate Authentication Material: Pass the Hash

Key Windows Security Event IDs used in scenarios:
  4768  Kerberos TGT requested                4769  Kerberos service ticket requested
  4662  Directory service operation            4624  Successful logon
  4648  Explicit-credential logon attempt      4672  Special privileges assigned to logon
"""

CREDENTIAL_ACCESS_SCENARIOS: list[dict] = [
    # ── BENIGN 1: IT team registering SPN for new web-service deployment ──────
    {
        "id": "cred-001",
        "category": "credential_access",
        "difficulty": "easy-medium",
        "is_true_threat": False,
        "severity": "medium",
        "mitre": {
            "tactic": "Privilege Escalation",
            "technique": "T1134",
            "name": "Access Token Manipulation",
        },
        "alert": {
            "rule": "Service Principal Name (SPN) Registration — Multiple Accounts",
            "description": (
                "Active Directory audit: t.okoro (Domain Admin) registered 4 new SPNs "
                "on service accounts in 6 minutes. Bulk SPN writes match Kerberoasting "
                "target-prep patterns."
            ),
        },
        "source": {"ip": "10.0.1.50", "domain": "corp.local", "geo": "INTERNAL"},
        "target": {
            "host": "DC01.corp.local",
            "ip": "10.0.0.5",
            "user": "t.okoro",
            "department": "IT Infrastructure",
            "role": "Senior Systems Administrator",
            "criticality": "high",
        },
        "indicators": {
            "event_id": 5136,
            "operation": "SetSPN",
            "accounts_modified": [
                "svc-webapp-payments",
                "svc-webapp-reporting",
                "svc-webapp-api",
                "svc-webapp-scheduler",
            ],
            "domain": "CORP",
        },
        "raw_log": (
            "Security Event 5136: A directory service object was modified.\n"
            "  Subject: t.okoro | DC01.corp.local | Logon ID: 0x3A7F2\n"
            "  Object DN: CN=svc-webapp-payments,OU=ServiceAccounts,DC=corp,DC=local\n"
            "  Attribute: servicePrincipalName\n"
            "  Value Written: HTTP/payments-web01.corp.local:443\n"
            "  2026-04-16T10:04:17Z | Correlates to 4 similar events in 6 min window"
        ),
        "investigate": {
            "analyze_headers": (
                "Active Directory audit event context:\n"
                "  Subject account: t.okoro (adminCount=1, Domain Admins member)\n"
                "  Logon source: 10.0.1.50 → IT admin workstation ITADM-WS-02\n"
                "  Authentication: Kerberos TGT, AES-256 (strong cipher)\n"
                "  Session created: 2026-04-16T09:55:00Z — within normal shift hours\n"
                "  Time zone: EST (09:55 local — not after-hours)\n"
                "  Remote desktop or console: CONSOLE (physically present)"
            ),
            "query_siem": (
                "2026-04-16T10:04:12Z  AD Audit | 5136 | SetSPN HTTP/payments-web01.corp.local:443 "
                "on svc-webapp-payments\n"
                "2026-04-16T10:04:43Z  AD Audit | 5136 | SetSPN HTTP/reporting-web01.corp.local:443 "
                "on svc-webapp-reporting\n"
                "2026-04-16T10:05:11Z  AD Audit | 5136 | SetSPN HTTP/api-gw01.corp.local:443 "
                "on svc-webapp-api\n"
                "2026-04-16T10:05:38Z  AD Audit | 5136 | SetSPN HTTP/sched01.corp.local:8080 "
                "on svc-webapp-scheduler\n"
                "Pattern: All SPNs follow HTTP/<host>:<port> format. No CIFS, HOST, or MSSQLSvc "
                "SPNs (Kerberoast-preferred targets). Only new SPNs — no existing ones modified."
            ),
            "check_reputation": (
                "t.okoro: Senior Systems Administrator, IT Infrastructure, 4-year tenure.\n"
                "  Previous SPN operations: 11 over past 24 months — all correlated to deployments.\n"
                "  No security incidents. Last logon: yesterday 17:22 (normal).\n"
                "  IP 10.0.1.50: admin workstation, IT department segment (verified in CMDB).\n"
                "  No VirusTotal or threat intel hits for this IP or account.\n"
                "  Risk score: 8/100."
            ),
            "check_asset": (
                "Service accounts modified:\n"
                "  svc-webapp-* (4 accounts) — OU=ServiceAccounts,DC=corp,DC=local\n"
                "  All created today (2026-04-16) by t.okoro — new deployment batch\n"
                "  Password policy: 32-char random (LAPS-equivalent managed)\n"
                "  Group memberships: minimal — only 'WebAppServices' (custom group, no admin rights)\n"
                "  No Admin or DA group membership on any target account"
            ),
            "analyze_payload": (
                "SPN format analysis:\n"
                "  HTTP/payments-web01.corp.local:443   — valid web service SPN\n"
                "  HTTP/reporting-web01.corp.local:443  — valid web service SPN\n"
                "  HTTP/api-gw01.corp.local:443         — valid API gateway SPN\n"
                "  HTTP/sched01.corp.local:8080         — valid scheduler SPN\n"
                "All hostnames resolve to servers provisioned today per CMDB.\n"
                "Jira INFRA-7841: 'Deploy v4.2 payments suite — register Kerberos SPNs'\n"
                "Approved by: cto@company.com | Priority: P2 | Due: 2026-04-16"
            ),
            "correlate_alerts": (
                "Jira INFRA-7841 (open → in-progress at 10:00, closed at 10:08): deployment task.\n"
                "Correlates with server provisioning alert CMDB-NEW-007 (10 new VMs spun up today).\n"
                "No 4769 events (TGS requests) for these SPNs from any other host — not being "
                "targeted for roasting. No suspicious WMI, PowerShell, or Rubeus indicators.\n"
                "Verdict: authorized SPN registration for new application deployment."
            ),
        },
        "optimal_actions": [1, 4, 5, 10],
        "impact_if_missed": (
            "None — authorized deployment task. Blocking would prevent Kerberos-authenticated "
            "payments suite from launching, causing business outage."
        ),
    },

    # ── BENIGN 2: Quest AD Audit health check (authorized monitoring) ─────────
    {
        "id": "cred-002",
        "category": "credential_access",
        "difficulty": "medium",
        "is_true_threat": False,
        "severity": "medium",
        "mitre": {
            "tactic": "Discovery",
            "technique": "T1087.002",
            "name": "Account Discovery: Domain Account",
        },
        "alert": {
            "rule": "High-Volume LDAP Enumeration — User and Group Objects",
            "description": (
                "Domain controller LDAP audit: svc-ad-monitor queried 2,847 user objects "
                "and 312 group objects in 90 seconds. Volume consistent with automated "
                "credential-harvesting or AD reconnaissance tools."
            ),
        },
        "source": {"ip": "10.0.5.22", "domain": "corp.local", "geo": "INTERNAL"},
        "target": {
            "host": "DC01.corp.local",
            "ip": "10.0.0.5",
            "user": "svc-ad-monitor",
            "department": "IT Security",
            "role": "AD Monitoring Service Account",
            "criticality": "high",
        },
        "indicators": {
            "event_id": 1644,
            "query_volume": 3159,
            "filter": "(objectClass=user)(objectClass=group)",
            "source_tool_agent": "Quest AD Audit Plus 9.2",
        },
        "raw_log": (
            "DC01 LDAP Diagnostic Event 1644: Expensive Search\n"
            "  Client: 10.0.5.22:49801 | Account: CORP\\svc-ad-monitor\n"
            "  Base DN: DC=corp,DC=local | Scope: Subtree\n"
            "  Filter: (&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))\n"
            "  Returned: 2847 entries | Elapsed: 340ms\n"
            "  2026-04-16T08:00:02Z — recurs every 15 minutes (cron)"
        ),
        "investigate": {
            "analyze_headers": (
                "LDAP session context:\n"
                "  Bind DN: CN=svc-ad-monitor,OU=ServiceAccounts,DC=corp,DC=local\n"
                "  LDAP version: 3 | TLS: LDAPS (port 636, TLS 1.3)\n"
                "  Source: 10.0.5.22 → AD monitoring server (ADAUDIT-SRV-01 in CMDB)\n"
                "  Connection established: 2026-04-16T08:00:00Z\n"
                "  Session type: service bind (no interactive logon, SPN-authenticated)\n"
                "  Query interval: every 15 minutes (01:00, 08:00, 08:15, 08:30...)"
            ),
            "query_siem": (
                "LDAP query history for svc-ad-monitor (last 24 hours):\n"
                "  96 identical LDAP queries (every 15 min, round-the-clock)\n"
                "  All queries: same filter, same base DN, same result count (~2847 users)\n"
                "  No writes, no Add/Modify/Delete LDAP operations\n"
                "  No 4648 (explicit-credential logon) or 4769 (TGS request) from this source\n"
                "  No Nmap, BloodHound, or PowerView signatures in network traffic"
            ),
            "check_reputation": (
                "svc-ad-monitor: Service account, IT Security team (owner: p.nguyen).\n"
                "  Created: 2023-11-01. Purpose: Quest AD Audit Plus health polling.\n"
                "  IP 10.0.5.22: AD monitoring server, IT Security subnet (documented in CMDB).\n"
                "  Account has never been used interactively — no workstation logons.\n"
                "  Threat intel: IP and account have zero threat-feed hits.\n"
                "  Risk score: 4/100."
            ),
            "check_asset": (
                "ADAUDIT-SRV-01 (10.0.5.22):\n"
                "  OS: Windows Server 2022 Datacenter | Role: AD monitoring / SIEM feed\n"
                "  Owner: IT Security | Patch level: current (KB5034440 applied)\n"
                "  Software: Quest AD Audit Plus 9.2 (licensed, asset tag AA-2247)\n"
                "  Data leaving host: syslog feed to SIEM only (UDP 514 to SIEM-01)\n"
                "  No outbound internet, no cloud sync enabled"
            ),
            "analyze_payload": (
                "LDAP filter breakdown:\n"
                "  (&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))\n"
                "  → All enabled user accounts (excludes disabled via UF_ACCOUNTDISABLE bit)\n"
                "  Second query: (objectClass=group)(groupType:1.2.840.113556.1.4.803:=2147483648)\n"
                "  → All global security groups\n"
                "  These are standard AD Audit Plus baseline queries (documented in vendor guide).\n"
                "  No queries for msDS-SupportedEncryptionTypes (Kerberoast prep) or "
                "userAccountControl=4194304 (DONT_REQ_PREAUTH — AS-REP prep)."
            ),
            "correlate_alerts": (
                "Quest AD Audit Plus generates this exact alert weekly per vendor design.\n"
                "Previous identical alerts: 2026-04-09, 2026-04-02, 2026-03-26 — all resolved benign.\n"
                "No changes to ADAUDIT-SRV-01 or svc-ad-monitor in past 30 days.\n"
                "No concurrent suspicious activity on DC01 or any other DC.\n"
                "Verdict: authorized monitoring tool, recurring false positive."
            ),
        },
        "optimal_actions": [1, 3, 5, 10],
        "impact_if_missed": (
            "None — blocking monitoring service would blind the SOC to real AD attacks. "
            "svc-ad-monitor provides 40% of the SIEM's AD telemetry."
        ),
    },

    # ── THREAT 1: Kerberoasting — T1558.003 ───────────────────────────────────
    {
        "id": "cred-003",
        "category": "credential_access",
        "difficulty": "hard",
        "is_true_threat": True,
        "severity": "critical",
        "mitre": {
            "tactic": "Credential Access",
            "technique": "T1558.003",
            "name": "Steal or Forge Kerberos Tickets: Kerberoasting",
        },
        "alert": {
            "rule": "Kerberos TGS Burst — RC4 Encryption Anomaly (Potential Kerberoasting)",
            "description": (
                "DC01 Security log: 23 Kerberos TGS requests (Event 4769) in 4 minutes from "
                "workstation WS-CONTRACTOR-09 (10.0.8.143). All tickets requested with "
                "TicketEncryptionType=0x17 (RC4-HMAC). No legitimate workload generates this "
                "pattern — consistent with Rubeus.exe kerberoast /rc4opsec."
            ),
        },
        "source": {"ip": "10.0.8.143", "domain": "corp.local", "geo": "INTERNAL"},
        "target": {
            "host": "DC01.corp.local",
            "ip": "10.0.0.5",
            "user": "c.reeves",
            "department": "Finance (Contractor)",
            "role": "Financial Systems Contractor",
            "criticality": "critical",
        },
        "indicators": {
            "event_id": 4769,
            "ticket_encryption_type": "0x17 (RC4-HMAC)",
            "spns_targeted": 23,
            "duration_seconds": 247,
            "tool_indicator": "Rubeus.exe /rc4opsec pattern",
        },
        "raw_log": (
            "Security Event 4769 [x23 in 4m07s] — Kerberos Service Ticket Operations\n"
            "  Account Name: c.reeves@CORP.LOCAL | Client Address: 10.0.8.143\n"
            "  Service Names: svc-sql-prod, svc-backup-mgr, svc-exchange-scanning, "
            "svc-sap-finance, svc-vmware-api, svc-jenkins, svc-splunk-fwd [+16 more]\n"
            "  Ticket Encryption Type: 0x17 (RC4-HMAC) ← ALL 23 tickets\n"
            "  Ticket Options: 0x40810000 | Failure Code: 0x0 (success)\n"
            "  2026-04-16T21:44:11Z — Friday evening, outside business hours"
        ),
        "investigate": {
            "analyze_headers": (
                "Event 4769 metadata (23 events, 2026-04-16T21:44:11Z–21:48:18Z):\n"
                "  Account: c.reeves@CORP.LOCAL (contractor, finance systems)\n"
                "  Source IP: 10.0.8.143 | Hostname: WS-CONTRACTOR-09\n"
                "  Logon ID: 0x8C3F14 — session created 21:41:30 (3 min before burst starts)\n"
                "  All 23 TGS requests: TicketEncryptionType=0x17 (RC4-HMAC)\n"
                "  Expected for modern AD: 0x12 (AES-256) or 0x11 (AES-128)\n"
                "  RC4 downgrade on AES-capable accounts requires explicit request — "
                "Rubeus does this to produce crackable hashes.\n"
                "  Time: Friday 21:44 EST — after-hours. c.reeves badged out at 18:02."
            ),
            "query_siem": (
                "Timeline on WS-CONTRACTOR-09 (10.0.8.143):\n"
                "2026-04-16T21:41:28Z  4624  c.reeves logged in (Kerberos, Type 2 interactive)\n"
                "2026-04-16T21:42:15Z  4688  Process: powershell.exe (PPID: explorer.exe)\n"
                "2026-04-16T21:42:19Z  4688  Process: Rubeus.exe → spawned from powershell\n"
                "  cmdline: Rubeus.exe kerberoast /rc4opsec /outfile:C:\\Temp\\hashes.txt\n"
                "2026-04-16T21:44:11Z  4769 × 23  TGS burst, all RC4, unique SPNs\n"
                "2026-04-16T21:48:22Z  4688  Process: certutil.exe -encode hashes.txt out.b64\n"
                "2026-04-16T21:48:45Z  DNS  query: pastebin.com (anomalous for corp network)\n"
                "Note: Rubeus.exe binary not in CMDB software inventory. Hash on VirusTotal: "
                "known offensive tool signature."
            ),
            "check_reputation": (
                "c.reeves: Finance contractor, 6-week engagement, badged out 18:02 today.\n"
                "  Account has no legitimate reason to request TGS for svc-sql-prod or svc-backup.\n"
                "  10.0.8.143 is in contractor VLAN — should have no AD service access.\n"
                "  Rubeus.exe SHA-256: 3b1c4e7d9a2f5b8c... — VirusTotal 42/72 detections.\n"
                "  c.reeves has no Jira/ServiceNow tickets for after-hours work.\n"
                "  Prior incident: WS-CONTRACTOR-09 had Mimikatz detected via EDR 2 days ago "
                "(alert THREAT-20260414-002, remediation pending)."
            ),
            "check_asset": (
                "23 targeted SPNs include high-value accounts:\n"
                "  svc-sql-prod       — SA-equivalent on PROD-SQL-01, SQL-02, SQL-03\n"
                "  svc-backup-mgr     — Local admin on ALL 847 domain-joined servers (via GPO)\n"
                "  svc-exchange-scanning — Exchange Organization Management\n"
                "  svc-sap-finance    — SAP BASIS admin, accesses financial ledger data\n"
                "  svc-vmware-api     — vCenter Administrator role\n"
                "Cracking svc-backup-mgr alone = admin on every server. Risk: MAXIMUM.\n"
                "Password age on these accounts: 180-730 days (all overdue for rotation)."
            ),
            "analyze_payload": (
                "Kerberos ticket analysis (Event 4769 fields):\n"
                "  TicketEncryptionType: 0x17 for all 23 requests\n"
                "  This forces RC4-HMAC even if account supports AES — Rubeus /rc4opsec flag\n"
                "  RC4 Kerberos tickets = NTLM hash in the TGS response body\n"
                "  Hashcat mode 13100 ($krb5tgs$23$*...) — crackable offline\n"
                "  C:\\Temp\\hashes.txt created at 21:48:18 (via EDR file-create telemetry)\n"
                "  Estimated crack time on RTX 4090: complex 8-char alphanumeric = 4-6 hours.\n"
                "  certutil.exe base64 encode + DNS query to pastebin.com = exfil attempt."
            ),
            "correlate_alerts": (
                "THREAT-20260414-002 (2 days ago): Mimikatz lsass dump on WS-CONTRACTOR-09 — "
                "remediation assigned but not completed.\n"
                "THREAT-20260416-001 (this alert): Kerberoasting from same workstation.\n"
                "Attack chain: initial access → lsass dump → kerberoasting → hash exfil → "
                "offline crack → lateral movement with service account creds.\n"
                "Blast radius: svc-backup-mgr = local admin on ALL domain servers.\n"
                "MANDATORY: disable c.reeves, isolate WS-CONTRACTOR-09, force-rotate all "
                "23 service account passwords, reset krbtgt (twice, 10h apart), escalate to CISO."
            ),
        },
        "optimal_actions": [1, 2, 5, 8, 6, 9],
        "impact_if_missed": (
            "Attacker cracks svc-backup-mgr offline → local admin on 847 servers → "
            "complete domain compromise within 6-12 hours of the kerberoasting event."
        ),
    },

    # ── THREAT 2: AS-REP Roasting — T1558.004 ─────────────────────────────────
    {
        "id": "cred-004",
        "category": "credential_access",
        "difficulty": "hard",
        "is_true_threat": True,
        "severity": "high",
        "mitre": {
            "tactic": "Credential Access",
            "technique": "T1558.004",
            "name": "Steal or Forge Kerberos Tickets: AS-REP Roasting",
        },
        "alert": {
            "rule": "AS-REP Roasting Detected — DONT_REQ_PREAUTH Accounts Targeted",
            "description": (
                "DC01 Security log: 8 Kerberos AS-REQ events (Event 4768) with "
                "PreAuthType=0 in 3 minutes from an unregistered host (10.0.99.47). "
                "Pre-authentication bypass requests on this cadence indicate Impacket "
                "GetNPUsers or Rubeus asreproast against known vulnerable accounts."
            ),
        },
        "source": {"ip": "10.0.99.47", "domain": "corp.local", "geo": "INTERNAL"},
        "target": {
            "host": "DC01.corp.local",
            "ip": "10.0.0.5",
            "user": "MULTIPLE",
            "department": "MULTIPLE",
            "role": "Targeted accounts: svc-backup, svc-monitoring, hr-admin-svc [+5]",
            "criticality": "high",
        },
        "indicators": {
            "event_id": 4768,
            "pre_auth_type": 0,
            "accounts_targeted": 8,
            "source_os_ttl": 64,
            "source_mac_vendor": "VMware (virtual machine)",
        },
        "raw_log": (
            "Security Event 4768 [x8 in 2m47s] — Kerberos Authentication Ticket (TGT) Requested\n"
            "  Client Address: 10.0.99.47 | Pre-Authentication Type: 0 (None)\n"
            "  Target Accounts: svc-backup, svc-monitoring, hr-admin-svc, svc-sccm-client,\n"
            "                   finance-rpt, svc-legacy-app, svc-print-mgr, cad-svc-acct\n"
            "  Encryption Type: 0x17 (RC4) | Failure Code: 0x0 (AS-REP issued)\n"
            "  2026-04-16T14:32:07Z–14:34:54Z | Source not in CMDB"
        ),
        "investigate": {
            "analyze_headers": (
                "Event 4768 session metadata:\n"
                "  Source: 10.0.99.47 — VLAN 99 (guest/quarantine segment)\n"
                "  Hostname reverse DNS: NONE (not in AD, not in DHCP/CMDB)\n"
                "  Network TTL observed: 64 (Linux default — Kali or similar)\n"
                "  Pre-Authentication Type: 0 = no pre-auth required\n"
                "  This works because targeted accounts have msDS-SupportedEncryptionTypes "
                "set with DONT_REQ_PREAUTH (UAC flag 0x400000).\n"
                "  AS-REP returned contains TGT encrypted with account's NTLM hash — "
                "offline crackable (hashcat mode 18200)."
            ),
            "query_siem": (
                "2026-04-16T14:20:14Z  NetFlow | 10.0.99.47 → DC01 TCP:88 SYN (port scan)\n"
                "2026-04-16T14:25:01Z  NetFlow | 10.0.99.47 → DC01 TCP:389 (LDAP query)\n"
                "2026-04-16T14:31:52Z  DNS  | 10.0.99.47 PTR lookup for DC01.corp.local\n"
                "2026-04-16T14:32:07Z  4768 × 8  AS-REP roasting burst, PreAuthType=0\n"
                "2026-04-16T14:35:03Z  NetFlow | 10.0.99.47 → SIEM-01 TCP:443 (BLOCKED by FW)\n"
                "Note: LDAP at 14:25 suggests prior discovery (BloodHound or ldapsearch) "
                "to identify DONT_REQ_PREAUTH accounts before roasting."
            ),
            "check_reputation": (
                "10.0.99.47: Not in CMDB. DHCP lease issued today 14:01 (MAC: 00:0C:29:xx — VMware).\n"
                "  Guest VLAN should NOT have LDAP or Kerberos access to DC01 — firewall rule gap.\n"
                "  Threat intel: IP not externally known (internal VM). MAC OUI = VMware Workstation.\n"
                "  3 of 8 targeted accounts are privileged:\n"
                "    svc-backup: local admin on all servers via GPO\n"
                "    svc-monitoring: can read all DC event logs + registry\n"
                "    hr-admin-svc: ADP/Workday admin (SSN, salary, PII)\n"
                "  All 8 accounts confirmed DONT_REQ_PREAUTH via AD query."
            ),
            "check_asset": (
                "10.0.99.47 — rogue VM on guest VLAN:\n"
                "  No CMDB record. No NAC certificate. No domain join.\n"
                "  MAC: 00:0C:29:A3:72:B1 (VMware Workstation) — virtual machine\n"
                "  OS: Linux (TTL=64 confirmed) — likely Kali Linux or ParrotOS\n"
                "  Open ports (Nmap from VLAN gw): 22/tcp, 4444/tcp — SSH + possible C2 listener\n"
                "  DONT_REQ_PREAUTH accounts often set by legacy app vendors to avoid MFA friction."
            ),
            "analyze_payload": (
                "AS-REP hash format captured (inferred from Event 4768 + Wireshark mirror):\n"
                "  $krb5asrep$23$svc-backup@CORP.LOCAL:e3f2a1...7b9c$aabbcc...\n"
                "  Mode 18200 in hashcat. RTX 4090 speed: ~1.1 GH/s for NTLM-based\n"
                "  Estimated crack time (rockyou + rules): 15 min – 2 hours for common passwords.\n"
                "  svc-backup last password change: 547 days ago.\n"
                "  Firewall blocked outbound 443 to SIEM-01 (possibly misidentified C2 — check).\n"
                "  AS-REPs for all 8 accounts were issued by DC01 successfully."
            ),
            "correlate_alerts": (
                "Rogue VM appeared on guest VLAN 47 minutes before roasting (DHCP at 14:01).\n"
                "LDAP scan at 14:25 identified DONT_REQ_PREAUTH accounts — deliberate recon.\n"
                "No prior events from this MAC address.\n"
                "Three DONT_REQ_PREAUTH accounts are high-privilege (svc-backup, svc-monitoring, "
                "hr-admin-svc) — cracking any one = significant lateral movement or PII exposure.\n"
                "Immediate actions: block 10.0.99.47 at VLAN gateway, remove DONT_REQ_PREAUTH "
                "from all 8 accounts, force password reset for all 8, audit guest VLAN ACL rules."
            ),
        },
        "optimal_actions": [2, 1, 5, 6, 8, 9],
        "impact_if_missed": (
            "Attacker cracks svc-backup offline (weak password, 547 days old) → local admin "
            "on all servers. hr-admin-svc crack → 4,200 employee SSNs and salary data exposed."
        ),
    },

    # ── THREAT 3: DCSync attack — T1003.006 (SOX compliance) ─────────────────
    {
        "id": "cred-005",
        "category": "credential_access",
        "difficulty": "expert",
        "is_true_threat": True,
        "severity": "critical",
        "mitre": {
            "tactic": "Credential Access",
            "technique": "T1003.006",
            "name": "OS Credential Dumping: DCSync",
        },
        "alert": {
            "rule": "DCSync Attack Detected — DS-Replication-Get-Changes-All from Non-DC",
            "description": (
                "DC01 Security log: Event 4662 — directory replication right "
                "DS-Replication-Get-Changes-All ({1131f6ad-...}) exercised by "
                "svc-reporting (10.0.3.201). This DRSUAPI right is reserved for "
                "domain controllers only. Non-DC usage = Mimikatz DCSync or Impacket "
                "secretsdump — full NTDS.dit hash dump in progress."
            ),
        },
        "source": {"ip": "10.0.3.201", "domain": "corp.local", "geo": "INTERNAL"},
        "target": {
            "host": "DC01.corp.local",
            "ip": "10.0.0.5",
            "user": "svc-reporting",
            "department": "Finance IT",
            "role": "Reporting Service Account",
            "criticality": "critical",
        },
        "indicators": {
            "event_id": 4662,
            "right_guid": "{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}",
            "operation": "DS-Replication-Get-Changes-All",
            "object_type": "domainDNS",
            "source_host": "FINRPT-WS-11",
        },
        "raw_log": (
            "Security Event 4662: An operation was performed on an object.\n"
            "  Subject Account: CORP\\svc-reporting | Logon ID: 0x5DE4A2\n"
            "  Object Type: domainDNS | Object Name: DC=corp,DC=local\n"
            "  Operation Type: Object Access\n"
            "  Access Mask: 0x100 (Control Access)\n"
            "  Properties: {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2} "
            "[DS-Replication-Get-Changes-All]\n"
            "  Client: 10.0.3.201 (FINRPT-WS-11) | 2026-04-16T23:12:44Z"
        ),
        "investigate": {
            "analyze_headers": (
                "Event 4662 replication context:\n"
                "  Account: svc-reporting — service account, Finance IT, NOT a domain controller\n"
                "  Right exercised: {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}\n"
                "  = DS-Replication-Get-Changes-All (highest-privilege AD replication right)\n"
                "  Normally held only by: Domain Controllers, Domain Admins, Enterprise Admins\n"
                "  svc-reporting should have NO replication rights — Finance reporting role only\n"
                "  Source host: FINRPT-WS-11 (10.0.3.201) — Finance workstation, not a DC\n"
                "  Time: Friday 23:12 EST (deep after-hours, no staff scheduled)\n"
                "  How svc-reporting got this right: see correlate_alerts"
            ),
            "query_siem": (
                "Timeline on FINRPT-WS-11 (10.0.3.201):\n"
                "2026-04-16T23:08:12Z  4624  svc-reporting interactive logon (suspicious: "
                "service accounts should not log in interactively)\n"
                "2026-04-16T23:09:44Z  4688  Process: python.exe (PPID: cmd.exe)\n"
                "  cmdline: python secretsdump.py CORP/svc-reporting@DC01.corp.local -just-dc\n"
                "2026-04-16T23:10:01Z  Network  DRSUAPI RPC bind to DC01 port 49157 (ephemeral)\n"
                "2026-04-16T23:12:44Z  4662 × 12  DS-Replication-Get-Changes-All (all DCs)\n"
                "2026-04-16T23:14:33Z  4662  DS-Replication-Get-Changes (final sync confirmed)\n"
                "Impacket secretsdump uses DsGetNCChanges DRSUAPI call — matches this exactly."
            ),
            "check_reputation": (
                "svc-reporting: Finance reporting service account, created 2022-08-14.\n"
                "  Prior role: run Crystal Reports, read-only SQL queries. No replication rights.\n"
                "  Account was Kerberoasted 6 days ago (THREAT-20260410-001) — password cracked!\n"
                "  THREAT-20260410-001 linked to same attack campaign.\n"
                "  10.0.3.201 (FINRPT-WS-11): Finance workstation, assigned to contractor c.reeves.\n"
                "  Same c.reeves from THREAT-20260416-001 (Kerberoasting alert).\n"
                "  Attack path: Kerberoast svc-reporting → crack password → DCSync with stolen creds.\n"
                "  Risk score: 100/100 — ACTIVE DOMAIN COMPROMISE."
            ),
            "check_asset": (
                "DCSync blast radius:\n"
                "  DsGetNCChanges returns ALL account hashes from NTDS.dit:\n"
                "    Administrator (RID 500) — domain-wide admin\n"
                "    krbtgt — enables Golden Ticket forgery (persistent, 10-year TTL)\n"
                "    All 2,847 user accounts including C-suite and finance\n"
                "    All 312 service accounts\n"
                "  SOX-regulated systems accessible via extracted hashes:\n"
                "    - financial-ledger-01 (SAP S/4HANA — quarterly earnings data)\n"
                "    - audit-db-01 (SOX audit trail database)\n"
                "    - payroll-01 (ADP integration server)\n"
                "  krbtgt hash enables forging valid Kerberos tickets for any service, "
                "any user, indefinitely — until krbtgt is reset twice."
            ),
            "analyze_payload": (
                "DRSUAPI call analysis:\n"
                "  GetNCChanges request: naming context = DC=corp,DC=local (full domain)\n"
                "  Attributes requested: unicodePwd, ntPwdHistory, lmPwdHistory, supplementalCredentials\n"
                "  These attributes contain RC4 NT hashes + AES Kerberos keys for all accounts\n"
                "  12 replication events × domain partition = ALL user, computer, and service hashes\n"
                "  Including: krbtgt (current + previous), Administrator, all DA/EA accounts\n"
                "  Impacket output file: /tmp/corp.local.ntds (inferred from secretsdump behavior)\n"
                "  MANDATORY: reset krbtgt password TWICE (10h apart) to invalidate Golden Tickets."
            ),
            "correlate_alerts": (
                "Complete attack chain:\n"
                "2026-04-10 THREAT-20260410-001: svc-reporting Kerberoasted (RC4 hash captured)\n"
                "2026-04-14 THREAT-20260414-002: Mimikatz on WS-CONTRACTOR-09 (c.reeves)\n"
                "2026-04-16 THREAT-20260416-001: Kerberoasting burst (23 SPNs) from c.reeves\n"
                "2026-04-16 THREAT-20260416-002 (THIS): DCSync from FINRPT-WS-11 with "
                "cracked svc-reporting password\n"
                "Attacker has now dumped ALL domain hashes. Assume full domain compromise.\n"
                "INCIDENT RESPONSE REQUIRED: Purple team engagement, forensic imaging, "
                "krbtgt double-reset, force password reset for ALL accounts, IOC sweep."
            ),
        },
        "optimal_actions": [1, 2, 5, 7, 8, 9],
        "impact_if_missed": (
            "Attacker retains krbtgt hash → forges Golden Tickets indefinitely. "
            "SOX audit data and financial ledger accessible. Full domain remains compromised "
            "even after password resets unless krbtgt is rotated."
        ),
        "compliance": {
            "framework": "SOX",
            "data_classification": "Financial Records and Audit Trail",
            "breach_notification_hours": 72,
            "breach_notification_window": (
                "Immediate CISO and CFO notification. SEC material disclosure review within 4 days "
                "if financial data accessed. External auditor (KPMG) notification per SOX § 302."
            ),
        },
    },

    # ── THREAT 4: Pass-the-Hash lateral movement — T1550.002 (PCI-DSS) ───────
    {
        "id": "cred-006",
        "category": "credential_access",
        "difficulty": "expert",
        "is_true_threat": True,
        "severity": "critical",
        "mitre": {
            "tactic": "Lateral Movement",
            "technique": "T1550.002",
            "name": "Use Alternate Authentication Material: Pass the Hash",
        },
        "alert": {
            "rule": "NTLM Pass-the-Hash Lateral Movement — CDE Servers Targeted",
            "description": (
                "SIEM correlation: same NTLM hash (Administrator RID-500) used to authenticate "
                "to 14 servers in 45 minutes. Source: PAYROLL-WS-03 (10.0.4.88). "
                "Target servers include PCI-DSS Cardholder Data Environment (CDE). "
                "No human can authenticate to 14 servers in 45 min — automated PtH. "
                "Impacket wmiexec or Mimikatz sekurlsa::pth signature."
            ),
        },
        "source": {"ip": "10.0.4.88", "domain": "corp.local", "geo": "INTERNAL"},
        "target": {
            "host": "pos-gateway-01.corp.local / payment-processor-02 / cde-db-03 [+11]",
            "ip": "10.0.10.0/24 (CDE subnet)",
            "user": "Administrator",
            "department": "MULTIPLE (Finance, POS, Payments)",
            "role": "Domain Administrator (RID 500) — via stolen hash",
            "criticality": "critical",
        },
        "indicators": {
            "event_id": 4624,
            "logon_type": 3,
            "auth_package": "NTLM",
            "servers_hit": 14,
            "time_window_minutes": 45,
            "nt_hash_partial": "aad3b435b51404ee...",
        },
        "raw_log": (
            "Security Event 4624 [x14 across CDE subnet, 21:05–21:50] — Account Logged On\n"
            "  Account: Administrator | Logon Type: 3 (Network)\n"
            "  Auth Package: NTLM | Logon Process: NtLmSsp\n"
            "  Workstation: PAYROLL-WS-03 | Source: 10.0.4.88\n"
            "  Key Length: 0 (indicates NTLM hash — NOT plaintext password)\n"
            "  Targets: pos-gateway-01, payment-processor-02, cde-db-03, cde-app-01,\n"
            "           cde-app-02, cde-db-04, tokenization-svc-01 [+7 more CDE hosts]\n"
            "  4672 on each: SeImpersonatePrivilege + SeTcbPrivilege assigned at each logon"
        ),
        "investigate": {
            "analyze_headers": (
                "Event 4624 NTLM logon metadata (representative sample):\n"
                "  Account: Administrator (RID 500) — built-in domain admin\n"
                "  Logon Type: 3 (Network) with Auth Package: NtLmSsp\n"
                "  Key Length: 0 — characteristic of Pass-the-Hash (no session key negotiated)\n"
                "  WorkstationName: PAYROLL-WS-03 in all 14 events (consistent source)\n"
                "  Impersonation Level: %%1833 (Impersonation) — typical for PtH lateral movement\n"
                "  4672 follows each 4624: SeImpersonatePrivilege, SeTcbPrivilege, SeDebugPrivilege\n"
                "    = full admin token. Attacker has unrestricted access on each target host.\n"
                "  First event: 21:05:17Z. Last: 21:49:58Z. Interval: ~3-4 min/host = automated."
            ),
            "query_siem": (
                "Timeline on PAYROLL-WS-03 (10.0.4.88):\n"
                "2026-04-16T21:01:14Z  4688  python.exe spawned (PPID: cmd.exe)\n"
                "  cmdline: python wmiexec.py -hashes :aad3b435b51404eeaad3b435b51404ee:"
                "32ed87bdb5fdc5e9cba88547376818d4 Administrator@pos-gateway-01\n"
                "2026-04-16T21:05:17Z  4624 Logon  Administrator → pos-gateway-01 (CDE)\n"
                "2026-04-16T21:05:22Z  4688  cmd.exe on pos-gateway-01 (remote execution)\n"
                "... [12 more hosts, same pattern, 3-4 min apart]\n"
                "2026-04-16T21:49:58Z  4624 Logon  Administrator → cde-db-04 (last host)\n"
                "2026-04-16T21:50:11Z  5145  cde-db-04 ADMIN$ share accessed (file drop)\n"
                "Hash 32ed87bdb5... matches Administrator hash from DCSync on 2026-04-16T23:14Z "
                "— WAIT: DCSync was AFTER this PtH. Hash source = Mimikatz from earlier lsass dump."
            ),
            "check_reputation": (
                "PAYROLL-WS-03 (10.0.4.88): Payroll department workstation, assigned to b.santos.\n"
                "  b.santos on PTO since 2026-04-14 — workstation should be idle.\n"
                "  Connected to after b.santos badged in at 2026-04-16T20:58 (badge cloned?)\n"
                "  Administrator hash matches THREAT-20260414-002 Mimikatz dump on WS-CONTRACTOR-09.\n"
                "  Attacker pivoted from WS-CONTRACTOR-09 → PAYROLL-WS-03 using earlier foothold.\n"
                "  14 PCI-DSS CDE servers accessed — PAN storage DB, tokenization service, "
                "POS gateway, payment processor. Scope: potential full cardholder data breach.\n"
                "  Risk score: 100/100 — ACTIVE PCI-DSS BREACH IN PROGRESS."
            ),
            "check_asset": (
                "CDE servers accessed (PCI-DSS scope):\n"
                "  pos-gateway-01       — POS payment authorization gateway (3.2M transactions/day)\n"
                "  payment-processor-02 — Card brand connectivity (Visa, Mastercard)\n"
                "  cde-db-03/04         — PAN storage (encrypted) + cardholder data vault\n"
                "  tokenization-svc-01  — Token/PAN mapping database (if stolen = full PAN access)\n"
                "  cde-app-01/02        — PCI web application servers\n"
                "  All CDE servers: Admin$ share accessed (5145 event) = file drop confirmed.\n"
                "  Dropped files not yet identified — may be ransomware staging, exfil tool, or "
                "persistence implant. Forensic imaging required immediately."
            ),
            "analyze_payload": (
                "PtH technical indicators:\n"
                "  NTLM hash used: 32ed87bdb5fdc5e9cba88547376818d4 (Administrator NT hash)\n"
                "  Impacket wmiexec signature: uses DCOM/WMI for remote execution, no PSExec noise\n"
                "  Event 5145 on cde-db-04: \\\\cde-db-04\\ADMIN$ accessed with Accesses: WriteData\n"
                "  File written: C:\\Windows\\Temp\\svc_update.exe (35,840 bytes, PE32+ executable)\n"
                "  SHA-256: 8f3a2c1d7e4b9f0e... — queried VirusTotal: 0 detections (new/custom tool)\n"
                "  Process tree: wmiexec → WMI service → cmd.exe → svc_update.exe (not yet run)\n"
                "  svc_update.exe not executed yet — containment window still open."
            ),
            "correlate_alerts": (
                "Full attack timeline confirmed:\n"
                "2026-04-10: svc-reporting Kerberoasted (THREAT-20260410-001)\n"
                "2026-04-14: Mimikatz lsass dump on WS-CONTRACTOR-09 → Admin hash stolen\n"
                "2026-04-16T21:05: PtH lateral movement to 14 CDE servers (THIS ALERT)\n"
                "2026-04-16T23:12: DCSync from FINRPT-WS-11 (simultaneous, two attacker threads)\n"
                "svc_update.exe dropped on 14 CDE servers but NOT YET EXECUTED — containment window.\n"
                "IMMEDIATE ACTIONS:\n"
                "  1. Block 10.0.4.88 at CDE firewall now\n"
                "  2. Isolate all 14 CDE hosts (network segment them)\n"
                "  3. Do NOT power off — preserve forensic memory for svc_update.exe analysis\n"
                "  4. Disable local Administrator account on all CDE hosts\n"
                "  5. PCI-DSS: notify acquiring bank within 24 hours, card brands within 72 hours\n"
                "  6. Engage QSA (Qualified Security Assessor) for breach investigation"
            ),
        },
        "optimal_actions": [1, 2, 5, 7, 6, 9],
        "impact_if_missed": (
            "svc_update.exe executes on 14 CDE servers → ransomware encryption or cardholder data "
            "exfiltration of 3.2M daily transactions. PCI-DSS Level 1 breach: $5,000-$100,000/month "
            "card brand fines + potential card processing suspension."
        ),
        "compliance": {
            "framework": "PCI-DSS",
            "data_classification": "Cardholder Data Environment (CDE)",
            "breach_notification_hours": 24,
            "breach_notification_window": (
                "PCI-DSS v4.0 § 12.10.7: Notify acquiring bank within 24 hours. "
                "Card brand (Visa/Mastercard) notification within 72 hours. "
                "Engage PFI (PCI Forensic Investigator) within 3 business days."
            ),
        },
    },
]
