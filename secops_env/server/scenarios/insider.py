"""Insider threat scenario templates for the SOC RL environment."""

INSIDER_SCENARIOS = [
    # BENIGN 1 -- Employee working late on a deadline
    {
        "id": "insider-001",
        "category": "insider_threat",
        "difficulty": "medium",
        "is_true_threat": False,
        "severity": "low",
        "mitre": {"tactic": "Initial Access", "technique": "T1078", "name": "Valid Accounts"},
        "alert": {
            "rule": "After-Hours Logon Detected",
            "description": "User authenticated to workstation outside normal business hours (02:14 AM local time).",
        },
        "source": {"ip": "10.20.5.42", "domain": "corp.acmeinc.local", "email": "", "geo": "INTERNAL"},
        "target": {
            "host": "WS-FIN-0117", "ip": "10.20.5.42", "user": "maria.gonzalez",
            "email": "maria.gonzalez@acmeinc.com", "department": "Finance",
            "role": "Senior Financial Analyst", "criticality": "medium",
        },
        "indicators": {
            "logon_time": "2026-04-12T02:14:33Z", "badge_swipe": "2026-04-12T02:10:08Z",
            "files_accessed": 12, "files_modified": 3, "external_transfers": 0, "vpn_active": False,
        },
        "raw_log": (
            "Apr 12 02:14:33 WS-FIN-0117 sshd[4821]: Accepted password for maria.gonzalez from 10.20.5.42 port 55412 ssh2\n"
            "Apr 12 02:15:01 WS-FIN-0117 audit[4821]: USER_AUTH user=maria.gonzalez exe=/usr/bin/login res=success\n"
            "Apr 12 02:16:44 WS-FIN-0117 kernel: USB mass-storage not detected\n"
            "Apr 12 02:17:02 WS-FIN-0117 app[Excel]: Opened Q1_Revenue_Forecast.xlsx\n"
            "Apr 12 02:45:19 WS-FIN-0117 app[Excel]: Saved Q1_Revenue_Forecast.xlsx"
        ),
        "investigate": {
            "analyze_headers": "Authentication via local console logon (Type 2). MFA satisfied with hardware token at 02:14 AM.",
            "query_siem": (
                "2026-04-12T02:14:33Z  EventID=4624 LogonType=2 User=maria.gonzalez Host=WS-FIN-0117\n"
                "2026-04-12T02:17:02Z  EventID=4663 File=Q1_Revenue_Forecast.xlsx Access=Read,Write\n"
                "2026-04-12T02:45:19Z  EventID=4663 File=Q1_Revenue_Forecast.xlsx Access=Write\n"
                "2026-04-12T03:12:07Z  EventID=4634 LogoffType=2 User=maria.gonzalez"
            ),
            "check_reputation": "User maria.gonzalez: no prior alerts in last 90 days. Risk score: 12/100. Account in good standing.",
            "check_asset": "WS-FIN-0117 -- assigned to maria.gonzalez, Finance dept. Asset criticality: medium. Last patched: 2026-04-10. AV signatures current. No open vulnerabilities.",
            "analyze_payload": "Files accessed: Q1_Revenue_Forecast.xlsx, Budget_Adjustments.docx, GL_Export_April.csv. All within Finance SharePoint scope. No encrypted archives created. No external uploads.",
            "correlate_alerts": "Badge swipe at Building-A main entrance at 02:10 AM matches logon time. Calendar shows 'Q1 Close Deadline' event for 2026-04-12. Manager (j.park) approved overtime request on 04-11.",
        },
        "optimal_actions": ["classify_benign", "add_context_note", "close_alert"],
        "impact_if_missed": "No real impact. Escalating would waste SOC analyst time and create unnecessary friction with the Finance team.",
    },
    # BENIGN 2 -- IT admin performing scheduled maintenance
    {
        "id": "insider-002",
        "category": "insider_threat",
        "difficulty": "medium",
        "is_true_threat": False,
        "severity": "low",
        "mitre": {"tactic": "Persistence", "technique": "T1098", "name": "Account Manipulation"},
        "alert": {
            "rule": "Privileged Account Group Modification",
            "description": "Service account added to Domain Admins group by privileged user during non-change-window hours.",
        },
        "source": {"ip": "10.10.1.15", "domain": "corp.acmeinc.local", "email": "", "geo": "INTERNAL"},
        "target": {
            "host": "DC-PROD-01", "ip": "10.10.1.5", "user": "svc_patchmgmt",
            "email": "it-ops@acmeinc.com", "department": "IT Operations",
            "role": "Service Account", "criticality": "high",
        },
        "indicators": {
            "group_modified": "Domain Admins", "actor": "robert.chen",
            "change_ticket": "CHG-20260411-0042", "change_window": "2026-04-12 01:00-05:00 UTC",
            "mfa_verified": True, "files_accessed": 0, "external_transfers": 0,
        },
        "raw_log": (
            "Apr 12 01:32:14 DC-PROD-01 samba[1102]: Group 'Domain Admins' member added: svc_patchmgmt by robert.chen\n"
            "Apr 12 01:32:14 DC-PROD-01 audit[1102]: EventID=4728 TargetGroup=Domain Admins MemberAdded=svc_patchmgmt Actor=robert.chen\n"
            "Apr 12 01:33:00 DC-PROD-01 samba[1102]: Group policy update applied to svc_patchmgmt\n"
            "Apr 12 03:47:55 DC-PROD-01 samba[1102]: Group 'Domain Admins' member removed: svc_patchmgmt by robert.chen"
        ),
        "investigate": {
            "analyze_headers": "Modification originated from admin jump-box 10.10.1.15 (YOURJUMPBOX-01). Session authenticated via MFA smartcard.",
            "query_siem": (
                "2026-04-12T01:30:02Z  EventID=4624 LogonType=3 User=robert.chen Host=DC-PROD-01 Src=10.10.1.15\n"
                "2026-04-12T01:32:14Z  EventID=4728 Group=Domain Admins MemberAdded=svc_patchmgmt Actor=robert.chen\n"
                "2026-04-12T03:47:55Z  EventID=4729 Group=Domain Admins MemberRemoved=svc_patchmgmt Actor=robert.chen\n"
                "2026-04-12T03:48:10Z  EventID=4634 User=robert.chen Logoff"
            ),
            "check_reputation": "robert.chen: Senior SysAdmin, IT Operations. 7 years tenure. Privileged Access Workstation (PAW) user. No prior incidents.",
            "check_asset": "DC-PROD-01 -- Primary domain controller. Criticality: critical. OS: Windows Server 2022. Fully patched. CrowdStrike Falcon agent healthy.",
            "analyze_payload": "Change ticket CHG-20260411-0042 approved by manager k.williams on 2026-04-11. Scope: temporary DA elevation for svc_patchmgmt to deploy KB5035853 across domain. Elevation removed after patching completed.",
            "correlate_alerts": "WSUS logs confirm patch deployment activity from svc_patchmgmt between 01:35-03:40 UTC. 214 hosts patched. No other privilege modifications detected.",
        },
        "optimal_actions": ["verify_change_ticket", "classify_benign", "close_alert"],
        "impact_if_missed": "No impact. False escalation would delay legitimate patch deployment and erode IT Operations trust in the SOC.",
    },
    # BENIGN 3 -- Employee accessing files for a legitimate project
    {
        "id": "insider-003",
        "category": "insider_threat",
        "difficulty": "medium",
        "is_true_threat": False,
        "severity": "low",
        "mitre": {"tactic": "Collection", "technique": "T1078", "name": "Valid Accounts"},
        "alert": {
            "rule": "Bulk File Access -- Sensitive Repository",
            "description": "User accessed 47 files in the Engineering shared drive within a 15-minute window.",
        },
        "source": {"ip": "10.30.8.91", "domain": "corp.acmeinc.local", "email": "", "geo": "INTERNAL"},
        "target": {
            "host": "WS-ENG-0233", "ip": "10.30.8.91", "user": "aisha.patel",
            "email": "aisha.patel@acmeinc.com", "department": "Engineering",
            "role": "Staff Software Engineer", "criticality": "medium",
        },
        "indicators": {
            "files_accessed": 47, "files_modified": 0, "time_window_minutes": 15,
            "file_types": [".py", ".yaml", ".md"], "destination_external": False, "usb_detected": False,
        },
        "raw_log": (
            "Apr 11 14:02:11 FS-ENG-01 audit[2201]: EventID=4663 User=aisha.patel File=//eng-share/project-atlas/src/*.py Access=Read Count=31\n"
            "Apr 11 14:08:44 FS-ENG-01 audit[2201]: EventID=4663 User=aisha.patel File=//eng-share/project-atlas/deploy/*.yaml Access=Read Count=9\n"
            "Apr 11 14:15:02 FS-ENG-01 audit[2201]: EventID=4663 User=aisha.patel File=//eng-share/project-atlas/docs/*.md Access=Read Count=7"
        ),
        "investigate": {
            "analyze_headers": "All access via SMB from workstation WS-ENG-0233. Kerberos ticket valid; no ticket anomalies.",
            "query_siem": (
                "2026-04-11T14:02:11Z  EventID=4663 User=aisha.patel Share=eng-share Path=project-atlas/src/ AccessCount=31\n"
                "2026-04-11T14:08:44Z  EventID=4663 User=aisha.patel Share=eng-share Path=project-atlas/deploy/ AccessCount=9\n"
                "2026-04-11T14:15:02Z  EventID=4663 User=aisha.patel Share=eng-share Path=project-atlas/docs/ AccessCount=7\n"
                "No write or delete events. No copy-to-external."
            ),
            "check_reputation": "aisha.patel: 4 years at company. Current security clearance level 2. No prior alerts. Member of project-atlas team since 2026-01-15.",
            "check_asset": "WS-ENG-0233 -- assigned to aisha.patel, Engineering. EDR agent healthy. No malware detections. OS: Ubuntu 22.04.",
            "analyze_payload": "All 47 files reside in project-atlas repository to which aisha.patel has authorized read access via AD group ENG-ATLAS-DEVS. File types: Python source, Kubernetes manifests, Markdown docs. No archives created.",
            "correlate_alerts": "Jira ticket ATLAS-1187 assigned to aisha.patel: 'Onboard to Atlas codebase and review architecture.' Ticket created 2026-04-10 by tech lead d.nakamura. Sprint board confirms active assignment.",
        },
        "optimal_actions": ["verify_project_membership", "classify_benign", "close_alert"],
        "impact_if_missed": "No impact. Escalation would slow down a legitimate engineering onboarding task and generate a false positive.",
    },
    # THREAT 1 -- Data hoarding before resignation
    {
        "id": "insider-004",
        "category": "insider_threat",
        "difficulty": "medium",
        "is_true_threat": True,
        "severity": "high",
        "compliance": {
            "framework": "GDPR",
            "data_type": "PII",
            "breach_notification_hours": 72,
            "data_volume": "bulk",
            "mandatory_escalation": False,
        },
        "mitre": {"tactic": "Collection", "technique": "T1078", "name": "Valid Accounts"},
        "alert": {
            "rule": "Anomalous Bulk Download -- Departing Employee",
            "description": "User on HR departure watchlist downloaded 312 files from multiple departments over the last 48 hours.",
        },
        "source": {"ip": "10.20.3.77", "domain": "corp.acmeinc.local", "email": "", "geo": "INTERNAL"},
        "target": {
            "host": "WS-SALES-0054", "ip": "10.20.3.77", "user": "kevin.murphy",
            "email": "kevin.murphy@acmeinc.com", "department": "Sales",
            "role": "Regional Sales Director", "criticality": "high",
        },
        "indicators": {
            "files_accessed": 312, "files_downloaded": 312,
            "departments_accessed": ["Sales", "Marketing", "Product"],
            "time_span_hours": 48, "resignation_date": "2026-04-20", "hr_watchlist": True,
            "usb_detected": False, "cloud_sync_active": True, "cloud_destination": "personal OneDrive",
        },
        "raw_log": (
            "Apr 10 22:41:07 FS-CORP-02 audit[3301]: EventID=4663 User=kevin.murphy File=//sales-share/accounts/*.xlsx Access=Read Count=89\n"
            "Apr 11 08:15:33 FS-CORP-02 audit[3301]: EventID=4663 User=kevin.murphy File=//mktg-share/campaigns/2026/*.pptx Access=Read Count=47\n"
            "Apr 11 11:02:19 FS-CORP-02 audit[3301]: EventID=4663 User=kevin.murphy File=//product-share/roadmap/*.pdf Access=Read Count=23\n"
            "Apr 11 14:44:51 PROXY-01 squid[8812]: CONNECT onedrive.live.com:443 kevin.murphy UPLOAD 2.3GB"
        ),
        "investigate": {
            "analyze_headers": "Logon sessions from WS-SALES-0054 spanning two days. Kerberos tickets refreshed 14 times -- abnormally high. OneDrive personal sync client detected.",
            "query_siem": (
                "2026-04-10T22:41:07Z  Bulk read: //sales-share/accounts/ 89 files\n"
                "2026-04-11T08:15:33Z  Bulk read: //mktg-share/campaigns/ 47 files\n"
                "2026-04-11T11:02:19Z  Bulk read: //product-share/roadmap/ 23 files\n"
                "2026-04-11T12:30:00Z  Bulk read: //sales-share/pipeline/ 153 files\n"
                "2026-04-11T14:44:51Z  Proxy: 2.3 GB upload to onedrive.live.com (personal tenant)\n"
                "Historical baseline: kevin.murphy avg 18 file reads/day over prior 90 days."
            ),
            "check_reputation": "kevin.murphy: flagged on HR departure watchlist since 2026-04-08. Resignation submitted 2026-04-07, last day 2026-04-20. Competitor employment rumored. Risk score elevated to 78/100.",
            "check_asset": "WS-SALES-0054 -- assigned to kevin.murphy. OneDrive personal sync client installed (policy violation). DLP agent detected but in monitor-only mode.",
            "analyze_payload": "Downloaded files include: client account lists, revenue forecasts, 2026 marketing campaign decks, product roadmap PDFs. kevin.murphy has read access to Sales share but NOT authorized for Marketing or Product shares -- accessed via inherited group permissions not yet revoked.",
            "correlate_alerts": "DLP alert: 2.3 GB upload to personal OneDrive at 14:44. No prior DLP alerts for this user. HR confirmed resignation and competitor move. Manager (l.thompson) was not notified of cross-department access.",
        },
        "optimal_actions": ["isolate_endpoint", "disable_account", "preserve_evidence", "notify_hr_legal", "block_cloud_sync", "escalate_to_tier3"],
        "impact_if_missed": "Departing employee exfiltrates client lists, revenue data, and product roadmaps to a competitor, causing significant competitive harm and potential regulatory violations.",
    },
    # THREAT 2 -- Privilege escalation attempt
    {
        "id": "insider-005",
        "category": "insider_threat",
        "difficulty": "medium",
        "is_true_threat": True,
        "severity": "critical",
        "mitre": {"tactic": "Persistence", "technique": "T1098", "name": "Account Manipulation"},
        "alert": {
            "rule": "Unauthorized Group Policy Object Modification",
            "description": "Non-admin user attempted to modify Domain Admins group membership via compromised service account.",
        },
        "source": {"ip": "10.30.2.104", "domain": "corp.acmeinc.local", "email": "", "geo": "INTERNAL"},
        "target": {
            "host": "DC-PROD-01", "ip": "10.10.1.5", "user": "svc_helpdesk",
            "email": "", "department": "IT Support",
            "role": "Service Account", "criticality": "critical",
        },
        "indicators": {
            "actor_user": "james.wright", "actor_role": "IT Helpdesk Technician",
            "service_account_used": "svc_helpdesk", "target_group": "Domain Admins",
            "attempt_count": 3, "succeeded": False, "time_of_day": "23:47", "change_ticket_exists": False,
        },
        "raw_log": (
            "Apr 11 23:47:12 DC-PROD-01 samba[1102]: FAILED Group 'Domain Admins' add member: james.wright by svc_helpdesk -- INSUFFICIENT PRIVILEGES\n"
            "Apr 11 23:47:45 DC-PROD-01 samba[1102]: FAILED Group 'Domain Admins' add member: james.wright by svc_helpdesk -- INSUFFICIENT PRIVILEGES\n"
            "Apr 11 23:48:33 DC-PROD-01 samba[1102]: FAILED Group 'Enterprise Admins' add member: svc_helpdesk by svc_helpdesk -- INSUFFICIENT PRIVILEGES\n"
            "Apr 11 23:49:01 WS-HELPDESK-07 powershell[5510]: Invoke-Command -ComputerName DC-PROD-01 -ScriptBlock {Add-ADGroupMember 'Domain Admins' james.wright}"
        ),
        "investigate": {
            "analyze_headers": "Requests originated from WS-HELPDESK-07 (10.30.2.104) using svc_helpdesk credentials. svc_helpdesk password was last rotated 247 days ago -- well beyond 90-day policy.",
            "query_siem": (
                "2026-04-11T23:45:00Z  EventID=4624 LogonType=3 User=svc_helpdesk Src=10.30.2.104 Dst=DC-PROD-01\n"
                "2026-04-11T23:47:12Z  EventID=4728 FAIL Group=Domain Admins Target=james.wright Actor=svc_helpdesk\n"
                "2026-04-11T23:47:45Z  EventID=4728 FAIL Group=Domain Admins Target=james.wright Actor=svc_helpdesk\n"
                "2026-04-11T23:48:33Z  EventID=4728 FAIL Group=Enterprise Admins Target=svc_helpdesk Actor=svc_helpdesk\n"
                "2026-04-11T23:49:01Z  EventID=4104 ScriptBlock: Add-ADGroupMember detected on WS-HELPDESK-07"
            ),
            "check_reputation": "james.wright: IT Helpdesk Technician, 11 months tenure. Two prior policy warnings for unauthorized software installation. Risk score: 61/100. Not authorized for Domain Admin tasks.",
            "check_asset": "WS-HELPDESK-07 -- assigned to james.wright. Standard helpdesk workstation. No PAW designation. PowerShell remoting enabled (should be restricted to PAW only).",
            "analyze_payload": "PowerShell transcript shows three attempts to add james.wright to Domain Admins via svc_helpdesk, then one attempt to elevate svc_helpdesk to Enterprise Admins. All failed due to insufficient privileges. Clear intent to gain persistent domain-level access.",
            "correlate_alerts": "No change ticket for this activity. svc_helpdesk password found in plaintext in //helpdesk-share/scripts/deploy.ps1 (accessible to all IT Support staff). No manager approval on file. james.wright badge shows he was alone in Building-B server room area at 23:40.",
        },
        "optimal_actions": ["disable_service_account", "disable_user_account", "isolate_endpoint", "rotate_credentials", "preserve_evidence", "escalate_to_tier3", "notify_management"],
        "impact_if_missed": "Malicious insider gains Domain Admin privileges, enabling unrestricted access to all corporate systems, data theft, ransomware deployment, or persistent backdoor installation.",
    },
    # THREAT 3 -- Unauthorized USB data copy
    {
        "id": "insider-006",
        "category": "insider_threat",
        "difficulty": "medium",
        "is_true_threat": True,
        "severity": "high",
        "compliance": {
            "framework": "GDPR",
            "data_type": "Internal",
            "breach_notification_hours": 72,
            "data_volume": "bulk",
            "mandatory_escalation": True,
        },
        "mitre": {"tactic": "Exfiltration", "technique": "T1052", "name": "Exfiltration Over Physical Medium"},
        "alert": {
            "rule": "Unauthorized Removable Media -- Sensitive Data Copy",
            "description": "USB mass storage device connected and large volume of classified R&D files copied outside DLP policy.",
        },
        "source": {"ip": "10.30.9.18", "domain": "corp.acmeinc.local", "email": "", "geo": "INTERNAL"},
        "target": {
            "host": "WS-RND-0089", "ip": "10.30.9.18", "user": "li.zhang",
            "email": "li.zhang@acmeinc.com", "department": "Research & Development",
            "role": "Research Scientist", "criticality": "high",
        },
        "indicators": {
            "usb_vendor": "Kingston", "usb_serial": "KNG-0xA4F7E201", "usb_capacity_gb": 128,
            "files_copied_to_usb": 84, "data_volume_mb": 4710,
            "file_types": [".docx", ".pdf", ".xlsx", ".zip"],
            "dlp_policy_bypassed": True, "after_hours": True, "time": "20:33",
        },
        "raw_log": (
            "Apr 11 20:33:07 WS-RND-0089 kernel: usb 2-1: new high-speed USB device number 4 using xhci_hcd\n"
            "Apr 11 20:33:08 WS-RND-0089 kernel: usb-storage 2-1:1.0: Kingston DataTraveler 128GB [KNG-0xA4F7E201]\n"
            "Apr 11 20:34:15 WS-RND-0089 audit[6620]: EventID=4663 User=li.zhang Copy //rnd-share/project-phoenix/ -> /media/usb0/ Files=84 Size=4710MB\n"
            "Apr 11 20:51:42 WS-RND-0089 dlp[4401]: ALERT policy=BLOCK_USB action=LOG_ONLY (agent in audit mode) user=li.zhang\n"
            "Apr 11 20:52:01 WS-RND-0089 kernel: usb 2-1: USB disconnect"
        ),
        "investigate": {
            "analyze_headers": "USB device Kingston DataTraveler 128GB connected at 20:33. Device serial KNG-0xA4F7E201 is NOT on the approved device whitelist. DLP agent was in audit-only mode due to recent migration -- enforcement not active.",
            "query_siem": (
                "2026-04-11T20:33:07Z  USB device connected: Kingston 128GB Serial=KNG-0xA4F7E201\n"
                "2026-04-11T20:34:15Z  File copy: //rnd-share/project-phoenix/ -> /media/usb0/ 84 files, 4.7GB\n"
                "2026-04-11T20:51:42Z  DLP alert: USB copy detected, policy=LOG_ONLY\n"
                "2026-04-11T20:52:01Z  USB disconnected\n"
                "Historical: li.zhang has never connected a USB device in the past 12 months."
            ),
            "check_reputation": "li.zhang: Research Scientist, 3 years tenure. Access to project-phoenix (classified). Recently denied promotion per HR records (2026-03-28). Risk score updated to 72/100.",
            "check_asset": "WS-RND-0089 -- assigned to li.zhang, R&D. USB ports should be disabled per policy; however, DLP agent is in audit-only mode since 2026-04-05 migration. Full disk encryption active.",
            "analyze_payload": "84 files from project-phoenix: design specifications, patent draft documents, test results, and a ZIP archive containing source code. All classified as 'Company Confidential.' Total 4.7 GB copied to unencrypted USB.",
            "correlate_alerts": "Badge records show li.zhang was the only person in the R&D lab at 20:30. No after-hours access request filed. DLP migration ticket INC-20260405-0118 confirms enforcement gap. li.zhang's LinkedIn profile updated yesterday with 'Open to Work' status.",
        },
        "optimal_actions": ["isolate_endpoint", "disable_account", "preserve_evidence", "notify_hr_legal", "physical_security_usb_recovery", "escalate_to_tier3", "enable_dlp_enforcement"],
        "impact_if_missed": "Classified R&D intellectual property -- including patent drafts and source code -- is physically exfiltrated, potentially reaching a competitor and causing millions in lost IP value.",
    },
]
