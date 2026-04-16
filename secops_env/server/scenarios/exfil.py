"""Data exfiltration scenario templates for the SOC RL environment."""

EXFIL_SCENARIOS = [
    # BENIGN 1 -- Authorized cloud backup
    {
        "id": "exfil-001",
        "category": "data_exfiltration",
        "difficulty": "easy-medium",
        "is_true_threat": False,
        "severity": "medium",
        "mitre": {"tactic": "Exfiltration", "technique": "T1567", "name": "Exfiltration Over Web Service"},
        "alert": {
            "rule": "Large Outbound Transfer to Cloud Storage",
            "description": "12.4 GB upload to Azure Blob Storage detected from internal backup server during non-standard hours.",
        },
        "source": {"ip": "10.10.5.20", "domain": "corp.acmeinc.local", "email": "", "geo": "INTERNAL"},
        "target": {
            "host": "SRV-BACKUP-01", "ip": "10.10.5.20", "user": "svc_azbackup",
            "email": "it-ops@acmeinc.com", "department": "IT Operations",
            "role": "Service Account -- Azure Backup", "criticality": "medium",
        },
        "indicators": {
            "destination": "acmeinc-backup.blob.core.windows.net", "transfer_size_gb": 12.4,
            "protocol": "HTTPS", "duration_minutes": 47, "scheduled_task": True,
            "tenant": "corporate (verified)", "encryption": "AES-256 at rest, TLS 1.3 in transit",
        },
        "raw_log": (
            "Apr 12 02:00:01 SRV-BACKUP-01 cron[1801]: Starting scheduled task: AzureBackup_Weekly_Full\n"
            "Apr 12 02:00:05 SRV-BACKUP-01 azcopy[1805]: Transfer started to acmeinc-backup.blob.core.windows.net/weekly-full/\n"
            "Apr 12 02:00:05 SRV-BACKUP-01 azcopy[1805]: Source: /srv/backup/full-2026-04-12/ Size: 12.4GB\n"
            "Apr 12 02:47:33 SRV-BACKUP-01 azcopy[1805]: Transfer complete. 12.4GB uploaded. 0 errors. 0 skipped.\n"
            "Apr 12 02:47:34 SRV-BACKUP-01 cron[1801]: Task AzureBackup_Weekly_Full completed successfully"
        ),
        "investigate": {
            "analyze_headers": "Upload to acmeinc-backup.blob.core.windows.net -- corporate Azure tenant (tenant ID verified: a3f1c2d4-...). Authentication via managed identity bound to SRV-BACKUP-01. TLS 1.3 encrypted.",
            "query_siem": (
                "2026-04-12T02:00:01Z  Scheduled task AzureBackup_Weekly_Full started on SRV-BACKUP-01\n"
                "2026-04-12T02:00:05Z  azcopy transfer to acmeinc-backup.blob.core.windows.net 12.4GB\n"
                "2026-04-12T02:47:33Z  Transfer complete, 0 errors\n"
                "Historical: this task runs every Sunday at 02:00 UTC. Last 12 executions: avg 11.8GB, all successful. Current transfer size within 1 std dev."
            ),
            "check_reputation": "svc_azbackup: dedicated backup service account. Managed identity -- no password to rotate. Scoped to Azure Blob Storage only. No interactive logon permitted. No prior alerts.",
            "check_asset": "SRV-BACKUP-01: dedicated backup server, IT Operations. Hardened -- no internet access except Azure Blob endpoints. CrowdStrike healthy. OS: Ubuntu 22.04 LTS. Patched.",
            "analyze_payload": "Backup contents: encrypted database dumps and file server snapshots. All data encrypted with AES-256 before upload. Destination is the authorized corporate backup container with immutability policy enabled.",
            "correlate_alerts": "Backup schedule documented in ITIL CMDB under CI-BACKUP-001. Weekly full backup approved in change record CHG-PERM-0003 (permanent change). Size consistent with historical trend. No anomalous processes on SRV-BACKUP-01.",
        },
        "optimal_actions": [5, 3, 0, 10],
        "impact_if_missed": "No impact. Escalating a routine corporate backup wastes SOC resources and may trigger unnecessary incident procedures.",
    },
    # BENIGN 2 -- Large email with legitimate attachments
    {
        "id": "exfil-002",
        "category": "data_exfiltration",
        "difficulty": "easy",
        "is_true_threat": False,
        "severity": "medium",
        "mitre": {"tactic": "Exfiltration", "technique": "T1567", "name": "Exfiltration Over Web Service"},
        "alert": {
            "rule": "Outbound Email -- Large Attachment to External Recipient",
            "description": "Email with 38 MB attachment sent to external recipient from Legal department.",
        },
        "source": {"ip": "10.20.4.61", "domain": "corp.acmeinc.local", "email": "rachel.foster@acmeinc.com", "geo": "INTERNAL"},
        "target": {
            "host": "WS-LEGAL-0008", "ip": "10.20.4.61", "user": "rachel.foster",
            "email": "rachel.foster@acmeinc.com", "department": "Legal",
            "role": "Associate General Counsel", "criticality": "medium",
        },
        "indicators": {
            "recipient": "m.hartwell@bakermckenzie.com", "recipient_domain": "bakermckenzie.com",
            "attachment_name": "AcmeInc_Patent_Filing_Draft_v3.pdf", "attachment_size_mb": 38,
            "dlp_classification": "Attorney-Client Privileged",
            "encryption": "TLS 1.3 (O365 to O365)", "external_domain_trusted": True,
        },
        "raw_log": (
            "Apr 11 16:22:07 EXCH-01 transport[4401]: MessageID=<AANLkTi9x@acmeinc.com> From=rachel.foster@acmeinc.com To=m.hartwell@bakermckenzie.com Subject='Patent Filing Draft v3 - For Review' Attach=AcmeInc_Patent_Filing_Draft_v3.pdf Size=38MB\n"
            "Apr 11 16:22:07 EXCH-01 dlp[4402]: SCAN MessageID=<AANLkTi9x@acmeinc.com> Classification=Attorney-Client Result=ALLOW (trusted external counsel domain)\n"
            "Apr 11 16:22:08 EXCH-01 transport[4401]: MessageID=<AANLkTi9x@acmeinc.com> Delivered via TLS 1.3"
        ),
        "investigate": {
            "analyze_headers": "Email sent from rachel.foster@acmeinc.com to m.hartwell@bakermckenzie.com. Baker McKenzie is the company's registered external patent counsel. Email encrypted via TLS 1.3 (both sides on O365). SPF/DKIM/DMARC all pass.",
            "query_siem": (
                "2026-04-11T16:22:07Z  Email sent: rachel.foster -> m.hartwell@bakermckenzie.com, 38MB attachment\n"
                "2026-04-11T16:22:07Z  DLP scan: Attorney-Client Privileged, ALLOWED (bakermckenzie.com in trusted counsel list)\n"
                "Historical: rachel.foster sends 2-4 emails/month to bakermckenzie.com, avg size 12MB. Current email larger than usual but within policy limits (50MB max)."
            ),
            "check_reputation": "rachel.foster: Associate General Counsel, 6 years tenure. Authorized to communicate with external counsel. No prior DLP incidents. Risk score: 5/100. bakermckenzie.com: on approved external counsel domain whitelist since 2022.",
            "check_asset": "WS-LEGAL-0008: Legal dept workstation. Full disk encryption. DLP agent active (enforce mode). O365 Information Protection labels applied. No anomalies.",
            "analyze_payload": "Attachment: AcmeInc_Patent_Filing_Draft_v3.pdf -- patent application draft for USPTO filing. Labeled 'Attorney-Client Privileged.' Content consistent with prior versions (v1 sent Mar 15, v2 sent Mar 28). No embedded macros or suspicious metadata.",
            "correlate_alerts": "Legal matter tracker LM-2026-0087: 'Patent Filing -- Project Phoenix Sensor Array.' Active matter, rachel.foster is lead in-house counsel. Baker McKenzie engagement letter on file. Filing deadline: April 18, 2026.",
        },
        "optimal_actions": [2, 5, 4, 10],
        "impact_if_missed": "No impact. Blocking or escalating would delay a time-sensitive patent filing and disrupt the attorney-client workflow.",
    },
    # THREAT 1 -- DNS tunneling exfiltration
    {
        "id": "exfil-003",
        "category": "data_exfiltration",
        "difficulty": "hard",
        "is_true_threat": True,
        "severity": "critical",
        "compliance": {
            "framework": "GDPR",
            "data_type": "PII",
            "breach_notification_hours": 72,
            "data_volume": "massive",
            "mandatory_escalation": True,
            "data_classification": "EU Personal Data",
        },
        "mitre": {"tactic": "Exfiltration", "technique": "T1048", "name": "Exfiltration Over Alternative Protocol"},
        "alert": {
            "rule": "DNS Tunneling -- High-Entropy Subdomain Queries",
            "description": "Internal host generating anomalous DNS queries with high-entropy subdomain labels to a single authoritative domain at a rate of 940 queries/hour.",
        },
        "source": {"ip": "10.10.2.21", "domain": "corp.acmeinc.local", "email": "", "geo": "INTERNAL"},
        "target": {
            "host": "APP-API-01", "ip": "10.10.2.21", "user": "svc_backup",
            "email": "", "department": "IT Operations",
            "role": "Service Account (compromised)", "criticality": "critical",
        },
        "indicators": {
            "dns_queries_per_hour": 940, "query_domain": "x4t7data.darkcloud.xyz",
            "avg_subdomain_length": 52, "subdomain_entropy": 4.8, "query_type": "TXT",
            "response_size_avg_bytes": 230, "estimated_throughput_kbps": 48,
            "duration_hours": 6, "estimated_data_exfiltrated_mb": 105,
        },
        "raw_log": (
            "Apr 12 05:15:01 DNS-INT-01 named[2201]: client 10.10.2.21: query: aGVsbG8gd29ybGQgdGhpcyBpcyBlbmNv.x4t7data.darkcloud.xyz IN TXT\n"
            "Apr 12 05:15:01 DNS-INT-01 named[2201]: client 10.10.2.21: query: ZGVkIGRhdGEgZXhmaWx0cmF0aW9uIHRl.x4t7data.darkcloud.xyz IN TXT\n"
            "Apr 12 05:15:02 DNS-INT-01 named[2201]: client 10.10.2.21: query: c3QgZm9yIHNjZW5hcmlvIHRlbXBsYXRl.x4t7data.darkcloud.xyz IN TXT\n"
            "[... 937 more queries in this hour ...]\n"
            "Apr 12 05:15:02 DNS-INT-01 named[2201]: response from 185.220.101.44: TXT 230 bytes"
        ),
        "investigate": {
            "analyze_headers": "DNS TXT queries from APP-API-01 (10.10.2.21) to x4t7data.darkcloud.xyz. Subdomain labels are Base64-encoded data chunks (avg 52 chars, entropy 4.8 -- well above normal of 2.5). Authoritative NS resolves to 185.220.101.44 (known malicious infrastructure). Classic DNS tunneling pattern using iodine/dnscat2.",
            "query_siem": (
                "2026-04-11T23:10:00Z  DNS tunneling started: 10.10.2.21 -> x4t7data.darkcloud.xyz\n"
                "2026-04-12T05:15:00Z  Current rate: 940 queries/hour, sustained for 6+ hours\n"
                "2026-04-12T05:15:00Z  Estimated data exfiltrated: ~105MB\n"
                "2026-04-12T04:18:47Z  Recall: svc_backup account was compromised via RDP brute force (see lateral-003)\n"
                "Baseline: APP-API-01 normally generates ~50 DNS queries/hour, all to known internal/external domains."
            ),
            "check_reputation": "x4t7data.darkcloud.xyz: registered 3 days ago via Njalla (privacy registrar). NS points to 185.220.101.44 -- Tor exit node, linked to APT campaigns. VirusTotal: 14/89 vendors flag as malicious. Threat intel: associated with data exfiltration operations.",
            "check_asset": "APP-API-01: production API server, processes customer transactions. Compromised via svc_backup account (see lateral-003). EDR shows dnscat2 binary at /tmp/.cache/systemd-resolved (masquerading as system service).",
            "analyze_payload": "Base64-decoded subdomain samples reveal fragments of SQL query results -- customer records from the production database. Data includes names, emails, addresses, and hashed payment tokens. Estimated 105MB exfiltrated over 6 hours at ~48 kbps throughput. Tunneling tool: dnscat2 with encryption disabled (data visible in queries).",
            "correlate_alerts": "Full attack chain confirmed: phishing (WS-MKTG-0041) -> mimikatz/PtH -> RDP brute force -> svc_backup compromise -> service account pivot to DB-PROD-01 -> data dump -> DNS tunneling exfiltration from APP-API-01. C2 IP 185.220.101.44 seen in lateral-002 and lateral-005. Data from customers table matches DB-PROD-01 dump in lateral-004.",
        },
        "optimal_actions": [2, 0, 5, 6, 7],
        "impact_if_missed": "105+ MB of customer PII actively exfiltrated via DNS tunneling to attacker-controlled infrastructure. Continued exfiltration risks full database dump. Mandatory breach notification and regulatory penalties under GDPR/CCPA.",
    },
    # THREAT 2 -- Large upload to personal cloud storage
    {
        "id": "exfil-004",
        "category": "data_exfiltration",
        "difficulty": "medium",
        "is_true_threat": True,
        "severity": "high",
        "mitre": {"tactic": "Exfiltration", "technique": "T1567", "name": "Exfiltration Over Web Service"},
        "alert": {
            "rule": "Unauthorized Cloud Upload -- Personal Storage Service",
            "description": "3.1 GB upload to personal Google Drive detected from Engineering workstation during after-hours.",
        },
        "source": {"ip": "10.30.8.44", "domain": "corp.acmeinc.local", "email": "", "geo": "INTERNAL"},
        "target": {
            "host": "WS-ENG-0190", "ip": "10.30.8.44", "user": "marcus.reed",
            "email": "marcus.reed@acmeinc.com", "department": "Engineering",
            "role": "Senior Backend Engineer", "criticality": "high",
        },
        "indicators": {
            "destination": "drive.google.com", "google_account": "marcusreed.personal@gmail.com",
            "transfer_size_gb": 3.1, "protocol": "HTTPS", "files_uploaded": 1,
            "filename": "atlas-core-export.tar.gz", "dlp_classification": "Source Code -- Confidential",
            "after_hours": True, "time": "21:47",
        },
        "raw_log": (
            "Apr 11 21:40:12 WS-ENG-0190 audit[8801]: EventID=4688 Process=tar User=marcus.reed Args='czf /tmp/atlas-core-export.tar.gz /home/marcus.reed/projects/atlas-core/'\n"
            "Apr 11 21:44:55 WS-ENG-0190 audit[8801]: EventID=4663 File=/tmp/atlas-core-export.tar.gz Size=3.1GB Created\n"
            "Apr 11 21:47:01 PROXY-01 squid[8812]: CONNECT drive.google.com:443 marcus.reed POST /upload 3.1GB Account=marcusreed.personal@gmail.com\n"
            "Apr 11 21:47:01 PROXY-01 dlp[8813]: ALERT policy=BLOCK_PERSONAL_CLOUD action=LOG (enforcement pending)\n"
            "Apr 11 22:08:33 PROXY-01 squid[8812]: Upload complete drive.google.com 3.1GB"
        ),
        "investigate": {
            "analyze_headers": "Upload to drive.google.com authenticated as marcusreed.personal@gmail.com (personal account, not corporate Google Workspace). File: atlas-core-export.tar.gz (3.1 GB). DLP policy flagged but did not block -- enforcement mode pending deployment.",
            "query_siem": (
                "2026-04-11T21:40:12Z  tar archive created: atlas-core-export.tar.gz, 3.1GB, source=/home/marcus.reed/projects/atlas-core/\n"
                "2026-04-11T21:47:01Z  Upload to drive.google.com (personal account) 3.1GB\n"
                "2026-04-11T22:08:33Z  Upload completed\n"
                "Historical: marcus.reed has no prior uploads to personal cloud. Baseline outbound traffic: ~200MB/day.\n"
                "2026-04-11T21:35:00Z  marcus.reed ran 'git clone' of atlas-core repo (full history, all branches)"
            ),
            "check_reputation": "marcus.reed: Senior Backend Engineer, 2.5 years tenure. Core contributor to project-atlas. HR note: received competing job offer from rival firm (per resignation risk flag raised by manager on 2026-04-09). Risk score: 67/100.",
            "check_asset": "WS-ENG-0190: Engineering workstation, Ubuntu 22.04. Assigned to marcus.reed. DLP agent installed but in monitor-only mode for Engineering VLAN (exception INC-20260401-0205). Full disk encryption active.",
            "analyze_payload": "atlas-core-export.tar.gz contains the complete atlas-core repository: 847 source files, 23 configuration files with API keys (redacted in repo but present in local config), CI/CD pipeline definitions, and proprietary ML model weights (trade secret). Total: 3.1 GB of company IP.",
            "correlate_alerts": "Manager d.nakamura flagged marcus.reed as resignation risk on 2026-04-09 (competing offer from TechRival Inc). marcus.reed cloned full atlas-core repo at 21:35 (unusual -- normally works on feature branches). Archive created at 21:40, upload started at 21:47 to personal Gmail account. Pattern matches insider exfiltration playbook.",
        },
        "optimal_actions": [2, 1, 5, 7, 8, 6],
        "impact_if_missed": "Complete proprietary source code repository including trade secret ML model weights exfiltrated to personal cloud, potentially shared with a direct competitor. Loss of competitive advantage and possible trade secret litigation.",
    },
    # THREAT 3 -- Encrypted archive exfiltration via HTTPS
    {
        "id": "exfil-005",
        "category": "data_exfiltration",
        "difficulty": "expert",
        "is_true_threat": True,
        "severity": "critical",
        "compliance": {
            "framework": "SOX",
            "data_type": "Financial",
            "breach_notification_hours": 48,
            "data_volume": "bulk",
            "mandatory_escalation": True,
            "data_classification": "Financial Records and Audit Trail",
        },
        "mitre": {"tactic": "Exfiltration", "technique": "T1048", "name": "Exfiltration Over Alternative Protocol"},
        "alert": {
            "rule": "Encrypted Archive Upload to Uncategorized Domain",
            "description": "Password-protected 7z archive (1.8 GB) uploaded via HTTPS POST to a recently registered domain from a finance workstation.",
        },
        "source": {"ip": "10.20.5.19", "domain": "corp.acmeinc.local", "email": "", "geo": "INTERNAL"},
        "target": {
            "host": "WS-FIN-0093", "ip": "10.20.5.19", "user": "carlos.mendez",
            "email": "carlos.mendez@acmeinc.com", "department": "Finance",
            "role": "Financial Controller", "criticality": "high",
        },
        "indicators": {
            "destination_domain": "secure-fileshare-corp.com", "domain_age_days": 5,
            "registrar": "Njalla (privacy)", "destination_ip": "91.215.85.102",
            "hosting": "BuyVM (bulletproof)", "transfer_size_gb": 1.8,
            "archive_type": "7z (AES-256 encrypted)", "archive_name": "Q1_Consolidated.7z",
            "dlp_inspectable": False, "ssl_cert": "Let's Encrypt (5 days old)", "time": "23:15",
        },
        "raw_log": (
            "Apr 11 23:08:22 WS-FIN-0093 audit[9901]: EventID=4688 Process=7z.exe User=carlos.mendez Args='a Q1_Consolidated.7z C:\\Users\\carlos.mendez\\Finance\\* -p<REDACTED> -mhe=on'\n"
            "Apr 11 23:12:44 WS-FIN-0093 audit[9901]: EventID=4663 File=C:\\Users\\carlos.mendez\\Q1_Consolidated.7z Size=1.8GB Created\n"
            "Apr 11 23:15:01 PROXY-01 squid[8812]: CONNECT secure-fileshare-corp.com:443 carlos.mendez POST /upload 1.8GB\n"
            "Apr 11 23:15:01 PROXY-01 ssl[8814]: SNI=secure-fileshare-corp.com Cert=LetsEncrypt Issued=2026-04-07\n"
            "Apr 11 23:38:17 PROXY-01 squid[8812]: Upload complete secure-fileshare-corp.com 1.8GB"
        ),
        "investigate": {
            "analyze_headers": "HTTPS POST to secure-fileshare-corp.com (91.215.85.102). SSL certificate issued by Let's Encrypt 5 days ago. Domain registered 5 days ago via Njalla (known privacy/anonymity registrar). Hosting: BuyVM -- frequently associated with bulletproof hosting. The domain name deliberately mimics a legitimate file-sharing service.",
            "query_siem": (
                "2026-04-11T23:08:22Z  7z.exe: archive with AES-256 encryption + header encryption (-mhe=on), source C:\\Users\\carlos.mendez\\Finance\\*\n"
                "2026-04-11T23:12:44Z  Q1_Consolidated.7z created, 1.8GB\n"
                "2026-04-11T23:15:01Z  HTTPS upload to secure-fileshare-corp.com 1.8GB\n"
                "2026-04-11T23:38:17Z  Upload completed\n"
                "Historical: carlos.mendez has never accessed secure-fileshare-corp.com. No other employee has accessed this domain. Finance dept baseline outbound: ~50MB/day."
            ),
            "check_reputation": "secure-fileshare-corp.com: registered 2026-04-07 via Njalla. WHOIS: privacy-protected. IP 91.215.85.102: BuyVM/Frantech, Luxembourg. VirusTotal: 0/89 (too new for detections). URLhaus: not listed. Passive DNS: only A record, no MX/TXT -- single-purpose upload site. Threat assessment: highly suspicious.",
            "check_asset": "WS-FIN-0093: Finance dept workstation assigned to carlos.mendez. Handles consolidated financial reporting, M&A data, revenue forecasts. DLP cannot inspect AES-256 encrypted 7z archives with header encryption. EDR shows no malware -- this appears to be intentional user action.",
            "analyze_payload": "Archive source directory C:\\Users\\carlos.mendez\\Finance\\ contains: Q1 consolidated financial statements, M&A due diligence documents for Project Titan (confidential acquisition target), board presentation decks, revenue projections through 2028. AES-256 encryption with header encryption (-mhe=on) prevents DLP content inspection. Total: 1.8 GB of material nonpublic financial information.",
            "correlate_alerts": "carlos.mendez accessed 230 files from the Finance restricted share between 22:00-23:00 (10x normal daily rate). 7z installed on workstation 2 days ago (not in approved software list). HR records: carlos.mendez under investigation by Internal Audit for expense irregularities since 2026-03-20. Pattern suggests deliberate exfiltration of M&A data -- potential for insider trading or sale to third parties.",
        },
        "optimal_actions": [2, 1, 5, 6, 7, 8],
        "impact_if_missed": "Material nonpublic financial information including M&A details exfiltrated. If used for insider trading, triggers SEC enforcement action. If sold, causes catastrophic deal leakage for Project Titan acquisition, potential billions in lost deal value and severe regulatory consequences.",
    },
]
