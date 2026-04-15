"""Phishing scenario templates for the SecOps Alert Router RL environment.

Eight scenarios: 3 benign false-positives, 5 true threats.
MITRE ATT&CK: T1566.001, T1566.002.  Difficulty: easy -> expert.
"""

PHISHING_SCENARIOS: list[dict] = [
    # ---- 1  BENIGN: Marketing newsletter flagged by spam filter ----
    {
        "id": "phish-001", "category": "phishing", "difficulty": "easy",
        "is_true_threat": False, "severity": "medium",
        "mitre": {"tactic": "Initial Access", "technique": "T1566.002",
                  "name": "Phishing: Spearphishing Link"},
        "alert": {"rule": "Suspicious External Link in Email Body",
                  "description": "Gateway flagged HubSpot newsletter with tracking links."},
        "source": {"ip": "192.0.2.18", "domain": "email.hubspot.com",
                    "email": "promo@marketing.acmecorp.com", "geo": "US"},
        "target": {"host": "ws-amartinez.corp.local", "ip": "10.0.3.22",
                    "user": "amartinez", "email": "ana.martinez@company.com",
                    "department": "Marketing", "role": "Campaign Manager",
                    "criticality": "low"},
        "indicators": {"subject": "Your March Campaign Performance Report",
                        "urls": ["https://email.hubspot.com/e/c/eyJlbWFpbF9pZCI6...",
                                 "https://track.hubspot.com/open/abc123"]},
        "raw_log": (
            "Date: Mon, 09 Mar 2026 08:14:22 -0500\nFrom: promo@marketing.acmecorp.com\n"
            "To: ana.martinez@company.com\nSubject: Your March Campaign Performance Report\n"
            "X-Mailer: HubSpot\nContent-Type: text/html; charset=UTF-8\n\n"
            "Body: Hi Ana, here is your monthly campaign summary."),
        "investigate": {
            "analyze_headers": (
                "SPF: PASS (192.0.2.18 permitted by marketing.acmecorp.com)\n"
                "DKIM: PASS (selector hs1, domain hubspot.com)\nDMARC: PASS\n"
                "Received: from smtp-out.hubspot.com (192.0.2.18)"),
            "query_siem": (
                "2026-03-09 08:14:22 | EMAIL_RECV | from=promo@marketing.acmecorp.com "
                "verdict=CLEAN\n08:14:23 | URL_CLICK | user=amartinez "
                "url=track.hubspot.com/open/abc123 category=Marketing action=ALLOW"),
            "check_reputation": (
                "IP 192.0.2.18: CLEAN Sender Score 94/100\n"
                "email.hubspot.com: CLEAN Registered 2006, Email Marketing Platform\n"
                "No blocklist entries (Spamhaus, SURBL, URIBL)"),
            "check_asset": (
                "ws-amartinez.corp.local (10.0.3.22) | Ana Martinez | Marketing\n"
                "Criticality: Low | AV: Healthy | EDR v4.2.1\n"
                "Note: User subscribed to HubSpot marketing platform"),
            "analyze_payload": (
                "URLs resolve to HubSpot CDN, valid certs, no suspicious redirects.\n"
                "Tracking pixel: benign. Sandbox: No malicious behavior."),
            "correlate_alerts": (
                "3 similar HubSpot alerts in 30 days for Marketing - all false positive.\n"
                "No credential-theft or malware alerts for amartinez."),
        },
        "optimal_actions": [1, 2, 4], "impact_if_missed": "low",
    },
    # ---- 2  BENIGN: Internal IT password-rotation reminder ----
    {
        "id": "phish-002", "category": "phishing", "difficulty": "easy-medium",
        "is_true_threat": False, "severity": "medium",
        "mitre": {"tactic": "Initial Access", "technique": "T1566.002",
                  "name": "Phishing: Spearphishing Link"},
        "alert": {"rule": "Password Reset Link Detected in Email",
                  "description": "Internal IT email with password-reset URL to corporate SSO."},
        "source": {"ip": "10.0.1.5", "domain": "corp.local",
                    "email": "it-noreply@company.com", "geo": "US"},
        "target": {"host": "ws-jlee.corp.local", "ip": "10.0.4.88",
                    "user": "jlee", "email": "james.lee@company.com",
                    "department": "Engineering", "role": "Software Developer",
                    "criticality": "medium"},
        "indicators": {"subject": "Action Required: 90-Day Password Rotation",
                        "urls": ["https://sso.company.com/password-reset?token=abc123"]},
        "raw_log": (
            "Date: Wed, 11 Mar 2026 10:02:44 -0500\nFrom: it-noreply@company.com\n"
            "To: james.lee@company.com\nSubject: Action Required: 90-Day Password Rotation\n"
            "X-Internal-Origin: exchange01.corp.local\n\n"
            "Body: Hi James, your domain password expires in 7 days."),
        "investigate": {
            "analyze_headers": (
                "SPF: PASS (10.0.1.5 internal mail relay)\nDKIM: PASS (company.com)\n"
                "DMARC: PASS\nReceived: from exchange01.corp.local (10.0.1.5)"),
            "query_siem": (
                "2026-03-11 10:02:44 | EMAIL_SEND | from=it-noreply@company.com "
                "origin=exchange01.corp.local\n"
                "Same template sent to 142 users (quarterly rotation batch)"),
            "check_reputation": (
                "IP 10.0.1.5: INTERNAL Corporate Exchange relay\n"
                "sso.company.com: INTERNAL DigiCert cert valid to 2027-01-15\n"
                "URL matches known corporate SSO portal"),
            "check_asset": (
                "ws-jlee.corp.local (10.0.4.88) | James Lee | Engineering\n"
                "Criticality: Medium | Password last changed 89 days ago\n"
                "AV: Healthy | EDR v4.2.1"),
            "analyze_payload": (
                "sso.company.com/password-reset -> 10.0.1.20 (internal SSO), TLS 1.3\n"
                "Standard Okta password-change form. Sandbox: Legitimate SSO flow."),
            "correlate_alerts": (
                "142 identical alerts from quarterly batch. IT Change Ticket CHG-8832.\n"
                "No anomalies."),
        },
        "optimal_actions": [1, 2, 4], "impact_if_missed": "low",
    },
    # ---- 3  BENIGN: Salesforce marketing campaign ----
    {
        "id": "phish-003", "category": "phishing", "difficulty": "medium",
        "is_true_threat": False, "severity": "medium",
        "mitre": {"tactic": "Initial Access", "technique": "T1566.002",
                  "name": "Phishing: Spearphishing Link"},
        "alert": {"rule": "External Email With Embedded Tracking Pixels",
                  "description": "Salesforce email with tracking images and redirect URLs."},
        "source": {"ip": "198.51.100.33", "domain": "mail.salesforce.com",
                    "email": "events@salesforce.com", "geo": "US"},
        "target": {"host": "ws-rjohnson.corp.local", "ip": "10.0.2.55",
                    "user": "rjohnson", "email": "rachel.johnson@company.com",
                    "department": "Sales", "role": "Account Executive",
                    "criticality": "medium"},
        "indicators": {"subject": "You're Invited: Dreamforce 2026 Early Access",
                        "urls": ["https://www.salesforce.com/dreamforce/register?ref=em-003",
                                 "https://click.salesforce.com/track/v2/redir?c=abc"]},
        "raw_log": (
            "Date: Fri, 13 Mar 2026 14:32:10 -0700\nFrom: events@salesforce.com\n"
            "To: rachel.johnson@company.com\nSubject: Dreamforce 2026 Early Access\n"
            "List-Unsubscribe: <https://pages.salesforce.com/unsub>\n\n"
            "Body: Rachel, as a valued customer you have early access to registration."),
        "investigate": {
            "analyze_headers": (
                "SPF: PASS (198.51.100.33 permitted by salesforce.com)\n"
                "DKIM: PASS (sf2024, salesforce.com)\nDMARC: PASS (policy=reject)\n"
                "List-Unsubscribe header present and valid"),
            "query_siem": (
                "2026-03-13 14:32:10 | EMAIL_RECV | from=events@salesforce.com "
                "verdict=CLEAN\n14:45:00 | URL_CLICK | user=rjohnson "
                "url=salesforce.com/dreamforce/register action=ALLOW"),
            "check_reputation": (
                "IP 198.51.100.33: CLEAN Salesforce mail infra\n"
                "salesforce.com: CLEAN Registered 1999, Fortune 500\n"
                "All URLs resolve to salesforce.com, no third-party redirects"),
            "check_asset": (
                "ws-rjohnson.corp.local (10.0.2.55) | Rachel Johnson | Sales\n"
                "Criticality: Medium | Salesforce license: Enterprise (active)\n"
                "AV: Healthy | EDR v4.2.1"),
            "analyze_payload": (
                "salesforce.com/dreamforce/register -> TLS 1.3, cert CN=*.salesforce.com\n"
                "Standard registration page. click.salesforce.com -> redirect to dreamforce.\n"
                "Sandbox: Benign marketing content."),
            "correlate_alerts": (
                "8 identical Dreamforce alerts in Sales dept in 24h.\n"
                "Company is active Salesforce customer (SF-2024-112). No threat alerts."),
        },
        "optimal_actions": [1, 2, 4], "impact_if_missed": "low",
    },
    # ---- 4  THREAT: Credential harvesting - fake Microsoft 365 login ----
    {
        "id": "phish-004", "category": "phishing", "difficulty": "easy",
        "is_true_threat": True, "severity": "high",
        "compliance": {
            "framework": "SOX",
            "data_type": "Financial",
            "breach_notification_hours": 72,
            "data_volume": "bulk",
            "mandatory_escalation": True,
        },
        "mitre": {"tactic": "Initial Access", "technique": "T1566.002",
                  "name": "Phishing: Spearphishing Link"},
        "alert": {"rule": "Credential Harvesting Page Detected",
                  "description": "Link to fake Microsoft 365 login on typosquat domain."},
        "source": {"ip": "203.0.113.42", "domain": "microsofft-365.com",
                    "email": "security@microsofft-365.com", "geo": "RU"},
        "target": {"host": "ws-bthompson.corp.local", "ip": "10.0.5.17",
                    "user": "bthompson", "email": "brian.thompson@company.com",
                    "department": "Finance", "role": "Financial Analyst",
                    "criticality": "high"},
        "indicators": {"subject": "Urgent: Verify Your Account to Avoid Suspension",
                        "urls": ["https://microsofft-365.com/signin/oauth2?client_id=fake"],
                        "redirect_chain": ["https://bit.ly/3xR9kz2",
                                           "https://microsofft-365.com/signin/oauth2"]},
        "raw_log": (
            "Date: Tue, 17 Mar 2026 09:21:07 +0000\n"
            "From: security@microsofft-365.com\nTo: brian.thompson@company.com\n"
            "Subject: Urgent: Verify Your Account to Avoid Suspension\n"
            "Reply-To: no-reply@microsofft-365.com\n\n"
            "Body: We detected unusual sign-in activity. Verify within 24h\n"
            "or your account will be permanently suspended."),
        "investigate": {
            "analyze_headers": (
                "SPF: FAIL (203.0.113.42 NOT permitted, no SPF record)\n"
                "DKIM: FAIL (no signature)\nDMARC: FAIL (no DMARC record)\n"
                "Received: from mail.microsofft-365.com (203.0.113.42)\n"
                "NOTE: Typosquat of microsoft365.com (Levenshtein=1)"),
            "query_siem": (
                "2026-03-17 09:21:07 | EMAIL_RECV | from=security@microsofft-365.com "
                "verdict=SUSPICIOUS\n09:23:44 | URL_CLICK | user=bthompson "
                "url=bit.ly/3xR9kz2 -> microsofft-365.com action=BLOCK\n"
                "09:23:45 | PROXY_BLOCK | dst=microsofft-365.com reason=PHISHING"),
            "check_reputation": (
                "IP 203.0.113.42: MALICIOUS Spamhaus SBL, AbuseIPDB 97%\n"
                "microsofft-365.com: MALICIOUS Registered 2026-03-15 (2 days), "
                "Namecheap privacy proxy, VirusTotal 14/82 phishing"),
            "check_asset": (
                "ws-bthompson.corp.local (10.0.5.17) | Brian Thompson | Finance\n"
                "Criticality: High (SAP FI module access)\n"
                "AV: Healthy | EDR v4.2.1 | URL blocked by proxy before loading"),
            "analyze_payload": (
                "microsofft-365.com/signin -> 203.0.113.42, TLS 1.2, LE cert 2026-03-15\n"
                "Clones M365 login (HTML similarity 96%), POSTs to /collect.php\n"
                "JS keylogger in page source. Sandbox: Evilginx2 credential harvester"),
            "correlate_alerts": (
                "5 other Finance users got same email in 30 min (campaign wave).\n"
                "2 clicked; both blocked by proxy. No credential submissions."),
        },
        "optimal_actions": [1, 2, 3, 5, 7], "impact_if_missed": "high",
    },
    # ---- 5  THREAT: Spearphishing with macro-enabled Excel ----
    {
        "id": "phish-005", "category": "phishing", "difficulty": "medium",
        "is_true_threat": True, "severity": "high",
        "compliance": {
            "framework": "PCI-DSS",
            "data_type": "PCI",
            "breach_notification_hours": 72,
            "data_volume": "bulk",
            "mandatory_escalation": True,
        },
        "mitre": {"tactic": "Initial Access", "technique": "T1566.001",
                  "name": "Phishing: Spearphishing Attachment"},
        "alert": {"rule": "Suspicious Email Attachment Detected",
                  "description": "Macro-enabled .xlsm from unknown external sender."},
        "source": {"ip": "203.0.113.87", "domain": "acme-supplies.net",
                    "email": "invoice@acme-supplies.net", "geo": "CN"},
        "target": {"host": "ws-jsmith.corp.local", "ip": "10.0.5.42",
                    "user": "jsmith", "email": "john.smith@company.com",
                    "department": "Finance", "role": "Senior Accountant",
                    "criticality": "high"},
        "indicators": {"subject": "Urgent: Updated Q4 Invoice - Payment Overdue",
                        "file_name": "Invoice_Q4_Updated.xlsm",
                        "file_hash": "e3b0c44298fc1c149afbf4c8996fb924"
                                     "27ae41e4649b934ca495991b7852b855",
                        "file_size": "287 KB"},
        "raw_log": (
            "Date: Thu, 19 Mar 2026 06:47:33 +0800\n"
            "From: invoice@acme-supplies.net\nTo: john.smith@company.com\n"
            "Subject: Urgent: Updated Q4 Invoice - Payment Overdue\n"
            "X-Attachment: Invoice_Q4_Updated.xlsm (287 KB)\n\n"
            "Body: Dear John, please find attached the updated invoice.\n"
            "Payment is now overdue. Please process urgently."),
        "investigate": {
            "analyze_headers": (
                "SPF: SOFTFAIL (203.0.113.87 not explicitly permitted, ~all)\n"
                "DKIM: FAIL (body hash mismatch)\nDMARC: FAIL (policy=none)\n"
                "Received: from smtp.acme-supplies.net (203.0.113.87)\n"
                "NOTE: First email ever received from this domain"),
            "query_siem": (
                "2026-03-19 06:47:33 | EMAIL_RECV | attachment=Invoice_Q4_Updated.xlsm "
                "verdict=QUARANTINED\n"
                "06:47:34 | SANDBOX_SUBMIT | file=Invoice_Q4_Updated.xlsm status=ANALYZING"),
            "check_reputation": (
                "IP 203.0.113.87: SUSPICIOUS AbuseIPDB 72%, spam 14d\n"
                "acme-supplies.net: Registered 2026-03-12 (7d), NameSilo privacy, "
                "no web presence\nFile hash: VirusTotal 8/68 Trojan.Downloader.Macro"),
            "check_asset": (
                "ws-jsmith.corp.local (10.0.5.42) | John Smith | Finance\n"
                "Criticality: High (SAP payment approver)\n"
                "No prior correspondence with acme-supplies.net\n"
                "Email quarantine: Attachment held, user has NOT opened it"),
            "analyze_payload": (
                "Invoice_Q4_Updated.xlsm: Auto_Open macro detected\n"
                "VBA: Shell() -> cmd.exe + obfuscated PowerShell\n"
                "Downloads hxxp://203.0.113.87/up.ps1, creates sched task\n"
                "Anti-sandbox: mouse movement + uptime checks\n"
                "Detonation: cmd->powershell->203.0.113.87:443, drops %TEMP%\\svchost.exe\n"
                "Verdict: MALICIOUS Trojan Downloader (Emotet loader variant)"),
            "correlate_alerts": (
                "2 other Finance users got similar emails. All quarantined, none opened.\n"
                "File hash matches known Emotet loader variant."),
        },
        "optimal_actions": [1, 2, 3, 5, 6, 7], "impact_if_missed": "critical",
    },
    # ---- 6  THREAT: CEO impersonation / BEC wire-transfer fraud ----
    {
        "id": "phish-006", "category": "phishing", "difficulty": "medium-hard",
        "is_true_threat": True, "severity": "critical",
        "compliance": {
            "framework": "SOX",
            "data_type": "Financial",
            "breach_notification_hours": 48,
            "data_volume": "single",
            "mandatory_escalation": True,
        },
        "mitre": {"tactic": "Initial Access", "technique": "T1566.002",
                  "name": "Phishing: Spearphishing Link"},
        "alert": {"rule": "Executive Display Name Spoofing Detected",
                  "description": "CEO display name from external lookalike domain."},
        "source": {"ip": "198.51.100.77", "domain": "company-exec.com",
                    "email": "ceo@company-exec.com", "geo": "NG"},
        "target": {"host": "ws-lpatel.corp.local", "ip": "10.0.5.60",
                    "user": "lpatel", "email": "lisa.patel@company.com",
                    "department": "Finance", "role": "VP of Finance",
                    "criticality": "critical"},
        "indicators": {"subject": "Re: Confidential - Wire Transfer Needed Today",
                        "display_name_mismatch": True,
                        "display_name": "David Chen (CEO)",
                        "actual_sender": "ceo@company-exec.com",
                        "real_ceo_email": "david.chen@company.com"},
        "raw_log": (
            "Date: Mon, 23 Mar 2026 15:42:18 +0000\n"
            'From: "David Chen (CEO)" <ceo@company-exec.com>\n'
            "To: lisa.patel@company.com\n"
            "Subject: Re: Confidential - Wire Transfer Needed Today\n"
            "Reply-To: david.chen.ceo@gmail.com\n\n"
            "Body: Lisa, process an urgent wire transfer of $147,000 to a\n"
            "new vendor before EOD. I'm in meetings and can't call."),
        "investigate": {
            "analyze_headers": (
                "SPF: PASS (198.51.100.77 permitted by company-exec.com - NOT company.com)\n"
                "DKIM: PASS (company-exec.com - NOT company.com)\n"
                "DMARC: N/A (from company-exec.com, company.com DMARC doesn't apply)\n"
                "Reply-To: david.chen.ceo@gmail.com (MISMATCH)\n"
                "CRITICAL: Display name matches real CEO, envelope is company-exec.com"),
            "query_siem": (
                "2026-03-23 15:42:18 | EMAIL_RECV | from=ceo@company-exec.com "
                "display_name='David Chen (CEO)' verdict=WARN\n"
                "15:43:02 | EMAIL_READ | user=lpatel\n"
                "15:44:30 | EMAIL_REPLY | user=lpatel replied to gmail.com Reply-To"),
            "check_reputation": (
                "IP 198.51.100.77: NEUTRAL DigitalOcean VPS, low sender score\n"
                "company-exec.com: Registered 2026-03-21 (2d), GoDaddy privacy, "
                "no web content, Zoho MX\n"
                "Reply-To gmail.com: Free email, no corporate association"),
            "check_asset": (
                "ws-lpatel.corp.local (10.0.5.60) | Lisa Patel | Finance VP\n"
                "Criticality: Critical (wire approver, SAP FI admin, $500K authority)\n"
                "Real CEO: david.chen@company.com\n"
                "NOTE: User already read AND REPLIED to the email"),
            "analyze_payload": (
                "No attachments or URLs. Social engineering analysis:\n"
                "Urgency ('before EOD'), Authority (CEO name), Isolation ('can't call')\n"
                "Financial request: $147K wire. Reply-To: gmail vs company.com\n"
                "Classification: BEC - CEO Fraud / Wire Transfer Scheme"),
            "correlate_alerts": (
                "No prior emails from company-exec.com. Real CEO sent 3 emails today, "
                "none about wire transfers.\n"
                "CRITICAL: lpatel already replied. Alert Finance team immediately."),
        },
        "optimal_actions": [1, 2, 3, 5, 7, 8], "impact_if_missed": "critical",
    },
    # ---- 7  THREAT: Fake Okta password reset (AiTM credential theft) ----
    {
        "id": "phish-007", "category": "phishing", "difficulty": "hard",
        "is_true_threat": True, "severity": "high",
        "compliance": {
            "framework": "GDPR",
            "data_type": "PII",
            "breach_notification_hours": 72,
            "data_volume": "bulk",
            "mandatory_escalation": True,
        },
        "mitre": {"tactic": "Initial Access", "technique": "T1566.002",
                  "name": "Phishing: Spearphishing Link"},
        "alert": {"rule": "Password Reset Link From Unverified Source",
                  "description": "Okta password-reset mimic from okta-servicedesk.com."},
        "source": {"ip": "192.0.2.201", "domain": "okta-servicedesk.com",
                    "email": "noreply@okta-servicedesk.com", "geo": "DE"},
        "target": {"host": "ws-kwilliams.corp.local", "ip": "10.0.6.14",
                    "user": "kwilliams", "email": "karen.williams@company.com",
                    "department": "Human Resources", "role": "HR Director",
                    "criticality": "critical"},
        "indicators": {"subject": "Password Reset Request - Action Required",
                        "urls": ["https://okta-servicedesk.com/reset?u=kwilliams&t=a9f3"],
                        "legitimate_okta_domain": "company.okta.com"},
        "raw_log": (
            "Date: Wed, 25 Mar 2026 11:08:55 +0100\n"
            "From: noreply@okta-servicedesk.com\nTo: karen.williams@company.com\n"
            "Subject: Password Reset Request - Action Required\n"
            "X-Mailer: PHPMailer 6.8\n\n"
            "Body: A password reset was requested for your Okta account.\n"
            "Click below to secure your account. Link expires in 60 min."),
        "investigate": {
            "analyze_headers": (
                "SPF: PASS (192.0.2.201 permitted - attacker controls DNS)\n"
                "DKIM: PASS (okta-servicedesk.com - NOT okta.com)\n"
                "DMARC: N/A (from okta-servicedesk.com, not okta.com)\n"
                "X-Mailer: PHPMailer 6.8 (real Okta uses Sendgrid)\n"
                "NOTE: Legitimate Okta sends from noreply@okta.com"),
            "query_siem": (
                "2026-03-25 11:08:55 | EMAIL_RECV | from=noreply@okta-servicedesk.com "
                "verdict=DELIVERED\n11:12:03 | URL_CLICK | user=kwilliams "
                "url=okta-servicedesk.com/reset action=ALLOW\n"
                "11:12:08 | HTTP_POST | dst=okta-servicedesk.com uri=/auth/callback"),
            "check_reputation": (
                "IP 192.0.2.201: SUSPICIOUS Hetzner VPS, first seen 2026-03-24\n"
                "okta-servicedesk.com: Registered 2026-03-22 (3d), Porkbun privacy, "
                "LE cert, VirusTotal 3/82 phishing. NOT affiliated with Okta Inc."),
            "check_asset": (
                "ws-kwilliams.corp.local (10.0.6.14) | Karen Williams | HR Director\n"
                "Criticality: Critical (PII, Workday admin, salary data)\n"
                "Okta MFA: Enrolled (Okta Verify push)\n"
                "CRITICAL: User clicked link AND submitted form (POST /auth/callback)"),
            "analyze_payload": (
                "okta-servicedesk.com/reset -> 192.0.2.201, TLS 1.2, LE cert\n"
                "Near-perfect clone of company.okta.com. Captures user+pass+MFA token.\n"
                "Creds relayed real-time to company.okta.com (AiTM proxy).\n"
                "User redirected to real portal after capture.\n"
                "Verdict: MALICIOUS AiTM credential theft"),
            "correlate_alerts": (
                "No other users targeted (single-target spearphish vs HR Director).\n"
                "Okta admin: No password reset initiated by IT.\n"
                "CRITICAL: 12 min after POST, Okta sign-in from 192.0.2.205 (same /24) "
                "using kwilliams creds. MFA bypassed via stolen session cookie.\n"
                "IMMEDIATE: Revoke all kwilliams sessions."),
        },
        "optimal_actions": [1, 2, 3, 5, 6, 7, 8], "impact_if_missed": "critical",
    },
    # ---- 8  THREAT: Watering-hole via compromised industry forum ----
    {
        "id": "phish-008", "category": "phishing", "difficulty": "expert",
        "is_true_threat": True, "severity": "high",
        "mitre": {"tactic": "Initial Access", "technique": "T1566.002",
                  "name": "Phishing: Spearphishing Link"},
        "alert": {"rule": "Known Watering Hole Domain Accessed",
                  "description": "Legitimate industry forum now serving drive-by exploit kit."},
        "source": {"ip": "198.51.100.112", "domain": "infosec-weekly.com",
                    "email": "editor@infosec-weekly.com", "geo": "US"},
        "target": {"host": "ws-dpark.corp.local", "ip": "10.0.7.31",
                    "user": "dpark", "email": "daniel.park@company.com",
                    "department": "IT Security", "role": "Security Engineer",
                    "criticality": "critical"},
        "indicators": {"subject": "Weekly Threat Briefing - March 2026",
                        "watering_hole_url": "https://infosec-weekly.com/briefing/2026-03",
                        "injected_iframe": "https://203.0.113.200/analytics.js",
                        "exploit_kit": "RIG EK v4"},
        "raw_log": (
            "Date: Fri, 27 Mar 2026 13:15:22 -0400\n"
            "From: editor@infosec-weekly.com\nTo: daniel.park@company.com\n"
            "Subject: Weekly Threat Briefing - March 2026\n\n"
            "Body: This week's briefing covers ransomware trends and APT campaigns.\n"
            "Read: https://infosec-weekly.com/briefing/2026-03"),
        "investigate": {
            "analyze_headers": (
                "SPF: PASS (198.51.100.112 permitted)\nDKIM: PASS (infosec-weekly.com)\n"
                "DMARC: PASS\nNOTE: Email is LEGITIMATE. The website was compromised "
                "AFTER the email was sent."),
            "query_siem": (
                "2026-03-27 13:15:22 | EMAIL_RECV | verdict=CLEAN\n"
                "14:02:17 | URL_CLICK | user=dpark url=infosec-weekly.com/briefing "
                "action=ALLOW\n14:02:19 | HTTP_GET | dst=203.0.113.200 "
                "uri=/analytics.js referrer=infosec-weekly.com\n"
                "14:02:20 | HTTP_GET | dst=203.0.113.200 uri=/payload.wasm\n"
                "14:02:22 | PROCESS_CREATE | host=ws-dpark parent=chrome.exe "
                "child=rundll32.exe cmd='rundll32 %TEMP%\\msedge.dll,Entry'"),
            "check_reputation": (
                "IP 198.51.100.112: CLEAN infosec-weekly.com (legit since 2018)\n"
                "infosec-weekly.com: CLEAN BUT US-CERT VU#2026-0342 issued today: "
                "site compromised, exploit kit via iframe since 2026-03-26 18:00 UTC\n"
                "IP 203.0.113.200: MALICIOUS RIG EK C2, AbuseIPDB 99%, "
                "bulletproof hosting Belize"),
            "check_asset": (
                "ws-dpark.corp.local (10.0.7.31) | Daniel Park | IT Security\n"
                "Criticality: Critical (SIEM admin, firewall access, IR team)\n"
                "Chrome 122.0 (current patch)\n"
                "CRITICAL: EDR detected rundll32.exe spawned by Chrome loading "
                "DLL from Temp. Endpoint may be compromised."),
            "analyze_payload": (
                "Stage 1: infosec-weekly.com -> injected invisible iframe to 203.0.113.200\n"
                "Stage 2: analytics.js -> fingerprinting + CVE-2026-1234 (V8 UAF)\n"
                "Stage 3: payload.wasm -> WebAssembly shellcode drops DLL\n"
                "Stage 4: msedge.dll -> Cobalt Strike beacon, C2 203.0.113.201 HTTPS\n"
                "  sleep 60s jitter 37%, pipe \\\\.\\pipe\\msedge_ipc_7f3a\n"
                "Verdict: MALICIOUS supply-chain watering-hole + Cobalt Strike"),
            "correlate_alerts": (
                "3 IT Security members got same newsletter. 1 (mchen) clicked but "
                "Chrome sandbox blocked exploit.\n"
                "EDR: ws-dpark rundll32 loaded unsigned DLL - CRITICAL.\n"
                "Network: HTTPS beaconing 10.0.7.31->203.0.113.201 every ~60s.\n"
                "IMMEDIATE: Isolate ws-dpark, revoke dpark creds, scan all hosts "
                "that visited infosec-weekly.com in 48h."),
        },
        "optimal_actions": [1, 2, 3, 5, 6, 7, 8], "impact_if_missed": "critical",
    },
]
