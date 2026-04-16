"""Healthcare / HIPAA scenario templates for the SecOps Alert Router RL environment.

Six scenarios covering EHR access anomalies, medical device compromise,
healthcare ransomware, PHI exfiltration, and credential attacks.

All true-threat scenarios carry HIPAA compliance tags with the 2.5× reward
penalty multiplier. HIPAA § 164.412 mandates notification within 60 days
of breach discovery; significant financial penalties per affected record.

MITRE ATT&CK: T1078, T1005, T1486, T1567, T1110.003
"""

HEALTHCARE_SCENARIOS: list[dict] = [
    # ── BENIGN 1: Authorized bulk EHR export for IRB-approved research ────────
    {
        "id": "health-001",
        "category": "healthcare",
        "difficulty": "medium",
        "is_true_threat": False,
        "severity": "high",
        "mitre": {
            "tactic": "Collection",
            "technique": "T1005",
            "name": "Data from Local System",
        },
        "alert": {
            "rule": "Bulk EHR Record Export — Volume Anomaly",
            "description": (
                "Epic EHR audit log: user r.patterson exported 8,400 patient records "
                "via Crystal Reports in one session. Exceeds 500-record daily alert threshold."
            ),
        },
        "source": {"ip": "10.100.2.45", "domain": "ehr.hospital.local", "geo": "INTERNAL"},
        "target": {
            "host": "epic-app-01.hospital.local",
            "ip": "10.100.2.10",
            "user": "r.patterson",
            "department": "Clinical Research",
            "role": "Research Data Coordinator",
            "criticality": "high",
        },
        "indicators": {
            "ehr_system": "Epic Hyperspace 2025",
            "records_accessed": 8400,
            "query_type": "Crystal Reports bulk export",
            "data_categories": ["diagnosis_codes", "medications", "lab_results"],
            "pii_fields": ["MRN", "DOB", "zip_code"],
        },
        "raw_log": (
            "Epic Audit Log: 2026-04-16T09:15:33 | User: r.patterson (Research Data Coord)\n"
            "Action: Crystal Reports export | Template: IRB-ONCOLOGY-2026-Q1\n"
            "Records: 8,400 | Fields: MRN, DOB, Zip, ICD-10 Dx, Medication, Lab values\n"
            "Workstation: CLIN-RES-WS-04 (10.100.2.45) | Session ID: EHR-2026-04-16-09150\n"
            "Export target: \\\\research-share\\irb\\2026\\oncology\\q1_dataset.csv"
        ),
        "investigate": {
            "analyze_headers": (
                "Epic EHR session metadata:\n"
                "  User: r.patterson — authorized research coordinator (badge ID R-2247)\n"
                "  Auth method: Active Directory SSO + RSA SecureID (MFA)\n"
                "  Workstation: CLIN-RES-WS-04 — research VLAN, hardened, encrypted disk\n"
                "  Report template: IRB-ONCOLOGY-2026-Q1 (pre-approved, field-restricted)\n"
                "  Fields included: MRN (pseudonym), DOB, 3-digit ZIP, ICD-10, meds, labs\n"
                "  Excluded: full name, SSN, full address, insurance ID (de-identified)"
            ),
            "query_siem": (
                "2026-04-16T09:15:33  Epic Audit | Crystal Export 8,400 records\n"
                "2026-04-16T09:15:33  File Activity | Write \\\\research-share\\irb\\2026\\oncology\\\n"
                "2026-04-16T09:17:44  DLP | File classification: PHI-RESEARCH (expected, monitored)\n"
                "Research share access: restricted to IRB-approved users, logged, virus-scanned.\n"
                "Prior exports by r.patterson: 6 quarterly exports in past 18 months (avg 7,200 records)."
            ),
            "check_reputation": (
                "r.patterson: 7 years tenure, Clinical Research Dept. Clearance: RESEARCH-L2.\n"
                "  IRB protocol 2024-ONCO-0044 approved: 'Chemotherapy outcomes, 10,000 records'\n"
                "  HIPAA training: completed 2026-01-08. Privacy signed: 2025-12-30.\n"
                "  DLP baseline: 7,200-record quarterly exports are her expected workflow.\n"
                "  Risk score: 9/100. No prior violations."
            ),
            "check_asset": (
                "epic-app-01 Epic Hyperspace server:\n"
                "  Data: ~850,000 patient records (oncology, cardiology, general med)\n"
                "  HIPAA: covered entity, BAA with all research teams on file\n"
                "  Research share: \\\\research-share\\irb\\ — HIPAA-compliant storage\n"
                "  Encryption at rest: AES-256. TLS 1.3 in transit.\n"
                "  Access log retention: 7 years (HIPAA minimum 6 years)."
            ),
            "analyze_payload": (
                "Export file: q1_dataset.csv\n"
                "  Fields verified: MRN (pseudonymized), DOB (year only), ZIP (first 3), "
                "ICD-10 codes, medication names, lab reference ranges\n"
                "  HIPAA Safe Harbor: 18 of 18 direct identifiers removed or generalized\n"
                "  De-identification method: Expert Determination (approved 2025-11-14)\n"
                "  No SSN, full name, full DOB, email, phone, or device identifiers present."
            ),
            "correlate_alerts": (
                "IRB protocol 2024-ONCO-0044 status: ACTIVE (approved through 2027-03-31).\n"
                "Data use agreement: executed 2024-10-01 (research-share\\ custodian: DPO).\n"
                "Prior 6 exports: identical de-identification, identical destination, no violations.\n"
                "Quarterly volume expected: Q1 higher due to 2025 oncology unit expansion (+15%).\n"
                "Verdict: authorized IRB export. Close alert."
            ),
        },
        "optimal_actions": [1, 3, 4, 5, 10],
        "impact_if_missed": "None — authorized IRB research export. Escalating would delay peer-reviewed oncology research.",
    },

    # ── BENIGN 2: IT admin performing scheduled EHR backup ────────────────────
    {
        "id": "health-002",
        "category": "healthcare",
        "difficulty": "medium-hard",
        "is_true_threat": False,
        "severity": "high",
        "mitre": {
            "tactic": "Collection",
            "technique": "T1005",
            "name": "Data from Local System",
        },
        "alert": {
            "rule": "EHR Database Backup to External Storage Detected",
            "description": (
                "DLP alert: 94 GB Epic EHR database backup transferred to "
                "backup-vault.hospital.local via rsync. High volume data movement flagged."
            ),
        },
        "source": {"ip": "10.100.5.3", "domain": "backup01.hospital.local", "geo": "INTERNAL"},
        "target": {
            "host": "backup-vault.hospital.local",
            "ip": "10.100.10.50",
            "user": "svc-epic-backup",
            "department": "IT Infrastructure",
            "role": "Backup Service Account",
            "criticality": "high",
        },
        "indicators": {
            "data_size_gb": 94,
            "transfer_protocol": "rsync+ssh",
            "destination": "backup-vault.hospital.local",
            "schedule": "nightly 02:00-04:30 UTC",
            "encryption": "AES-256-GCM at rest",
        },
        "raw_log": (
            "2026-04-16T02:01:17  rsync[3814]: starting backup epic-db-primary to backup-vault\n"
            "2026-04-16T02:01:17  sshd[3815]: Accepted publickey for svc-epic-backup from 10.100.5.3\n"
            "2026-04-16T04:23:44  rsync[3814]: sent 94.2 GB, received 1.2 KB, 11.8 MB/s\n"
            "2026-04-16T04:23:44  Backup completed. Checksum: SHA256 verified. Encrypted: YES\n"
            "DLP trigger: volume threshold >50 GB on healthcare network segment"
        ),
        "investigate": {
            "analyze_headers": (
                "SSH session metadata:\n"
                "  Client: backup01.hospital.local (10.100.5.3)\n"
                "  Auth: RSA-4096 public key (svc-epic-backup, rotated 2026-01-15)\n"
                "  Destination: backup-vault.hospital.local (10.100.10.50) — dedicated backup VLAN\n"
                "  MFA: Service account key auth (no interactive MFA — by design for automation)\n"
                "  TLS: SSH 8.9 with cipher chacha20-poly1305 (strong)\n"
                "  Transfer bandwidth: 11.8 MB/s (throttled to avoid prod impact)"
            ),
            "query_siem": (
                "Nightly backup schedule: 02:00–04:30 UTC daily (registered in ITSM)\n"
                "2026-04-16T02:01:17  Backup job started (on-time, ±2min normal drift)\n"
                "2026-04-16T04:23:44  Backup completed (143 min — normal range 130-160 min)\n"
                "Last 30 nights: 30/30 successful. Avg transfer: 91.4 GB ±4.2 GB.\n"
                "Today 94.2 GB: within normal range (Epic DB grew 2.8 GB this week)."
            ),
            "check_reputation": (
                "svc-epic-backup: Service account. Owner: IT Infrastructure team.\n"
                "  Permissions: read-only on Epic DB filesystems, write to backup-vault only.\n"
                "  backup-vault: Veeam target, encrypted, WORM-protected (30-day retention).\n"
                "  HIPAA technical safeguard: data encrypted in transit (rsync+SSH) and at rest.\n"
                "  Business Associate Agreement with backup vendor: on file."
            ),
            "check_asset": (
                "backup-vault.hospital.local:\n"
                "  Location: on-premises, locked data center, badge access only\n"
                "  Encryption: AES-256-GCM per-volume, keys in HSM\n"
                "  WORM: 30-day immutable retention (HIPAA minimum)\n"
                "  Network: isolated backup VLAN, no outbound internet\n"
                "  Last restore test: 2026-03-15 (quarterly). Successful."
            ),
            "analyze_payload": (
                "Backup scope: Epic EHR primary database (PostgreSQL 16 + Epic-proprietary)\n"
                "Contents: patient records, clinical notes, medications, scheduling, billing\n"
                "Destination: isolated on-prem vault with no external reachability\n"
                "Verification: SHA256 checksum match confirmed. No corruption.\n"
                "HIPAA compliance: encrypted backup stored within covered entity's control."
            ),
            "correlate_alerts": (
                "ITSM job ID: BACKUP-2026-04-16-EPIC-01. Scheduled job, no change requests needed.\n"
                "IT runbook: PROC-IT-BACKUP-007 (EHR backup procedure, approved by CISO 2025-12-01).\n"
                "Data flows approved in HIPAA risk assessment RA-2025-003.\n"
                "Verdict: routine authorized nightly backup. Close alert."
            ),
        },
        "optimal_actions": [1, 3, 5, 10],
        "impact_if_missed": "None — routine backup. Escalating would trigger unnecessary incident response.",
    },

    # ── THREAT 1: Nurse accessing 300 records outside her ward ────────────────
    {
        "id": "health-003",
        "category": "healthcare",
        "difficulty": "medium",
        "is_true_threat": True,
        "severity": "high",
        "compliance": {
            "framework": "HIPAA",
            "data_type": "PHI",
            "data_classification": "Protected Health Information (PHI)",
            "breach_notification_hours": 1440,
            "data_volume": "bulk",
            "mandatory_escalation": True,
        },
        "mitre": {
            "tactic": "Collection",
            "technique": "T1005",
            "name": "Data from Local System",
        },
        "alert": {
            "rule": "EHR Access Outside Authorized Patient Panel — Anomaly Detected",
            "description": (
                "Epic break-the-glass audit: n.okeke (RN, Cardiology Ward B) accessed "
                "312 patient records in 3 hours, 298 of whom are NOT in her assigned panel."
            ),
        },
        "source": {"ip": "10.100.3.88", "domain": "ehr.hospital.local", "geo": "INTERNAL"},
        "target": {
            "host": "epic-app-01.hospital.local",
            "ip": "10.100.2.10",
            "user": "n.okeke",
            "department": "Cardiology — Ward B",
            "role": "Registered Nurse",
            "criticality": "high",
        },
        "indicators": {
            "records_accessed": 312,
            "authorized_panel_size": 14,
            "outside_panel_count": 298,
            "time_window_hours": 3,
            "data_viewed": ["full_name", "DOB", "SSN_partial", "diagnosis", "medications"],
            "break_the_glass": True,
        },
        "raw_log": (
            "Epic Privacy Audit: 2026-04-16T06:00:00-09:04:22\n"
            "User: n.okeke (RN) | Ward: Cardiology-B | Authorized panel: 14 patients\n"
            "Records accessed: 312 | Outside panel: 298 (95.5%)\n"
            "Break-the-glass used: YES (51 times — no emergency documented)\n"
            "Departments accessed: Oncology (88), Neurology (72), Orthopedics (64), OB/GYN (74)\n"
            "Access pattern: 2.1 min/record avg, viewed: demographics, SSN, insurance, Dx, meds"
        ),
        "investigate": {
            "analyze_headers": (
                "Epic EHR session analysis:\n"
                "  User n.okeke: RN, Cardiology Ward B, authorized panel = 14 active patients\n"
                "  Auth: hospital badge (RFID) + Epic credentials (no MFA for clinical staff)\n"
                "  Workstation: mobile nursing station CLIN-CART-14 (cardiology hallway)\n"
                "  Break-the-glass: 51 uses (override for 'emergency access' — requires justification)\n"
                "  Justification field: 'clinical care' — generic, no specific patient reason\n"
                "  Access time: 06:00-09:04 (shift start, low supervisor presence)"
            ),
            "query_siem": (
                "2026-04-16T06:00:12  Epic | n.okeke session start on CLIN-CART-14\n"
                "2026-04-16T06:02:44  Epic | Record #1 (her panel) viewed 1m 12s\n"
                "2026-04-16T06:04:01  Epic | Break-the-glass: Oncology patient (unrelated ward)\n"
                "... 50 more break-the-glass overrides over 3 hours ...\n"
                "2026-04-16T09:04:22  Epic | Session end\n"
                "Historical baseline: n.okeke averages 15-20 record views per shift (her panel only)."
            ),
            "check_reputation": (
                "n.okeke: RN, 3 years. Cardiology Ward B. No prior HIPAA incidents.\n"
                "  Normal behavior: 15-20 views/shift, panel-only access.\n"
                "  Today: 312 records across 4 unrelated departments — 20x normal volume.\n"
                "  Personal context (HR flag): submitted resignation 2026-04-12 (4 days ago).\n"
                "  Financial: wage garnishment filed by creditor 2026-03-28.\n"
                "  PHI broker market: identity theft rings pay $50-200/record (SSN+Dx+insurance)."
            ),
            "check_asset": (
                "Epic EHR system:\n"
                "  PHI categories accessed: full name, SSN (partial), DOB, insurance ID,\n"
                "    ICD-10 diagnoses, medications, physician names, visit history\n"
                "  OB/GYN records: 74 accessed — highly sensitive (reproductive health, HIPAA 42 CFR)\n"
                "  oncology: 88 — terminal diagnoses, family history, genetic info\n"
                "  Estimated breach: 298 patients' full PHI compromised\n"
                "  HIPAA definition: unauthorized disclosure of PHI to a person without authorization"
            ),
            "analyze_payload": (
                "Access pattern analysis:\n"
                "  Records viewed for 1-3 minutes each — consistent with transcription/copying\n"
                "  Fields systematically viewed: demographics → insurance → SSN → diagnosis → meds\n"
                "  No legitimate clinical purpose identifiable (patients not in her care)\n"
                "  No concurrent nursing documentation (no chart notes written during session)\n"
                "  Device forensics needed: was patient data photographed with phone?"
            ),
            "correlate_alerts": (
                "Dark web intelligence (Recorded Future): hospital patient data listed on forum "
                "2026-04-14 (2 days before this event — may be separate incident or advance sale).\n"
                "HR: n.okeke resignation accepted, last day 2026-04-30.\n"
                "HIPAA breach: 298 records = REPORTABLE to HHS OCR within 60 days.\n"
                "Action: suspend n.okeke access immediately, preserve forensic copy of Epic session,\n"
                "notify Privacy Officer, initiate HIPAA breach analysis, notify 298 patients."
            ),
        },
        "optimal_actions": [1, 2, 4, 5, 8],
        "impact_if_missed": "High — 298 patient PHI records breach, HIPAA reportable. Potential identity theft of 298 patients.",
    },

    # ── THREAT 2: Ransomware on EHR server (Epic) ─────────────────────────────
    {
        "id": "health-004",
        "category": "healthcare",
        "difficulty": "hard",
        "is_true_threat": True,
        "severity": "critical",
        "compliance": {
            "framework": "HIPAA",
            "data_type": "PHI",
            "data_classification": "Protected Health Information (PHI)",
            "breach_notification_hours": 1440,
            "data_volume": "massive",
            "mandatory_escalation": True,
        },
        "mitre": {
            "tactic": "Impact",
            "technique": "T1486",
            "name": "Data Encrypted for Impact",
        },
        "alert": {
            "rule": "Mass File Encryption Detected on EHR Server",
            "description": (
                "CrowdStrike EDR: epidemic file rename pattern on epic-app-01.hospital.local. "
                "Files renamed to *.LOCKBIT3 at 12,000/min. EHR service stopping."
            ),
        },
        "source": {"ip": "10.100.4.22", "domain": "corp.hospital.local", "geo": "INTERNAL"},
        "target": {
            "host": "epic-app-01.hospital.local",
            "ip": "10.100.2.10",
            "user": "HOSPITAL\\svc-epic",
            "department": "Clinical IT",
            "role": "Epic EHR Application Server",
            "criticality": "critical",
        },
        "indicators": {
            "ransomware_family": "LockBit 3.0",
            "files_encrypted_per_min": 12000,
            "extension": ".LOCKBIT3",
            "ransom_note": "!!-Restore-My-Files-!!.txt",
            "c2_ip": "198.51.100.200",
            "affected_patients_count": 850000,
        },
        "raw_log": (
            "CrowdStrike EDR CRITICAL: Ransomware Process Tree on epic-app-01.hospital.local\n"
            "Process: svchost.exe (PID 4812) → encrypting EHR database files\n"
            "Parent: wscript.exe (PID 4233) ← VBS script from phishing email 48h prior\n"
            "Files renamed: 12,000/min | Extension: .LOCKBIT3\n"
            "Ransom note dropped: C:\\EpicFiles\\!!-Restore-My-Files-!!.txt\n"
            "C2 beacon: 198.51.100.200:443 (HTTPS, Cobalt Strike pattern)\n"
            "Network: LLMNR poisoning + WMI lateral movement observed 3h prior"
        ),
        "investigate": {
            "analyze_headers": (
                "CrowdStrike process tree analysis:\n"
                "  Stage 1 (48h ago): phishing email → outlook.exe opened .docx\n"
                "  Stage 2 (47h ago): VBS macro → dropped payload.dll to %APPDATA%\n"
                "  Stage 3 (progressive): Cobalt Strike beacon, C2 198.51.100.200\n"
                "  Stage 4 (3h ago): Lateral movement via WMI to 12 servers including epic-app-01\n"
                "  Stage 5 (NOW): LockBit 3.0 encryptor executing as HOSPITAL\\svc-epic\n"
                "  Encryptor: legitimate PsExec used to run encryptor (LOLBin)"
            ),
            "query_siem": (
                "2026-04-14T09:22Z  Email | phishing attachment .docx opened by admin-user\n"
                "2026-04-14T09:25Z  EDR | VBS macro → payload.dll written to disk\n"
                "2026-04-14T09:26Z  Network | C2 beacon 10.100.4.22 → 198.51.100.200:443\n"
                "2026-04-16T04:10Z  EDR | LLMNR poisoning on hospital-corp LAN (48h dormant)\n"
                "2026-04-16T04:15Z  Active Directory | HOSPITAL\\admin credentials harvested (Mimikatz)\n"
                "2026-04-16T05:45Z  WMI | Lateral movement to epic-app-01, file-srv-01, domain-ctrl-01\n"
                "2026-04-16T06:03Z  EDR | LockBit 3.0 encryptor launched — ENCRYPTION ACTIVE"
            ),
            "check_reputation": (
                "198.51.100.200: LockBit 3.0 C2 infrastructure. AbuseIPDB 99%.\n"
                "  IOC: matches CISA Alert AA23-165A (LockBit 3.0 healthcare campaign).\n"
                "  Threat actor: LockBit RaaS affiliate targeting hospitals for double extortion.\n"
                "  Ransom demand (from decrypted note): $4.5M USD in XMR, 72-hour deadline.\n"
                "  LockBit data exfiltration: 94 GB patient data confirmed uploaded to C2 BEFORE encryption."
            ),
            "check_asset": (
                "epic-app-01.hospital.local:\n"
                "  Hosts: Epic Hyperspace EHR (850,000 patient records)\n"
                "  Status: EHR service DOWN. All clinical operations reverting to paper.\n"
                "  Impact: surgeries delayed, ER diversion, medication administration manual\n"
                "  Encrypted files: *.edb, *.mdf, *.ldf, *.bak (database + backups)\n"
                "  CRITICAL: Ransomware targeted backup directories — offline backups unaffected\n"
                "  Domain controller: also compromised — AD password reset required"
            ),
            "analyze_payload": (
                "LockBit 3.0 encryptor analysis:\n"
                "  Encryption: AES-256 per-file, RSA-2048 key exchange\n"
                "  Exfiltration (pre-encryption): 94 GB patient PHI to C2 via HTTPS\n"
                "  Shadow copies: DELETED (vssadmin delete shadows /all /quiet)\n"
                "  Backups on NAS: encrypted (network shares mapped before encryption)\n"
                "  Offline tape backup (air-gapped): INTACT (last backup 2026-04-15 23:00)\n"
                "  Recovery path: restore from tape. Estimated downtime: 18-36 hours."
            ),
            "correlate_alerts": (
                "850,000 patient records = HIPAA Tier 3 breach (>500 records) → HHS OCR notification\n"
                "REQUIRED within 60 days. Also: media notification if >500 in single state.\n"
                "Patient notification letters required to all 850,000.\n"
                "IMMEDIATE response:\n"
                "  1. Isolate epic-app-01 and domain-ctrl-01 NOW\n"
                "  2. Activate hospital downtime procedures (paper-based)\n"
                "  3. Contact FBI (healthcare ransomware mandatory reporting)\n"
                "  4. Do NOT pay ransom (US Treasury OFAC compliance)\n"
                "  5. Begin tape restore of EHR (18h ETA)"
            ),
        },
        "optimal_actions": [1, 2, 3, 5, 7, 8],
        "impact_if_missed": "Critical — 850K patient PHI breach + hospital operations halted. Patient safety risk.",
    },

    # ── THREAT 3: PHI exfiltration to personal cloud storage ──────────────────
    {
        "id": "health-005",
        "category": "healthcare",
        "difficulty": "medium-hard",
        "is_true_threat": True,
        "severity": "high",
        "compliance": {
            "framework": "HIPAA",
            "data_type": "PHI",
            "data_classification": "Protected Health Information (PHI)",
            "breach_notification_hours": 1440,
            "data_volume": "bulk",
            "mandatory_escalation": True,
        },
        "mitre": {
            "tactic": "Exfiltration",
            "technique": "T1567.002",
            "name": "Exfiltration to Code Repository",
        },
        "alert": {
            "rule": "PHI File Upload to Personal Cloud Storage",
            "description": (
                "DLP: Epic export file patient_data_q1.csv (42 MB, PHI classification) "
                "uploaded from ws-bchang to dropbox.com. Personal account, not corporate."
            ),
        },
        "source": {"ip": "10.100.1.77", "domain": "www.dropbox.com", "geo": "US-CLOUD"},
        "target": {
            "host": "ws-bchang.hospital.local",
            "ip": "10.100.1.77",
            "user": "b.chang",
            "department": "Revenue Cycle Management",
            "role": "Billing Specialist",
            "criticality": "high",
        },
        "indicators": {
            "file_name": "patient_data_q1.csv",
            "file_size_mb": 42,
            "destination": "dropbox.com",
            "account_type": "personal (not corporate)",
            "phi_classification": "PHI — billing, insurance, diagnosis codes, SSN partial",
            "records_count": 11400,
        },
        "raw_log": (
            "DLP Alert: 2026-04-16T14:07:22 | SEVERITY=HIGH\n"
            "User: b.chang (Billing Specialist) | Workstation: ws-bchang (10.100.1.77)\n"
            "File: patient_data_q1.csv (42.3 MB) | Classification: PHI-BILLING\n"
            "Destination: dropbox.com (HTTPS PUT to api.dropboxapi.com)\n"
            "Account: personal dropbox (b.chang.personal@gmail.com)\n"
            "Network: DLP proxy intercepted upload before completion (blocked at 67%)"
        ),
        "investigate": {
            "analyze_headers": (
                "DLP proxy session analysis:\n"
                "  User: b.chang, Revenue Cycle, billing access to 850,000-record EHR\n"
                "  Destination: api.dropboxapi.com (personal Dropbox, not corporate Dropbox Business)\n"
                "  Upload: HTTPS PUT, intercepted at 67% (28.3 MB transferred before block)\n"
                "  File signature: CSV, first row headers match Epic billing export template\n"
                "  Time: 14:07 (business hours, but b.chang called in sick today — ANOMALOUS)\n"
                "  VPN: NOT connected (workstation on local LAN, unattended)"
            ),
            "query_siem": (
                "2026-04-16T13:58:11  Epic | b.chang export: patient_data_q1.csv (11,400 records)\n"
                "2026-04-16T13:58:12  Epic | Export authorization: MISSING (no manager approval)\n"
                "2026-04-16T14:06:55  Proxy | Dropbox.com connection initiated from ws-bchang\n"
                "2026-04-16T14:07:22  DLP | PHI upload BLOCKED (67% transferred)\n"
                "Badge log: b.chang badge NOT used today (called in sick)\n"
                "CRITICAL: Workstation accessed but employee is home — unauthorized physical access?"
            ),
            "check_reputation": (
                "b.chang: Billing Specialist, 5 years. Authorized to export billing records "
                "for insurance claims — WITH manager approval.\n"
                "  No approval on file for this export.\n"
                "  Personal email: b.chang.personal@gmail.com (NOT an authorized storage location).\n"
                "  HIPAA: Dropbox personal = unauthorized third party without BAA.\n"
                "  HR flag: Performance review pending (underperformance PIP, 2026-03-15).\n"
                "  28.3 MB transferred before block: ~6,800 records fully uploaded."
            ),
            "check_asset": (
                "patient_data_q1.csv contents:\n"
                "  11,400 patient billing records: name, DOB, SSN (partial), insurance ID,\n"
                "    ICD-10 codes, CPT codes, claim amounts, physician NPI\n"
                "  HIPAA categories: financial + medical — highly sensitive combination\n"
                "  28.3 MB transferred: ~6,800 records in personal Dropbox (no BAA)\n"
                "  Remaining 13,200 records: blocked, still on local workstation\n"
                "  Workstation: ws-bchang — b.chang called in sick, who is at the keyboard?"
            ),
            "analyze_payload": (
                "DLP content inspection of intercepted upload:\n"
                "  Row 1-100 sample: confirmed PHI — SSN last 4, full name, ICD-10, insurance\n"
                "  No de-identification applied\n"
                "  Dropbox personal: no HIPAA BAA, data stored on Dropbox servers (not covered)\n"
                "  28.3 MB already in personal Dropbox — constitute unauthorized disclosure\n"
                "  Dropbox API token: b.chang personal account authenticated with saved token"
            ),
            "correlate_alerts": (
                "Physical security: b.chang badge NOT scanned today.\n"
                "  Who accessed the workstation? → review CCTV footage for ws-bchang area.\n"
                "HIPAA breach: 6,800 records in unauthorized third-party storage.\n"
                "  HHS OCR reporting required within 60 days.\n"
                "  Dropbox legal hold request required immediately to preserve/delete data.\n"
                "Action: disable b.chang account, preserve ws-bchang forensic image,\n"
                "contact Dropbox security for emergency deletion request,\n"
                "notify Privacy Officer, initiate patient notification for 6,800 records."
            ),
        },
        "optimal_actions": [1, 2, 4, 5, 8],
        "impact_if_missed": "High — 6,800 patient PHI in unauthorized personal cloud storage. HIPAA reportable.",
    },

    # ── THREAT 4: Medical device C2 communication (IoMT compromise) ──────────
    {
        "id": "health-006",
        "category": "healthcare",
        "difficulty": "expert",
        "is_true_threat": True,
        "severity": "critical",
        "compliance": {
            "framework": "HIPAA",
            "data_type": "PHI",
            "data_classification": "Protected Health Information (PHI) and Medical Device Data",
            "breach_notification_hours": 0,
            "data_volume": "single",
            "mandatory_escalation": True,
        },
        "mitre": {
            "tactic": "Command and Control",
            "technique": "T1071.001",
            "name": "Application Layer Protocol: Web Protocols",
        },
        "alert": {
            "rule": "Medical Device Unexpected Outbound Internet Connection",
            "description": (
                "INFUSION-PUMP-ICU-07 (BD Alaris 8015 infusion pump, ICU) established "
                "outbound HTTPS connection to 203.0.113.150 — not a known vendor endpoint."
            ),
        },
        "source": {"ip": "10.200.7.15", "domain": "203.0.113.150", "geo": "RU-MSK"},
        "target": {
            "host": "INFUSION-PUMP-ICU-07",
            "ip": "10.200.7.15",
            "user": "device-service-account",
            "department": "Intensive Care Unit",
            "role": "BD Alaris 8015 Infusion Pump",
            "criticality": "critical",
        },
        "indicators": {
            "device_type": "BD Alaris 8015 Infusion Pump",
            "device_firmware": "11.1.2 (vulnerable to CVE-2022-26390)",
            "c2_ip": "203.0.113.150",
            "beacon_interval_sec": 30,
            "patient_connected": True,
            "medication": "Heparin IV — dose-critical",
        },
        "raw_log": (
            "Firewall DENY+ALERT: 2026-04-16T22:14:07Z\n"
            "src=10.200.7.15 (INFUSION-PUMP-ICU-07) dst=203.0.113.150:443 proto=HTTPS\n"
            "Rule: MEDICAL-DEVICE-INTERNET-DENY (IoMT VLAN outbound blocked)\n"
            "Previous events: 847 connection attempts to 203.0.113.150 in last 24h (every 30s)\n"
            "Device VLAN: IoMT-ICU (10.200.7.0/24) — should only reach BD vendor + HL7 server\n"
            "NOTE: Same IP seen in CISA ICS Advisory AA22-083A (BD Alaris firmware backdoor)"
        ),
        "investigate": {
            "analyze_headers": (
                "Network packet capture from IoMT VLAN firewall:\n"
                "  Source: INFUSION-PUMP-ICU-07 (10.200.7.15) — BD Alaris 8015\n"
                "  Destination: 203.0.113.150:443 — TLS 1.2, SNI: 'updates.bd-alaris.net' (FAKE)\n"
                "  Real BD Alaris update server: 69.x.x.x (bd.com netblock) — MISMATCH\n"
                "  Beacon pattern: every 30 ±2 seconds (jitter), consistent C2 heartbeat\n"
                "  First beacon: 2026-04-15T22:14Z (24h ago) — correlated with firmware push"
            ),
            "query_siem": (
                "2026-04-15T14:00Z  Biomedical | Firmware update pushed to INFUSION-PUMP-ICU-07\n"
                "  Update source: biomed-admin workstation (10.100.8.20)\n"
                "  Firmware version pushed: 11.1.2 (VULNERABLE — CVE-2022-26390 unpatched)\n"
                "2026-04-15T22:14Z  Firewall | First C2 beacon from INFUSION-PUMP-ICU-07\n"
                "2026-04-16T22:14Z  Firewall | 847th beacon — 24h continuous C2 activity\n"
                "biomed-admin workstation: check for compromise (source of malicious firmware)"
            ),
            "check_reputation": (
                "203.0.113.150: Russia-based IP. CISA ICS Advisory AA22-083A: C2 server for "
                "BD Alaris infusion pump backdoor (CVE-2022-26390).\n"
                "  VirusTotal: 67/88 malicious. Threat actor: Volt Typhoon (state-sponsored).\n"
                "  CVE-2022-26390: Remote code execution in BD Alaris 8015 firmware <12.0.\n"
                "  Patch: BD firmware 12.0.1 available since 2022-09-15 — NOT applied.\n"
                "  FDA Safety Communication: SC-2022-033 recommends immediate patch."
            ),
            "check_asset": (
                "INFUSION-PUMP-ICU-07 (BD Alaris 8015):\n"
                "  Location: ICU Bed 7 — patient connected (active infusion)\n"
                "  Current medication: Heparin 25,000 units/500mL at 12 mL/hr\n"
                "  PATIENT SAFETY: Compromised pump could alter infusion rate → overdose risk\n"
                "  Firmware 11.1.2: VULNERABLE. Attacker has RCE capability.\n"
                "  Additional pumps on same model/firmware: 23 units across ICU, CCU, OR"
            ),
            "analyze_payload": (
                "TLS session inspection (via enterprise MITM cert):\n"
                "  POST /api/v2/heartbeat: device ID, current patient MRN (PHI LEAK!)\n"
                "  POST /api/v2/config: received configuration JSON (potential rate change cmd)\n"
                "  Command received (decrypted): {\"action\":\"standby\",\"delay\":3600}\n"
                "  Interpretation: attacker may be staging timed disruption\n"
                "  IMMEDIATE PATIENT SAFETY RISK: attacker can send medication rate change commands"
            ),
            "correlate_alerts": (
                "23 additional BD Alaris pumps on same firmware: all potentially compromised.\n"
                "IMMEDIATE PATIENT SAFETY ACTIONS:\n"
                "  1. Notify ICU charge nurse + clinical staff — SWITCH TO MANUAL INFUSION NOW\n"
                "  2. Physically disconnect all 24 BD Alaris 8015 pumps from network\n"
                "  3. Contact BD Medical (1-888-BD-ALARIS) for emergency response\n"
                "  4. Report to FDA MedWatch + CISA ICS-CERT\n"
                "  5. Preserve device forensic image before power cycle\n"
                "  Patient MRN leaked to C2: HIPAA breach notification required."
            ),
        },
        "optimal_actions": [1, 2, 3, 5, 7, 8],
        "impact_if_missed": "Critical — active patient safety risk. Compromised infusion pump can alter medication dosing.",
    },
]
