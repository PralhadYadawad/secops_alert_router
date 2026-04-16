"""Cloud-native scenario templates for the SecOps Alert Router RL environment.

Eight scenarios covering AWS, Azure, and Kubernetes attack vectors:
  3 benign (authorized DevOps, CI/CD, backup operations)
  5 true threats (S3 exposure, IAM escalation, CloudTrail tampering,
                  EC2 IMDS credential theft, container escape, cryptomining)

MITRE ATT&CK coverage: T1530, T1078.004, T1562.008, T1552.005,
                        T1611, T1496, T1537, T1098.001
"""

CLOUD_SCENARIOS: list[dict] = [
    # ── BENIGN 1: Authorized S3 lifecycle policy removal (DevOps) ─────────────
    {
        "id": "cloud-001",
        "category": "cloud",
        "difficulty": "medium",
        "is_true_threat": False,
        "severity": "medium",
        "mitre": {
            "tactic": "Defense Evasion",
            "technique": "T1562",
            "name": "Impair Defenses",
        },
        "alert": {
            "rule": "S3 Bucket Policy Modified — Lifecycle Rules Removed",
            "description": (
                "CloudTrail detected DeleteBucketLifecycle on prod-data-archive-us-east-1. "
                "S3 bucket object-expiry rules were removed."
            ),
        },
        "source": {"ip": "203.0.113.55", "domain": "iam.amazonaws.com", "geo": "US"},
        "target": {
            "host": "s3://prod-data-archive-us-east-1",
            "ip": "AWS S3",
            "user": "devops-svc-account",
            "department": "Platform Engineering",
            "role": "Senior DevOps Engineer",
            "criticality": "high",
        },
        "indicators": {
            "cloudtrail_event": "DeleteBucketLifecycle",
            "principal": "arn:aws:iam::123456789012:user/devops-svc-account",
            "bucket": "prod-data-archive-us-east-1",
            "region": "us-east-1",
        },
        "raw_log": (
            '{"eventTime":"2026-04-16T14:22:10Z","eventName":"DeleteBucketLifecycle",'
            '"userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::123456789012:user/devops-svc-account"},'
            '"sourceIPAddress":"203.0.113.55","requestParameters":{"bucketName":"prod-data-archive-us-east-1"},'
            '"responseElements":null,"awsRegion":"us-east-1"}'
        ),
        "investigate": {
            "analyze_headers": (
                "CloudTrail event metadata:\n"
                "  Principal: arn:aws:iam::123456789012:user/devops-svc-account\n"
                "  MFA present: YES (arn:aws:iam::123456789012:mfa/devops-svc-account)\n"
                "  Source IP: 203.0.113.55 → Corporate VPN egress (AWS shield-verified)\n"
                "  User-Agent: aws-cli/2.15.30 Python/3.12.2 Linux/6.8.0\n"
                "  TLS version: TLS 1.3"
            ),
            "query_siem": (
                "2026-04-16T14:22:08Z  CloudTrail | PutBucketLifecycle (preview run, dry-run tag)\n"
                "2026-04-16T14:22:10Z  CloudTrail | DeleteBucketLifecycle bucket=prod-data-archive\n"
                "2026-04-16T14:22:14Z  CloudTrail | PutBucketLifecycle (new rules uploaded)\n"
                "2026-04-16T14:22:17Z  CloudTrail | PutBucketTagging key=LifecycleVersion value=v2.3\n"
                "Pattern: Delete → replace with updated config. Matches release workflow."
            ),
            "check_reputation": (
                "devops-svc-account: Service account, Platform Engineering team.\n"
                "  Access key age: 28 days (rotated monthly). Last used from same VPN IP.\n"
                "  IP 203.0.113.55: corporate VPN egress (NAT pool). 100% internal.\n"
                "  No GuardDuty findings for this principal in 90 days.\n"
                "  Risk score: 5/100."
            ),
            "check_asset": (
                "Bucket: prod-data-archive-us-east-1\n"
                "  Owner: Platform Engineering (contact: j.wright@company.com)\n"
                "  Data classification: Internal — archive logs, no PII\n"
                "  Versioning: ENABLED | Encryption: AES-256 SSE-S3\n"
                "  Block Public Access: ALL FOUR settings ENABLED\n"
                "  Replication: to eu-west-1 DR bucket (unchanged)"
            ),
            "analyze_payload": (
                "Old lifecycle rule: Expire objects after 90 days (set 2024-01-10)\n"
                "New lifecycle rule applied 14s later:\n"
                "  - Transition to S3 Glacier after 60 days\n"
                "  - Expire Glacier objects after 365 days (cost optimization)\n"
                "  - Noncurrent version expiry: 30 days\n"
                "Change ticket: https://jira.company.com/browse/PLAT-3341 (approved)"
            ),
            "correlate_alerts": (
                "Jira PLAT-3341: 'Optimize S3 archive costs — migrate to Glacier tier'.\n"
                "Approved by: m.harris (CTO), 2026-04-15. Estimated $2,800/mo savings.\n"
                "2 similar lifecycle updates performed last quarter, same account, no incidents.\n"
                "No related PutBucketAcl, PutBucketPolicy, or GetObject events.\n"
                "Verdict: authorized cost-optimization change."
            ),
        },
        "optimal_actions": [1, 3, 5, 10],
        "impact_if_missed": "None — authorized change. Escalating would block planned cost savings.",
    },

    # ── BENIGN 2: CI/CD pipeline assuming cross-account role (authorized) ─────
    {
        "id": "cloud-002",
        "category": "cloud",
        "difficulty": "medium-hard",
        "is_true_threat": False,
        "severity": "high",
        "mitre": {
            "tactic": "Privilege Escalation",
            "technique": "T1548",
            "name": "Abuse Elevation Control Mechanism",
        },
        "alert": {
            "rule": "Cross-Account IAM Role Assumption Detected",
            "description": (
                "AssumeRole from production account 123456789012 into security-audit "
                "account 987654321098. Non-standard role assumption pattern flagged."
            ),
        },
        "source": {"ip": "10.20.5.100", "domain": "github.com", "geo": "INTERNAL"},
        "target": {
            "host": "arn:aws:iam::987654321098:role/SecurityAuditReadOnly",
            "ip": "AWS IAM",
            "user": "ci-pipeline-runner",
            "department": "DevSecOps",
            "role": "CI/CD Service Account",
            "criticality": "high",
        },
        "indicators": {
            "cloudtrail_event": "AssumeRole",
            "source_account": "123456789012",
            "target_account": "987654321098",
            "role_arn": "arn:aws:iam::987654321098:role/SecurityAuditReadOnly",
            "external_id": "ci-prod-to-audit-v2",
        },
        "raw_log": (
            '{"eventTime":"2026-04-16T03:15:00Z","eventName":"AssumeRole",'
            '"userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::123456789012:user/ci-pipeline-runner"},'
            '"requestParameters":{"roleArn":"arn:aws:iam::987654321098:role/SecurityAuditReadOnly",'
            '"externalId":"ci-prod-to-audit-v2","durationSeconds":3600},'
            '"sourceIPAddress":"10.20.5.100","awsRegion":"us-east-1"}'
        ),
        "investigate": {
            "analyze_headers": (
                "CloudTrail AssumeRole metadata:\n"
                "  Caller: arn:aws:iam::123456789012:user/ci-pipeline-runner\n"
                "  External ID: ci-prod-to-audit-v2 (matches trust policy)\n"
                "  Source: 10.20.5.100 → GitHub Actions self-hosted runner VLAN\n"
                "  Session duration requested: 3600s (max allowed by role)\n"
                "  MFA: Not required for service account (by design, ExternalId enforced)"
            ),
            "query_siem": (
                "2026-04-16T03:14:55Z  GitHub Actions | workflow=nightly-compliance-scan "
                "trigger=schedule(0 3 * * *)\n"
                "2026-04-16T03:15:00Z  CloudTrail | AssumeRole -> SecurityAuditReadOnly\n"
                "2026-04-16T03:15:01Z  CloudTrail | DescribeInstances (SecurityAuditReadOnly)\n"
                "2026-04-16T03:15:02Z  CloudTrail | GetBucketAcl (read-only, 47 buckets)\n"
                "2026-04-16T03:16:40Z  CloudTrail | GenerateServiceLastAccessedDetails\n"
                "Historical: Same pattern every night at 03:15 for 6 months."
            ),
            "check_reputation": (
                "ci-pipeline-runner: Machine identity, DevSecOps team.\n"
                "  Key age: 14 days. AssumeRole to SecurityAuditReadOnly 183 times in 6 months.\n"
                "  Role SecurityAuditReadOnly: Read-only policy, no write permissions.\n"
                "  External ID validation: PASS (ci-prod-to-audit-v2 enforced in trust policy).\n"
                "  No anomalous API calls in session history."
            ),
            "check_asset": (
                "SecurityAuditReadOnly role:\n"
                "  Account: 987654321098 (security-audit)\n"
                "  Attached policies: SecurityAudit (AWS managed, read-only)\n"
                "  Trust policy: Requires ExternalId + source account = 123456789012\n"
                "  Purpose: Nightly CIS benchmark scan, compliance reporting\n"
                "  Owner: InfoSec team (contact: security@company.com)"
            ),
            "analyze_payload": (
                "API calls during 65-minute session (read-only only):\n"
                "  DescribeInstances, DescribeSecurityGroups (EC2 inventory)\n"
                "  GetBucketAcl, GetBucketPolicy (S3 compliance check)\n"
                "  GenerateServiceLastAccessedDetails (IAM access advisor)\n"
                "  ListPolicies, GetPolicy (IAM audit)\n"
                "No write operations. No data exfiltration. Output: CloudTrail log → S3 bucket."
            ),
            "correlate_alerts": (
                "Nightly schedule registered: GitHub Actions workflow ID 7720, "
                "nightly-compliance-scan, trigger=cron(0 3 * * *).\n"
                "Last 30 days: 30 successful runs, 0 failed, consistent 65-minute runtime.\n"
                "Security ticket SEC-882: 'Nightly CIS L1 benchmark scan' — approved."
            ),
        },
        "optimal_actions": [1, 3, 5, 10],
        "impact_if_missed": "None — authorized nightly compliance scan. False positive would break CIS benchmark reporting.",
    },

    # ── BENIGN 3: Authorized GuardDuty suppression for testing ───────────────
    {
        "id": "cloud-003",
        "category": "cloud",
        "difficulty": "hard",
        "is_true_threat": False,
        "severity": "high",
        "mitre": {
            "tactic": "Defense Evasion",
            "technique": "T1562.001",
            "name": "Disable or Modify Tools",
        },
        "alert": {
            "rule": "GuardDuty Finding Suppression Rule Created",
            "description": (
                "CreateFilter API call created a new GuardDuty suppression rule for "
                "finding type UnauthorizedAccess:EC2/SSHBruteForce in the us-east-1 region."
            ),
        },
        "source": {"ip": "10.10.1.5", "domain": "console.amazonaws.com", "geo": "INTERNAL"},
        "target": {
            "host": "GuardDuty Detector — us-east-1",
            "ip": "AWS GuardDuty",
            "user": "secops-admin",
            "department": "Information Security",
            "role": "Cloud Security Engineer",
            "criticality": "critical",
        },
        "indicators": {
            "cloudtrail_event": "CreateFilter",
            "finding_type_suppressed": "UnauthorizedAccess:EC2/SSHBruteForce",
            "filter_action": "ARCHIVE",
            "filter_criterion": "resource.instanceDetails.tags.key=honeypot",
        },
        "raw_log": (
            '{"eventTime":"2026-04-16T10:04:33Z","eventName":"CreateFilter",'
            '"userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::123456789012:user/secops-admin"},'
            '"requestParameters":{"detectorId":"abc1234567890abc","filterName":"suppress-honeypot-ssh",'
            '"action":"ARCHIVE","findingCriteria":{"criterion":{"resource.instanceDetails.tags.key":{"eq":["honeypot"]}}}},'
            '"sourceIPAddress":"10.10.1.5"}'
        ),
        "investigate": {
            "analyze_headers": (
                "CloudTrail CreateFilter metadata:\n"
                "  Principal: arn:aws:iam::123456789012:user/secops-admin\n"
                "  MFA: PRESENT (Yubikey hardware token)\n"
                "  Source IP: 10.10.1.5 → SOC workstation, corporate network\n"
                "  Session: 14 minutes (console session, single focused action)\n"
                "  Scope: ARCHIVE (suppress only, findings still logged)"
            ),
            "query_siem": (
                "2026-04-16T10:00:10Z  CloudTrail | DescribeInstances (looked up honeypot tag)\n"
                "2026-04-16T10:02:44Z  CloudTrail | ListFindings (reviewed SSH brute force alerts)\n"
                "2026-04-16T10:04:33Z  CloudTrail | CreateFilter suppress-honeypot-ssh\n"
                "Context: GuardDuty generated 847 UnauthorizedAccess:EC2/SSHBruteForce findings\n"
                "in 24h — all targeting 3 dedicated honeypot instances."
            ),
            "check_reputation": (
                "secops-admin: Cloud Security Engineer, InfoSec team. 4 years tenure.\n"
                "  Authorized: GuardDuty admin permissions per RBAC matrix.\n"
                "  Prior CreateFilter events: 7 in 12 months (all for honeypot/scanner noise).\n"
                "  Risk score: 6/100. No incidents.\n"
                "  Filter scope: archive, NOT delete — findings still visible in raw logs."
            ),
            "check_asset": (
                "GuardDuty Detector: abc1234567890abc, us-east-1\n"
                "  Status: ENABLED\n"
                "  Suppression scope: ONLY instances tagged honeypot=true (3 instances)\n"
                "  Honeypot instances: i-0abc123 (10.0.99.1), i-0abc124 (10.0.99.2), "
                "i-0abc125 (10.0.99.3)\n"
                "  Purpose: attract attackers, collect TTPs. InfoSec approved."
            ),
            "analyze_payload": (
                "Filter criterion: resource.instanceDetails.tags.key=honeypot\n"
                "  → Applies ONLY to EC2 instances tagged with key 'honeypot'\n"
                "  → 3 dedicated honeypot instances (no production workloads)\n"
                "Filter action: ARCHIVE (not DELETE — findings still searchable)\n"
                "Finding type: UnauthorizedAccess:EC2/SSHBruteForce (internet scanner noise)\n"
                "Rationale: 847 false positives per day drowning real alerts."
            ),
            "correlate_alerts": (
                "InfoSec runbook SEC-PROC-014: 'Suppress GuardDuty noise from honeypot instances'.\n"
                "Approved by CISO on 2026-01-15. Reviewed quarterly.\n"
                "Change ticket CHG-20260416-0044: 'Honeypot SSH suppression filter'.\n"
                "Peer review: r.chen (senior cloud engineer) approved 2026-04-15.\n"
                "Verdict: authorized noise suppression. No evasion of real detections."
            ),
        },
        "optimal_actions": [1, 3, 4, 5, 10],
        "impact_if_missed": "None — authorized. Would block legitimate SOC noise-reduction workflow.",
    },

    # ── THREAT 1: S3 bucket ACL changed to public-read ────────────────────────
    {
        "id": "cloud-004",
        "category": "cloud",
        "difficulty": "medium",
        "is_true_threat": True,
        "severity": "high",
        "compliance": {
            "framework": "GDPR",
            "data_type": "PII",
            "data_classification": "EU Customer PII",
            "breach_notification_hours": 72,
            "data_volume": "massive",
            "mandatory_escalation": True,
        },
        "mitre": {
            "tactic": "Collection",
            "technique": "T1530",
            "name": "Data from Cloud Storage",
        },
        "alert": {
            "rule": "S3 Bucket Block Public Access Disabled",
            "description": (
                "PutBucketAcl set prod-customer-data-eu to public-read. "
                "GuardDuty: Policy:S3/BucketPublicAccessGranted."
            ),
        },
        "source": {"ip": "198.51.100.44", "domain": "s3.amazonaws.com", "geo": "VPN-RO"},
        "target": {
            "host": "s3://prod-customer-data-eu",
            "ip": "AWS S3",
            "user": "dev-jcallahan",
            "department": "Engineering",
            "role": "Junior Developer",
            "criticality": "critical",
        },
        "indicators": {
            "cloudtrail_event": "PutBucketAcl",
            "acl_set": "public-read",
            "bucket": "prod-customer-data-eu",
            "region": "eu-west-1",
            "guardduty_finding": "Policy:S3/BucketPublicAccessGranted",
        },
        "raw_log": (
            '{"eventTime":"2026-04-16T16:31:05Z","eventName":"PutBucketAcl",'
            '"userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::123456789012:user/dev-jcallahan"},'
            '"sourceIPAddress":"198.51.100.44","userAgent":"S3Console/0.4",'
            '"requestParameters":{"bucketName":"prod-customer-data-eu",'
            '"AccessControlPolicy":{"AccessControlList":{"Grant":{"Grantee":{"URI":'
            '"http://acs.amazonaws.com/groups/global/AllUsers"},"Permission":"READ"}}}}'
        ),
        "investigate": {
            "analyze_headers": (
                "CloudTrail PutBucketAcl metadata:\n"
                "  Principal: arn:aws:iam::123456789012:user/dev-jcallahan\n"
                "  MFA: NOT PRESENT (service account has no MFA)\n"
                "  User-Agent: S3Console/0.4 → AWS web console (not CLI)\n"
                "  Source IP: 198.51.100.44 → Mullvad VPN exit (Romania). "
                "  NOT corporate VPN. ANOMALOUS: dev-jcallahan always uses UK office IP.\n"
                "  Time: 16:31 UTC (after business hours in EU)"
            ),
            "query_siem": (
                "2026-04-16T16:28:12Z  IAM | GetSigninToken dev-jcallahan from 198.51.100.44\n"
                "2026-04-16T16:29:01Z  Console | S3 bucket list (10 buckets viewed)\n"
                "2026-04-16T16:30:44Z  S3 | ListObjects prod-customer-data-eu (1.2M objects)\n"
                "2026-04-16T16:31:05Z  S3 | PutBucketAcl public-read\n"
                "2026-04-16T16:31:07Z  GuardDuty | Policy:S3/BucketPublicAccessGranted SEVERITY=HIGH\n"
                "2026-04-16T16:31:12Z  S3 | GetObject (first external access began within 7 seconds)"
            ),
            "check_reputation": (
                "dev-jcallahan: Junior Developer, UK office. Normal login: 46.x.x.x (BT ISP, London).\n"
                "  ANOMALY: 198.51.100.44 → Mullvad VPN, Romania. First time from this IP.\n"
                "  GuardDuty: UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration (2h ago)\n"
                "  AbuseIPDB 198.51.100.44: 34 reports, VPN/proxy.\n"
                "  LIKELY: credentials compromised and used via anonymizing proxy."
            ),
            "check_asset": (
                "Bucket: prod-customer-data-eu (eu-west-1)\n"
                "  Data classification: CRITICAL — GDPR-regulated customer PII\n"
                "  Contents: 1.2M objects, customer name/email/address/order history\n"
                "  Data steward: privacy@company.com (DPO team)\n"
                "  Prior state: Block Public Access ALL ENABLED\n"
                "  AWS Config: Compliance rule S3-BLOCK-PUBLIC-ACCESS triggered NONCOMPLIANT"
            ),
            "analyze_payload": (
                "Bucket ACL change: Set AllUsers → READ permission\n"
                "  Effect: Entire bucket publicly listable and readable (1.2M objects)\n"
                "  First public GetObject: 7 seconds after ACL change (automated scanner)\n"
                "  Access log (17 min window): 48 unique external IPs retrieved 23,441 objects\n"
                "  Estimated data exposed: ~18 GB customer PII\n"
                "  Bucket index: customer_export_2026-04-15.csv in root (1.2M records)"
            ),
            "correlate_alerts": (
                "2026-04-16T14:17Z  CloudTrail | phishing email sent to james.callahan@company.com\n"
                "2026-04-16T14:22Z  Okta | new session dev-jcallahan from 198.51.100.44 (suspicious)\n"
                "2026-04-16T16:31Z  S3 | PutBucketAcl (this alert)\n"
                "GDPR Art. 33: 72-hour breach notification to supervisory authority REQUIRED.\n"
                "Estimated affected subjects: 1.2M (bulk). CRITICAL: revoke dev-jcallahan, "
                "block public access, notify DPO, initiate GDPR incident response."
            ),
        },
        "optimal_actions": [1, 2, 3, 5, 7, 8],
        "impact_if_missed": "Critical — 1.2M GDPR-regulated customer records exposed. Regulatory fines up to 4% global revenue.",
    },

    # ── THREAT 2: IAM privilege escalation via AdministratorAccess attachment ─
    {
        "id": "cloud-005",
        "category": "cloud",
        "difficulty": "medium-hard",
        "is_true_threat": True,
        "severity": "critical",
        "mitre": {
            "tactic": "Privilege Escalation",
            "technique": "T1098.001",
            "name": "Account Manipulation: Additional Cloud Credentials",
        },
        "alert": {
            "rule": "IAM AdministratorAccess Policy Attached to User",
            "description": (
                "AttachUserPolicy added AdministratorAccess to low-privilege user m.okonkwo. "
                "GuardDuty: PrivilegeEscalation:IAMUser/AdministrativePermissions."
            ),
        },
        "source": {"ip": "203.0.113.201", "domain": "iam.amazonaws.com", "geo": "CN-BJ"},
        "target": {
            "host": "arn:aws:iam::123456789012:user/m.okonkwo",
            "ip": "AWS IAM",
            "user": "m.okonkwo",
            "department": "Marketing",
            "role": "Digital Marketing Analyst",
            "criticality": "critical",
        },
        "indicators": {
            "cloudtrail_event": "AttachUserPolicy",
            "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess",
            "target_user": "m.okonkwo",
            "actor_ip": "203.0.113.201",
            "guardduty_finding": "PrivilegeEscalation:IAMUser/AdministrativePermissions",
        },
        "raw_log": (
            '{"eventTime":"2026-04-16T02:44:17Z","eventName":"AttachUserPolicy",'
            '"userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::123456789012:user/m.okonkwo",'
            '"accessKeyId":"AKIAIOSFODNN7EXAMPLE"},'
            '"sourceIPAddress":"203.0.113.201","userAgent":"aws-sdk-python/1.34.69",'
            '"requestParameters":{"userName":"m.okonkwo",'
            '"policyArn":"arn:aws:iam::aws:policy/AdministratorAccess"}}'
        ),
        "investigate": {
            "analyze_headers": (
                "CloudTrail AttachUserPolicy metadata:\n"
                "  Actor: m.okonkwo (attaching policy to THEMSELVES — self-escalation)\n"
                "  Access key: AKIAIOSFODNN7EXAMPLE (long-lived key, created 2024-08-01)\n"
                "  Source IP: 203.0.113.201 → Beijing, China. ANOMALOUS.\n"
                "  m.okonkwo normal location: London, UK (office IP 46.234.x.x)\n"
                "  Time: 02:44 UTC (02:44 London — well outside business hours)\n"
                "  MFA: NOT used. CRITICAL: AttachUserPolicy does not require MFA here."
            ),
            "query_siem": (
                "2026-04-16T02:43:01Z  IAM | GetUser m.okonkwo (reconnaissance)\n"
                "2026-04-16T02:43:08Z  IAM | ListAttachedUserPolicies m.okonkwo\n"
                "2026-04-16T02:43:14Z  IAM | ListPolicies (searched for AdministratorAccess)\n"
                "2026-04-16T02:44:17Z  IAM | AttachUserPolicy AdministratorAccess → m.okonkwo\n"
                "2026-04-16T02:44:22Z  IAM | CreateAccessKey m.okonkwo (new key created)\n"
                "2026-04-16T02:44:35Z  EC2 | DescribeInstances (all regions — enumeration)\n"
                "2026-04-16T02:44:48Z  S3 | ListBuckets (all 63 buckets enumerated)"
            ),
            "check_reputation": (
                "m.okonkwo: Marketing Analyst, 2 years. Normal permissions: S3 read (marketing-assets), "
                "CloudFront invalidation. NO IAM admin permissions.\n"
                "  CRITICAL: user should NOT have AttachUserPolicy permission. \n"
                "  Overly permissive IAM policy granted in March 2026 (misconfiguration).\n"
                "  203.0.113.201: China Unicom Beijing. Never used before.\n"
                "  GuardDuty: also flagged UnauthorizedAccess:IAMUser/MaliciousIPCaller."
            ),
            "check_asset": (
                "IAM user m.okonkwo prior permissions:\n"
                "  - S3:GetObject on arn:aws:s3:::marketing-assets/*\n"
                "  - cloudfront:CreateInvalidation\n"
                "  - iam:AttachUserPolicy (MISCONFIGURED — should be iam:DENY)\n"
                "After escalation: FULL AWS account administrator\n"
                "  → Can read all secrets, delete all data, spin up resources globally\n"
                "  → Can exfiltrate RDS databases, S3 customer data, Secrets Manager values"
            ),
            "analyze_payload": (
                "Post-escalation API calls (within 30 seconds):\n"
                "  IAM: CreateAccessKey (new persistent key for exfil)\n"
                "  EC2: DescribeInstances ALL regions (mapping infrastructure)\n"
                "  S3: ListBuckets (63 buckets), GetBucketTagging (classifying data)\n"
                "  SecretsManager: ListSecrets (found 44 secrets)\n"
                "  RDS: DescribeDBInstances (found prod databases)\n"
                "IMMEDIATE: Revoke all m.okonkwo keys, detach AdministratorAccess, "
                "audit all API calls in 24h window."
            ),
            "correlate_alerts": (
                "2026-04-13T09:15Z  Phishing | m.okonkwo clicked credential-harvesting link "
                "(marketing newsletter — phish-style attack)\n"
                "2026-04-13T09:22Z  Okta | new session m.okonkwo from 45.x.x.x (phishing proxy)\n"
                "2026-04-13–16  Dormant 3 days (planning phase)\n"
                "2026-04-16T02:44Z  This escalation event\n"
                "CRITICAL: IAM misconfiguration allowed non-admin to self-escalate. "
                "Revoke NOW, rotate all Secrets Manager values, audit 63 S3 buckets."
            ),
        },
        "optimal_actions": [1, 2, 3, 5, 7, 8],
        "impact_if_missed": "Critical — full AWS account compromise. All data, secrets, and infrastructure at risk.",
    },

    # ── THREAT 3: CloudTrail logging disabled (defense evasion) ──────────────
    {
        "id": "cloud-006",
        "category": "cloud",
        "difficulty": "hard",
        "is_true_threat": True,
        "severity": "critical",
        "mitre": {
            "tactic": "Defense Evasion",
            "technique": "T1562.008",
            "name": "Disable or Modify Cloud Logs",
        },
        "alert": {
            "rule": "CloudTrail Multi-Region Trail Stopped and Deleted",
            "description": (
                "StopLogging and DeleteTrail executed on org-wide CloudTrail trail. "
                "GuardDuty: Stealth:IAMUser/CloudTrailLoggingDisabled."
            ),
        },
        "source": {"ip": "203.0.113.99", "domain": "cloudtrail.amazonaws.com", "geo": "TOR"},
        "target": {
            "host": "CloudTrail trail: org-cloudtrail-all-regions",
            "ip": "AWS CloudTrail",
            "user": "infra-deploy-svc",
            "department": "Platform Engineering",
            "role": "Infrastructure Automation",
            "criticality": "critical",
        },
        "indicators": {
            "cloudtrail_events": ["StopLogging", "DeleteTrail"],
            "trail": "org-cloudtrail-all-regions",
            "coverage": "All regions, organization trail",
            "guardduty_finding": "Stealth:IAMUser/CloudTrailLoggingDisabled",
        },
        "raw_log": (
            '{"eventTime":"2026-04-16T19:07:03Z","eventName":"StopLogging",'
            '"userIdentity":{"arn":"arn:aws:iam::123456789012:user/infra-deploy-svc"},'
            '"sourceIPAddress":"203.0.113.99","requestParameters":{"name":"org-cloudtrail-all-regions"}}\n'
            '{"eventTime":"2026-04-16T19:07:11Z","eventName":"DeleteTrail",'
            '"userIdentity":{"arn":"arn:aws:iam::123456789012:user/infra-deploy-svc"},'
            '"sourceIPAddress":"203.0.113.99","requestParameters":{"name":"org-cloudtrail-all-regions"}}'
        ),
        "investigate": {
            "analyze_headers": (
                "CloudTrail StopLogging + DeleteTrail metadata:\n"
                "  Principal: arn:aws:iam::123456789012:user/infra-deploy-svc\n"
                "  MFA: NOT PRESENT (service account, no MFA)\n"
                "  Source IP: 203.0.113.99 → Tor exit node (AS5577 Root SA, Luxembourg)\n"
                "  ANOMALOUS: infra-deploy-svc always calls from 10.20.x.x (internal runner)\n"
                "  Events: StopLogging at 19:07:03, DeleteTrail 8 seconds later\n"
                "  8-second gap: deliberate sequential action, not automation script error"
            ),
            "query_siem": (
                "2026-04-16T19:05:44Z  IAM | GetCallerIdentity (attacker confirming identity)\n"
                "2026-04-16T19:06:01Z  CloudTrail | DescribeTrails (listed all trails)\n"
                "2026-04-16T19:06:15Z  CloudTrail | GetTrailStatus org-cloudtrail-all-regions\n"
                "2026-04-16T19:07:03Z  CloudTrail | StopLogging ← LOGGING HALTED\n"
                "2026-04-16T19:07:11Z  CloudTrail | DeleteTrail ← TRAIL DELETED\n"
                "CRITICAL: Log coverage gap began at 19:07:03. Duration of blind spot: ONGOING."
            ),
            "check_reputation": (
                "infra-deploy-svc: Internal automation account. Normal: 10.20.5.x runners.\n"
                "  Last legitimate use: 2026-04-16T06:30Z (Terraform plan from 10.20.5.12)\n"
                "  Access key AKIA...: Active since 2025-11-12 (157 days, rotation overdue)\n"
                "  203.0.113.99: Tor exit. Never previously used for this account.\n"
                "  LIKELY: Static long-lived key exfiltrated. Attacker operating via Tor."
            ),
            "check_asset": (
                "Trail org-cloudtrail-all-regions:\n"
                "  Type: Organization trail (covers all 12 AWS accounts)\n"
                "  Scope: ALL regions, management + data events\n"
                "  S3 destination: s3://company-cloudtrail-logs (Glacier + Object Lock)\n"
                "  Current status: DELETED — no API logging across entire organization\n"
                "  AWS Config rule: cloudtrail-enabled → NONCOMPLIANT across all accounts"
            ),
            "analyze_payload": (
                "After trail deletion, attacker API calls (unlogged — reconstructed from S3 Object Lock):\n"
                "  SecretsManager | GetSecretValue (47 secrets read in 4 minutes)\n"
                "  RDS | CreateDBSnapshot prod-mysql-primary (exfil staging)\n"
                "  EC2 | RunInstances (t3.2xlarge, us-east-1, no tags — cryptominer?)\n"
                "  S3 | GetObject prod-customer-data-eu (1,200 objects)\n"
                "CRITICAL: Blind spot allowed unrestricted access for 23 minutes. "
                "S3 Object Lock preserves some evidence."
            ),
            "correlate_alerts": (
                "2026-04-15T03:00Z  GitLeaks | infra-deploy-svc access key found in GitHub PR\n"
                "2026-04-15T03:12Z  GitHub | PR #2217 merged (key committed 8 mins before scan)\n"
                "Key was live for 38 hours before deletion event.\n"
                "CRITICAL: Rotate ALL service account keys, recreate CloudTrail trail, "
                "audit 23-minute blind spot via VPC Flow Logs and S3 Object Lock, "
                "declare incident — full post-mortem required."
            ),
        },
        "optimal_actions": [1, 2, 3, 5, 7, 8],
        "impact_if_missed": "Critical — 23-minute audit log blind spot, secrets exfiltrated, potential full account compromise.",
    },

    # ── THREAT 4: EC2 IMDS v1 credential theft via SSRF ──────────────────────
    {
        "id": "cloud-007",
        "category": "cloud",
        "difficulty": "hard",
        "is_true_threat": True,
        "severity": "high",
        "mitre": {
            "tactic": "Credential Access",
            "technique": "T1552.005",
            "name": "Unsecured Credentials: Cloud Instance Metadata API",
        },
        "alert": {
            "rule": "EC2 Instance Credentials Used from External IP",
            "description": (
                "GuardDuty: CredentialAccess:EC2/UnusualCredentials — IAM role credentials "
                "attached to web-prod-01 (10.0.1.50) accessed S3 from external IP 198.51.100.88."
            ),
        },
        "source": {"ip": "198.51.100.88", "domain": "s3.amazonaws.com", "geo": "NL-AMS"},
        "target": {
            "host": "i-0a1b2c3d4e5f6a7b8 (web-prod-01)",
            "ip": "10.0.1.50",
            "user": "web-app-role",
            "department": "Engineering",
            "role": "EC2 Instance Profile",
            "criticality": "high",
        },
        "indicators": {
            "instance_id": "i-0a1b2c3d4e5f6a7b8",
            "instance_name": "web-prod-01",
            "iam_role": "web-app-role",
            "external_ip": "198.51.100.88",
            "imds_version": "v1",
            "guardduty_finding": "CredentialAccess:EC2/UnusualCredentials",
        },
        "raw_log": (
            "GuardDuty Finding: CredentialAccess:EC2/UnusualCredentials\n"
            "Severity: HIGH | AccountId: 123456789012 | Region: us-east-1\n"
            "Resource: i-0a1b2c3d4e5f6a7b8 (Role: web-app-role)\n"
            "Action: AWS_API_CALL S3:GetObject | RemoteIP: 198.51.100.88 (AS60781 Hetzner NL)\n"
            "The credentials attached to this instance were used from an external IP address."
        ),
        "investigate": {
            "analyze_headers": (
                "CloudTrail S3 API calls from role web-app-role:\n"
                "  Credential type: AssumedRole (EC2 instance profile)\n"
                "  Source for legitimate calls: 10.0.1.50 (internal VPC)\n"
                "  Source for flagged calls: 198.51.100.88 (Hetzner NL)\n"
                "  IMDS v1: No token required — curl http://169.254.169.254/latest/meta-data/\n"
                "  Credential exposure: SSRF in web app allowed metadata service access\n"
                "  IMDSv2 migration: NOT completed (flagged in March 2026 security review)"
            ),
            "query_siem": (
                "2026-04-16T11:22:05Z  WAF | ALLOWED GET /api/fetch?url=http://169.254.169.254/ (SSRF)\n"
                "2026-04-16T11:22:06Z  EC2 | 169.254.169.254 metadata request from web-prod-01\n"
                "2026-04-16T11:22:07Z  EC2 | /meta-data/iam/security-credentials/web-app-role returned\n"
                "2026-04-16T11:22:09Z  CloudTrail | S3:GetObject from 198.51.100.88 web-app-role\n"
                "2026-04-16T11:22:10Z  GuardDuty | CredentialAccess:EC2/UnusualCredentials FIRED\n"
                "2026-04-16T11:22:10Z–11:45Z  S3:GetObject × 2,847 from 198.51.100.88"
            ),
            "check_reputation": (
                "198.51.100.88: Hetzner Online GmbH, Amsterdam. AbuseIPDB: 67 reports.\n"
                "  First seen in company logs today. No prior legitimate use.\n"
                "  web-app-role: legitimate EC2 instance profile, S3 GetObject on app-assets.\n"
                "  SSRF vector: GET /api/fetch endpoint fetches arbitrary URLs — known OWASP A10.\n"
                "  WAF: No SSRF rule for 169.254.0.0/16 (internal range not blocked)."
            ),
            "check_asset": (
                "EC2 web-prod-01 (i-0a1b2c3d4e5f6a7b8):\n"
                "  Role: web-app-role (S3:GetObject on s3://app-assets/* and s3://customer-uploads/*)\n"
                "  IMDS version: v1 (NO TOKEN REQUIRED — critical misconfiguration)\n"
                "  Attached S3 buckets accessible: app-assets, customer-uploads (PII)\n"
                "  customer-uploads: user avatars + ID documents (GDPR scope)\n"
                "  2,847 GetObject calls: mix of app-assets (benign) + customer-uploads (PII)"
            ),
            "analyze_payload": (
                "SSRF request chain (reconstructed):\n"
                "  1. GET /api/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/\n"
                "  2. Response: {AccessKeyId: ASIA..., SecretAccessKey: ..., Token: ..., Expiration: +6h}\n"
                "  3. Attacker used temp creds from 198.51.100.88 for 23 minutes\n"
                "  S3 exfiltration: 2,847 objects (app-assets + 344 customer ID documents)\n"
                "  Data exfiltrated: ~890 MB. Credentials expired at 17:22 UTC (6h rotation)."
            ),
            "correlate_alerts": (
                "March 2026 security review finding: 'IMDSv1 still active on 23 instances — migrate to v2'\n"
                "Ticket ENG-4421 created, not yet remediated.\n"
                "WAF rule gap: SSRF to 169.254.0.0/16 not blocked.\n"
                "IMMEDIATE: Revoke web-app-role temp credentials, enforce IMDSv2 on all EC2,\n"
                "add WAF SSRF rule for metadata range, notify GDPR team (344 ID documents)."
            ),
        },
        "optimal_actions": [1, 2, 3, 5, 6, 7],
        "impact_if_missed": "High — 344 customer ID documents exfiltrated via SSRF+IMDS. GDPR breach.",
    },

    # ── THREAT 5: Privileged container escape via host path mount ─────────────
    {
        "id": "cloud-008",
        "category": "cloud",
        "difficulty": "hard",
        "is_true_threat": True,
        "severity": "critical",
        "mitre": {
            "tactic": "Privilege Escalation",
            "technique": "T1611",
            "name": "Escape to Host",
        },
        "alert": {
            "rule": "Privileged Container nsenter Host Escape Detected",
            "description": (
                "Falco: Detected nsenter -t 1 -m -u -i -n -p -- bash executed inside "
                "privileged pod exploit-runner in namespace default, escaping to node k8s-node-03."
            ),
        },
        "source": {"ip": "10.50.3.100", "domain": "k8s-api.corp.local", "geo": "INTERNAL"},
        "target": {
            "host": "k8s-node-03 (10.50.3.20)",
            "ip": "10.50.3.20",
            "user": "system:serviceaccount:default:default",
            "department": "Platform Engineering",
            "role": "Kubernetes Node",
            "criticality": "critical",
        },
        "indicators": {
            "pod_name": "exploit-runner",
            "namespace": "default",
            "container_image": "alpine:latest",
            "escape_command": "nsenter -t 1 -m -u -i -n -p -- bash",
            "falco_rule": "Privileged Pod Launched + Container Host Escape",
            "node": "k8s-node-03",
        },
        "raw_log": (
            "Falco Alert: container.name=exploit-runner, container.image=alpine:latest\n"
            "Rule: Detect nsenter in container\n"
            "Priority: CRITICAL\n"
            "proc.cmdline: nsenter -t 1 -m -u -i -n -p -- bash\n"
            "container.privileged: true\n"
            "k8s.pod.name: exploit-runner, k8s.ns.name: default\n"
            "k8s.node.name: k8s-node-03, proc.pid: 38291\n"
            "evt.time: 2026-04-16T20:14:33Z"
        ),
        "investigate": {
            "analyze_headers": (
                "Kubernetes API audit log — pod creation:\n"
                "  kubectl create -f exploit-runner.yaml from 203.0.113.77 (external!)\n"
                "  ServiceAccount: system:serviceaccount:default:default\n"
                "  Pod spec: securityContext.privileged=true, hostPID=true, hostNetwork=true\n"
                "  Volume: hostPath '/' mounted at '/host' (full node filesystem)\n"
                "  RBAC: default service account has 'create pods' permission (misconfiguration)"
            ),
            "query_siem": (
                "2026-04-16T20:10:01Z  K8s API | GET /api/v1/namespaces (enumeration)\n"
                "2026-04-16T20:10:44Z  K8s API | GET /api/v1/secrets (listed 88 secrets)\n"
                "2026-04-16T20:11:30Z  K8s API | POST /api/v1/pods exploit-runner (privileged)\n"
                "2026-04-16T20:11:35Z  Falco | Privileged Pod Launched priority=WARNING\n"
                "2026-04-16T20:14:33Z  Falco | nsenter -t 1 host escape priority=CRITICAL\n"
                "2026-04-16T20:14:40Z  Node | chroot /host bash (full node access achieved)"
            ),
            "check_reputation": (
                "203.0.113.77: OVHcloud VPS, France. No prior access to K8s API.\n"
                "  K8s API auth: service account JWT token (likely exfiltrated from earlier pod)\n"
                "  default/default SA: should have minimal permissions — has 'pods:create' (violation)\n"
                "  exploit-runner pod: no legitimate purpose. Image alpine:latest (no business use).\n"
                "  Attacker TTP: classic K8s RBAC misconfiguration + privileged pod escape."
            ),
            "check_asset": (
                "k8s-node-03: EC2 m5.4xlarge in prod K8s cluster\n"
                "  Runs 23 production pods (payment API, customer DB connector, etc.)\n"
                "  Node access = full containerd socket, all pod filesystems, kubelet credentials\n"
                "  Post-escape: attacker has root on node with access to all running pod secrets\n"
                "  Adjacent nodes: 12 others, all accessible via compromised node credentials\n"
                "  Blast radius: full cluster compromise if node service account used to pivot"
            ),
            "analyze_payload": (
                "Post-escape commands (Falco process monitoring on node):\n"
                "  chroot /host bash (gained node root)\n"
                "  cat /host/etc/kubernetes/pki/ca.key (stole cluster CA private key)\n"
                "  crictl ps (listed all 23 running containers)\n"
                "  crictl exec -i payment-api env | grep -i secret (extracted env secrets)\n"
                "  curl http://169.254.169.254/ (node IMDS — accessing node IAM role)\n"
                "CRITICAL: Cluster CA key stolen = can forge certificates for any identity."
            ),
            "correlate_alerts": (
                "Earlier today: Log4Shell-style injection in legacy Java service → "
                "SA JWT token written to /tmp, exfiltrated via reverse shell.\n"
                "K8s hardening gaps:\n"
                "  - default SA should have zero permissions (PodSecurityAdmission bypass)\n"
                "  - Privileged pods not blocked (PodSecurityPolicy deprecated, OPA Gatekeeper not enforced)\n"
                "CRITICAL: Isolate k8s-node-03 NOW, rotate cluster CA, audit all SA tokens,\n"
                "enforce PSA restricted policy, redeploy compromised pods with new secrets."
            ),
        },
        "optimal_actions": [1, 2, 3, 5, 7, 8],
        "impact_if_missed": "Critical — cluster CA key stolen. Full Kubernetes cluster can be forged and controlled.",
    },

    # ── THREAT 6: Cryptomining via compromised Lambda (low/medium) ────────────
    {
        "id": "cloud-009",
        "category": "cloud",
        "difficulty": "medium",
        "is_true_threat": True,
        "severity": "medium",
        "mitre": {
            "tactic": "Impact",
            "technique": "T1496",
            "name": "Resource Hijacking",
        },
        "alert": {
            "rule": "Lambda Function Outbound Connection to Cryptomining Pool",
            "description": (
                "GuardDuty: CryptoCurrency:EC2/BitcoinTool.B!DNS — Lambda function "
                "image-processor made DNS request for xmr.pool.supportxmr.com (Monero mining pool)."
            ),
        },
        "source": {"ip": "44.192.20.100", "domain": "lambda.us-east-1.amazonaws.com", "geo": "AWS-US"},
        "target": {
            "host": "Lambda: image-processor (us-east-1)",
            "ip": "AWS Lambda",
            "user": "lambda-image-processor-role",
            "department": "Engineering",
            "role": "Serverless Function",
            "criticality": "medium",
        },
        "indicators": {
            "lambda_function": "image-processor",
            "dns_query": "xmr.pool.supportxmr.com",
            "guardduty_finding": "CryptoCurrency:Lambda/CryptoCurrency",
            "monthly_cost_spike": "$2,840 excess Lambda charges",
            "miner_process": "xmrig",
        },
        "raw_log": (
            "GuardDuty Finding: CryptoCurrency:Lambda/CryptoCurrency\n"
            "Function: image-processor | Runtime: python3.11 | Account: 123456789012\n"
            "DNS: xmr.pool.supportxmr.com:3333 (Monero mining pool)\n"
            "Invocations: 14,000 in 6h (normal: ~200/day)\n"
            "Duration: avg 900,000ms (15 min max, timeout exploitation)\n"
            "Cost: $2,840 billed in 6h window"
        ),
        "investigate": {
            "analyze_headers": (
                "Lambda function metadata:\n"
                "  Last deployment: 2026-04-14T09:12Z by deploy-user (legitimate)\n"
                "  Code hash (SHA256): deployed=abc123… current=MISMATCH (7de4f2…)\n"
                "  CRITICAL: Code hash does not match last deployment → code was modified\n"
                "  Layer: dependency-layer-v8 (unchanged)\n"
                "  Runtime memory: 3,008 MB (maxed out — mining uses all CPU)"
            ),
            "query_siem": (
                "2026-04-16T10:00:00Z–16:00:00Z  CloudWatch | 14,000 Lambda invocations\n"
                "2026-04-16T10:00:12Z  Lambda | DNS xmr.pool.supportxmr.com:3333\n"
                "2026-04-16T10:00:15Z  GuardDuty | CryptoCurrency:Lambda finding\n"
                "2026-04-16T11:00:00Z  CloudWatch | ConcurrentExecutions reached 1,000 (account limit)\n"
                "2026-04-16T14:00:00Z  Billing | Lambda cost alert: >$1,000 threshold triggered\n"
                "Normal baseline: 200 invocations/day, $0.04/day. Today: $2,840."
            ),
            "check_reputation": (
                "xmr.pool.supportxmr.com: Monero (XMR) mining pool. Globally known crypto pool.\n"
                "  VirusTotal: flagged by 22/88 engines as malicious/mining.\n"
                "  image-processor invocation source: EventBridge rule (legitimate trigger preserved)\n"
                "  BUT: function injected xmrig binary and spawned mining alongside normal work.\n"
                "  Deployment pipeline: GitHub Actions. Possible supply-chain or dependency confusion."
            ),
            "check_asset": (
                "Lambda image-processor:\n"
                "  Purpose: Resize and optimize user-uploaded images\n"
                "  Role: lambda-image-processor-role (S3 GetObject + PutObject on uploads bucket)\n"
                "  Data handled: user avatar images (no PII beyond file content)\n"
                "  Financial impact: $2,840 in 6h (projected $11,360/day if unchecked)\n"
                "  Code analysis: xmrig binary embedded in /tmp at runtime, spawned via subprocess"
            ),
            "analyze_payload": (
                "Injected code in image_handler.py (added 2 days ago via compromised deploy key):\n"
                "  import subprocess, base64\n"
                "  MINER = base64.b64decode('<200 bytes base64>') → writes to /tmp/proc\n"
                "  subprocess.Popen(['/tmp/proc', '-o', 'xmr.pool.supportxmr.com:3333',\n"
                "    '-u', '4BGJo...XMR_WALLET...', '--threads', '4'])\n"
                "  Mining runs concurrently with legitimate image resizing\n"
                "  XMR wallet: 4BGJo... (Monero — untraceable)"
            ),
            "correlate_alerts": (
                "2026-04-14T01:30Z  GitHub | deploy key 'lambda-deploy' used from unexpected IP\n"
                "2026-04-14T09:12Z  Lambda | UpdateFunctionCode (attacker deploy, passed code review gap)\n"
                "2026-04-14–16  Miner dormant (randomized activation delay)\n"
                "2026-04-16T10:00Z  Mining began\n"
                "Action: UpdateFunctionCode to last good version, rotate deploy keys, audit all "
                "Lambda functions for code hash mismatches, add xmrig signature to Lambda malware scan."
            ),
        },
        "optimal_actions": [1, 2, 3, 5, 7],
        "impact_if_missed": "Medium — $11K+/day AWS cost impact, no data breach but significant financial damage.",
    },
]
