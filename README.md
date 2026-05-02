---
title: SecOps Alert Router
emoji: "\U0001F6A8"
colorFrom: blue
colorTo: red
sdk: docker
app_port: 8000
pinned: false
---
<div align="center">

# SecOps Alert Router

**The open-source RL environment for training AI agents to triage cybersecurity alerts like expert SOC analysts.**

[![CI](https://github.com/PralhadYadawad/secops_alert_router/actions/workflows/ci.yml/badge.svg)](https://github.com/PralhadYadawad/secops_alert_router/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: BSD-3](https://img.shields.io/badge/license-BSD--3-green.svg)](LICENSE)
[![OpenEnv Compatible](https://img.shields.io/badge/OpenEnv-compatible-purple.svg)](https://github.com/meta-pytorch/OpenEnv)
[![HF Space](https://img.shields.io/badge/HuggingFace-Live_Demo-yellow.svg)](https://huggingface.co/spaces/pralhadyadawad/secops-alert-router)

[**Live Demo**](https://huggingface.co/spaces/pralhadyadawad/secops-alert-router) | [Quick Start](#quick-start) | [API Reference](#api-reference) | [Contributing](#contributing)

</div>

---

## Why SecOps Alert Router?

Security Operations Centers process **10,000+ alerts per day**. Analysts suffer from alert fatigue. Critical threats get buried. Mean time to contain (MTTC) stretches from minutes to hours. The industry loses **$3.5B annually** to slow incident response.

Static SIEM playbooks can't adapt. Rule-based automation catches the obvious threats but fails on novel attacks, insider threats, and adversarial evasion. The triage decision — investigate more, contain now, or dismiss as benign — is fundamentally a **sequential decision-making problem under uncertainty**.

SecOps Alert Router is a high-fidelity RL environment that teaches AI agents this exact skill. Agents receive realistic security alerts mapped to the [MITRE ATT&CK](https://attack.mitre.org/) framework, investigate using simulated SIEM logs and threat intelligence, and must decide the right response with incomplete information — just like a real analyst.

### What makes this different

Most security-focused AI benchmarks test classification: "is this malicious?" SecOps Alert Router tests **the full triage workflow**:

- **Read and reason** over actual SIEM logs, IOC reputation data, sandbox analysis reports, and asset context
- **Decide investigation strategy** — which of 6 investigation types yields the most information for this specific scenario?
- **Act proportionally** — blocking a source IP is appropriate for a medium-severity phishing attempt; isolating a host is appropriate for an active APT campaign
- **Balance speed vs. accuracy** — critical threats demand fast containment, but false positives disrupt business operations

A keyword-matching heuristic scores **0.52 on phishing triage** and **0.67 on insider threats**. An LLM agent that actually reads the investigation data should significantly outperform this baseline. The environment is designed to reward genuine reasoning, not pattern matching. A 20% seeded noise injection layer (partial results, conflicting signals, red herrings) actively penalizes keyword shortcuts.

---

## At a Glance

| | |
|---|---|
| **Scenarios** | 61 hand-authored across 10 MITRE ATT&CK categories → 183-alert pool via procedural augmentation |
| **Tasks** | 12 tasks from Easy (spam-filter) to Expert (adversarial-evasion, auto-scaling-triage) |
| **Action space** | 11 discrete actions: 6 investigation + 3 containment + escalate + resolve |
| **Reward** | Information-theoretic, 6-component; GDPR/HIPAA/PCI-DSS compliance multipliers up to 3x |
| **Compliance** | 22+ scenarios tagged with GDPR, HIPAA, PCI-DSS, SOX — false negatives carry 2.5–3x penalties |
| **Noise** | 20% seeded investigation noise (partial/conflicting/red-herring) — reproducible, PYTHONHASHSEED-safe |
| **Dashboard** | Real-time SOC dark-mode UI with WebSocket streaming, playbook export, queue mode |
| **Framework** | [OpenEnv](https://github.com/meta-pytorch/OpenEnv) compatible (step/reset/state API) |

---

## Architecture

```
                    +-------------------+
                    |    LLM / Agent    |       "Query SIEM for related events"
                    |   (inference.py)  |----+
                    +-------------------+    |
                             |               |  POST /step {action_id: 1}
                             |               |
                    +--------v--------+      |
                    |   FastAPI App    |<-----+
                    |    (app.py)      |
                    +--------+--------+
                             |
                    +--------v--------+
                    |   Environment    |
                    |  step() reset()  |
                    +--------+--------+
                             |
           +---------+-------+-------+---------+
           |         |               |         |
     +-----v---+ +---v-----+ +------v--+ +----v----+
     |Scenario  | |Invest.  | | Reward  | | Grader  |
     | Engine   | | Engine  | | Engine  | |(tasks.py)|
     |61 curated| |SIEM/TI/ | |6-component| |4-dim   |
     |scenarios | |asset data| |shaping  | |scoring  |
     +---------+ +---------+ +---------+ +---------+
```

**Scenario Engine** generates alerts from 61 curated MITRE ATT&CK scenarios across 10 categories, procedurally expanded to a 183-alert pool to prevent memorization. **Investigation Engine** returns realistic text data (SIEM logs, threat intel, asset context) that agents must read. **Reward Engine** computes information-theoretic rewards based on investigation quality, response proportionality, and business impact (including compliance multipliers for GDPR/HIPAA/PCI-DSS). **Graders** score trajectories on 4 dimensions: accuracy, speed, evidence quality, and decisiveness.

---

## Scenario Quality

Every scenario contains hand-authored investigation data across 6 investigation types. Here's an example of what agents actually see when they investigate:

<details>
<summary><b>Example: AiTM Credential Theft (Phishing, Hard)</b></summary>

**Alert:** `Password Reset Link From Unverified Source` — Okta password-reset mimic from `okta-servicedesk.com`

**SIEM Log Query (action 1):**
```
2026-03-25 11:08:55 | EMAIL_RECV | from=noreply@okta-servicedesk.com verdict=DELIVERED
           11:12:03 | URL_CLICK  | user=kwilliams url=okta-servicedesk.com/reset action=ALLOW
           11:12:08 | HTTP_POST  | dst=okta-servicedesk.com uri=/auth/callback
```

**IOC Reputation (action 2):**
```
IP 192.0.2.201: SUSPICIOUS Hetzner VPS, first seen 2026-03-24
okta-servicedesk.com: Registered 2026-03-22 (3 days ago), Porkbun privacy,
  LE cert, VirusTotal 3/82 phishing. NOT affiliated with Okta Inc.
```

**Header Analysis (action 0):**
```
SPF: PASS (192.0.2.201 permitted - attacker controls DNS)
DKIM: PASS (okta-servicedesk.com - NOT okta.com)
DMARC: N/A (from okta-servicedesk.com, not okta.com)
X-Mailer: PHPMailer 6.8 (real Okta uses Sendgrid)
NOTE: Legitimate Okta sends from noreply@okta.com
```

**Alert Correlation (action 5):**
```
No other users targeted (single-target spearphish vs HR Director).
Okta admin: No password reset initiated by IT.
CRITICAL: 12 min after POST, Okta sign-in from 192.0.2.205 (same /24)
  using kwilliams creds. MFA bypassed via stolen session cookie.
IMMEDIATE: Revoke all kwilliams sessions.
```

The agent must synthesize evidence across all sources: the domain is 3 days old, the X-Mailer is wrong, the user already submitted credentials, and the attacker has already used the stolen session. **Correct response**: immediately disable the account (action 8) and isolate the host (action 7).

</details>

<details>
<summary><b>Example: Slow-and-Low APT (Defense Evasion, Expert)</b></summary>

**Alert:** `EDR-EVASION-SLOWLOW-001` — Low-frequency anomalous DNS queries and scheduled-task persistence on executive assistant workstation over 12-day window.

**SIEM Log Query:**
```
12-day retrospective: 2026-04-02T08:15Z rthompson opened attachment from
  contact@executive-briefing.com (spear-phish), regsvr32.exe first seen.
Apr 02-14: consistent 2-3 DNS TXT queries/hour during business hours only
  (09:00-17:30), zero weekends — evaded 24h volume threshold of 100 queries/domain.
Apr 08 14:22Z M&A-Project-Falcon accessed.
Apr 10 10:15Z Board meeting notes accessed.
```

**IOC Reputation:**
```
status-check.cloud: registered 30 days ago via Njalla (privacy registrar
  favored by APTs). Hosted on 193.42.60.18 (Alexhost SRL, Moldova).
Not in public threat feeds — purpose-built for this campaign.
DNS TXT responses contain base64 data decoding to encrypted C2 commands.
```

**Alert Correlation:**
```
No prior alerts — first detection after 12 days.
EDR anomaly engine flagged DNS pattern after accumulating baseline data.
executive-briefing.com also used against 2 other Fortune 500 companies
  (FS-ISAC TLP:RED).
TTPs match APT29 (Cozy Bear): slow-and-low, business-hours beaconing,
  steganographic exfil, M&A targeting.
```

Impact if missed: APT with 12-day foothold has exfiltrated M&A intelligence worth billions. TTPs match a known nation-state actor. **Correct response**: isolate the host immediately and escalate to incident response.

</details>

---

## Quick Start

### Install

```bash
git clone https://github.com/PralhadYadawad/secops_alert_router.git
cd secops_alert_router
pip install -r requirements.txt
```

### Run the agent

```bash
python inference.py
```

This runs all 12 tasks with a heuristic baseline (or an LLM if `HF_TOKEN` is set). Output follows the OpenEnv `[START]/[STEP]/[END]` format.

### Start the SOC dashboard

```bash
python -m secops_env.server.app
# Open http://localhost:8000
```

### Run tests

```bash
pytest tests/ -v
# 81 tests covering scenario data, reward engine, grader bounds, rubric normalization, security
```

### Docker

```bash
docker build -t secops-env -f secops_env/server/Dockerfile .
docker run -p 8000:8000 secops-env
```

---

## API Reference

### Python API

```python
from secops_env.models import SecOpsAction
from secops_env.server.secops_environment import SecOpsEnvironment

# Create environment with a specific task
env = SecOpsEnvironment(task_name="phishing-triage", seed=42)
obs = env.reset()

# obs contains rich context: alert details, MITRE mapping, source/target info
print(obs.rule_triggered)       # "Suspicious OAuth Token Request from External IP"
print(obs.mitre_tactic)         # "Initial Access"
print(obs.mitre_technique)      # "T1566.002 — Phishing: Spearphishing Link"
print(obs.severity)             # "high"

# Investigate: query SIEM logs
obs = env.step(SecOpsAction(action_id=1))
print(obs.investigation_history[-1]["result"])
# -> Actual SIEM log data the agent must read and reason about

# Investigate: check IOC reputation
obs = env.step(SecOpsAction(action_id=2))

# Now the agent has enough evidence. Contain the threat:
obs = env.step(SecOpsAction(action_id=6))  # block_source
print(obs.metadata["status"])              # "true_positive"
print(obs.reward)                          # +15.0 (with speed + evidence bonus)
print(obs.done)                            # True
```

### REST API

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/reset` | Start a new episode, returns initial observation |
| `POST` | `/step` | Execute an action, returns observation + reward + done |
| `GET` | `/state` | Get current environment state |
| `GET` | `/playbook` | Export SOAR playbook from last episode (JSON or Markdown) |
| `WS` | `/ws/stream` | WebSocket stream of live observations |
| `GET` | `/` | SOC dashboard UI |

```bash
curl -X POST http://localhost:8000/reset \
  -H "Content-Type: application/json" \
  -d '{"task_name": "insider-threat"}'

curl -X POST http://localhost:8000/step \
  -H "Content-Type: application/json" \
  -d '{"action": {"action_id": 1}}'
```

### Environment Configuration

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `task_name` | string | `"phishing-triage"` | One of the 12 task names |
| `max_steps` | int | Task-dependent | Episode timeout (overrides task default) |
| `seed` | int | None | Random seed for reproducibility |

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `API_BASE_URL` | LLM API endpoint | `https://router.huggingface.co/v1` |
| `MODEL_NAME` | LLM model identifier | `meta-llama/Meta-Llama-3-70B-Instruct` |
| `HF_TOKEN` | HuggingFace API token | None (falls back to heuristic) |
| `SECOPS_NOISE_LEVEL` | Investigation noise rate (0.0–1.0) | `0.20` |

---

## Environment Design

### Observation Space

Each observation provides 16+ fields of rich text context:

| Field | Type | Description |
|-------|------|-------------|
| `alert_id` | string | Unique alert identifier |
| `rule_triggered` | string | SIEM detection rule that fired |
| `severity` | string | `medium` / `high` / `critical` |
| `alert_description` | string | Detailed alert narrative |
| `mitre_tactic` | string | ATT&CK tactic (e.g., Initial Access, Lateral Movement) |
| `mitre_technique` | string | ATT&CK technique ID + name (e.g., T1566.002) |
| `source_ip` | string | Source IP address |
| `source_domain` | string | Source domain (if applicable) |
| `target_host` | string | Affected hostname |
| `target_user` | string | Affected user account |
| `target_department` | string | Business department (Finance, Engineering, etc.) |
| `raw_log_snippet` | string | Raw SIEM log extract |
| `investigation_history` | list[dict] | Accumulated investigation results (text data) |
| `actions_taken` | list[string] | Actions already performed this episode |
| `time_steps_elapsed` | int | Current step number |
| `max_steps` | int | Episode step limit |

### Action Space

**11 discrete actions** organized into 3 categories:

| ID | Action | Category | Description |
|----|--------|----------|-------------|
| 0 | `analyze_headers` | Investigate | Examine email/packet headers for anomalies |
| 1 | `query_siem` | Investigate | Search SIEM for related security events |
| 2 | `check_reputation` | Investigate | Lookup IOC reputation (IP, domain, hash) |
| 3 | `check_asset` | Investigate | Get target host/user business context |
| 4 | `analyze_payload` | Investigate | Sandbox/static analysis of suspicious files |
| 5 | `correlate_alerts` | Investigate | Find related alerts in the last 24 hours |
| 6 | `block_source` | Contain | Block source IP/domain at perimeter firewall |
| 7 | `isolate_host` | Contain | Network-quarantine the affected host |
| 8 | `disable_account` | Contain | Disable the compromised user account |
| 9 | `escalate` | Resolve | Escalate to senior analyst / incident response team |
| 10 | `resolve_benign` | Resolve | Mark as false positive and close the alert |

**Procedure enforcement:** Containment actions (6–8) require at least 2 prior investigation steps. Attempting containment without evidence results in a -5 procedure violation penalty.

**Proportional response:** The reward engine checks whether the containment action matches the threat severity. Blocking a source IP is proportional for medium/high threats; isolating a host is proportional for high/critical threats.

### Reward Function

Six-component information-theoretic reward shaping:

| Component | Range | Logic |
|-----------|-------|-------|
| **Information gain** | -0.85 to +0.5 | Higher reward for investigations that yield critical evidence for the scenario |
| **True Positive** | +10 to +20 | Base +10, plus speed bonus (contained in ≤4 steps), evidence bonus (depth), proportionality bonus |
| **False Positive** | -10 to -20 | Penalty scaled by target asset criticality (low=0.6x, critical=2.0x) |
| **Escalation** | +5 to -3 | Partial credit for true threats (+5), penalty for false alarms (-3) |
| **True Negative** | +3 to +4.5 | Bonus for investigation depth before resolution |
| **False Negative** | -25 to -100 | Severity-scaled penalty (medium=1x, critical=2x) amplified by compliance multipliers (GDPR 3x, HIPAA 2.5x, PCI-DSS 2x), clamped at -100 |

Additional penalties: duplicate investigation (-2), procedure violation (-5), timeout breach (-25 to -100, compliance-amplified).

Rubric normalizes cumulative episode reward to (0.01, 0.99) via `(cumulative + 100) / 120` before the OpenEnv evaluator scores it.

### Scenario Library

**61 curated scenarios** across 10 MITRE ATT&CK categories (expanded to 183 via procedural augmentation):

| Category | Count | MITRE Tactics | Difficulty Range |
|----------|-------|---------------|-----------------|
| Phishing | 8 | Initial Access (T1566) | Easy – Hard |
| Malware | 7 | Execution (T1059), Impact (T1486) | Easy – Hard |
| Insider Threat | 6 | Exfiltration (T1048, T1078) | Medium – Hard |
| Lateral Movement | 5 | Lateral Movement (T1550, T1021) | Medium – Hard |
| Data Exfiltration | 5 | Exfiltration (T1048, T1567) | Medium – Hard |
| DDoS | 4 | Impact (T1498, T1499) | Easy – Medium |
| Defense Evasion | 5 | Defense Evasion (T1218, T1036, T1027) | Hard – Expert |
| Cloud Native | 9 | Discovery, Privilege Escalation, Persistence | Medium – Expert |
| Healthcare / HIPAA | 6 | Impact (T1486), Exfiltration (T1048) | Medium – Expert |
| Credential Access | 6 | Credential Access (T1558, T1003, T1550) | Easy – Expert |

Each scenario includes **pre-authored investigation data for all 6 investigation types** — SIEM logs, IOC reputation lookups, asset context, sandbox analysis, header examination, and alert correlation. Threat scenarios include realistic indicators of compromise; benign scenarios include plausible false-positive context.

---

## Tasks

12 tasks with genuine difficulty progression:

| Task | Difficulty | Episodes | Max Steps | Threat Ratio | Focus |
|------|-----------|----------|-----------|-------------|-------|
| `spam-filter` | Easy | 5 | 8 | 30% | Dismiss obvious false positives quickly |
| `phishing-triage` | Easy–Medium | 8 | 10 | 50% | Ambiguous phishing — requires reading headers and SIEM data |
| `insider-threat` | Medium | 8 | 10 | 50% | Legitimate employee activity vs. data theft |
| `lateral-movement` | Medium–Hard | 8 | 12 | 70% | Detect attackers pivoting across network hosts |
| `apt-campaign` | Hard | 10 | 12 | 75% | Multi-stage attacks needing cross-alert correlation |
| `adversarial-evasion` | Expert | 10 | 15 | 80% | LOLBins, fileless malware, encoded payloads, slow-and-low APTs |
| `compliance-triage` | Medium–Hard | 8 | 12 | 65% | GDPR/HIPAA/PCI-DSS regulated data — compliance breaches carry 3x penalty |
| `cloud-native` | Medium–Hard | 8 | 12 | 65% | AWS/Azure/Kubernetes: IAM escalation, CloudTrail tampering, SSRF, container escape |
| `hipaa-triage` | Medium–Expert | 8 | 12 | 65% | Healthcare EHR/IoMT alerts — HIPAA false negatives carry 2.5x penalty |
| `credential-access` | Easy–Expert | 8 | 12 | 65% | AD attacks: Kerberoasting, AS-REP, DCSync, Pass-the-Hash |
| `queue-triage` | Medium | 3 | 40 total | 60% | Triage a 5-alert backlog — prioritize critical threats across concurrent incidents |
| `auto-scaling-triage` | Auto | 10 | 12 | 60% | Difficulty ramps from Easy to Expert based on win streak |

### Grading

Each task grades agent trajectories on **4 weighted dimensions**:

- **Accuracy** — correct decisions (contain threats, resolve benign)
- **Speed** — steps used relative to maximum
- **Evidence quality** — investigation depth before decisive actions
- **Decisive action rate** — direct containment/resolution vs. escalation (escalation receives partial credit but is suboptimal)

Task-specific weights emphasize what matters most: speed for lateral movement, evidence depth for insider threats, accuracy for phishing.

---

## Baseline Results

Heuristic baseline (3-tier weighted keyword matching + severity priors, no LLM):

| Task | Score | Key Observation |
|------|-------|-----------------|
| `spam-filter` | 0.742 | Correctly handles most obvious alerts |
| `phishing-triage` | 0.524 | Struggles with ambiguous phishing — can't reason about header anomalies |
| `insider-threat` | 0.675 | False positives from keyword overlap between normal and malicious activity |
| `lateral-movement` | 0.696 | Severity prior helps, but misidentifies some benign admin activity |
| `apt-campaign` | 0.867 | High threat ratio + aggressive containment yields good results |
| `adversarial-evasion` | 0.900 | Severity prior compensates for evasion, but real reasoning would do better |

**The gap between heuristic and LLM performance is the point.** Phishing-triage at 0.524 means a keyword matcher gets it wrong nearly half the time on ambiguous alerts. An LLM that reads `X-Mailer: PHPMailer 6.8 (real Okta uses Sendgrid)` and `domain registered 3 days ago` should score significantly higher. The environment is designed to reward genuine natural language reasoning about security evidence — not keyword matching.

---

## Project Structure

```
secops-alert-router/
├── inference.py                        # Entry point (LLM agent + heuristic fallback)
├── openenv.yaml                        # OpenEnv manifest (12 tasks, metadata)
├── requirements.txt                    # Python dependencies
├── tests/
│   └── test_environment.py             # 81 tests (scenarios, rewards, grading, security, rubric)
└── secops_env/
    ├── models.py                       # Pydantic: SecOpsAction, SecOpsObservation, SecOpsState
    └── server/
        ├── app.py                      # FastAPI server (OpenEnv routes + WS + dashboard)
        ├── secops_environment.py       # Core RL environment (step/reset/state lifecycle)
        ├── alert_generator.py          # Scenario-based alert factory with difficulty filters
        ├── investigation_engine.py     # Returns SIEM/threat-intel/asset data per action
        ├── investigation_noise.py      # 20% seeded noise injection (partial/conflicting/red-herring)
        ├── reward_engine.py            # 6-component information-theoretic rewards
        ├── tasks.py                    # 12 task definitions + 4-dimension graders
        ├── rubrics.py                  # Trajectory scoring rubric for OpenEnv evaluator
        ├── playbook_generator.py       # SOAR playbook generation from episode trajectory
        ├── queue_environment.py        # Multi-alert queue triage (5 concurrent alerts)
        ├── security.py                 # API key auth, rate limiting, CORS, WS connection limits
        ├── logging_config.py           # JSON structured logging
        ├── scenarios/                  # 61 curated MITRE ATT&CK scenarios (183 augmented)
        │   ├── __init__.py             # Scenario index + pick_scenario()
        │   ├── augmentor.py            # Procedural augmentation (3× pool via IP/host/user variation)
        │   ├── phishing.py             # 8 scenarios (spearphishing, BEC, AiTM, etc.)
        │   ├── malware.py              # 7 scenarios (Emotet, LockBit, CobaltStrike, etc.)
        │   ├── insider.py              # 6 scenarios (data theft, policy violations)
        │   ├── lateral.py              # 5 scenarios (pass-the-hash, RDP, WMI)
        │   ├── exfil.py                # 5 scenarios (DNS tunneling, cloud upload)
        │   ├── ddos.py                 # 4 scenarios (volumetric, application-layer)
        │   ├── evasion.py              # 5 scenarios (LOLBins, fileless, APT29)
        │   ├── cloud.py                # 9 scenarios (AWS IAM, CloudTrail, K8s, SSRF)
        │   ├── healthcare.py           # 6 scenarios (EHR, ransomware, PHI, IoMT — HIPAA)
        │   └── credential_access.py    # 6 scenarios (Kerberoasting, DCSync, Pass-the-Hash)
        ├── static/
        │   └── index.html              # SOC dark-mode dashboard (real-time triage UI)
        └── Dockerfile                  # Container deployment for HF Spaces
```

---

## Contributing

Contributions are welcome. The most impactful areas:

### Adding Scenarios

The fastest way to improve the environment. Each scenario is a Python dict in `secops_env/server/scenarios/`:

```python
{
    "id": "phish-009",
    "category": "phishing",
    "difficulty": "medium",
    "is_true_threat": True,
    "severity": "high",
    "mitre": {
        "tactic": "Initial Access",
        "technique": "T1566.001",
        "name": "Phishing: Spearphishing Attachment"
    },
    "alert": {
        "rule": "Your SIEM Rule Name",
        "description": "What the alert says"
    },
    "source": {"ip": "...", "domain": "...", "geo": "..."},
    "target": {"host": "...", "user": "...", "department": "...", "criticality": "high"},
    "investigate": {
        "analyze_headers": "Realistic header analysis output...",
        "query_siem": "Realistic SIEM log entries...",
        "check_reputation": "Realistic IOC reputation data...",
        "check_asset": "Asset context and business impact...",
        "analyze_payload": "Sandbox/static analysis results...",
        "correlate_alerts": "Related alert correlation data..."
    },
    "optimal_actions": [1, 2, 4],
}
```

Guidelines:
- Use realistic IP addresses, hostnames, timestamps, and log formats
- Benign scenarios should have plausible false-positive reasons (marketing campaigns, scheduled maintenance)
- Threat scenarios should have clear indicators spread across multiple investigation types
- Reference real MITRE ATT&CK technique IDs

### Other Contributions

- **New tasks** — define in `tasks.py` with grading weights
- **Reward tuning** — adjust multipliers in `reward_engine.py`
- **LLM prompt engineering** — improve `build_llm_prompt()` in `inference.py`
- **Dashboard features** — investigation data visualization, threat timeline

### Development Setup

```bash
git clone https://github.com/PralhadYadawad/secops_alert_router.git
cd secops_alert_router
pip install -r requirements.txt
pytest tests/ -v          # 81 tests
python inference.py       # heuristic baseline, no API key needed
```

---

## Roadmap

### Shipped in V3
- [x] WebSocket streaming for real-time dashboard updates
- [x] Multi-alert queue mode with switch penalty and priority bonuses
- [x] Dynamic difficulty auto-scaling based on win streak
- [x] SOAR playbook generation from episode trajectory (`/playbook` endpoint)
- [x] Compliance-aware rewards (GDPR 3x, HIPAA 2.5x, PCI-DSS 2x false-negative multipliers)
- [x] Investigation noise injection (20% partial/conflicting/red-herring, seed-deterministic)
- [x] Security hardening (API key auth, rate limiting, CORS, WS connection limits)
- [x] CI/CD pipeline (GitHub Actions: pytest + coverage + pip-audit on every push)

### Planned
- [ ] Integration with real SIEM APIs (Splunk, Elastic, Sentinel) for scenario generation
- [ ] Multi-agent coordination (L1/L2/L3 analyst hierarchy)
- [ ] Continuous learning from analyst feedback
- [ ] Attack simulation integration (Atomic Red Team, Caldera)
- [ ] SOC team training mode (human analyst vs. AI benchmark)

---

## Built With

- [OpenEnv](https://github.com/meta-pytorch/OpenEnv) — Meta's RL environment framework
- [FastAPI](https://fastapi.tiangolo.com/) — API server
- [Pydantic](https://docs.pydantic.dev/) — Data validation
- [MITRE ATT&CK](https://attack.mitre.org/) — Threat taxonomy

---

## License

BSD 3-Clause License. See [LICENSE](LICENSE) for details.

---

<div align="center">

**SecOps Alert Router** is built by [Team Phoenix](https://github.com/PralhadYadawad) for the Meta PyTorch OpenEnv Hackathon.

If this project is useful to you, consider giving it a star ⭐

</div>
