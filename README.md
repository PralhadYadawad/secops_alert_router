---
title: SecOps Alert Router
emoji: "\U0001F6A8"
colorFrom: blue
colorTo: red
sdk: docker
app_port: 8000
pinned: false
---

# SecOps Alert Router V2

**Cybersecurity Incident Triage RL Environment | Meta PyTorch OpenEnv Hackathon**

A rich RL environment where AI agents investigate and respond to realistic security alerts using SIEM logs, threat intelligence, asset context, and MITRE ATT&CK-mapped scenarios. Agents must reason about investigation evidence to decide whether to contain, escalate, or resolve each alert.

## Problem

SOCs face 10,000+ alerts/day. Analysts suffer alert fatigue, miss critical threats, and respond slowly. Static SIEM playbooks can't adapt. RL agents can learn the optimal investigate-vs-contain tradeoff dynamically by reading actual investigation data and making proportional response decisions.

## What Makes V2 Different

- **40 MITRE ATT&CK scenario templates** across 7 attack categories with realistic investigation data
- **Investigation actions return actual text data** (SIEM logs, IOC reputation results, asset context, sandbox analysis, alert correlation) that agents must read and reason about
- **Information-theoretic reward shaping** with 6 components: info-gain, urgency decay, proportional response, business impact, evidence quality, redundancy penalty
- **11 parameterized actions** (6 investigate, 3 proportional containment, escalate, resolve) with procedure enforcement
- **6 tasks with genuine difficulty progression** from spam filtering to adversarial evasion detection

## Environment Design

### Observation Space

Each observation provides rich text context that requires genuine reasoning:

| Field | Type | Description |
|-------|------|-------------|
| `alert_id` | string | Unique alert identifier |
| `rule_triggered` | string | SIEM detection rule that fired |
| `severity` | string | medium / high / critical |
| `alert_description` | string | Detailed alert narrative |
| `mitre_tactic` | string | MITRE ATT&CK tactic (e.g., Initial Access) |
| `mitre_technique` | string | MITRE ATT&CK technique ID + name |
| `source_ip` | string | Source IP address |
| `source_domain` | string | Source domain (if known) |
| `target_host` | string | Affected host |
| `target_user` | string | Affected user account |
| `target_department` | string | Business department |
| `raw_log_snippet` | string | Raw SIEM log extract |
| `investigation_history` | list | Accumulated investigation results (text) |
| `actions_taken` | list | Actions already performed |
| `time_steps_elapsed` | int | Steps taken |
| `max_steps` | int | Episode timeout |

### Action Space (11 Discrete Actions)

| ID | Action | Type | Effect |
|----|--------|------|--------|
| 0 | `analyze_headers` | Investigate | Examine email/packet headers for anomalies |
| 1 | `query_siem` | Investigate | Search SIEM for related security events |
| 2 | `check_reputation` | Investigate | Lookup IOC reputation (IP, domain, hash) |
| 3 | `check_asset` | Investigate | Get target host/user business context |
| 4 | `analyze_payload` | Investigate | Sandbox/static analysis of suspicious files |
| 5 | `correlate_alerts` | Investigate | Find related alerts in the last 24 hours |
| 6 | `block_source` | Contain | Block source IP/domain at firewall |
| 7 | `isolate_host` | Contain | Quarantine affected host from network |
| 8 | `disable_account` | Contain | Disable compromised user account |
| 9 | `escalate` | Resolve | Escalate to senior analyst / incident response |
| 10 | `resolve_benign` | Resolve | Mark as false positive, close alert |

**Procedure enforcement**: Containment actions (6-8) require at least 2 prior investigation steps.

### Reward Function

Information-theoretic reward shaping with proportional response scoring:

| Outcome | Reward Range | Description |
|---------|-------------|-------------|
| Useful investigation | -0.85 to +0.5 | Based on info-value of chosen investigation |
| True Positive containment | +10 to +20 | Base + speed bonus + evidence bonus + proportionality |
| False Positive containment | -10 to -20 | Scaled by target asset criticality |
| Escalation (true threat) | +5 to +6 | Partial credit for correct instinct |
| Escalation (false alarm) | -3 | Wasted senior analyst time |
| True Negative resolution | +3 to +4.5 | Bonus for evidence quality |
| False Negative (missed) | -25 to -50 | Severity-scaled catastrophic penalty |
| Timeout (breach) | -25 to -50 | Failed to respond in time |
| Duplicate investigation | -2 | Redundancy penalty |
| Procedure violation | -5 | Containment without evidence |

### Scenario Categories

| Category | Scenarios | MITRE Tactics |
|----------|-----------|---------------|
| Phishing | 8 | Initial Access (T1566) |
| Malware | 7 | Execution, Impact (T1059, T1486) |
| Insider Threat | 6 | Exfiltration (T1048, T1078) |
| Lateral Movement | 5 | Lateral Movement (T1550, T1021) |
| Data Exfiltration | 5 | Exfiltration (T1048, T1567) |
| DDoS | 4 | Impact (T1498, T1499) |
| Defense Evasion | 5 | Defense Evasion (T1218, T1036) |

Each scenario includes pre-authored investigation data for all 6 investigation types, making it impossible to solve with simple heuristics — agents must actually read and reason about the evidence.

## Tasks

| Task | Difficulty | Episodes | Max Steps | Threat Ratio | Focus |
|------|-----------|----------|-----------|-------------|-------|
| `spam-filter` | Easy | 5 | 8 | 30% | Identify and dismiss obvious false positives |
| `phishing-triage` | Easy-Medium | 8 | 10 | 50% | Investigate phishing alerts with ambiguity |
| `insider-threat` | Medium | 8 | 10 | 50% | Distinguish legitimate behavior from insider threats |
| `lateral-movement` | Medium-Hard | 8 | 12 | 70% | Detect attackers moving across hosts |
| `apt-campaign` | Hard | 10 | 12 | 75% | Multi-stage attacks requiring cross-alert correlation |
| `adversarial-evasion` | Expert | 10 | 15 | 80% | LOLBins, fileless malware, encoded payloads |

Grading uses 4 dimensions: accuracy, speed, evidence quality, and decisive action rate with task-specific weights.

## Quick Start

```bash
pip install -r requirements.txt
python inference.py
```

### Run Tests

```bash
python tests/test_environment.py
```

### Start Server

```bash
cd secops_env
python -m secops_env.server.app
# Dashboard at http://localhost:8000
```

### Docker

```bash
docker build -t secops-env -f secops_env/server/Dockerfile .
docker run -p 8000:8000 secops-env
```

## Usage

```python
from secops_env.models import SecOpsAction
from secops_env.server.secops_environment import SecOpsEnvironment

env = SecOpsEnvironment(task_name="phishing-triage", seed=42)
obs = env.reset()

# Investigate: query SIEM logs
obs = env.step(SecOpsAction(action_id=1))
print(f"SIEM data: {obs.investigation_history[-1]['result']}")

# Investigate: check IOC reputation
obs = env.step(SecOpsAction(action_id=2))

# Contain: block source based on evidence
obs = env.step(SecOpsAction(action_id=6))
print(f"Outcome: {obs.metadata['status']}, Reward: {obs.reward}")
```

## Project Structure

```
secops-alert-router/
├── inference.py                     # Entry point (LLM + heuristic fallback)
├── openenv.yaml                     # OpenEnv manifest (6 tasks)
├── requirements.txt
├── tests/
│   └── test_environment.py          # 10 programmatic tests
└── secops_env/
    ├── models.py                    # Pydantic models (Action, Observation, State)
    └── server/
        ├── app.py                   # FastAPI server
        ├── secops_environment.py    # Core environment (step/reset/state)
        ├── alert_generator.py       # Scenario-based alert factory
        ├── investigation_engine.py  # Returns SIEM/threat-intel/asset data
        ├── reward_engine.py         # Information-theoretic reward computation
        ├── tasks.py                 # 6 tasks + 4-dimension graders
        ├── rubrics.py               # Trajectory scoring rubric
        ├── scenarios/               # 40 MITRE ATT&CK scenario templates
        │   ├── phishing.py          # 8 scenarios
        │   ├── malware.py           # 7 scenarios
        │   ├── insider.py           # 6 scenarios
        │   ├── lateral.py           # 5 scenarios
        │   ├── exfil.py             # 5 scenarios
        │   ├── ddos.py              # 4 scenarios
        │   └── evasion.py           # 5 scenarios
        ├── static/
        │   └── index.html           # SOC dashboard UI
        └── Dockerfile
```

## Baseline Scores (Heuristic Policy)

| Task | Final Score | Description |
|------|------------|-------------|
| spam-filter | 0.742 | Correct on most easy alerts |
| phishing-triage | 0.524 | Struggles with ambiguous phishing |
| insider-threat | 0.675 | Mixes decisive and uncertain decisions |
| lateral-movement | 0.696 | Good threat detection, some FPs |
| apt-campaign | 0.867 | Strong containment on high-threat ratio |
| adversarial-evasion | 0.900 | Severity prior compensates for evasion |

These scores demonstrate genuine difficulty progression. An LLM agent that reads and reasons about investigation text should significantly outperform the keyword-based heuristic, especially on ambiguous phishing and insider threat scenarios.

## OpenEnv Compliance

Built on the OpenEnv framework with standard `step()` / `reset()` / `state()` API. Passes `openenv validate` (local + runtime).

## License

BSD 3-Clause License
