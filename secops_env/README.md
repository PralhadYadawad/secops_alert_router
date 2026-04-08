# SecOps Alert Router — Cybersecurity Incident Triage Environment

**RL environment for the Meta PyTorch OpenEnv Hackathon**

An RL environment where AI agents learn to triage security alerts in a simulated Security Operations Center (SOC), balancing investigation speed against accuracy.

## Problem Statement & Motivation

Security Operations Centers face unprecedented alert volumes (10,000+ alerts/day), leading to:
- **Alert fatigue**: 70% of SOC analysts report burnout from false positives
- **Missed threats**: Critical attacks slip through when analysts are overwhelmed
- **Slow response**: Mean Time to Containment (MTTC) suffers as teams are stretched thin

**Why RL?** Traditional rule-based SIEM systems use static playbooks. RL agents learn the optimal investigate-vs-contain tradeoff dynamically, adapting to alert severity and accumulated evidence. This maps directly to real-world SOAR (Security Orchestration, Automation and Response) playbooks used in production SOCs.

## Environment Design

### Observation Space

| Field | Type | Description |
|-------|------|-------------|
| `alert_type` | int (0-4) | Phishing, PrivilegeAbuse, Malware, DDoS, DataExfiltration |
| `severity` | int (0-2) | Medium, High, Critical |
| `confidence_score` | float (0-1) | Evidence confidence |
| `time_steps_elapsed` | int | Steps taken so far |
| `evidence_flags` | list[bool] len=4 | Which evidence types collected |

### Action Space (Discrete 0-7)

| ID | Action | Type | Effect |
|----|--------|------|--------|
| 0 | `analyze_headers` | Safe | +0.15 confidence |
| 1 | `query_logs` | Safe | +0.20 confidence |
| 2 | `verify_identity` | Safe | +0.15 confidence |
| 3 | `scope_environment` | Safe | +0.10 confidence |
| 4 | `block_ip` | Risky | Terminal containment |
| 5 | `isolate_host` | Risky | Terminal containment |
| 6 | `disable_account` | Risky | Terminal containment |
| 7 | `acknowledge_allow` | Resolve | Mark as benign |

### Reward Function

| Condition | Reward | Rationale |
|-----------|--------|-----------|
| True Positive (contain real threat) | +10 | Correct containment |
| TP + fast critical (≤3 steps) | +12 | Speed bonus |
| False Positive (contain benign) | -10 | Business disruption |
| True Negative (resolve benign) | +1 | Correct resolution |
| False Negative (miss real threat) | -50 | Security breach |
| Investigation step | -1 | Time pressure (MTTC) |
| Contain without evidence | -5 | Procedure violation |
| Duplicate action | -0.5 | Redundant work |
| Timeout breach (threat) | -50 | Missed containment |
| Timeout benign | +1 | No harm done |

## Tasks

Three tasks with increasing difficulty:

### Task 1: `benign-filter` (Easy)

- **Episodes**: 5
- **Profile**: Medium severity, 80% benign alerts
- **Tests**: Can the agent correctly identify and resolve benign alerts without unnecessary containment?
- **Grader**: 70% accuracy + 30% speed

### Task 2: `mixed-triage` (Medium)

- **Episodes**: 10
- **Profile**: Mixed severity, 50/50 threats vs benign
- **Tests**: Balancing investigation speed vs accuracy across diverse alert types
- **Grader**: 50% accuracy + 30% speed + 20% false positive rate penalty

### Task 3: `critical-escalation` (Hard)

- **Episodes**: 10
- **Profile**: Mostly critical severity, 90% true threats
- **Tests**: Rapid containment under time pressure with minimal false negatives
- **Grader**: 40% accuracy + 30% speed + 30% false negative rate penalty

## Setup & Usage

```bash
pip install -r requirements.txt
python inference.py
```

### Docker

```bash
docker build -t secops-env -f secops_env/server/Dockerfile .
docker run -p 8000:8000 secops-env
```

### Programmatic Usage

```python
from secops_env.models import SecOpsAction
from secops_env.server.secops_environment import SecOpsEnvironment

env = SecOpsEnvironment(task_name="mixed-triage", seed=42)
obs = env.reset()

# Investigate
obs = env.step(SecOpsAction(action_id=1))  # query_logs
print(f"Confidence: {obs.confidence_score}")

# Contain
obs = env.step(SecOpsAction(action_id=5))  # isolate_host
print(f"Reward: {obs.reward}, Done: {obs.done}")

env.close()
```

## Baseline Scores

| Task | Score | Avg Steps | Strategy |
|------|-------|-----------|----------|
| benign-filter | ~0.75 | ~2.0 | Investigate once, resolve if low confidence |
| mixed-triage | ~0.65 | ~2.5 | Investigate 1-2x, decide by severity+confidence |
| critical-escalation | ~0.60 | ~2.0 | Investigate once, contain fast |

*(Scores are from heuristic baseline policy)*

## Architecture

```
secops_env/
├── __init__.py           # Package exports
├── models.py             # Pydantic models (Action, Observation, State)
├── client.py             # WebSocket client for remote access
├── openenv.yaml          # OpenEnv manifest
├── pyproject.toml        # Package config
└── server/
    ├── __init__.py
    ├── app.py            # FastAPI app via create_app()
    ├── secops_environment.py  # Core environment logic
    ├── alert_generator.py     # Synthetic alert factory
    ├── tasks.py          # 3 task configs + graders
    ├── rubrics.py        # Trajectory rubric
    └── Dockerfile        # Container deployment
```

## OpenEnv Compatibility

Built on the OpenEnv framework with standard `step()` / `reset()` / `state()` API. Passes `openenv validate`.

## License

BSD 3-Clause License
