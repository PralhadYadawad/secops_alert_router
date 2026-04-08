"""Programmatic test cases for the SecOps Alert Triage environment.

5 tests from the research spec:
1. Critical threat escalation within 3 steps
2. Benign resolution without containment
3. Evidence-before-action enforcement
4. No timeout on critical (agent acts in time)
5. FPR < 20% over many episodes
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from secops_env.models import SecOpsAction
from secops_env.server.secops_environment import SecOpsEnvironment
from secops_env.server.tasks import TASKS, TASK_NAMES, CORRECT_OUTCOMES, grade_task


# ---------- Test 1: Critical threat contained within 3 steps ----------
def test_critical_threat_fast_containment():
    """Agent must contain critical true-threat in <=3 steps and get speed bonus."""
    for seed in range(100):
        env = SecOpsEnvironment(task_name="critical-escalation", seed=seed)
        obs = env.reset()
        if obs.severity == 2 and env.state.is_true_threat:
            obs = env.step(SecOpsAction(action_id=1))  # query_logs
            obs = env.step(SecOpsAction(action_id=5))  # isolate_host
            assert obs.done, "Episode should end after containment"
            assert obs.reward == 12.0, f"Expected 12.0 (TP+speed bonus), got {obs.reward}"
            assert obs.metadata["status"] == "true_positive_fast"
            print("PASS: test_critical_threat_fast_containment")
            return
    print("SKIP: no critical true-threat seed found in 100 tries")


# ---------- Test 2: Benign alert resolved correctly ----------
def test_benign_resolution():
    """Agent resolves a benign alert with acknowledge_allow -> TN +1."""
    for seed in range(100):
        env = SecOpsEnvironment(task_name="benign-filter", seed=seed)
        obs = env.reset()
        if not env.state.is_true_threat:
            obs = env.step(SecOpsAction(action_id=7))  # acknowledge_allow
            assert obs.done, "Episode should end after resolve"
            assert obs.reward == 1.0, f"Expected TN reward 1.0, got {obs.reward}"
            assert obs.metadata["status"] == "true_negative"
            print("PASS: test_benign_resolution")
            return
    print("SKIP: no benign seed found in 100 tries")


# ---------- Test 3: Evidence-before-action enforcement ----------
def test_procedure_violation():
    """Containment without evidence must give -5 penalty and NOT end the episode."""
    env = SecOpsEnvironment(task_name="mixed-triage", seed=42)
    obs = env.reset()
    obs = env.step(SecOpsAction(action_id=5))  # isolate_host with no evidence
    assert not obs.done, "Procedure violation should NOT end episode"
    assert obs.reward == -5.0, f"Expected -5.0 penalty, got {obs.reward}"
    assert obs.metadata["status"] == "procedure_violation"
    assert obs.metadata["last_action_error"] is not None
    print("PASS: test_procedure_violation")


# ---------- Test 4: Timeout triggers correctly at max_steps ----------
def test_timeout_on_max_steps():
    """Repeated safe actions must trigger hard timeout at max_steps."""
    env = SecOpsEnvironment(task_name="mixed-triage", seed=42)
    obs = env.reset()
    # Do 5 safe actions (some will be duplicates)
    actions = [0, 1, 2, 3, 0]  # 5th is duplicate but still hits timeout
    for a in actions:
        obs = env.step(SecOpsAction(action_id=a))
    assert obs.done, "Episode must end at max_steps"
    assert obs.metadata["status"] in ("timeout_breach", "timeout_benign")
    print("PASS: test_timeout_on_max_steps")


# ---------- Test 5: FPR < 20% with heuristic over 100 episodes ----------
def test_low_false_positive_rate():
    """Heuristic policy should achieve FPR < 20% over 100 episodes."""
    fp_count = 0
    total = 100
    for seed in range(total):
        env = SecOpsEnvironment(task_name="mixed-triage", seed=seed)
        obs = env.reset()
        # Run heuristic: query_logs first, then decide based on confidence
        obs = env.step(SecOpsAction(action_id=1))  # query_logs
        if obs.done:
            if obs.metadata["status"] == "false_positive":
                fp_count += 1
            continue
        # If confidence high -> contain, else resolve
        if obs.confidence_score >= 0.20:
            obs = env.step(SecOpsAction(action_id=4))  # block_ip
        else:
            obs = env.step(SecOpsAction(action_id=7))  # acknowledge_allow
        if obs.metadata["status"] == "false_positive":
            fp_count += 1
    fpr = fp_count / total
    assert fpr < 0.20, f"FPR {fpr:.2%} exceeds 20% threshold"
    print(f"PASS: test_low_false_positive_rate (FPR={fpr:.2%})")


# ---------- Test 6: Grader returns score in [0, 1] ----------
def test_grader_bounds():
    """grade_task must return a float in [0.0, 1.0] for all tasks."""
    for task_name in TASK_NAMES:
        results = [{"reward": -50, "steps": 5, "outcome": "timeout_breach", "max_steps": 5}]
        score = grade_task(task_name, results)
        assert 0.0 <= score <= 1.0, f"{task_name} worst-case score {score} out of bounds"

        results = [{"reward": 12, "steps": 2, "outcome": "true_positive_fast", "max_steps": 5}]
        score = grade_task(task_name, results)
        assert 0.0 <= score <= 1.0, f"{task_name} best-case score {score} out of bounds"
    print("PASS: test_grader_bounds")


# ---------- Test 7: Timeout on repeated procedure violations (bug fix) ----------
def test_timeout_on_procedure_violations():
    """Repeated risky actions without evidence must still hit hard timeout."""
    env = SecOpsEnvironment(task_name="mixed-triage", seed=42)
    obs = env.reset()
    for _ in range(10):  # Try 10 risky actions with no evidence
        obs = env.step(SecOpsAction(action_id=5))  # isolate_host
        if obs.done:
            break
    assert obs.done, "Episode must end via hard timeout even with procedure violations"
    assert obs.metadata["status"] in ("timeout_breach", "timeout_benign")
    print("PASS: test_timeout_on_procedure_violations")


if __name__ == "__main__":
    test_critical_threat_fast_containment()
    test_benign_resolution()
    test_procedure_violation()
    test_timeout_on_max_steps()
    test_low_false_positive_rate()
    test_grader_bounds()
    test_timeout_on_procedure_violations()
    print("\nAll tests passed!")
