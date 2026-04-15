"""Tests for SecOps Alert Router V2 environment."""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from secops_env.models import SecOpsAction, SecOpsObservation
from secops_env.server.secops_environment import SecOpsEnvironment
from secops_env.server.tasks import TASKS, TASK_NAMES, grade_task
from secops_env.server.reward_engine import ACTION_NAMES, SAFE_ACTIONS


def test_reset_returns_rich_observation():
    """Reset should return observation with alert context fields."""
    env = SecOpsEnvironment(task_name="spam-filter", seed=42)
    obs = env.reset()

    assert isinstance(obs, SecOpsObservation)
    assert obs.rule_triggered != "", "rule_triggered should be populated"
    assert obs.severity in ("medium", "high", "critical")
    assert obs.raw_log_snippet != "", "raw_log_snippet should be populated"
    assert obs.target_host != "", "target_host should be populated"
    assert obs.time_steps_elapsed == 0
    assert obs.done is False
    assert obs.investigation_history == []
    assert obs.actions_taken == []
    print("PASS: test_reset_returns_rich_observation")


def test_investigation_returns_data():
    """Investigation actions should populate investigation_history."""
    env = SecOpsEnvironment(task_name="phishing-triage", seed=42)
    obs = env.reset()

    obs = env.step(SecOpsAction(action_id=1))  # query_siem
    assert not obs.done
    assert "query_siem" in obs.actions_taken
    assert len(obs.investigation_history) >= 1, "Should have investigation data"
    assert obs.investigation_history[0]["result"] != "", "Investigation result should have content"

    obs = env.step(SecOpsAction(action_id=2))  # check_reputation
    assert "check_reputation" in obs.actions_taken
    assert len(obs.investigation_history) >= 2
    print("PASS: test_investigation_returns_data")


def test_duplicate_investigation_penalty():
    """Repeating an investigation action should incur penalty."""
    env = SecOpsEnvironment(task_name="spam-filter", seed=42)
    env.reset()

    env.step(SecOpsAction(action_id=1))  # query_siem
    obs2 = env.step(SecOpsAction(action_id=1))  # duplicate
    assert obs2.reward == -2.0, f"Duplicate should cost -2.0, got {obs2.reward}"
    assert obs2.metadata.get("status") == "duplicate_action"
    print("PASS: test_duplicate_investigation_penalty")


def test_procedure_violation():
    """Containment without enough investigation should be penalized."""
    env = SecOpsEnvironment(task_name="spam-filter", seed=42)
    env.reset()

    obs = env.step(SecOpsAction(action_id=7))  # isolate_host
    assert obs.reward == -5.0, f"Procedure violation should cost -5.0, got {obs.reward}"
    assert obs.metadata.get("status") == "procedure_violation"
    print("PASS: test_procedure_violation")


def test_containment_after_investigation():
    """Containment after sufficient investigation should be allowed."""
    env = SecOpsEnvironment(task_name="lateral-movement", seed=42)
    env.reset()

    env.step(SecOpsAction(action_id=1))
    env.step(SecOpsAction(action_id=2))

    obs = env.step(SecOpsAction(action_id=7))
    assert obs.done, "Containment should end episode"
    status = obs.metadata.get("status")
    assert status in ("true_positive", "false_positive"), f"Got unexpected status: {status}"
    print("PASS: test_containment_after_investigation")


def test_resolve_benign():
    """Resolving as benign should end the episode."""
    env = SecOpsEnvironment(task_name="spam-filter", seed=42)
    env.reset()

    obs = env.step(SecOpsAction(action_id=10))  # resolve_benign
    assert obs.done, "Resolve should end episode"
    status = obs.metadata.get("status")
    assert status in ("true_negative", "false_negative", "compliance_breach"), f"Got unexpected status: {status}"
    print("PASS: test_resolve_benign")


def test_escalation_ends_episode():
    """Escalation should end the episode."""
    env = SecOpsEnvironment(task_name="insider-threat", seed=42)
    env.reset()

    obs = env.step(SecOpsAction(action_id=9))  # escalate
    assert obs.done, "Escalation should end episode"
    status = obs.metadata.get("status")
    assert status in ("escalated_true_threat", "escalated_false_alarm"), f"Got: {status}"
    print("PASS: test_escalation_ends_episode")


def test_grader_bounds():
    """grade_task must return a float strictly in (0, 1) for all tasks."""
    for task_name in TASK_NAMES:
        results = [{"reward": -50, "steps": 12, "outcome": "timeout_breach", "max_steps": 12, "investigation_count": 0}]
        score = grade_task(task_name, results)
        assert 0.0 < score < 1.0, f"{task_name} worst-case score {score} out of bounds"

        results = [{"reward": 20, "steps": 3, "outcome": "true_positive", "max_steps": 12, "investigation_count": 3}]
        score = grade_task(task_name, results)
        assert 0.0 < score < 1.0, f"{task_name} best-case score {score} out of bounds"

        score = grade_task(task_name, [])
        assert 0.0 < score < 1.0, f"{task_name} empty score {score} out of bounds"
    print("PASS: test_grader_bounds")


def test_all_tasks_run():
    """Every task should run at least one episode without crashing."""
    for task_name in TASK_NAMES:
        task_config = TASKS[task_name]
        max_steps = task_config["max_steps"]
        env = SecOpsEnvironment(task_name=task_name, seed=42)
        obs = env.reset()

        steps = 0
        while not obs.done and steps < max_steps:
            if steps < 2:
                action_id = steps
            else:
                action_id = 10
            obs = env.step(SecOpsAction(action_id=action_id))
            steps += 1

        assert obs.done, f"Task {task_name} should complete within {max_steps} steps"
        env.close()
    print("PASS: test_all_tasks_run")


def test_scenario_has_investigation_data():
    """Scenarios should provide investigation data for all 6 actions."""
    from secops_env.server.scenarios import ALL_SCENARIOS

    for scenario in ALL_SCENARIOS:
        inv = scenario.get("investigate", {})
        assert "query_siem" in inv, f"Scenario {scenario['id']} missing query_siem"
        assert "check_reputation" in inv, f"Scenario {scenario['id']} missing check_reputation"
        assert inv["query_siem"] != "", f"Scenario {scenario['id']} has empty query_siem"
    print(f"PASS: test_scenario_has_investigation_data ({len(ALL_SCENARIOS)} scenarios)")


if __name__ == "__main__":
    test_reset_returns_rich_observation()
    test_investigation_returns_data()
    test_duplicate_investigation_penalty()
    test_procedure_violation()
    test_containment_after_investigation()
    test_resolve_benign()
    test_escalation_ends_episode()
    test_grader_bounds()
    test_all_tasks_run()
    test_scenario_has_investigation_data()
    print(f"\nAll tests passed!")
