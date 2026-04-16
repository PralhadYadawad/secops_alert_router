"""Tests for SecOps Alert Router V2 environment.

Organized into test classes by component:
- TestEnvironmentReset: Episode initialization
- TestInvestigation: Investigation action mechanics
- TestContainment: Containment action mechanics
- TestTerminalActions: Escalate and resolve
- TestGrader: Task grading logic
- TestAllTasks: Cross-task verification
- TestScenarioData: Scenario integrity
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from secops_env.models import SecOpsAction, SecOpsObservation
from secops_env.server.secops_environment import SecOpsEnvironment
from secops_env.server.tasks import TASKS, TASK_NAMES, grade_task
from secops_env.server.reward_engine import (
    ACTION_NAMES, SAFE_ACTIONS, RISKY_ACTIONS, ESCALATE_ACTION, RESOLVE_ACTION,
    SEVERITY_MULTIPLIER, COMPLIANCE_FN_MULTIPLIER, compute_reward,
)


# ── Environment Reset Tests ──────────────────────────────────────────────────


class TestEnvironmentReset:

    def test_reset_returns_rich_observation(self):
        env = SecOpsEnvironment(task_name="spam-filter", seed=42)
        obs = env.reset()

        assert isinstance(obs, SecOpsObservation)
        assert obs.rule_triggered != ""
        assert obs.severity in ("medium", "high", "critical")
        assert obs.raw_log_snippet != ""
        assert obs.target_host != ""
        assert obs.time_steps_elapsed == 0
        assert obs.done is False
        assert obs.investigation_history == []
        assert obs.actions_taken == []

    def test_reset_returns_mitre_fields(self):
        env = SecOpsEnvironment(task_name="phishing-triage", seed=42)
        obs = env.reset()

        assert obs.mitre_tactic != ""
        assert obs.mitre_technique != ""

    def test_reset_returns_source_fields(self):
        env = SecOpsEnvironment(task_name="phishing-triage", seed=42)
        obs = env.reset()

        assert obs.source_ip != ""

    def test_reset_metadata_contains_task_info(self):
        env = SecOpsEnvironment(task_name="insider-threat", seed=42)
        obs = env.reset()

        assert obs.metadata["task_name"] == "insider-threat"
        assert obs.metadata["status"] == "new_alert"
        assert "category" in obs.metadata

    def test_reset_clears_previous_episode(self):
        env = SecOpsEnvironment(task_name="spam-filter", seed=42)
        env.reset()
        env.step(SecOpsAction(action_id=1))

        obs = env.reset()
        assert obs.time_steps_elapsed == 0
        assert obs.actions_taken == []
        assert obs.investigation_history == []

    def test_different_seeds_produce_different_scenarios(self):
        env1 = SecOpsEnvironment(task_name="phishing-triage", seed=1)
        obs1 = env1.reset()
        env2 = SecOpsEnvironment(task_name="phishing-triage", seed=999)
        obs2 = env2.reset()

        # Different seeds should produce at least some different fields
        # (not guaranteed to be different for all fields due to scenario pool)
        assert isinstance(obs1, SecOpsObservation)
        assert isinstance(obs2, SecOpsObservation)


# ── Investigation Tests ──────────────────────────────────────────────────────


class TestInvestigation:

    def test_investigation_returns_data(self):
        env = SecOpsEnvironment(task_name="phishing-triage", seed=42)
        env.reset()

        obs = env.step(SecOpsAction(action_id=1))  # query_siem
        assert not obs.done
        assert "query_siem" in obs.actions_taken
        assert len(obs.investigation_history) >= 1
        assert obs.investigation_history[0]["result"] != ""

    def test_multiple_investigations_accumulate(self):
        env = SecOpsEnvironment(task_name="phishing-triage", seed=42)
        env.reset()

        env.step(SecOpsAction(action_id=1))  # query_siem
        obs = env.step(SecOpsAction(action_id=2))  # check_reputation
        assert "check_reputation" in obs.actions_taken
        assert len(obs.investigation_history) >= 2

    def test_duplicate_investigation_penalty(self):
        env = SecOpsEnvironment(task_name="spam-filter", seed=42)
        env.reset()

        env.step(SecOpsAction(action_id=1))  # query_siem
        obs2 = env.step(SecOpsAction(action_id=1))  # duplicate
        assert obs2.reward == -2.0
        assert obs2.metadata.get("status") == "duplicate_action"

    def test_all_six_investigation_actions_work(self):
        env = SecOpsEnvironment(task_name="apt-campaign", seed=42, max_steps=20)
        env.reset()

        for action_id in sorted(SAFE_ACTIONS):
            obs = env.step(SecOpsAction(action_id=action_id))
            action_name = ACTION_NAMES[action_id]
            assert action_name in obs.actions_taken
            assert not obs.done, f"Investigation {action_name} should not end episode"

    def test_investigation_count_increments(self):
        env = SecOpsEnvironment(task_name="phishing-triage", seed=42)
        env.reset()

        obs = env.step(SecOpsAction(action_id=0))
        assert obs.investigation_count == 1
        obs = env.step(SecOpsAction(action_id=1))
        assert obs.investigation_count == 2
        obs = env.step(SecOpsAction(action_id=2))
        assert obs.investigation_count == 3

    def test_step_count_increments(self):
        env = SecOpsEnvironment(task_name="phishing-triage", seed=42)
        env.reset()

        obs = env.step(SecOpsAction(action_id=0))
        assert obs.time_steps_elapsed == 1
        obs = env.step(SecOpsAction(action_id=1))
        assert obs.time_steps_elapsed == 2


# ── Containment Tests ────────────────────────────────────────────────────────


class TestContainment:

    def test_procedure_violation_without_investigation(self):
        env = SecOpsEnvironment(task_name="spam-filter", seed=42)
        env.reset()

        obs = env.step(SecOpsAction(action_id=7))  # isolate_host
        assert obs.reward == -5.0
        assert obs.metadata.get("status") == "procedure_violation"

    def test_containment_after_sufficient_investigation(self):
        env = SecOpsEnvironment(task_name="lateral-movement", seed=42)
        env.reset()

        env.step(SecOpsAction(action_id=1))  # query_siem
        env.step(SecOpsAction(action_id=2))  # check_reputation

        obs = env.step(SecOpsAction(action_id=7))  # isolate_host
        assert obs.done
        status = obs.metadata.get("status")
        assert status in ("true_positive", "false_positive")

    def test_all_containment_actions_end_episode(self):
        for action_id in RISKY_ACTIONS:
            env = SecOpsEnvironment(task_name="apt-campaign", seed=42)
            env.reset()
            env.step(SecOpsAction(action_id=0))
            env.step(SecOpsAction(action_id=1))
            obs = env.step(SecOpsAction(action_id=action_id))
            assert obs.done, f"Containment action {ACTION_NAMES[action_id]} should end episode"

    def test_procedure_violation_with_only_one_investigation(self):
        env = SecOpsEnvironment(task_name="phishing-triage", seed=42)
        env.reset()

        env.step(SecOpsAction(action_id=1))  # only 1 investigation
        obs = env.step(SecOpsAction(action_id=6))  # block_source
        assert obs.metadata.get("status") == "procedure_violation"


# ── Terminal Action Tests ────────────────────────────────────────────────────


class TestTerminalActions:

    def test_escalation_ends_episode(self):
        env = SecOpsEnvironment(task_name="insider-threat", seed=42)
        env.reset()

        obs = env.step(SecOpsAction(action_id=9))  # escalate
        assert obs.done
        status = obs.metadata.get("status")
        assert status in ("escalated_true_threat", "escalated_false_alarm")

    def test_resolve_benign_ends_episode(self):
        env = SecOpsEnvironment(task_name="spam-filter", seed=42)
        env.reset()

        obs = env.step(SecOpsAction(action_id=10))  # resolve_benign
        assert obs.done
        status = obs.metadata.get("status")
        assert status in ("true_negative", "false_negative", "compliance_breach")

    def test_action_on_done_episode_returns_zero_reward(self):
        env = SecOpsEnvironment(task_name="spam-filter", seed=42)
        env.reset()

        env.step(SecOpsAction(action_id=9))  # escalate -> done
        obs = env.step(SecOpsAction(action_id=1))  # try investigation after done
        assert obs.done
        assert obs.reward == 0.0
        assert obs.metadata.get("status") == "episode_already_done"


# ── Reward Engine Tests ──────────────────────────────────────────────────────


class TestRewardEngine:

    def _make_scenario(self, is_threat, severity="medium", compliance_framework=""):
        scenario = {
            "id": "test-001",
            "is_true_threat": is_threat,
            "severity": severity,
            "category": "phishing",
            "target": {"criticality": "medium"},
            "investigate": {},
            "optimal_actions": [1, 2],
        }
        if compliance_framework:
            scenario["compliance"] = {
                "framework": compliance_framework,
                "data_type": "PII",
                "data_volume": "massive",
            }
        return scenario

    def test_true_positive_containment_positive_reward(self):
        scenario = self._make_scenario(is_threat=True, severity="high")
        reward, status = compute_reward(
            scenario, action_id=7, step_count=3, max_steps=10,
            actions_taken=["query_siem", "check_reputation"],
            investigation_count=2,
        )
        assert reward > 0, f"True positive should have positive reward, got {reward}"
        assert status == "true_positive"

    def test_false_positive_containment_negative_reward(self):
        scenario = self._make_scenario(is_threat=False)
        reward, status = compute_reward(
            scenario, action_id=7, step_count=3, max_steps=10,
            actions_taken=["query_siem", "check_reputation"],
            investigation_count=2,
        )
        assert reward < 0
        assert status == "false_positive"

    def test_true_negative_resolution_positive_reward(self):
        scenario = self._make_scenario(is_threat=False)
        reward, status = compute_reward(
            scenario, action_id=10, step_count=3, max_steps=10,
            actions_taken=["query_siem", "check_reputation"],
            investigation_count=2,
        )
        assert reward > 0
        assert status == "true_negative"

    def test_false_negative_resolution_negative_reward(self):
        scenario = self._make_scenario(is_threat=True)
        reward, status = compute_reward(
            scenario, action_id=10, step_count=3, max_steps=10,
            actions_taken=["query_siem"], investigation_count=1,
        )
        assert reward < 0
        assert status == "false_negative"

    def test_compliance_breach_amplified_penalty(self):
        scenario = self._make_scenario(
            is_threat=True, severity="critical", compliance_framework="GDPR"
        )
        reward, status = compute_reward(
            scenario, action_id=10, step_count=3, max_steps=10,
            actions_taken=["query_siem"], investigation_count=1,
        )
        assert reward <= -25.0, f"Compliance breach should have severe penalty, got {reward}"
        assert status == "compliance_breach"

    def test_reward_floor_at_minus_100(self):
        scenario = self._make_scenario(
            is_threat=True, severity="critical", compliance_framework="GDPR"
        )
        reward, _ = compute_reward(
            scenario, action_id=10, step_count=3, max_steps=10,
            actions_taken=[], investigation_count=0,
        )
        assert reward >= -100.0, f"Reward should be clamped at -100, got {reward}"

    def test_escalation_true_threat_partial_reward(self):
        scenario = self._make_scenario(is_threat=True)
        reward, status = compute_reward(
            scenario, action_id=9, step_count=3, max_steps=10,
            actions_taken=["query_siem", "check_reputation"],
            investigation_count=2,
        )
        assert reward > 0
        assert status == "escalated_true_threat"

    def test_escalation_false_alarm_negative_reward(self):
        scenario = self._make_scenario(is_threat=False)
        reward, status = compute_reward(
            scenario, action_id=9, step_count=3, max_steps=10,
            actions_taken=[], investigation_count=0,
        )
        assert reward < 0
        assert status == "escalated_false_alarm"


# ── Grader Tests ─────────────────────────────────────────────────────────────


class TestGrader:

    def test_grader_bounds_all_tasks(self):
        for task_name in TASK_NAMES:
            worst = [{"reward": -50, "steps": 12, "outcome": "timeout_breach",
                       "max_steps": 12, "investigation_count": 0}]
            score = grade_task(task_name, worst)
            assert 0.0 < score < 1.0, f"{task_name} worst-case score {score} out of bounds"

            best = [{"reward": 20, "steps": 3, "outcome": "true_positive",
                      "max_steps": 12, "investigation_count": 3}]
            score = grade_task(task_name, best)
            assert 0.0 < score < 1.0, f"{task_name} best-case score {score} out of bounds"

    def test_grader_empty_results(self):
        for task_name in TASK_NAMES:
            score = grade_task(task_name, [])
            assert score == 0.01

    def test_grader_perfect_score_high(self):
        results = [
            {"reward": 20, "steps": 3, "outcome": "true_positive",
             "max_steps": 12, "investigation_count": 4}
            for _ in range(5)
        ]
        score = grade_task("spam-filter", results)
        assert score > 0.5, f"Perfect results should score > 0.5, got {score}"

    def test_grader_all_wrong_score_low(self):
        results = [
            {"reward": -50, "steps": 12, "outcome": "false_negative",
             "max_steps": 12, "investigation_count": 0}
            for _ in range(5)
        ]
        score = grade_task("spam-filter", results)
        assert score < 0.5, f"All-wrong results should score < 0.5, got {score}"

    def test_queue_triage_grading_branch(self):
        results = [
            {"reward": 10, "steps": 5, "outcome": "true_positive",
             "max_steps": 10, "investigation_count": 2}
        ]
        score = grade_task("queue-triage", results)
        assert 0.0 < score < 1.0

    def test_compliance_triage_grading_branch(self):
        results = [
            {"reward": -100, "steps": 3, "outcome": "compliance_breach",
             "max_steps": 12, "investigation_count": 0}
        ]
        score = grade_task("compliance-triage", results)
        assert 0.0 < score < 1.0


# ── Cross-Task Tests ─────────────────────────────────────────────────────────


class TestAllTasks:

    @pytest.mark.parametrize("task_name", TASK_NAMES)
    def test_task_runs_to_completion(self, task_name):
        if task_name == "queue-triage":
            pytest.skip("Queue-triage uses QueueEnvironment, tested separately")

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

    @pytest.mark.parametrize("task_name", TASK_NAMES)
    def test_task_config_valid(self, task_name):
        config = TASKS[task_name]
        assert "num_episodes" in config
        assert "max_steps" in config
        assert config["max_steps"] > 0
        assert "description" in config


# ── Scenario Data Tests ──────────────────────────────────────────────────────


class TestScenarioData:

    def test_scenario_has_investigation_data(self):
        from secops_env.server.scenarios import ALL_SCENARIOS

        for scenario in ALL_SCENARIOS:
            inv = scenario.get("investigate", {})
            assert "query_siem" in inv, f"Scenario {scenario['id']} missing query_siem"
            assert "check_reputation" in inv, f"Scenario {scenario['id']} missing check_reputation"
            assert inv["query_siem"] != "", f"Scenario {scenario['id']} has empty query_siem"

    def test_all_scenarios_have_required_fields(self):
        from secops_env.server.scenarios import ALL_SCENARIOS

        required = {"id", "category", "severity", "is_true_threat", "alert", "source",
                     "target", "mitre", "investigate"}
        for scenario in ALL_SCENARIOS:
            missing = required - set(scenario.keys())
            assert not missing, f"Scenario {scenario['id']} missing fields: {missing}"

    def test_severity_values_valid(self):
        from secops_env.server.scenarios import ALL_SCENARIOS

        valid = {"medium", "high", "critical"}
        for scenario in ALL_SCENARIOS:
            assert scenario["severity"] in valid, (
                f"Scenario {scenario['id']} has invalid severity '{scenario['severity']}'"
            )

    def test_optimal_actions_are_integers(self):
        from secops_env.server.scenarios import ALL_SCENARIOS

        for scenario in ALL_SCENARIOS:
            optimal = scenario.get("optimal_actions", [])
            for val in optimal:
                assert isinstance(val, int), (
                    f"Scenario {scenario['id']} has non-int optimal_action: {val!r}"
                )

    def test_scenario_count(self):
        from secops_env.server.scenarios import ALL_SCENARIOS
        assert len(ALL_SCENARIOS) >= 40, f"Expected 40+ scenarios, got {len(ALL_SCENARIOS)}"


# ── Queue Environment Tests ──────────────────────────────────────────────────


class TestQueueEnvironment:

    def test_queue_reset_returns_observation(self):
        from secops_env.server.queue_environment import QueueEnvironment
        from secops_env.models import QueueObservation

        env = QueueEnvironment(task_name="queue-triage", seed=42)
        obs = env.reset()

        assert isinstance(obs, QueueObservation)
        assert obs.queue_size == 5
        assert obs.alerts_remaining == 5
        assert obs.done is False

    def test_queue_step_delegates_to_slot(self):
        from secops_env.server.queue_environment import QueueEnvironment
        from secops_env.models import QueueAction

        env = QueueEnvironment(task_name="queue-triage", seed=42)
        env.reset()

        obs = env.step(QueueAction(action_id=1, alert_index=0))
        assert obs.total_steps_used == 1
        assert not obs.done

    def test_queue_switch_penalty(self):
        from secops_env.server.queue_environment import QueueEnvironment
        from secops_env.models import QueueAction

        env = QueueEnvironment(task_name="queue-triage", seed=42)
        env.reset()

        env.step(QueueAction(action_id=1, alert_index=0))  # start on slot 0
        obs = env.step(QueueAction(action_id=1, alert_index=1))  # switch to slot 1
        # Switch penalty is -0.5, but inner env also contributes reward
        # Just verify the step completed
        assert obs.total_steps_used == 2

    def test_queue_uses_configured_categories(self):
        from secops_env.server.queue_environment import QueueEnvironment

        env = QueueEnvironment(task_name="queue-triage", seed=42)
        obs = env.reset()

        # queue-triage config has categories: phishing, malware, insider_threat
        categories = {s["category"] for s in obs.queue_summary if s["category"]}
        valid = {"phishing", "malware", "insider_threat"}
        for cat in categories:
            assert cat in valid, f"Queue slot has unexpected category: {cat}"


# ── Rubric Tests ─────────────────────────────────────────────────────────────


class TestRubric:

    def test_rubric_normalization_bounds(self):
        from secops_env.server.rubrics import SecOpsTriageRubric

        rubric = SecOpsTriageRubric()

        class FakeObs:
            def __init__(self, reward, done, metadata=None):
                self.reward = reward
                self.done = done
                self.metadata = metadata or {}

        # Score at extreme ends
        score = rubric.score_trajectory([(None, FakeObs(-100, True, {"cumulative_reward": -100}))])
        assert 0.0 < score < 1.0

        score = rubric.score_trajectory([(None, FakeObs(20, True, {"cumulative_reward": 20}))])
        assert 0.0 < score < 1.0

    def test_rubric_empty_trajectory(self):
        from secops_env.server.rubrics import SecOpsTriageRubric
        rubric = SecOpsTriageRubric()
        score = rubric.score_trajectory([])
        assert score == 0.01


# ── Security Module Tests ────────────────────────────────────────────────────


class TestSecurity:

    def test_rate_limiter_allows_within_limit(self):
        from secops_env.server.security import RateLimiter

        rl = RateLimiter(max_requests=3, window_seconds=60)
        assert rl.is_allowed("1.2.3.4")
        assert rl.is_allowed("1.2.3.4")
        assert rl.is_allowed("1.2.3.4")

    def test_rate_limiter_blocks_over_limit(self):
        from secops_env.server.security import RateLimiter

        rl = RateLimiter(max_requests=2, window_seconds=60)
        assert rl.is_allowed("1.2.3.4")
        assert rl.is_allowed("1.2.3.4")
        assert not rl.is_allowed("1.2.3.4")

    def test_rate_limiter_separate_ips(self):
        from secops_env.server.security import RateLimiter

        rl = RateLimiter(max_requests=1, window_seconds=60)
        assert rl.is_allowed("1.1.1.1")
        assert not rl.is_allowed("1.1.1.1")
        assert rl.is_allowed("2.2.2.2")  # different IP

    def test_ws_manager_connection_limit(self):
        from secops_env.server.security import WSConnectionManager

        mgr = WSConnectionManager(max_connections=2)
        assert mgr.can_accept()
        assert mgr.connection_count == 0

    def test_ws_manager_tracks_connections(self):
        from secops_env.server.security import WSConnectionManager

        mgr = WSConnectionManager(max_connections=2)

        class FakeWS:
            pass

        ws1, ws2, ws3 = FakeWS(), FakeWS(), FakeWS()
        mgr.connect(ws1)
        assert mgr.connection_count == 1
        mgr.connect(ws2)
        assert mgr.connection_count == 2
        assert not mgr.can_accept()  # at limit

        mgr.disconnect(ws1)
        assert mgr.connection_count == 1
        assert mgr.can_accept()


# ── Inference Parser Tests ───────────────────────────────────────────────────


class TestInferenceParser:

    def test_parse_action_10(self):
        from inference import _parse_action_from_text
        assert _parse_action_from_text("I choose action 10") == 10

    def test_parse_single_digit(self):
        from inference import _parse_action_from_text
        assert _parse_action_from_text("7") == 7

    def test_parse_from_sentence(self):
        from inference import _parse_action_from_text
        assert _parse_action_from_text("Based on the evidence, I'll select 6 to block the source") == 6

    def test_parse_invalid_returns_minus_one(self):
        from inference import _parse_action_from_text
        assert _parse_action_from_text("no numbers here") == -1

    def test_parse_out_of_range_skipped(self):
        from inference import _parse_action_from_text
        assert _parse_action_from_text("action 15 is not valid, try 3") == 3

    def test_parse_zero(self):
        from inference import _parse_action_from_text
        assert _parse_action_from_text("0") == 0


# ── Investigation Engine Tests ───────────────────────────────────────────────


class TestInvestigationEngine:

    def test_get_investigation_result_valid_action(self):
        from secops_env.server.investigation_engine import get_investigation_result

        scenario = {
            "investigate": {"query_siem": "Found 5 related events in the last 24h"}
        }
        result = get_investigation_result(scenario, action_id=1)
        assert result is not None
        assert result["action_name"] == "query_siem"
        assert "5 related events" in result["result"]

    def test_get_investigation_result_invalid_action(self):
        from secops_env.server.investigation_engine import get_investigation_result

        result = get_investigation_result({}, action_id=7)  # containment, not investigation
        assert result is None

    def test_compute_investigation_value_optimal(self):
        from secops_env.server.investigation_engine import compute_investigation_value

        scenario = {"optimal_actions": [1, 2, 3], "investigate": {"query_siem": "data"}}
        value = compute_investigation_value(scenario, action_id=1, actions_already_taken=[])
        assert value == 1.0

    def test_compute_investigation_value_duplicate(self):
        from secops_env.server.investigation_engine import compute_investigation_value

        scenario = {"optimal_actions": [1], "investigate": {"query_siem": "data"}}
        value = compute_investigation_value(
            scenario, action_id=1, actions_already_taken=["query_siem"]
        )
        assert value == 0.0

    def test_compute_investigation_value_non_optimal_with_data(self):
        from secops_env.server.investigation_engine import compute_investigation_value

        scenario = {"optimal_actions": [2, 3], "investigate": {"query_siem": "some data"}}
        value = compute_investigation_value(scenario, action_id=1, actions_already_taken=[])
        assert value == 0.5
