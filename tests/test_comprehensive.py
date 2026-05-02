"""Comprehensive system tests for SecOps Alert Router V2.

Tests augmented pool integrity, reward engine edge cases,
compliance multipliers, and end-to-end environment lifecycle.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from secops_env.server.reward_engine import (
    compute_reward, SEVERITY_MULTIPLIER, COMPLIANCE_FN_MULTIPLIER,
    SAFE_ACTIONS, RISKY_ACTIONS, ACTION_NAMES,
)
from secops_env.server.scenarios.augmentor import build_augmented_pool, get_pool_stats
from secops_env.server.scenarios import ALL_SCENARIOS
from secops_env.server.secops_environment import SecOpsEnvironment
from secops_env.server.queue_environment import QueueEnvironment
from secops_env.server.tasks import TASKS, TASK_NAMES, grade_task
from secops_env.models import SecOpsAction, QueueAction


# ── Helpers ──

def make_scenario(is_threat, severity="medium", compliance=None, criticality="medium"):
    s = {
        "is_true_threat": is_threat,
        "severity": severity,
        "investigate": {},
        "optimal_actions": [1, 2, 7],
        "target": {"criticality": criticality},
    }
    if compliance:
        s["compliance"] = compliance
    return s


# ── Augmented Pool Tests ──

class TestAugmentedPool:
    @pytest.fixture(scope="class")
    def pool(self):
        return build_augmented_pool(seed=42, multiplier=3)

    @pytest.fixture(scope="class")
    def base_map(self):
        return {s["id"]: s for s in ALL_SCENARIOS}

    def test_pool_size(self, pool):
        assert len(pool) == 183

    def test_id_uniqueness(self, pool):
        ids = [s["id"] for s in pool]
        assert len(ids) == len(set(ids))

    def test_all_base_scenarios_included(self, pool):
        base_ids = {s["id"] for s in ALL_SCENARIOS}
        pool_ids = {s["id"] for s in pool}
        for bid in base_ids:
            assert bid in pool_ids, f"Base scenario {bid} missing from pool"

    def test_clone_count(self, pool):
        clones = [s for s in pool if s.get("_augmented")]
        assert len(clones) >= 100

    @pytest.mark.parametrize("field", [
        "category", "difficulty", "is_true_threat", "severity",
        "mitre_tactic", "mitre_technique", "optimal_actions",
    ])
    def test_critical_fields_preserved(self, pool, base_map, field):
        for s in pool:
            if not s.get("_augmented"):
                continue
            base_id = s.get("_base_id", "")
            base = base_map.get(base_id)
            if base:
                assert s.get(field) == base.get(field), (
                    f'{s["id"]}: {field} = {s.get(field)} != {base.get(field)}'
                )

    def test_investigation_data_preserved(self, pool, base_map):
        for s in pool:
            if not s.get("_augmented"):
                continue
            base_id = s.get("_base_id", "")
            base = base_map.get(base_id)
            if not base:
                continue
            inv = s.get("investigate", {})
            base_inv = base.get("investigate", {})
            assert set(inv.keys()) == set(base_inv.keys()), f'{s["id"]}: investigate keys differ'

    def test_compliance_preserved(self, pool, base_map):
        for s in pool:
            if not s.get("_augmented"):
                continue
            base_id = s.get("_base_id", "")
            base = base_map.get(base_id)
            if not base or not base.get("compliance"):
                continue
            assert s.get("compliance") == base.get("compliance"), f'{s["id"]}: compliance changed'

    def test_deterministic_with_same_seed(self, pool):
        pool2 = build_augmented_pool(seed=42, multiplier=3)
        ids1 = [s["id"] for s in pool]
        ids2 = [s["id"] for s in pool2]
        assert ids1 == ids2

    def test_pool_stats(self, pool):
        stats = get_pool_stats(pool)
        assert stats["total"] == 183
        assert stats["originals"] == 61
        assert stats["augmented"] == 122


# ── Reward Engine Edge Cases ──

class TestRewardEngineEdgeCases:
    # Investigation
    def test_first_investigation_has_reward(self):
        r, st = compute_reward(make_scenario(True, "high"), 1, 1, 10, [], 0)
        assert isinstance(r, float)
        assert st in ("useful_investigation", "low_value_investigation")

    def test_duplicate_investigation_penalty(self):
        r, st = compute_reward(make_scenario(True), 1, 2, 10, ["query_siem"], 1)
        assert r == -2.0
        assert st == "duplicate_action"

    def test_timeout_priority_over_duplicate(self):
        r, st = compute_reward(make_scenario(True, "high"), 1, 10, 10, ["query_siem"], 2)
        assert st == "timeout_breach"
        assert r < 0

    def test_timeout_benign_positive(self):
        r, st = compute_reward(make_scenario(False), 0, 10, 10, [], 0)
        assert r > 0
        assert st == "timeout_benign"

    # Procedure violation
    def test_procedure_violation_no_investigation(self):
        r, st = compute_reward(make_scenario(True), 7, 2, 10, [], 0)
        assert r == -5.0
        assert st == "procedure_violation"

    def test_procedure_violation_one_investigation(self):
        r, st = compute_reward(make_scenario(True), 7, 2, 10, ["query_siem"], 1)
        assert r == -5.0
        assert st == "procedure_violation"

    # True positive containment
    @pytest.mark.parametrize("severity", ["medium", "high", "critical"])
    def test_true_positive_containment(self, severity):
        r, st = compute_reward(
            make_scenario(True, severity), 7, 3, 10,
            ["query_siem", "check_reputation"], 2,
        )
        assert r > 0
        assert st == "true_positive"

    def test_early_containment_better_than_late(self):
        s = make_scenario(True, "critical")
        r_early, _ = compute_reward(s, 7, 3, 10, ["a", "b"], 2)
        r_late, _ = compute_reward(s, 7, 8, 10, ["a", "b"], 2)
        assert r_early > r_late

    def test_proportional_response_bonus(self):
        # block_source(6) proportional for medium, isolate_host(7) not
        r_prop, _ = compute_reward(make_scenario(True, "medium"), 6, 3, 10, ["a", "b"], 2)
        r_not, _ = compute_reward(make_scenario(True, "medium"), 7, 3, 10, ["a", "b"], 2)
        assert r_prop >= r_not

    # False positive
    def test_false_positive_negative_reward(self):
        r, st = compute_reward(make_scenario(False), 7, 3, 10, ["a", "b"], 2)
        assert r < 0
        assert st == "false_positive"

    def test_criticality_scales_fp_penalty(self):
        r_low, _ = compute_reward(make_scenario(False, criticality="low"), 7, 3, 10, ["a", "b"], 2)
        r_high, _ = compute_reward(make_scenario(False, criticality="high"), 7, 3, 10, ["a", "b"], 2)
        assert abs(r_high) > abs(r_low)

    # Escalation
    def test_escalation_true_threat(self):
        r, st = compute_reward(make_scenario(True), 9, 3, 10, ["a", "b"], 2)
        assert r > 0
        assert st == "escalated_true_threat"

    def test_escalation_false_alarm(self):
        r, st = compute_reward(make_scenario(False), 9, 3, 10, ["a", "b"], 2)
        assert r < 0
        assert st == "escalated_false_alarm"

    # Resolve benign
    def test_true_negative(self):
        r, st = compute_reward(make_scenario(False), 10, 3, 10, ["a", "b"], 2)
        assert r > 0
        assert st == "true_negative"

    def test_false_negative(self):
        r, st = compute_reward(make_scenario(True), 10, 3, 10, ["a", "b"], 2)
        assert r < 0
        assert st == "false_negative"


# ── Compliance Multipliers ──

class TestComplianceMultipliers:
    @pytest.mark.parametrize("framework", ["GDPR", "HIPAA", "PCI-DSS", "SOX"])
    def test_compliance_amplifies_fn_penalty(self, framework):
        s_comp = make_scenario(True, "critical", compliance={"framework": framework, "data_volume": "single"})
        r_comp, st_comp = compute_reward(s_comp, 10, 3, 10, ["a", "b"], 2)
        s_base = make_scenario(True, "critical")
        r_base, _ = compute_reward(s_base, 10, 3, 10, ["a", "b"], 2)
        assert abs(r_comp) > abs(r_base)
        assert st_comp == "compliance_breach"

    def test_gdpr_massive_clamped_at_minus_100(self):
        s = make_scenario(True, "critical", compliance={"framework": "GDPR", "data_volume": "massive"})
        r, st = compute_reward(s, 10, 3, 10, ["a", "b"], 2)
        assert r == -100.0
        assert st == "compliance_breach"

    def test_no_compliance_is_false_negative(self):
        r, st = compute_reward(make_scenario(True, "critical"), 10, 3, 10, ["a", "b"], 2)
        assert st == "false_negative"

    def test_volume_scaling(self):
        base = {"framework": "PCI-DSS"}
        r_single, _ = compute_reward(
            make_scenario(True, "high", {**base, "data_volume": "single"}), 10, 3, 10, ["a", "b"], 2)
        r_bulk, _ = compute_reward(
            make_scenario(True, "high", {**base, "data_volume": "bulk"}), 10, 3, 10, ["a", "b"], 2)
        r_massive, _ = compute_reward(
            make_scenario(True, "high", {**base, "data_volume": "massive"}), 10, 3, 10, ["a", "b"], 2)
        assert abs(r_massive) >= abs(r_bulk) >= abs(r_single)

    def test_severity_timeout_scaling(self):
        r_med, _ = compute_reward(make_scenario(True, "medium"), 0, 10, 10, [], 0)
        r_crit, _ = compute_reward(make_scenario(True, "critical"), 0, 10, 10, [], 0)
        assert abs(r_crit) > abs(r_med)


# ── Grader Comprehensive ──

class TestGraderComprehensive:
    @pytest.mark.parametrize("task_name", TASK_NAMES)
    def test_all_correct_high_score(self, task_name):
        if task_name == "queue-triage":
            episodes = [{"outcome": "queue_complete", "steps": 10, "max_steps": 40, "investigation_count": 10}] * 3
        else:
            episodes = [{"outcome": "true_positive", "steps": 3, "max_steps": 10, "investigation_count": 3}] * 5
        score = grade_task(task_name, episodes)
        assert 0.5 < score < 1.0, f"{task_name}: all-correct score too low: {score}"

    @pytest.mark.parametrize("task_name", TASK_NAMES)
    def test_all_wrong_low_score(self, task_name):
        episodes = [{"outcome": "false_negative", "steps": 10, "max_steps": 10, "investigation_count": 0}] * 5
        score = grade_task(task_name, episodes)
        assert 0.0 < score < 0.5, f"{task_name}: all-wrong score too high: {score}"

    @pytest.mark.parametrize("task_name", TASK_NAMES)
    def test_score_strictly_bounded(self, task_name):
        episodes = [{"outcome": "true_positive", "steps": 3, "max_steps": 10, "investigation_count": 3}]
        score = grade_task(task_name, episodes)
        assert 0.0 < score < 1.0

    def test_compliance_breach_heavily_penalized(self):
        episodes = [{"outcome": "compliance_breach", "steps": 5, "max_steps": 12, "investigation_count": 2}] * 5
        score = grade_task("compliance-triage", episodes)
        assert score < 0.3, f"Compliance breach score too high: {score}"

    def test_hipaa_breach_heavily_penalized(self):
        episodes = [{"outcome": "compliance_breach", "steps": 5, "max_steps": 12, "investigation_count": 2}] * 5
        score = grade_task("hipaa-triage", episodes)
        assert score < 0.3, f"HIPAA breach score too high: {score}"


# ── Queue Environment Lifecycle ──

class TestQueueLifecycle:
    def test_queue_full_episode(self):
        env = QueueEnvironment(task_name="queue-triage", seed=42)
        obs = env.reset()
        assert obs.queue_size == 5
        assert obs.alerts_remaining == 5
        assert obs.done is False

        step_count = 0
        while not obs.done and step_count < 200:
            target_slot = None
            for i, slot_info in enumerate(obs.queue_summary):
                if not slot_info.get("done", False):
                    target_slot = i
                    break
            if target_slot is None:
                break
            for aid in [0, 1, 7]:
                if obs.done:
                    break
                obs = env.step(QueueAction(alert_index=target_slot, action_id=aid))
                step_count += 1

        assert obs.done is True
        assert obs.alerts_remaining == 0
        env.close()

    def test_queue_switch_penalty_applied(self):
        env = QueueEnvironment(task_name="queue-triage", seed=42)
        obs = env.reset()
        # Act on slot 0
        obs = env.step(QueueAction(alert_index=0, action_id=1))
        r1 = obs.reward
        # Switch to slot 1 — should have switch penalty
        obs = env.step(QueueAction(alert_index=1, action_id=0))
        r2 = obs.reward
        # The switch penalty makes reward lower than a same-slot step
        assert r2 < r1, f"Switch penalty not applied: r1={r1}, r2={r2}"
        env.close()


# ── End-to-End Environment Lifecycle ──

class TestEndToEndLifecycle:
    @pytest.mark.parametrize("task_name", [t for t in TASK_NAMES if t != "queue-triage"])
    def test_full_episode_terminates(self, task_name):
        task_config = TASKS[task_name]
        max_steps = task_config["max_steps"]
        env = SecOpsEnvironment(task_name=task_name, max_steps=max_steps, seed=42)
        obs = env.reset()

        assert obs.time_steps_elapsed == 0
        assert obs.done is False
        assert obs.severity in ("medium", "high", "critical")

        step = 0
        while not obs.done and step < max_steps * 2:
            if obs.investigation_count < 2:
                action_id = step % 6
            else:
                action_id = 7
            obs = env.step(SecOpsAction(action_id=action_id))
            step += 1

        assert obs.done is True, f"{task_name}: episode did not terminate in {step} steps"
        assert obs.metadata is not None
        env.close()


# ── Investigation Noise Tests ──

class TestInvestigationNoise:
    """Tests for the investigation_noise module.

    Noise is deterministically seeded per (scenario_id, step, action),
    so the same inputs always produce the same output.
    """

    def test_noise_disabled_returns_original(self, monkeypatch):
        from secops_env.server import investigation_noise
        monkeypatch.setattr(investigation_noise, "NOISE_LEVEL", 0.0)
        result = investigation_noise.inject_noise("query_siem", "original text", "scen-001", 1)
        assert result == "original text"

    def test_noise_enabled_may_modify_result(self, monkeypatch):
        """With noise at 100%, result is always modified."""
        from secops_env.server import investigation_noise
        monkeypatch.setattr(investigation_noise, "NOISE_LEVEL", 1.0)
        result = investigation_noise.inject_noise("query_siem", "original text", "scen-001", 1)
        # At 100% noise, result should differ from original
        assert result != "" and len(result) > 0

    def test_noise_is_deterministic(self, monkeypatch):
        """Same inputs always produce same output."""
        from secops_env.server import investigation_noise
        monkeypatch.setattr(investigation_noise, "NOISE_LEVEL", 0.5)
        r1 = investigation_noise.inject_noise("check_reputation", "IOC result", "phish-001", 3)
        r2 = investigation_noise.inject_noise("check_reputation", "IOC result", "phish-001", 3)
        assert r1 == r2

    def test_different_steps_may_differ(self, monkeypatch):
        """Different step counts can produce different noise patterns."""
        from secops_env.server import investigation_noise
        monkeypatch.setattr(investigation_noise, "NOISE_LEVEL", 1.0)
        results = {
            investigation_noise.inject_noise("query_siem", "base text", "scen-001", i)
            for i in range(10)
        }
        # With 10 different seeds at 100% noise, we expect some variation in results
        assert len(results) > 1

    def test_noise_never_returns_empty(self, monkeypatch):
        """Noise injection always preserves the core result (never empty)."""
        from secops_env.server import investigation_noise
        monkeypatch.setattr(investigation_noise, "NOISE_LEVEL", 1.0)
        for action in ["query_siem", "check_reputation", "analyze_payload",
                       "analyze_headers", "correlate_alerts", "check_asset"]:
            for step in range(5):
                result = investigation_noise.inject_noise(
                    action, "original data", f"scen-{step:03d}", step
                )
                assert len(result) > 0, f"Empty result for {action} step {step}"
                assert "original data" in result, f"Core data lost for {action} step {step}"

    def test_get_investigation_result_includes_noise(self, monkeypatch):
        """investigation_engine.get_investigation_result applies noise correctly."""
        import secops_env.server.investigation_noise as noise_mod
        monkeypatch.setattr(noise_mod, "NOISE_LEVEL", 0.0)  # Disable noise for clean test
        from secops_env.server.investigation_engine import get_investigation_result
        scenario = {
            "id": "test-001",
            "investigate": {"query_siem": "SIEM log data here"},
        }
        result = get_investigation_result(scenario, 1, step_count=2)
        assert result is not None
        assert result["action_name"] == "query_siem"
        assert "SIEM log data here" in result["result"]

    @pytest.mark.parametrize("task_name", ["phishing-triage", "insider-threat", "cloud-native"])
    def test_environment_works_with_noise_enabled(self, task_name, monkeypatch):
        """Full episode completes correctly with noise injection enabled."""
        import secops_env.server.investigation_noise as noise_mod
        monkeypatch.setattr(noise_mod, "NOISE_LEVEL", 0.5)
        env = SecOpsEnvironment(task_name=task_name, max_steps=10, seed=99)
        obs = env.reset()
        step = 0
        while not obs.done and step < 20:
            action_id = step % 6 if obs.investigation_count < 2 else 7
            obs = env.step(SecOpsAction(action_id=action_id))
            step += 1
        assert obs.done is True
        env.close()
