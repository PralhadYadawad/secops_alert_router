"""SecOps Alert Triage Environment V2 for OpenEnv.

A cybersecurity incident triage RL environment where an agent investigates
realistic security alerts using SIEM logs, threat intelligence, and asset
context — then decides whether to contain, escalate, or resolve.
"""

import uuid
from typing import Any, Optional

from openenv.core.env_server import Environment

from ..models import SecOpsAction, SecOpsObservation, SecOpsState
from .alert_generator import AlertGenerator, ALERT_TYPE_NAMES, SEVERITY_NAMES
from .investigation_engine import get_investigation_result
from .reward_engine import (
    ACTION_NAMES,
    SAFE_ACTIONS,
    RISKY_ACTIONS,
    ESCALATE_ACTION,
    RESOLVE_ACTION,
    compute_reward,
)
from .rubrics import SecOpsTriageRubric
from .tasks import TASKS


class SecOpsEnvironment(Environment):
    """Cybersecurity incident triage environment V2.

    The agent receives rich security alert context and must:
    - Investigate (6 actions returning actual SIEM/threat-intel/asset data)
    - Contain (3 actions with proportional response scoring)
    - Escalate (partial reward for correct instinct)
    - Resolve (dismiss as benign)

    Reward structure uses information-theoretic shaping:
    - Useful investigation: +0.5 (optimal) to -1.0 (low value)
    - True positive containment: +10 to +20 (with speed/evidence/proportionality bonuses)
    - False positive containment: -10 to -20 (scaled by asset criticality)
    - Escalation: +5 to +6 (true threat) or -3 (false alarm)
    - True negative resolution: +3 to +4.5 (with evidence bonus)
    - False negative (missed threat): -25 to -50 (scaled by severity)
    - Timeout breach: -25 to -50 (severity scaled)
    - Duplicate/procedure violations: -2 to -5
    """

    def __init__(
        self,
        task_name: str = "phishing-triage",
        max_steps: int = 10,
        seed: Optional[int] = None,
    ):
        super().__init__(rubric=SecOpsTriageRubric())
        task_config = TASKS.get(task_name, TASKS["phishing-triage"])
        self._task_name = task_name
        self._max_steps = task_config.get("max_steps", max_steps)
        self._alert_gen = AlertGenerator(
            seed=seed,
            categories=task_config.get("categories"),
            difficulties=task_config.get("difficulties"),
            threat_ratio=task_config.get("threat_ratio"),
            max_steps=self._max_steps,
        )
        self._scenario: dict = {}
        self._done = False
        self._state = SecOpsState()
        self.reset()

    def reset(
        self,
        seed: Optional[int] = None,
        episode_id: Optional[str] = None,
        **kwargs: Any,
    ) -> SecOpsObservation:
        """Reset environment with a new scenario-based alert."""
        if self.rubric is not None:
            self.rubric.reset()

        self._scenario = self._alert_gen.generate()
        self._done = False

        alert = self._scenario.get("alert", {})
        source = self._scenario.get("source", {})
        target = self._scenario.get("target", {})
        mitre = self._scenario.get("mitre", {})

        self._state = SecOpsState(
            episode_id=episode_id or str(uuid.uuid4()),
            step_count=0,
            alert_type=self._scenario.get("category", ""),
            severity=self._scenario.get("severity", "medium"),
            is_true_threat=self._scenario.get("is_true_threat", False),
            scenario_id=self._scenario.get("id", ""),
            max_steps=self._max_steps,
            actions_taken=[],
            investigation_count=0,
            cumulative_reward=0.0,
            target_criticality=target.get("criticality", "medium"),
        )

        return SecOpsObservation(
            alert_id=f"ALT-{uuid.uuid4().hex[:8].upper()}",
            rule_triggered=alert.get("rule", ""),
            severity=self._scenario.get("severity", "medium"),
            alert_description=alert.get("description", ""),
            mitre_tactic=mitre.get("tactic", ""),
            mitre_technique=f"{mitre.get('technique', '')} — {mitre.get('name', '')}",
            source_ip=source.get("ip", ""),
            source_domain=source.get("domain", ""),
            target_host=target.get("host", ""),
            target_user=target.get("user", ""),
            target_department=target.get("department", ""),
            raw_log_snippet=self._scenario.get("raw_log", ""),
            investigation_history=[],
            time_steps_elapsed=0,
            max_steps=self._max_steps,
            actions_taken=[],
            done=False,
            reward=0.0,
            metadata={
                "status": "new_alert",
                "category": self._scenario.get("category", ""),
                "task_name": self._task_name,
            },
        )

    def step(
        self,
        action: SecOpsAction,
        timeout_s: Optional[float] = None,
        **kwargs: Any,
    ) -> SecOpsObservation:
        """Execute an action in the environment."""
        if self._done:
            return self._make_observation(
                reward=0.0, done=True, status="episode_already_done"
            )

        action_id = action.action_id
        action_name = ACTION_NAMES.get(action_id, "unknown")
        self._state.step_count += 1

        # Get investigation result if applicable
        inv_result = None
        if action_id in SAFE_ACTIONS and action_name not in self._state.actions_taken:
            inv_result = get_investigation_result(self._scenario, action_id)

        # Compute reward
        reward, status = compute_reward(
            scenario=self._scenario,
            action_id=action_id,
            step_count=self._state.step_count,
            max_steps=self._max_steps,
            actions_taken=self._state.actions_taken,
            investigation_count=self._state.investigation_count,
        )

        # Update state
        if action_id in SAFE_ACTIONS and action_name not in self._state.actions_taken:
            self._state.actions_taken.append(action_name)
            self._state.investigation_count += 1
        elif action_name not in self._state.actions_taken:
            self._state.actions_taken.append(action_name)

        self._state.cumulative_reward += reward

        # Determine if episode ends
        done = status in {
            "true_positive",
            "false_positive",
            "true_negative",
            "false_negative",
            "escalated_true_threat",
            "escalated_false_alarm",
            "timeout_breach",
            "timeout_benign",
        }

        self._done = done
        obs = self._make_observation(
            reward=reward, done=done, status=status, inv_result=inv_result
        )

        if self.rubric is not None:
            self.rubric(action, obs)

        return obs

    def _make_observation(
        self,
        reward: float,
        done: bool,
        status: str,
        inv_result: Optional[dict] = None,
    ) -> SecOpsObservation:
        """Build observation from current state."""
        alert = self._scenario.get("alert", {})
        source = self._scenario.get("source", {})
        target = self._scenario.get("target", {})
        mitre = self._scenario.get("mitre", {})

        # Build investigation history for observation
        inv_history = []
        for act_name in self._state.actions_taken:
            if act_name in {ACTION_NAMES[i] for i in SAFE_ACTIONS}:
                data = self._scenario.get("investigate", {}).get(act_name, "")
                if data:
                    act_id = next(
                        (k for k, v in ACTION_NAMES.items() if v == act_name), -1
                    )
                    from .investigation_engine import ACTION_DESCRIPTIONS
                    inv_history.append({
                        "action_name": act_name,
                        "description": ACTION_DESCRIPTIONS.get(act_id, act_name),
                        "result": data,
                    })

        return SecOpsObservation(
            alert_id=f"ALT-{self._state.scenario_id}",
            rule_triggered=alert.get("rule", ""),
            severity=self._scenario.get("severity", "medium"),
            alert_description=alert.get("description", ""),
            mitre_tactic=mitre.get("tactic", ""),
            mitre_technique=f"{mitre.get('technique', '')} — {mitre.get('name', '')}",
            source_ip=source.get("ip", ""),
            source_domain=source.get("domain", ""),
            target_host=target.get("host", ""),
            target_user=target.get("user", ""),
            target_department=target.get("department", ""),
            raw_log_snippet=self._scenario.get("raw_log", ""),
            investigation_history=inv_history,
            time_steps_elapsed=self._state.step_count,
            max_steps=self._max_steps,
            actions_taken=list(self._state.actions_taken),
            done=done,
            reward=reward,
            metadata={
                "status": status,
                "category": self._scenario.get("category", ""),
                "task_name": self._task_name,
                "cumulative_reward": self._state.cumulative_reward,
                "investigation_count": self._state.investigation_count,
            },
        )

    def close(self) -> None:
        pass

    @property
    def state(self) -> SecOpsState:
        return self._state
