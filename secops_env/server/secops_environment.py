"""
SecOps Alert Triage Environment for OpenEnv.

A cybersecurity incident triage RL environment where an agent learns to
balance investigation speed (MTTC) against accuracy (False Positive Rate).
"""

import uuid
from typing import Any, Optional

from openenv.core.env_server import Environment

from ..models import SecOpsAction, SecOpsObservation, SecOpsState
from .alert_generator import (
    ACTION_NAMES,
    ALERT_TYPE_NAMES,
    CONFIDENCE_BOOST_BENIGN,
    CONFIDENCE_BOOST_TRUE,
    RESOLVE_ACTION,
    RISKY_ACTIONS,
    SAFE_ACTIONS,
    SEVERITY_NAMES,
    AlertGenerator,
)
from .rubrics import SecOpsTriageRubric
from .tasks import TASKS


class SecOpsEnvironment(Environment):
    """
    Cybersecurity incident triage environment.

    The agent receives security alerts and must decide whether to:
    - Investigate (safe actions) to gather evidence
    - Contain (risky actions) to stop a threat
    - Resolve (acknowledge as benign)

    Reward structure balances speed vs accuracy:
    - True Positive containment: +10 (+2 bonus for fast critical response)
    - False Positive containment: -10 (business disruption)
    - True Negative resolution: +1
    - False Negative (missed threat): -50
    - Time step penalty: -1 per investigation action
    - Procedure violation (contain without evidence): -5
    """

    def __init__(self, task_name: str = "mixed-triage", max_steps: int = 5, seed: Optional[int] = None):
        super().__init__(rubric=SecOpsTriageRubric())
        task_config = TASKS.get(task_name, TASKS["mixed-triage"])
        self._task_name = task_name
        self._max_steps = task_config.get("max_steps", max_steps)
        self._alert_gen = AlertGenerator(
            seed=seed,
            severity_weights=task_config.get("severity_weights"),
            threat_probability=task_config.get("threat_probability"),
        )
        self._is_true_threat = False
        self._done = False
        self._last_action_error = None
        self._state = SecOpsState()
        self.reset()

    def reset(
        self,
        seed: Optional[int] = None,
        episode_id: Optional[str] = None,
        **kwargs: Any,
    ) -> SecOpsObservation:
        """Reset environment with a new random alert."""
        # Reset rubric
        if self.rubric is not None:
            self.rubric.reset()

        # Generate new alert
        alert = self._alert_gen.generate()

        self._is_true_threat = alert["is_true_threat"]
        self._done = False
        self._last_action_error = None

        self._state = SecOpsState(
            episode_id=episode_id or str(uuid.uuid4()),
            step_count=0,
            alert_type=alert["alert_type"],
            severity=alert["severity"],
            is_true_threat=alert["is_true_threat"],
            confidence_score=0.0,
            evidence_collected=[],
            max_steps=self._max_steps,
        )

        return SecOpsObservation(
            alert_type=alert["alert_type"],
            severity=alert["severity"],
            confidence_score=0.0,
            time_steps_elapsed=0,
            evidence_flags=[False, False, False, False],
            done=False,
            reward=0.0,
            metadata={
                "status": "new_alert",
                "alert_type_name": ALERT_TYPE_NAMES[alert["alert_type"]],
                "severity_name": SEVERITY_NAMES[alert["severity"]],
            },
        )

    def step(
        self,
        action: SecOpsAction,
        timeout_s: Optional[float] = None,
        **kwargs: Any,
    ) -> SecOpsObservation:
        """Execute an action in the environment."""
        self._last_action_error = None

        if self._done:
            self._last_action_error = "Episode already finished"
            return self._make_observation(reward=0.0, done=True,
                                          status="episode_already_done")

        action_id = action.action_id
        self._state.step_count += 1
        reward = 0.0
        done = False
        status = ""

        if action_id in SAFE_ACTIONS:
            action_name = ACTION_NAMES[action_id]

            # Check if already performed this specific action
            if action_name in self._state.evidence_collected:
                reward = -0.5
                status = "duplicate_action"
                self._last_action_error = "Duplicate action: already performed this investigation"
            else:
                # Collect evidence
                self._state.evidence_collected.append(action_name)

                # Update confidence
                if self._is_true_threat:
                    boost = CONFIDENCE_BOOST_TRUE[action_id]
                else:
                    boost = CONFIDENCE_BOOST_BENIGN

                self._state.confidence_score = min(
                    1.0, self._state.confidence_score + boost
                )

                reward = -1.0  # Time step penalty
                status = "evidence_collected"

            # Check timeout AFTER processing safe action
            if self._state.step_count >= self._max_steps:
                done = True
                if self._is_true_threat:
                    reward = -50.0  # Failed to contain — breach
                    status = "timeout_breach"
                else:
                    reward = 1.0  # Benign alert timed out, acceptable
                    status = "timeout_benign"

        elif action_id in RISKY_ACTIONS:
            # Must have at least 1 piece of evidence
            if len(self._state.evidence_collected) == 0:
                reward = -5.0  # Procedure violation
                status = "procedure_violation"
                self._last_action_error = "Procedure violation: must investigate before containment"
                # NOT terminal — but check hard timeout
                if self._state.step_count >= self._max_steps:
                    done = True
                    if self._is_true_threat:
                        reward = -50.0
                        status = "timeout_breach"
                    else:
                        reward = 1.0
                        status = "timeout_benign"
            else:
                done = True
                if self._is_true_threat:
                    reward = 10.0  # True positive containment
                    status = "true_positive"
                    # Speed bonus for fast critical threat response
                    if self._state.severity == 2 and self._state.step_count <= 3:
                        reward += 2.0
                        status = "true_positive_fast"
                else:
                    reward = -10.0  # False positive — business disruption
                    status = "false_positive"

        elif action_id == RESOLVE_ACTION:
            done = True
            if not self._is_true_threat:
                reward = 1.0  # Correct resolution
                status = "true_negative"
            else:
                reward = -50.0  # Missed a real threat!
                status = "false_negative"

        self._done = done
        obs = self._make_observation(reward=reward, done=done, status=status)

        # Apply rubric for trajectory tracking
        if self.rubric is not None:
            self.rubric(action, obs)

        return obs

    def _make_observation(
        self, reward: float, done: bool, status: str
    ) -> SecOpsObservation:
        """Build observation from current state."""
        # Build evidence flags from collected evidence
        evidence_flags = [
            ACTION_NAMES[i] in self._state.evidence_collected
            for i in range(4)
        ]

        return SecOpsObservation(
            alert_type=self._state.alert_type,
            severity=self._state.severity,
            confidence_score=self._state.confidence_score,
            time_steps_elapsed=self._state.step_count,
            evidence_flags=evidence_flags,
            done=done,
            reward=reward,
            metadata={
                "status": status,
                "alert_type_name": ALERT_TYPE_NAMES[self._state.alert_type],
                "severity_name": SEVERITY_NAMES[self._state.severity],
                "evidence_collected": list(self._state.evidence_collected),
                "task_name": self._task_name,
                "last_action_error": self._last_action_error,
            },
        )

    def close(self) -> None:
        """Clean up environment resources."""
        pass

    @property
    def state(self) -> SecOpsState:
        """Get current environment state."""
        return self._state
