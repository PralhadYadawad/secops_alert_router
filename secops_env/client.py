"""SecOps Alert Triage Environment Client (V2).

Provides the client for connecting to a SecOps Environment server
via WebSocket for persistent sessions.
"""

from __future__ import annotations

from typing import Any, Dict

from openenv.core.client_types import StepResult
from openenv.core.env_client import EnvClient

from .models import SecOpsAction, SecOpsObservation, SecOpsState


class SecOpsEnv(EnvClient[SecOpsAction, SecOpsObservation, SecOpsState]):
    """Client for SecOps Alert Triage Environment V2.

    Example:
        >>> with SecOpsEnv(base_url="http://localhost:8000") as client:
        ...     result = client.reset()
        ...     print(result.observation.rule_triggered)
        ...     result = client.step(SecOpsAction(action_id=1))
        ...     print(result.reward, result.done)
    """

    def _step_payload(self, action: SecOpsAction) -> Dict[str, Any]:
        """Convert SecOpsAction to JSON payload."""
        return {"action_id": action.action_id}

    def _parse_result(self, payload: Dict[str, Any]) -> StepResult[SecOpsObservation]:
        """Parse server response into StepResult[SecOpsObservation].

        The OpenEnv /step endpoint returns:
            {"observation": {...}, "reward": float, "done": bool}
        reward and done are top-level, NOT inside observation.
        """
        obs_data = payload.get("observation", {})

        observation = SecOpsObservation(
            alert_id=obs_data.get("alert_id", ""),
            rule_triggered=obs_data.get("rule_triggered", ""),
            severity=obs_data.get("severity", "medium"),
            alert_description=obs_data.get("alert_description", ""),
            mitre_tactic=obs_data.get("mitre_tactic", ""),
            mitre_technique=obs_data.get("mitre_technique", ""),
            source_ip=obs_data.get("source_ip", ""),
            source_domain=obs_data.get("source_domain", ""),
            target_host=obs_data.get("target_host", ""),
            target_user=obs_data.get("target_user", ""),
            target_department=obs_data.get("target_department", ""),
            raw_log_snippet=obs_data.get("raw_log_snippet", ""),
            data_classification=obs_data.get("data_classification", ""),
            regulatory_framework=obs_data.get("regulatory_framework", ""),
            breach_notification_window=obs_data.get("breach_notification_window", ""),
            investigation_history=obs_data.get("investigation_history", []),
            time_steps_elapsed=obs_data.get("time_steps_elapsed", 0),
            max_steps=obs_data.get("max_steps", 10),
            actions_taken=obs_data.get("actions_taken", []),
            outcome_status=obs_data.get("outcome_status", ""),
            alert_category=obs_data.get("alert_category", ""),
            investigation_count=obs_data.get("investigation_count", 0),
            episode_cumulative_reward=obs_data.get("episode_cumulative_reward", 0.0),
            # done/reward from top-level, fallback to obs
            done=payload.get("done", obs_data.get("done", False)),
            reward=payload.get("reward", obs_data.get("reward", 0.0)),
            metadata=obs_data.get("metadata", {}),
        )

        return StepResult(
            observation=observation,
            reward=payload.get("reward", observation.reward),
            done=payload.get("done", observation.done),
        )

    def _parse_state(self, payload: Dict[str, Any]) -> SecOpsState:
        """Parse server response into SecOpsState."""
        return SecOpsState(
            alert_type=payload.get("alert_type", ""),
            severity=payload.get("severity", "medium"),
            is_true_threat=payload.get("is_true_threat", False),
            scenario_id=payload.get("scenario_id", ""),
            max_steps=payload.get("max_steps", 10),
            actions_taken=payload.get("actions_taken", []),
            investigation_count=payload.get("investigation_count", 0),
            cumulative_reward=payload.get("cumulative_reward", 0.0),
            target_criticality=payload.get("target_criticality", "medium"),
        )
