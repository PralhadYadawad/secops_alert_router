"""
SecOps Alert Triage Environment Client.

Provides the client for connecting to a SecOps Environment server
via WebSocket for persistent sessions.
"""

from __future__ import annotations

from typing import Any, Dict

from openenv.core.client_types import StepResult
from openenv.core.env_client import EnvClient

from .models import SecOpsAction, SecOpsObservation, SecOpsState


class SecOpsEnv(EnvClient[SecOpsAction, SecOpsObservation, SecOpsState]):
    """
    Client for SecOps Alert Triage Environment.

    Example:
        >>> with SecOpsEnv(base_url="http://localhost:8000") as client:
        ...     result = client.reset()
        ...     print(result.observation.alert_type)
        ...     result = client.step(SecOpsAction(action_id=1))
        ...     print(result.reward, result.done)
    """

    def _step_payload(self, action: SecOpsAction) -> Dict[str, Any]:
        """Convert SecOpsAction to JSON payload."""
        return {"action_id": action.action_id}

    def _parse_result(self, payload: Dict[str, Any]) -> StepResult[SecOpsObservation]:
        """Parse server response into StepResult[SecOpsObservation]."""
        obs_data = payload.get("observation", {})

        observation = SecOpsObservation(
            alert_type=obs_data.get("alert_type", 0),
            severity=obs_data.get("severity", 0),
            confidence_score=obs_data.get("confidence_score", 0.0),
            time_steps_elapsed=obs_data.get("time_steps_elapsed", 0),
            evidence_flags=obs_data.get("evidence_flags", [False, False, False, False]),
            done=obs_data.get("done", False),
            reward=obs_data.get("reward", 0.0),
            metadata=obs_data.get("metadata", {}),
        )

        return StepResult(
            observation=observation,
            reward=observation.reward,
            done=observation.done,
        )

    def _parse_state(self, payload: Dict[str, Any]) -> SecOpsState:
        """Parse server response into SecOpsState."""
        return SecOpsState(
            episode_id=payload.get("episode_id", ""),
            step_count=payload.get("step_count", 0),
            alert_type=payload.get("alert_type", 0),
            severity=payload.get("severity", 0),
            is_true_threat=payload.get("is_true_threat", False),
            confidence_score=payload.get("confidence_score", 0.0),
            evidence_collected=payload.get("evidence_collected", []),
            max_steps=payload.get("max_steps", 5),
        )
