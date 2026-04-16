"""Trajectory rubric for SecOps Alert Router V2.

Normalizes cumulative episode reward to the (0.01, 0.99) range
required by the OpenEnv evaluator.
"""

from typing import Any, List, Tuple

try:
    from openenv.core.rubrics.trajectory import ExponentialDiscountingTrajectoryRubric
except ModuleNotFoundError:

    class ExponentialDiscountingTrajectoryRubric:
        """Compatibility fallback when the installed core lacks rubrics."""

        def __init__(self, gamma: float = 0.99, intermediate_reward: float = 0.0):
            self.gamma = gamma
            self.intermediate_reward = intermediate_reward
            self._trajectory: List[Tuple[Any, Any]] = []

        def __call__(self, action: Any, observation: Any) -> float:
            self._trajectory.append((action, observation))
            if getattr(observation, "done", False):
                return self.score_trajectory(self._trajectory)
            return self.intermediate_reward

        def reset(self) -> None:
            self._trajectory = []

        def compute_step_rewards(self) -> List[float]:
            if not self._trajectory:
                return []
            final_score = self.score_trajectory(self._trajectory)
            total_steps = len(self._trajectory)
            return [
                self.gamma ** (total_steps - 1 - step_index) * final_score
                for step_index in range(total_steps)
            ]


# V2 reward range: worst = -100 (compliance breach on critical), best = +20 (perfect fast containment)
MIN_RAW_REWARD = -100.0
MAX_RAW_REWARD = 20.0


class SecOpsTriageRubric(ExponentialDiscountingTrajectoryRubric):
    """Score triage trajectory with temporal discounting.

    Uses gamma=0.95 for short episodes (1-15 steps). Maps cumulative
    reward from [-100, +20] to (0.01, 0.99).
    """

    def __init__(self, gamma: float = 0.95):
        super().__init__(gamma=gamma)

    def score_trajectory(self, trajectory: List[Tuple[Any, Any]]) -> float:
        """Score based on cumulative reward from the trajectory.

        Returns:
            Normalized score strictly in (0, 1).
        """
        if not trajectory:
            return 0.01

        _, final_obs = trajectory[-1]

        # Try cumulative reward from metadata first, fall back to final reward
        cumulative = getattr(final_obs, "metadata", {}).get("cumulative_reward", None)
        raw = cumulative if cumulative is not None else getattr(final_obs, "reward", 0.0)

        normalized = (raw - MIN_RAW_REWARD) / (MAX_RAW_REWARD - MIN_RAW_REWARD)
        return max(0.01, min(0.99, normalized))
