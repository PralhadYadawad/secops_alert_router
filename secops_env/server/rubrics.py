"""SecOps-specific rubrics for reward computation.

Provides SecOpsTriageRubric that extends ExponentialDiscountingTrajectoryRubric
for temporally-discounted rewards in security triage episodes.
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


class SecOpsTriageRubric(ExponentialDiscountingTrajectoryRubric):
    """Score triage episode with temporal discounting.

    Uses gamma=0.95 (higher than chess default) because episodes are short (1-5 steps).
    The environment computes rewards directly; this rubric provides trajectory-level
    credit assignment for training infrastructure.

    Terminal rewards (from environment):
    - True Positive: +10 (or +12 with speed bonus)
    - False Positive: -10
    - True Negative: +1
    - False Negative: -50
    """

    def __init__(self, gamma: float = 0.95):
        super().__init__(gamma=gamma)

    def score_trajectory(self, trajectory: List[Tuple[Any, Any]]) -> float:
        """Score based on episode outcome from final observation.

        Args:
            trajectory: List of (action, observation) tuples.

        Returns:
            Terminal reward from the final observation.
        """
        if not trajectory:
            return 0.0
        _, final_obs = trajectory[-1]
        return getattr(final_obs, "reward", 0.0)
