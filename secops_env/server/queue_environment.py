"""Multi-alert queue triage environment for SecOps Alert Router V2.

The agent receives a queue of N concurrent alerts and must triage all of them.
They can switch between alerts, prioritize critical ones first, and earn bonus
rewards for clearing the entire queue efficiently.
"""

from typing import Any, Optional

from openenv.core.env_server import Environment

from ..models import QueueAction, QueueObservation, SecOpsAction, SecOpsObservation
from .rubrics import SecOpsTriageRubric
from .secops_environment import SecOpsEnvironment
from .tasks import TASKS


class QueueEnvironment(Environment):
    """Multi-alert queue triage: agent triages N concurrent alerts.

    Each alert slot wraps a separate ``SecOpsEnvironment`` instance.
    The agent acts on one alert at a time via ``alert_index`` in
    ``QueueAction``.  Episode ends when all slots are resolved or
    ``total_steps_max`` is reached.

    Reward shaping:
        - Per-slot: delegated to the inner SecOpsEnvironment's reward engine.
        - Queue completion bonus: ``+5 * (resolved / queue_size)`` at episode end.
        - Priority bonus: ``+2`` if a critical alert resolved before any medium.
        - Switch penalty: ``-0.5`` for changing ``alert_index`` without resolving
          the current alert.
    """

    def __init__(
        self,
        task_name: str = "queue-triage",
        queue_size: int = 5,
        max_total_steps: int = 40,
        seed: Optional[int] = None,
    ):
        """Initialize the queue triage environment.

        Args:
            task_name: Name of the task configuration to load from ``TASKS``.
            queue_size: Number of concurrent alert slots in the queue.
            max_total_steps: Total step budget across all alert slots.
            seed: Optional random seed for reproducibility.
        """
        super().__init__(rubric=SecOpsTriageRubric())
        task_config = TASKS.get(task_name, TASKS.get("queue-triage", {}))
        self._queue_size = task_config.get("queue_size", queue_size)
        self._max_total_steps = task_config.get("max_total_steps", max_total_steps)
        self._task_name = task_name
        self._seed = seed

        # Inner environment configuration
        self._inner_categories = task_config.get("categories")
        self._inner_difficulties = task_config.get("difficulties")

        self._slots: list[dict] = []
        self._active_index = 0
        self._total_steps = 0
        self._done = False
        self._previous_index = 0
        self._critical_resolved_before_medium = False

        self.reset()

    def reset(
        self,
        seed: Optional[int] = None,
        episode_id: Optional[str] = None,
        **kwargs: Any,
    ) -> QueueObservation:
        """Initialize the queue with N fresh alert environments.

        Each slot gets its own ``SecOpsEnvironment`` instance so that
        investigation state, reward tracking, and terminal conditions are
        fully independent.

        Args:
            seed: Optional random seed.  Each slot receives ``seed + i`` so
                that alerts are deterministic but distinct.
            episode_id: Optional episode identifier (passed through to inner
                environments).
            **kwargs: Additional keyword arguments forwarded to inner resets.

        Returns:
            A ``QueueObservation`` with the initial queue state.
        """
        self._slots = []
        for i in range(self._queue_size):
            # Give inner envs a step budget large enough that they never fire their
            # own timeout penalty — the outer _max_total_steps budget controls
            # episode termination, preventing double-penalty.
            env = SecOpsEnvironment(
                task_name=self._task_name,
                seed=(seed + i) if seed else None,
                max_steps=self._max_total_steps,
            )
            obs = env.reset()
            self._slots.append({
                "env": env,
                "obs": obs,
                "done": False,
                "outcome": "",
                "steps_used": 0,
                "cumulative_reward": 0.0,
            })
        self._active_index = 0
        self._total_steps = 0
        self._done = False
        self._previous_index = 0
        self._critical_resolved_before_medium = False
        return self._build_queue_obs(reward=0.0, done=False)

    def step(self, action: QueueAction, **kwargs: Any) -> QueueObservation:
        """Route an action to the specified alert slot and return the result.

        The method applies a switch penalty if the agent changes focus to a
        different alert without resolving the previous one.  When the episode
        ends (all slots resolved or budget exhausted), a queue completion
        bonus is added.

        Args:
            action: A ``QueueAction`` containing the ``action_id`` and the
                ``alert_index`` indicating which slot to act on.
            **kwargs: Additional keyword arguments (unused).

        Returns:
            A ``QueueObservation`` reflecting the updated queue state.
        """
        if self._done:
            return self._build_queue_obs(reward=0.0, done=True)

        idx = min(action.alert_index, len(self._slots) - 1)
        slot = self._slots[idx]

        # Switch penalty: changed alert without resolving the previous one
        switch_penalty = 0.0
        if idx != self._previous_index and not self._slots[self._previous_index]["done"]:
            switch_penalty = -0.5
        self._previous_index = idx
        self._active_index = idx

        # If this slot is already done, small penalty for wasting a step
        if slot["done"]:
            self._total_steps += 1
            return self._build_queue_obs(reward=-1.0, done=self._check_episode_done())

        # Delegate to inner environment
        inner_action = SecOpsAction(action_id=action.action_id)
        inner_obs = slot["env"].step(inner_action)

        slot["obs"] = inner_obs
        slot["steps_used"] += 1
        slot["cumulative_reward"] += inner_obs.reward
        self._total_steps += 1

        reward = inner_obs.reward + switch_penalty

        if inner_obs.done:
            slot["done"] = True
            slot["outcome"] = (inner_obs.metadata or {}).get("status", "unknown")

            # Track priority ordering for bonus
            sev = inner_obs.severity
            if sev == "critical":
                all_mediums_done = all(
                    s["done"]
                    for s in self._slots
                    if s["obs"].severity == "medium"
                )
                if not all_mediums_done:
                    self._critical_resolved_before_medium = True

        episode_done = self._check_episode_done()
        if episode_done:
            reward += self._queue_completion_bonus()

        return self._build_queue_obs(reward=reward, done=episode_done)

    def _check_episode_done(self) -> bool:
        """Check whether the queue episode should end.

        The episode ends when every alert slot has been resolved or the
        total step budget is exhausted.

        Returns:
            ``True`` if the episode is over, ``False`` otherwise.
        """
        all_resolved = all(s["done"] for s in self._slots)
        budget_exhausted = self._total_steps >= self._max_total_steps
        self._done = all_resolved or budget_exhausted
        return self._done

    def _queue_completion_bonus(self) -> float:
        """Compute the end-of-episode bonus for queue clearance.

        The bonus scales linearly with the fraction of resolved alerts and
        adds an extra ``+2`` if critical alerts were resolved before medium
        ones (priority ordering incentive).

        Returns:
            The bonus reward value.
        """
        resolved = sum(1 for s in self._slots if s["done"])
        ratio = resolved / self._queue_size
        bonus = 5.0 * ratio
        if self._critical_resolved_before_medium:
            bonus += 2.0  # Priority ordering bonus
        return bonus

    def _build_queue_obs(self, reward: float, done: bool) -> QueueObservation:
        """Construct a ``QueueObservation`` from the current slot states.

        Args:
            reward: The reward for the current step.
            done: Whether the episode has ended.

        Returns:
            A ``QueueObservation`` containing the active alert detail,
            queue summary, and step accounting.
        """
        # Queue summary: one entry per slot
        summary = []
        for i, slot in enumerate(self._slots):
            obs = slot["obs"]
            summary.append({
                "alert_id": obs.alert_id if hasattr(obs, "alert_id") else f"SLOT-{i}",
                "severity": obs.severity if hasattr(obs, "severity") else "medium",
                "category": (obs.metadata or {}).get("category", ""),
                "done": slot["done"],
                "outcome": slot["outcome"],
                "steps_used": slot["steps_used"],
            })

        # Active alert observation as dict
        active_slot = self._slots[self._active_index]
        active_obs = active_slot["obs"]
        active_dict = (
            active_obs.model_dump() if hasattr(active_obs, "model_dump") else {}
        )

        alerts_remaining = sum(1 for s in self._slots if not s["done"])

        total_cumulative = sum(s["cumulative_reward"] for s in self._slots)
        # Store per-slot average so SecOpsTriageRubric's [-100, +20] normalization
        # remains discriminative across queue sizes (raw total would overflow the range).
        avg_cumulative = total_cumulative / self._queue_size if self._queue_size else 0.0
        return QueueObservation(
            active_alert=active_dict,
            queue_summary=summary,
            queue_size=self._queue_size,
            alerts_remaining=alerts_remaining,
            total_steps_used=self._total_steps,
            total_steps_max=self._max_total_steps,
            done=done,
            reward=reward,
            metadata={
                "active_index": self._active_index,
                "task_name": self._task_name,
                "cumulative_reward": avg_cumulative,
                "total_cumulative_reward": total_cumulative,
            },
        )

    def close(self) -> None:
        """Clean up all inner slot environments."""
        for slot in self._slots:
            slot["env"].close()

    @property
    def state(self):
        """Return the active slot's internal state for debugging.

        Returns:
            The ``SecOpsState`` of the currently active inner environment,
            or ``None`` if no slots have been initialized.
        """
        if self._slots:
            return self._slots[self._active_index]["env"].state
        return None
