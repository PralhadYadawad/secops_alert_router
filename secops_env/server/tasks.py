"""Task definitions and grading for the SecOps triage environment."""

TASKS = {
    "benign-filter": {
        "num_episodes": 5,
        "severity_weights": [0.80, 0.15, 0.05],
        "threat_probability": {0: 0.20, 1: 0.30, 2: 0.50},
        "max_steps": 5,
        "description": "Easy: Correctly identify and resolve benign medium-severity alerts",
    },
    "mixed-triage": {
        "num_episodes": 10,
        "severity_weights": [0.33, 0.34, 0.33],
        "threat_probability": {0: 0.50, 1: 0.50, 2: 0.50},
        "max_steps": 5,
        "description": "Medium: Triage mixed-severity alerts balancing investigation speed vs accuracy",
    },
    "critical-escalation": {
        "num_episodes": 10,
        "severity_weights": [0.05, 0.15, 0.80],
        "threat_probability": {0: 0.80, 1: 0.85, 2: 0.90},
        "max_steps": 5,
        "description": "Hard: Rapidly contain critical threats with minimal false positives under time pressure",
    },
}

TASK_NAMES = list(TASKS.keys())

CORRECT_OUTCOMES = {"true_positive", "true_positive_fast", "true_negative", "timeout_benign"}


def grade_task(task_name: str, episode_results: list[dict]) -> float:
    """Grade a completed task based on episode results.

    Args:
        task_name: One of the keys in TASKS.
        episode_results: List of dicts with keys:
            reward (float), steps (int), outcome (str), max_steps (int)

    Returns:
        Score clamped to [0.0, 1.0].
    """
    total = len(episode_results)
    if total == 0:
        return 0.0

    correct_count = sum(1 for ep in episode_results if ep["outcome"] in CORRECT_OUTCOMES)
    accuracy = correct_count / total

    avg_steps = sum(ep["steps"] for ep in episode_results) / total
    max_steps = episode_results[0]["max_steps"]
    avg_speed = 1.0 - (avg_steps / max_steps)

    if task_name == "benign-filter":
        score = 0.7 * accuracy + 0.3 * avg_speed

    elif task_name == "mixed-triage":
        fp_count = sum(1 for ep in episode_results if ep["outcome"] == "false_positive")
        false_positive_rate = fp_count / total
        score = 0.5 * accuracy + 0.3 * avg_speed + 0.2 * (1.0 - false_positive_rate)

    elif task_name == "critical-escalation":
        fn_count = sum(1 for ep in episode_results if ep["outcome"] == "false_negative")
        false_negative_rate = fn_count / total
        score = 0.4 * accuracy + 0.3 * avg_speed + 0.3 * (1.0 - false_negative_rate)

    else:
        score = accuracy

    return max(0.0, min(1.0, score))
