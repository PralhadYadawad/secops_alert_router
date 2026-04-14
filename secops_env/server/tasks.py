"""Task definitions and grading for SecOps Alert Router V2.

Six tasks with genuine difficulty progression from spam-filter (easy)
to adversarial-evasion (expert). Graders score based on accuracy,
speed, evidence quality, and proportional response.
"""

TASKS = {
    "spam-filter": {
        "num_episodes": 5,
        "categories": ["phishing", "ddos"],
        "difficulties": ["easy"],
        "threat_ratio": 0.30,
        "max_steps": 8,
        "description": "Easy: Identify and dismiss obvious spam/false-positive alerts with clear indicators",
    },
    "phishing-triage": {
        "num_episodes": 8,
        "categories": ["phishing"],
        "difficulties": ["easy", "easy-medium", "medium"],
        "threat_ratio": 0.50,
        "max_steps": 10,
        "description": "Easy-Medium: Investigate phishing alerts with varying ambiguity levels",
    },
    "insider-threat": {
        "num_episodes": 8,
        "categories": ["insider_threat"],
        "difficulties": ["medium", "medium-hard"],
        "threat_ratio": 0.50,
        "max_steps": 10,
        "description": "Medium: Distinguish legitimate employee behavior from insider threats",
    },
    "lateral-movement": {
        "num_episodes": 8,
        "categories": ["lateral_movement", "malware"],
        "difficulties": ["medium", "medium-hard", "hard"],
        "threat_ratio": 0.70,
        "max_steps": 12,
        "description": "Medium-Hard: Detect attackers moving through the network across multiple hosts",
    },
    "apt-campaign": {
        "num_episodes": 10,
        "categories": ["malware", "lateral_movement", "data_exfiltration"],
        "difficulties": ["hard", "medium-hard"],
        "threat_ratio": 0.75,
        "max_steps": 12,
        "description": "Hard: Investigate multi-stage attacks requiring correlation across alerts and systems",
    },
    "adversarial-evasion": {
        "num_episodes": 10,
        "categories": ["evasion", "data_exfiltration"],
        "difficulties": ["hard", "expert"],
        "threat_ratio": 0.80,
        "max_steps": 15,
        "description": "Expert: Detect adversaries using LOLBins, fileless malware, and encoded payloads that evade standard detection",
    },
}

TASK_NAMES = list(TASKS.keys())

# Outcomes that count as correct decisions
CORRECT_OUTCOMES = {
    "true_positive",
    "true_negative",
    "escalated_true_threat",
    "timeout_benign",
}

# Outcomes that are partially correct (not wrong, but not optimal)
PARTIAL_OUTCOMES = {
    "escalated_false_alarm",  # Unnecessary escalation but not harmful
}

# Decisive correct outcomes (better than escalation)
DECISIVE_CORRECT = {"true_positive", "true_negative"}


def grade_task(task_name: str, episode_results: list[dict]) -> float:
    """Grade a completed task based on episode results.

    Scoring dimensions:
    - Accuracy: correct decisions / total episodes
    - Speed: how quickly episodes are resolved
    - Evidence quality: investigation depth before decisive actions
    - Decisive action rate: direct containment/resolution vs escalation

    Returns:
        Score strictly in (0, 1).
    """
    total = len(episode_results)
    if total == 0:
        return 0.01

    correct_count = sum(
        1 for ep in episode_results if ep["outcome"] in CORRECT_OUTCOMES
    )
    partial_count = sum(
        1 for ep in episode_results if ep["outcome"] in PARTIAL_OUTCOMES
    )
    decisive_count = sum(
        1 for ep in episode_results if ep["outcome"] in DECISIVE_CORRECT
    )

    accuracy = (correct_count + 0.5 * partial_count) / total
    decisive_rate = decisive_count / total if total > 0 else 0.0

    # Speed: ratio of steps used vs max steps
    avg_steps = sum(ep["steps"] for ep in episode_results) / total
    max_steps = episode_results[0].get("max_steps", 10)
    speed = 1.0 - (avg_steps / max_steps)

    # Evidence quality: average investigation actions before resolution
    avg_evidence = sum(ep.get("investigation_count", 0) for ep in episode_results) / total
    evidence_quality = min(avg_evidence / 3.0, 1.0)  # Normalize: 3 investigations = full score

    # Task-specific weighting
    if task_name == "spam-filter":
        # Easy: mostly about accuracy and speed
        score = 0.50 * accuracy + 0.30 * speed + 0.20 * evidence_quality

    elif task_name == "phishing-triage":
        # Balanced: accuracy + evidence + speed + decisiveness
        fp_count = sum(1 for ep in episode_results if ep["outcome"] == "false_positive")
        fpr = fp_count / total
        score = 0.35 * accuracy + 0.15 * speed + 0.20 * evidence_quality + 0.15 * (1.0 - fpr) + 0.15 * decisive_rate

    elif task_name == "insider-threat":
        # Evidence-heavy: need careful investigation + decisive action
        fp_count = sum(1 for ep in episode_results if ep["outcome"] == "false_positive")
        fn_count = sum(1 for ep in episode_results if ep["outcome"] == "false_negative")
        fpr = fp_count / total
        fnr = fn_count / total
        score = 0.30 * accuracy + 0.20 * evidence_quality + 0.15 * (1.0 - fpr) + 0.15 * (1.0 - fnr) + 0.20 * decisive_rate

    elif task_name == "lateral-movement":
        # Speed + accuracy: threats need fast containment
        fn_count = sum(1 for ep in episode_results if ep["outcome"] in {"false_negative", "timeout_breach"})
        miss_rate = fn_count / total
        score = 0.35 * accuracy + 0.25 * speed + 0.20 * (1.0 - miss_rate) + 0.20 * decisive_rate

    elif task_name == "apt-campaign":
        # Deep investigation + decisive action
        fn_count = sum(1 for ep in episode_results if ep["outcome"] in {"false_negative", "timeout_breach"})
        miss_rate = fn_count / total
        score = 0.30 * accuracy + 0.25 * evidence_quality + 0.25 * (1.0 - miss_rate) + 0.20 * decisive_rate

    elif task_name == "adversarial-evasion":
        # Hardest: everything matters, heavy weight on not missing threats
        fn_count = sum(1 for ep in episode_results if ep["outcome"] in {"false_negative", "timeout_breach"})
        miss_rate = fn_count / total
        score = 0.30 * accuracy + 0.25 * evidence_quality + 0.25 * (1.0 - miss_rate) + 0.20 * decisive_rate

    else:
        score = accuracy

    return max(0.01, min(0.99, score))
