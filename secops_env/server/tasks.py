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
    "compliance-triage": {
        "num_episodes": 8,
        "categories": ["data_exfiltration", "insider_threat", "phishing"],
        "difficulties": ["medium", "hard"],
        "threat_ratio": 0.65,
        "max_steps": 12,
        "description": (
            "Triage alerts involving regulated data (GDPR/HIPAA/PCI-DSS). "
            "Breaching compliance-tagged data carries amplified penalties."
        ),
    },
    "cloud-native": {
        "num_episodes": 8,
        "categories": ["cloud"],
        "difficulties": ["medium", "medium-hard", "hard"],
        "threat_ratio": 0.65,
        "max_steps": 12,
        "description": (
            "Investigate AWS, Azure, and Kubernetes security alerts. "
            "Distinguish authorized DevOps operations from IAM escalation, "
            "CloudTrail tampering, SSRF credential theft, and container escapes."
        ),
    },
    "hipaa-triage": {
        "num_episodes": 8,
        "categories": ["healthcare"],
        "difficulties": ["medium", "medium-hard", "hard", "expert"],
        "threat_ratio": 0.65,
        "max_steps": 12,
        "description": (
            "Triage healthcare security alerts involving EHR systems and medical devices. "
            "HIPAA false negatives carry a 2.5× compliance penalty. "
            "Identify PHI breaches, ransomware, insider access anomalies, and IoMT compromise."
        ),
    },
    "credential-access": {
        "num_episodes": 8,
        "categories": ["credential_access"],
        "difficulties": ["easy-medium", "medium", "hard", "expert"],
        "threat_ratio": 0.65,
        "max_steps": 12,
        "description": (
            "Detect Active Directory credential attacks: Kerberoasting, AS-REP roasting, "
            "DCSync, and Pass-the-Hash lateral movement. "
            "DCSync/PtH carry SOX/PCI-DSS compliance multipliers."
        ),
    },
    "queue-triage": {
        "num_episodes": 3,
        "queue_size": 5,
        "categories": ["phishing", "malware", "insider_threat"],
        "difficulties": ["easy", "medium"],
        "threat_ratio": 0.60,
        "max_steps": 10,
        "max_total_steps": 40,
        "description": (
            "Triage a 5-alert backlog. Prioritize critical threats. "
            "Queue episode ends when all slots are resolved or total steps exhausted."
        ),
    },
    "auto-scaling-triage": {
        "num_episodes": 10,
        "categories": ["phishing", "malware", "insider_threat", "lateral_movement", "data_exfiltration", "evasion"],
        "difficulties": ["auto"],
        "threat_ratio": 0.60,
        "max_steps": 12,
        "description": "Auto-Scaling: Difficulty automatically ramps up from Easy to Expert depending on the agent's win streak",
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

    Known outcome strings in episode_results:
        "true_positive", "true_negative", "false_positive", "false_negative",
        "escalated_true_threat", "escalated_false_alarm", "timeout_benign",
        "timeout_breach", "compliance_breach" (compliance-triage worst outcome —
        indicates regulated data was breached due to incorrect triage decision).

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

    # Speed: ratio of steps used vs max steps, clamped to [0, 1]
    avg_steps = sum(ep["steps"] for ep in episode_results) / total
    max_steps = episode_results[0].get("max_steps", 10)
    speed = max(0.0, 1.0 - (avg_steps / max_steps))

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

    elif task_name == "compliance-triage":
        # Penalise compliance breaches heavily — regulators don't grade on a curve.
        # accuracy: correct triage decisions
        # evidence_quality: investigated before deciding
        # breach_rate: fraction of episodes ending in compliance_breach (worst outcome)
        # decisive_rate: direct contain/resolve vs escalation
        compliance_breach_count = sum(
            1 for ep in episode_results if ep.get("outcome") == "compliance_breach"
        )
        breach_rate = compliance_breach_count / total
        score = (
            0.30 * accuracy
            + 0.25 * evidence_quality
            + 0.30 * (1.0 - breach_rate)
            + 0.15 * decisive_rate
        )

    elif task_name == "cloud-native":
        # Cloud alerts: authorised ops are common false positives — accuracy + evidence matter.
        # Heavily penalise missing true threats (misconfiguration = breach, container escape = RCE).
        fn_count = sum(
            1 for ep in episode_results
            if ep["outcome"] in {"false_negative", "timeout_breach", "compliance_breach"}
        )
        miss_rate = fn_count / total
        fp_count = sum(1 for ep in episode_results if ep["outcome"] == "false_positive")
        fpr = fp_count / total
        score = (
            0.30 * accuracy
            + 0.25 * evidence_quality
            + 0.25 * (1.0 - miss_rate)
            + 0.10 * (1.0 - fpr)
            + 0.10 * decisive_rate
        )

    elif task_name == "hipaa-triage":
        # HIPAA: false negatives on PHI breaches are the worst outcome.
        # Compliance breach rate drives a large portion of the score.
        # Evidence quality critical — must investigate before deciding on EHR anomalies.
        compliance_breach_count = sum(
            1 for ep in episode_results if ep.get("outcome") in {"compliance_breach", "false_negative"}
        )
        breach_rate = compliance_breach_count / total
        score = (
            0.25 * accuracy
            + 0.25 * evidence_quality
            + 0.35 * (1.0 - breach_rate)
            + 0.15 * decisive_rate
        )

    elif task_name == "credential-access":
        # AD attacks: DCSync and PtH are high-stakes. Speed matters — attacker acts fast.
        # Missing a credential attack (fn) = domain compromise within hours.
        # False positives (blocking authorized SPN ops) have real business impact — penalise.
        fn_count = sum(
            1 for ep in episode_results
            if ep["outcome"] in {"false_negative", "timeout_breach"}
        )
        miss_rate = fn_count / total
        fp_count = sum(1 for ep in episode_results if ep["outcome"] == "false_positive")
        fpr = fp_count / total
        score = (
            0.25 * accuracy
            + 0.20 * speed
            + 0.25 * (1.0 - miss_rate)
            + 0.15 * (1.0 - fpr)
            + 0.15 * decisive_rate
        )

    elif task_name == "queue-triage":
        # Multi-alert queue: accuracy, speed (total budget), and completion rate matter.
        # Queue episodes report per-slot outcomes aggregated into episode_results.
        fn_count = sum(
            1 for ep in episode_results if ep["outcome"] in {"false_negative", "timeout_breach", "compliance_breach"}
        )
        miss_rate = fn_count / total
        score = (
            0.30 * accuracy
            + 0.25 * speed
            + 0.25 * (1.0 - miss_rate)
            + 0.20 * decisive_rate
        )

    else:
        score = accuracy

    return max(0.01, min(0.99, score))
