"""Information-theoretic reward engine for SecOps Alert Router V2.

Computes rewards based on:
- Information gain from investigation actions
- Urgency decay for time-sensitive scenarios
- Proportional response matching
- Business impact of target asset
- Evidence quality before decisive actions
"""

from .investigation_engine import compute_investigation_value
from .logging_config import get_logger

logger = get_logger("reward")

# Action categories
SAFE_ACTIONS = {0, 1, 2, 3, 4, 5}
RISKY_ACTIONS = {6, 7, 8}
ESCALATE_ACTION = 9
RESOLVE_ACTION = 10

ACTION_NAMES = {
    0: "analyze_headers",
    1: "query_siem",
    2: "check_reputation",
    3: "check_asset",
    4: "analyze_payload",
    5: "correlate_alerts",
    6: "block_source",
    7: "isolate_host",
    8: "disable_account",
    9: "escalate",
    10: "resolve_benign",
}

# Severity multipliers for reward scaling
SEVERITY_MULTIPLIER = {"medium": 1.0, "high": 1.5, "critical": 2.0}

# Asset criticality multipliers for false positive penalties
CRITICALITY_PENALTY = {"low": 0.6, "medium": 1.0, "high": 1.5, "critical": 2.0}

# Compliance penalty multipliers — missing a threat with regulated data is far worse
COMPLIANCE_FN_MULTIPLIER = {
    "GDPR": 3.0,      # GDPR breach: fines up to 4% of global annual revenue
    "HIPAA": 2.5,      # HIPAA: per-record fines for protected health information
    "PCI-DSS": 2.0,    # PCI-DSS: card-brand fines and mandatory forensic audit
    "SOX": 1.5,        # SOX: financial record integrity, legal exposure
}

DATA_VOLUME_MULTIPLIER = {
    "massive": 2.0,    # >100K records
    "bulk": 1.5,       # 1K-100K records
    "single": 1.0,     # Individual record or no data volume context
}

# Minimum investigation actions before containment is allowed
MIN_EVIDENCE_FOR_CONTAINMENT = 2


def compute_reward(
    scenario: dict,
    action_id: int,
    step_count: int,
    max_steps: int,
    actions_taken: list[str],
    investigation_count: int,
) -> tuple[float, str]:
    """Compute the reward and outcome status for an action.

    Returns:
        Tuple of (reward_float, status_string).
    """
    action_name = ACTION_NAMES[action_id]
    severity = scenario.get("severity", "medium")
    is_threat = scenario["is_true_threat"]
    criticality = scenario.get("target", {}).get("criticality", "medium")

    # === INVESTIGATION ACTIONS (0-5) ===
    if action_id in SAFE_ACTIONS:
        # Timeout check BEFORE duplicate check — duplicates must not bypass termination
        if step_count >= max_steps:
            return _timeout_reward(is_threat, severity), _timeout_status(is_threat)

        if action_name in actions_taken:
            return -2.0, "duplicate_action"

        info_value = compute_investigation_value(
            scenario, action_id, actions_taken
        )

        # Base cost + info gain reward
        # Good investigation: -0.5 (net useful), bad: -1.5 (wasted time)
        reward = -1.0 + (info_value * 1.5)  # range: -1.0 to +0.5

        status = "useful_investigation" if info_value >= 0.5 else "low_value_investigation"

        return reward, status

    # === CONTAINMENT ACTIONS (6-8) ===
    if action_id in RISKY_ACTIONS:
        # Procedure violation: must have enough evidence
        if investigation_count < MIN_EVIDENCE_FOR_CONTAINMENT:
            penalty = -5.0
            status = "procedure_violation"
            if step_count >= max_steps:
                return _timeout_reward(is_threat, severity), _timeout_status(is_threat)
            return penalty, status

        if is_threat:
            base = 10.0

            # Speed bonus for critical threats handled quickly
            sev_mult = SEVERITY_MULTIPLIER.get(severity, 1.0)
            if step_count <= 4:
                base += 2.0 * sev_mult

            # Evidence quality bonus (more investigation = higher confidence)
            evidence_bonus = min(investigation_count - MIN_EVIDENCE_FOR_CONTAINMENT, 3) * 1.0
            base += evidence_bonus

            # Proportional response bonus
            if _is_proportional_response(action_id, severity):
                base += 3.0

            return base, "true_positive"
        else:
            # False positive — penalty scaled by asset criticality
            crit_mult = CRITICALITY_PENALTY.get(criticality, 1.0)
            return -10.0 * crit_mult, "false_positive"

    # === ESCALATE (9) ===
    if action_id == ESCALATE_ACTION:
        if is_threat:
            # Good instinct but not decisive — partial reward
            base = 5.0
            if investigation_count >= 2:
                base += 1.0  # Bonus for investigating before escalating
            return base, "escalated_true_threat"
        else:
            # Wasted senior analyst time
            return -3.0, "escalated_false_alarm"

    # === RESOLVE BENIGN (10) ===
    if action_id == RESOLVE_ACTION:
        if not is_threat:
            # Correct! Bonus for evidence quality
            base = 3.0
            evidence_bonus = min(investigation_count, 3) * 0.5
            base += evidence_bonus
            return base, "true_negative"
        else:
            # Missed a real threat — severity-scaled, amplified by compliance obligations
            sev_mult = SEVERITY_MULTIPLIER.get(severity, 1.0)
            compliance = scenario.get("compliance", {})
            framework = compliance.get("framework", "")
            comp_mult = COMPLIANCE_FN_MULTIPLIER.get(framework, 1.0)
            vol_mult = DATA_VOLUME_MULTIPLIER.get(
                compliance.get("data_volume", "single"), 1.0
            )
            # Compliance breach is distinct from generic false negative
            outcome = "compliance_breach" if framework else "false_negative"
            raw_penalty = -25.0 * sev_mult * comp_mult * vol_mult
            clamped = max(raw_penalty, -100.0)  # floor at -100 for rubric normalization
            if framework:
                logger.warning(
                    "Compliance breach: %s severity=%s framework=%s penalty=%.1f",
                    scenario.get("id", "?"), severity, framework, clamped,
                    extra={
                        "scenario_id": scenario.get("id", ""),
                        "severity": severity,
                        "outcome": outcome,
                        "reward": clamped,
                    },
                )
            return clamped, outcome

    return 0.0, "unknown_action"


def _timeout_reward(is_threat: bool, severity: str) -> float:
    """Reward when episode ends due to step limit."""
    if is_threat:
        sev_mult = SEVERITY_MULTIPLIER.get(severity, 1.0)
        return -25.0 * sev_mult  # Breach due to slow response
    return 0.5  # Benign alert timed out — acceptable but not great


def _timeout_status(is_threat: bool) -> str:
    return "timeout_breach" if is_threat else "timeout_benign"


def _is_proportional_response(action_id: int, severity: str) -> bool:
    """Check if the containment action matches the threat severity."""
    # block_source(6) = appropriate for medium/high
    # isolate_host(7) = appropriate for high/critical
    # disable_account(8) = appropriate for high/critical with account compromise
    proportional_map = {
        6: {"medium", "high"},
        7: {"high", "critical"},
        8: {"high", "critical"},
    }
    return severity in proportional_map.get(action_id, set())
