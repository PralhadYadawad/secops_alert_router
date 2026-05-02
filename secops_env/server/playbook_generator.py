"""SOAR playbook generator for SecOps Alert Router V2.

Converts a completed episode trajectory into a structured incident response
playbook. Deterministic template fill -- no LLM required.
"""

from datetime import datetime, timezone

_VERDICT_LABELS = {
    "true_positive": "True Positive -- Threat Contained",
    "false_positive": "False Positive -- Legitimate Activity Blocked",
    "true_negative": "True Negative -- Benign Activity Confirmed",
    "false_negative": "False Negative -- Threat Missed",
    "compliance_breach": "Compliance Breach -- Regulated Data Compromised",
    "escalated_true_threat": "Escalated -- Threat Forwarded to Senior Analyst",
    "escalated_false_alarm": "Escalated -- False Alarm (Unnecessary)",
    "timeout_breach": "Timeout -- Threat Not Addressed In Time",
    "timeout_benign": "Timeout -- Benign Alert Expired",
}

_RECOMMENDATIONS = {
    "true_positive": [
        "Block source IP at perimeter firewall",
        "Reset credentials for affected user",
        "Review lateral movement from compromised host",
        "Submit IOCs to threat intel platform",
    ],
    "false_negative": [
        "IMMEDIATE: Activate incident response plan",
        "Preserve forensic evidence",
        "Notify CISO and legal counsel",
        "Begin breach notification process",
    ],
    "compliance_breach": [
        "IMMEDIATE: Activate incident response plan",
        "Preserve forensic evidence",
        "Notify CISO and legal counsel",
        "Begin breach notification process",
    ],
    "true_negative": [
        "Update detection rule to reduce false-positive rate",
        "Document as known-good pattern",
    ],
    "false_positive": [
        "Review containment action -- restore service if applicable",
        "Tune detection rule to avoid recurrence",
    ],
}

_DEFAULT_RECOMMENDATIONS = [
    "Review episode for training value",
    "Document lessons learned",
]

# Maps investigation action names to human-readable tool names.
_ACTION_TOOL_NAMES = {
    "analyze_headers": "Header Analysis",
    "query_siem": "SIEM Log Query",
    "check_reputation": "IOC Reputation Check",
    "check_asset": "Asset Context Lookup",
    "analyze_payload": "Payload / Sandbox Analysis",
    "correlate_alerts": "Alert Correlation",
    "block_source": "Block Source IP/Domain",
    "isolate_host": "Isolate Host from Network",
    "disable_account": "Disable Compromised Account",
    "escalate": "Escalate to Senior Analyst",
    "resolve_benign": "Resolve as Benign",
}


def generate_playbook(
    scenario: dict,
    actions_taken: list[str],
    investigation_history: list[dict],
    outcome: str,
    cumulative_reward: float,
    steps_taken: int,
) -> dict:
    """Generate a structured SOAR incident playbook from a completed episode.

    Args:
        scenario: The full scenario dict used during the episode, containing
            keys like ``id``, ``severity``, ``category``, ``mitre``,
            ``source``, ``target``, ``compliance``, and ``indicators``.
        actions_taken: Ordered list of action name strings the agent executed.
        investigation_history: List of dicts with keys ``action_name``,
            ``description``, and ``result`` for each investigation step.
        outcome: Terminal outcome string (e.g. ``"true_positive"``).
        cumulative_reward: Total reward accumulated during the episode.
        steps_taken: Number of environment steps the agent used.

    Returns:
        A structured playbook dict ready for JSON serialization.
    """
    mitre = scenario.get("mitre", {})
    source = scenario.get("source", {})
    target = scenario.get("target", {})
    compliance = scenario.get("compliance", {})

    timeline = _build_timeline(investigation_history, actions_taken)
    recommendations = _RECOMMENDATIONS.get(outcome, _DEFAULT_RECOMMENDATIONS)
    compliance_notes = _build_compliance_notes(compliance)

    return {
        "playbook_version": "2.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "incident": {
            "id": f"INC-{scenario.get('id', 'UNKNOWN').upper()}",
            "severity": scenario.get("severity", "medium"),
            "category": scenario.get("category", ""),
            "mitre_tactic": mitre.get("tactic", ""),
            "mitre_technique": mitre.get("technique", ""),
            "mitre_name": mitre.get("name", ""),
            "source_ip": source.get("ip", ""),
            "target_user": target.get("user", ""),
            "target_host": target.get("host", ""),
            "target_department": target.get("department", ""),
        },
        "verdict": outcome,
        "verdict_label": _VERDICT_LABELS.get(outcome, outcome),
        "response_score": round(cumulative_reward, 2),
        "steps_taken": steps_taken,
        "timeline": timeline,
        "recommendations": recommendations,
        "iocs": scenario.get("indicators", {}),
        "compliance_notes": compliance_notes,
    }


def _build_timeline(
    investigation_history: list[dict],
    actions_taken: list[str],
) -> list[dict]:
    """Build a chronological timeline of investigation and response steps.

    Args:
        investigation_history: List of investigation result dicts, each with
            ``action_name``, ``description``, and ``result``.
        actions_taken: Ordered list of all action name strings from the episode.

    Returns:
        List of timeline entry dicts with ``step``, ``type``, ``action``,
        ``tool``, and ``finding`` keys.
    """
    timeline: list[dict] = []
    step_num = 1

    # Add investigation steps
    for entry in investigation_history:
        action_name = entry.get("action_name", "unknown")
        result_text = entry.get("result", "")
        if isinstance(result_text, dict):
            result_text = str(result_text)
        timeline.append({
            "step": step_num,
            "type": "investigation",
            "action": action_name,
            "tool": _ACTION_TOOL_NAMES.get(action_name, action_name),
            "finding": _truncate(result_text),
        })
        step_num += 1

    # Only add a "response" entry if the last action was a containment/resolution action.
    # Timeout episodes end on an investigation action — mislabeling it as "response" is wrong.
    _RESPONSE_ACTIONS = {"block_source", "isolate_host", "disable_account", "escalate", "resolve_benign"}
    if actions_taken and actions_taken[-1] in _RESPONSE_ACTIONS:
        terminal_action = actions_taken[-1]
        timeline.append({
            "step": step_num,
            "type": "response",
            "action": terminal_action,
            "tool": _ACTION_TOOL_NAMES.get(terminal_action, terminal_action),
            "finding": "",
        })

    return timeline


def _build_compliance_notes(compliance: dict) -> str:
    """Generate compliance notification notes from scenario compliance data.

    Args:
        compliance: Dict with optional ``framework``, ``data_type``, and
            ``volume`` keys describing the regulatory context.

    Returns:
        Human-readable compliance note string, or empty string if no
        framework is specified.
    """
    framework = compliance.get("framework", "")
    if not framework:
        return ""

    data_type = compliance.get("data_type", "Unknown")
    volume = compliance.get("data_volume", "unknown")

    notification_windows = {
        "GDPR": "72-hour notification window activated",
        "HIPAA": "60-day notification window activated",
        "PCI-DSS": "Immediate notification required",
        "SOX": "Escalate to legal counsel immediately",
    }

    window = notification_windows.get(framework, "Review notification obligations")
    return f"{framework}: {window}. Data type: {data_type}. Volume: {volume}."


def _truncate(text: str, max_len: int = 200) -> str:
    """Truncate text to a maximum length, appending ellipsis if needed.

    Args:
        text: The input string to truncate.
        max_len: Maximum allowed length (default 200).

    Returns:
        The original string if within the limit, otherwise the first
        ``max_len`` characters followed by ``'...'``.
    """
    if len(text) <= max_len:
        return text
    return text[:max_len] + "..."
