"""Investigation engine for SecOps Alert Router V2.

Returns realistic investigation data (SIEM logs, threat intel, asset info)
from scenario templates when the agent performs investigation actions.
"""

from typing import Optional

# Maps action_id -> investigation data key in scenario["investigate"]
ACTION_TO_INVESTIGATE_KEY = {
    0: "analyze_headers",
    1: "query_siem",
    2: "check_reputation",
    3: "check_asset",
    4: "analyze_payload",
    5: "correlate_alerts",
}

ACTION_DESCRIPTIONS = {
    0: "Header Analysis",
    1: "SIEM Log Query",
    2: "IOC Reputation Check",
    3: "Asset Context Lookup",
    4: "Payload/Sandbox Analysis",
    5: "Alert Correlation",
}


def get_investigation_result(
    scenario: dict,
    action_id: int,
) -> Optional[dict]:
    """Return investigation data for a given action on a scenario.

    Args:
        scenario: The active scenario dict.
        action_id: Investigation action (0-5).

    Returns:
        Dict with 'action_name', 'description', and 'result' text,
        or None if action_id is not an investigation action.
    """
    key = ACTION_TO_INVESTIGATE_KEY.get(action_id)
    if key is None:
        return None

    investigate_data = scenario.get("investigate", {})
    result_text = investigate_data.get(key, "No data available for this investigation type.")

    return {
        "action_name": key,
        "description": ACTION_DESCRIPTIONS[action_id],
        "result": result_text,
    }


def compute_investigation_value(
    scenario: dict,
    action_id: int,
    actions_already_taken: list[str],
) -> float:
    """Compute how valuable an investigation action is for this scenario.

    Returns a value between 0.0 (useless) and 1.0 (critical evidence).
    Used by the reward engine to give information-gain rewards.
    """
    key = ACTION_TO_INVESTIGATE_KEY.get(action_id)
    if key is None:
        return 0.0

    # Duplicate action has no value
    if key in actions_already_taken:
        return 0.0

    optimal = scenario.get("optimal_actions", [])
    if action_id in optimal:
        return 1.0  # Critical evidence for this scenario

    # Some investigation is still useful even if not optimal
    investigate_data = scenario.get("investigate", {})
    result_text = investigate_data.get(key, "")
    if not result_text or result_text == "No data available for this investigation type.":
        return 0.1

    return 0.5  # Useful but not critical


def format_investigation_for_observation(history: list[dict]) -> str:
    """Format accumulated investigation results for display in the observation.

    Args:
        history: List of investigation result dicts.

    Returns:
        Formatted multi-line string for the LLM prompt.
    """
    if not history:
        return "No investigation data collected yet."

    lines = []
    for i, entry in enumerate(history, 1):
        lines.append(f"[Step {i}] {entry['description']}:")
        for line in entry["result"].strip().split("\n"):
            lines.append(f"  {line}")
        lines.append("")

    return "\n".join(lines)
