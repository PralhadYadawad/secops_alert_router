"""Pydantic data models for the SecOps Alert Router V2 environment."""

from openenv.core.env_server import Action, Observation, State
from pydantic import Field
from typing import List, Dict, Any, Optional


class SecOpsAction(Action):
    """Action for SecOps Alert Router V2 environment.

    Attributes:
        action_id: Discrete action index (0-10) mapping to triage decisions.
            Investigation: 0=analyze_headers, 1=query_siem, 2=check_reputation,
                3=check_asset, 4=analyze_payload, 5=correlate_alerts.
            Containment: 6=block_source, 7=isolate_host, 8=disable_account.
            Other: 9=escalate, 10=resolve_benign.
    """

    action_id: int = Field(
        ge=0,
        le=10,
        description=(
            "Discrete action index (0-10). "
            "Investigation: 0=analyze_headers, 1=query_siem, 2=check_reputation, "
            "3=check_asset, 4=analyze_payload, 5=correlate_alerts. "
            "Containment: 6=block_source, 7=isolate_host, 8=disable_account. "
            "Other: 9=escalate, 10=resolve_benign"
        ),
    )


class SecOpsObservation(Observation):
    """Rich observation for SecOps Alert Router V2.

    Contains the full alert context visible on reset plus accumulated
    investigation results as the agent investigates.
    """

    # Alert context (visible from reset)
    alert_id: str = Field(default="", description="Unique alert identifier")
    rule_triggered: str = Field(default="", description="Detection rule that fired")
    severity: str = Field(default="medium", description="Alert severity: medium, high, critical")
    alert_description: str = Field(default="", description="Human-readable alert description")
    mitre_tactic: str = Field(default="", description="MITRE ATT&CK tactic")
    mitre_technique: str = Field(default="", description="MITRE ATT&CK technique ID and name")
    source_ip: str = Field(default="", description="Source IP address")
    source_domain: str = Field(default="", description="Source domain if applicable")
    target_host: str = Field(default="", description="Target hostname")
    target_user: str = Field(default="", description="Target username")
    target_department: str = Field(default="", description="Target user department")
    raw_log_snippet: str = Field(default="", description="Raw log/email snippet from the alert")

    # Compliance context — visible to agent so they know what data is at risk
    data_classification: str = Field(
        default="",
        description="Data type at risk: PII, PHI, PCI, Financial, Internal",
    )
    regulatory_framework: str = Field(
        default="",
        description="Applicable regulatory framework: GDPR, HIPAA, PCI-DSS, SOX",
    )
    breach_notification_window: str = Field(
        default="",
        description="Required notification window e.g. '72 hours (GDPR Art. 33)'",
    )

    # Investigation results (grows as agent investigates)
    investigation_history: List[Dict[str, str]] = Field(
        default_factory=list,
        description="List of investigation results from actions taken",
    )

    # State tracking
    time_steps_elapsed: int = Field(default=0, description="Steps taken so far")
    max_steps: int = Field(default=10, description="Maximum steps per episode")
    actions_taken: List[str] = Field(
        default_factory=list,
        description="Names of actions already taken this episode",
    )

    # Episode outcome fields (OpenEnv strips metadata; these are explicit so they survive serialization)
    outcome_status: str = Field(
        default="",
        description="Terminal outcome: true_positive, false_positive, true_negative, "
        "false_negative, compliance_breach, escalated_true_threat, "
        "escalated_false_alarm, timeout_breach, timeout_benign",
    )
    alert_category: str = Field(
        default="",
        description="Alert category: phishing, malware, insider_threat, "
        "lateral_movement, data_exfiltration, ddos, evasion",
    )
    investigation_count: int = Field(
        default=0,
        description="Number of investigation actions completed this episode",
    )
    episode_cumulative_reward: float = Field(
        default=0.0,
        description="Running total of rewards accumulated this episode",
    )


class SecOpsState(State):
    """Internal state for SecOps Alert Router V2.

    Tracks the full episode state including scenario reference,
    investigation history, and accumulated rewards.
    """

    alert_type: str = Field(default="", description="Alert category")
    severity: str = Field(default="medium", description="Alert severity")
    is_true_threat: bool = Field(default=False, description="Ground truth")
    scenario_id: str = Field(default="", description="ID of the loaded scenario")
    max_steps: int = Field(default=10, description="Max steps this episode")
    actions_taken: List[str] = Field(
        default_factory=list,
        description="Names of actions taken so far",
    )
    investigation_count: int = Field(
        default=0,
        description="Number of investigation actions completed",
    )
    cumulative_reward: float = Field(
        default=0.0,
        description="Running total of rewards this episode",
    )
    target_criticality: str = Field(
        default="medium",
        description="Business criticality of target asset",
    )


class QueueAction(Action):
    """Action for multi-alert queue triage mode.

    Same action space as SecOpsAction but includes which alert to act on.

    Attributes:
        action_id: Discrete action index 0-10 (same mapping as SecOpsAction).
        alert_index: Which alert slot in the queue to target (0-based).
    """

    action_id: int = Field(
        ge=0,
        le=10,
        description="Discrete action index (0-10). Same mapping as SecOpsAction.",
    )
    alert_index: int = Field(
        ge=0,
        le=9,
        default=0,
        description="Which alert in the queue to act on (0-based index)",
    )


class QueueObservation(Observation):
    """Observation for multi-alert queue triage mode.

    The agent sees a summary of all queued alerts plus the full detail
    of the currently focused alert (active_alert).

    Attributes:
        active_alert: Full observation dict for the currently focused alert slot.
        queue_summary: List of dicts summarising each alert slot's status.
        queue_size: Total number of alert slots in the queue.
        alerts_remaining: Number of alert slots not yet resolved.
        total_steps_used: Steps used across all slots this episode.
        total_steps_max: Maximum total steps allowed for the queue episode.
    """

    active_alert: Dict[str, Any] = Field(
        default_factory=dict,
        description="Full observation of the focused alert slot",
    )
    queue_summary: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="[{alert_id, severity, category, done, outcome, steps_used}] for each slot",
    )
    queue_size: int = Field(default=5, description="Total alert slots in queue")
    alerts_remaining: int = Field(default=5, description="Unresolved alert slots")
    total_steps_used: int = Field(default=0, description="Steps used across all slots")
    total_steps_max: int = Field(default=40, description="Max steps for entire queue episode")
