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
