"""Pydantic data models for the SecOps Alert Router environment."""

from openenv.core.env_server import Action, Observation, State
from pydantic import Field
from typing import List


class SecOpsAction(Action):
    """Action for SecOps Alert Router environment.

    Attributes:
        action_id: Discrete action index (0-7) mapping to triage decisions.
            Safe: 0=analyze_headers, 1=query_logs, 2=verify_identity, 3=scope_environment.
            Risky: 4=block_ip, 5=isolate_host, 6=disable_account.
            Resolve: 7=acknowledge_allow.
    """

    action_id: int = Field(
        ge=0,
        le=7,
        description=(
            "Discrete action index (0-7). Safe: 0=analyze_headers, 1=query_logs, "
            "2=verify_identity, 3=scope_environment. Risky: 4=block_ip, "
            "5=isolate_host, 6=disable_account. Resolve: 7=acknowledge_allow"
        ),
    )


class SecOpsObservation(Observation):
    """Observation for SecOps Alert Router environment.

    Attributes:
        alert_type: Alert category (0-4): 0=Phishing, 1=PrivilegeAbuse,
            2=Malware, 3=DDoS, 4=DataExfil.
        severity: Severity level (0-2): 0=Medium, 1=High, 2=Critical.
        confidence_score: ML model confidence score in the range [0.0, 1.0].
        time_steps_elapsed: Number of environment steps taken so far.
        evidence_flags: Boolean flags indicating which evidence sources have
            been collected (4 sources).
        done: Whether the episode is finished (inherited from Observation).
        reward: Reward signal for the last action (inherited from Observation).
        metadata: Additional metadata dict (inherited from Observation).
    """

    alert_type: int = Field(
        default=0,
        description="Alert category (0-4): 0=Phishing, 1=PrivilegeAbuse, 2=Malware, 3=DDoS, 4=DataExfil",
    )
    severity: int = Field(
        default=0,
        description="Severity level (0-2): 0=Medium, 1=High, 2=Critical",
    )
    confidence_score: float = Field(
        default=0.0,
        description="ML model confidence score in the range [0.0, 1.0]",
    )
    time_steps_elapsed: int = Field(
        default=0,
        description="Number of environment steps taken so far",
    )
    evidence_flags: List[bool] = Field(
        default_factory=lambda: [False, False, False, False],
        description="Boolean flags for 4 evidence sources collected",
    )


class SecOpsState(State):
    """Internal state for SecOps Alert Router environment.

    Attributes:
        alert_type: Alert category (0-4): 0=Phishing, 1=PrivilegeAbuse,
            2=Malware, 3=DDoS, 4=DataExfil.
        severity: Severity level (0-2): 0=Medium, 1=High, 2=Critical.
        is_true_threat: Ground-truth label indicating if the alert is a real threat.
        confidence_score: ML model confidence score in the range [0.0, 1.0].
        evidence_collected: List of evidence source names that have been gathered.
        max_steps: Maximum number of steps allowed per episode.
        episode_id: Unique episode identifier (inherited from State).
        step_count: Current step within the episode (inherited from State).
    """

    alert_type: int = Field(
        default=0,
        description="Alert category (0-4): 0=Phishing, 1=PrivilegeAbuse, 2=Malware, 3=DDoS, 4=DataExfil",
    )
    severity: int = Field(
        default=0,
        description="Severity level (0-2): 0=Medium, 1=High, 2=Critical",
    )
    is_true_threat: bool = Field(
        default=False,
        description="Ground-truth label indicating if the alert is a real threat",
    )
    confidence_score: float = Field(
        default=0.0,
        description="ML model confidence score in the range [0.0, 1.0]",
    )
    evidence_collected: List[str] = Field(
        default_factory=list,
        description="List of evidence source names that have been gathered",
    )
    max_steps: int = Field(
        default=5,
        description="Maximum number of steps allowed per episode",
    )
