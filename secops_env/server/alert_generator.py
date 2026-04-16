"""Scenario-based alert generator for SecOps Alert Router V2.

Replaces V1's simple random integer generator with rich scenario templates
loaded from the scenarios package.
"""

import random
from typing import Optional

from .reward_engine import ACTION_NAMES, SAFE_ACTIONS, RISKY_ACTIONS, ESCALATE_ACTION, RESOLVE_ACTION
from .scenarios import pick_scenario

# Re-export constants for backward compatibility
ALERT_TYPE_NAMES = {
    "phishing": "Phishing",
    "malware": "Malware",
    "insider_threat": "Insider Threat",
    "lateral_movement": "Lateral Movement",
    "data_exfiltration": "Data Exfiltration",
    "ddos": "DDoS",
    "evasion": "Adversarial Evasion",
    "cloud": "Cloud-Native",
    "healthcare": "Healthcare / HIPAA",
    "credential_access": "Credential Access",
}

SEVERITY_NAMES = {"medium": "Medium", "high": "High", "critical": "Critical"}


class AlertGenerator:
    """Generates security alerts from scenario templates.

    Each call to generate() picks a scenario matching the configured
    category/difficulty filters, providing rich context for the agent.
    """

    def __init__(
        self,
        seed: Optional[int] = None,
        categories: Optional[list[str]] = None,
        difficulties: Optional[list[str]] = None,
        threat_ratio: Optional[float] = None,
        max_steps: int = 10,
    ):
        self._rng = random.Random(seed)
        self._categories = categories
        self._difficulties = difficulties
        self._threat_ratio = threat_ratio
        self._max_steps = max_steps

    def generate(self) -> dict:
        """Generate a scenario-based alert.

        Returns:
            Full scenario dict with alert context, investigation data,
            and ground truth labels.
        """
        scenario = pick_scenario(
            rng=self._rng,
            categories=self._categories,
            difficulties=self._difficulties,
            threat_ratio=self._threat_ratio,
        )
        return scenario
