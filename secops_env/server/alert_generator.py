"""Synthetic alert generator for the SecOps triage environment."""

import random
from typing import Optional

ACTION_NAMES = {
    0: "analyze_headers", 1: "query_logs", 2: "verify_identity",
    3: "scope_environment", 4: "block_ip", 5: "isolate_host",
    6: "disable_account", 7: "acknowledge_allow"
}
ALERT_TYPE_NAMES = {
    0: "Phishing", 1: "PrivilegeAbuse", 2: "Malware", 3: "DDoS", 4: "DataExfiltration"
}
SEVERITY_NAMES = {0: "Medium", 1: "High", 2: "Critical"}
SAFE_ACTIONS = {0, 1, 2, 3}
RISKY_ACTIONS = {4, 5, 6}
RESOLVE_ACTION = 7

# Confidence boosts per safe action when alert IS a true threat
CONFIDENCE_BOOST_TRUE = {0: 0.15, 1: 0.20, 2: 0.15, 3: 0.10}
# Confidence boost when alert is benign (weak noisy signal)
CONFIDENCE_BOOST_BENIGN = 0.05

class AlertGenerator:
    """Generates synthetic security alerts with configurable randomness."""

    def __init__(self, seed: Optional[int] = None, severity_weights=None, threat_probability=None):
        self._rng = random.Random(seed)
        self._severity_weights = severity_weights or [0.30, 0.45, 0.25]
        self._threat_probability = threat_probability or {0: 0.40, 1: 0.60, 2: 0.80}

    def generate(self) -> dict:
        """Generate a random alert.

        Returns:
            dict with keys: alert_type (0-4), severity (0-2), is_true_threat (bool)
        """
        alert_type = self._rng.randint(0, 4)

        # Weighted severity using cumulative weights
        severity_roll = self._rng.random()
        cumulative = 0.0
        severity = 2
        for i, w in enumerate(self._severity_weights):
            cumulative += w
            if severity_roll < cumulative:
                severity = i
                break

        # Threat probability depends on severity
        is_true_threat = self._rng.random() < self._threat_probability[severity]

        return {
            "alert_type": alert_type,
            "severity": severity,
            "is_true_threat": is_true_threat,
        }
