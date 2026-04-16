"""Scenario templates for SecOps Alert Router V2.

Each scenario is a dict containing:
- id, category, difficulty, is_true_threat, severity
- mitre tactic/technique mapping
- alert rule and description
- source/target entity details
- indicators (IOCs)
- raw_log snippet shown on reset
- investigation data returned by each action
- optimal_actions and impact metadata
"""

import copy
import random
from typing import Optional

from .phishing import PHISHING_SCENARIOS
from .malware import MALWARE_SCENARIOS
from .insider import INSIDER_SCENARIOS
from .lateral import LATERAL_SCENARIOS
from .exfil import EXFIL_SCENARIOS
from .ddos import DDOS_SCENARIOS
from .evasion import EVASION_SCENARIOS
from .cloud import CLOUD_SCENARIOS
from .healthcare import HEALTHCARE_SCENARIOS
from .credential_access import CREDENTIAL_ACCESS_SCENARIOS

ALL_SCENARIOS = (
    PHISHING_SCENARIOS
    + MALWARE_SCENARIOS
    + INSIDER_SCENARIOS
    + LATERAL_SCENARIOS
    + EXFIL_SCENARIOS
    + DDOS_SCENARIOS
    + EVASION_SCENARIOS
    + CLOUD_SCENARIOS
    + HEALTHCARE_SCENARIOS
    + CREDENTIAL_ACCESS_SCENARIOS
)

# Index by category and difficulty
_BY_CATEGORY: dict[str, list[dict]] = {}
_BY_DIFFICULTY: dict[str, list[dict]] = {}
_BY_ID: dict[str, dict] = {}

for _s in ALL_SCENARIOS:
    _BY_CATEGORY.setdefault(_s["category"], []).append(_s)
    _BY_DIFFICULTY.setdefault(_s["difficulty"], []).append(_s)
    _BY_ID[_s["id"]] = _s

CATEGORIES = list(_BY_CATEGORY.keys())
DIFFICULTIES = ["easy", "easy-medium", "medium", "medium-hard", "hard", "expert"]


def get_scenarios_by_category(category: str) -> list[dict]:
    return _BY_CATEGORY.get(category, [])


def get_scenarios_by_difficulty(difficulty: str) -> list[dict]:
    return _BY_DIFFICULTY.get(difficulty, [])


def get_scenario_by_id(scenario_id: str) -> Optional[dict]:
    return _BY_ID.get(scenario_id)


def pick_scenario(
    rng: random.Random,
    categories: Optional[list[str]] = None,
    difficulties: Optional[list[str]] = None,
    threat_ratio: Optional[float] = None,
) -> dict:
    """Pick a random scenario matching the given filters.

    Args:
        rng: Random instance for reproducibility.
        categories: Allowed categories (None = all).
        difficulties: Allowed difficulties (None = all).
        threat_ratio: If set, override is_true_threat with this probability.

    Returns:
        A scenario dict (copy with possibly overridden is_true_threat).
    """
    pool = ALL_SCENARIOS

    if categories:
        pool = [s for s in pool if s["category"] in categories]
    if difficulties:
        pool = [s for s in pool if s["difficulty"] in difficulties]

    if not pool:
        pool = ALL_SCENARIOS

    scenario = copy.deepcopy(rng.choice(pool))

    if threat_ratio is not None:
        scenario["is_true_threat"] = rng.random() < threat_ratio

    return scenario
