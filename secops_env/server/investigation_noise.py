"""Investigation noise injection for SecOps Alert Router V2.

Adds realistic ambiguity to investigation results to make genuine LLM
reasoning more valuable than keyword matching.

Three noise types:
  PARTIAL    — Results are incomplete (ingestion lag, timeout, API limits)
  CONFLICTING — A contradicting signal is appended (mixed vendor verdicts)
  RED_HERRING — A plausible but misleading indicator is injected

Noise is seeded and reproducible. Controlled via the SECOPS_NOISE_LEVEL
environment variable (float 0.0–1.0, default 0.20).
Set to 0.0 to disable completely (fully clean investigation data).
"""

import os
import random

# ── Configuration ──────────────────────────────────────────────────────────────

NOISE_LEVEL: float = float(os.getenv("SECOPS_NOISE_LEVEL", "0.20"))

# Probability split among enabled noise types when noise fires
_NOISE_TYPE_WEIGHTS = {
    "partial": 0.45,
    "conflicting": 0.35,
    "red_herring": 0.20,
}

# ── Partial result wrappers ────────────────────────────────────────────────────

_PARTIAL_PREFIXES = {
    "query_siem": [
        "⚠ Log ingestion delay (~4 min lag). Events shown may not reflect current state.\n\n",
        "⚠ Collector restart at 14:12 UTC — events from 14:00–14:30 window unavailable. Partial log:\n\n",
        "⚠ SIEM index currently at 63% capacity. Some events may be missing. Partial results:\n\n",
    ],
    "check_reputation": [
        "⚠ VirusTotal API rate-limited. Serving 6-hour cached result. Manual re-check recommended.\n\n",
        "⚠ Threat intel feed sync failed 2h ago. Results may be stale.\n\n",
        "⚠ One of 3 reputation feeds unavailable (timeout). Results from 2 remaining feeds:\n\n",
    ],
    "analyze_payload": [
        "⚠ Sandbox timeout at 58% analysis completion. Partial detonation report:\n\n",
        "⚠ Memory dump analysis incomplete — system resource limit hit. Partial static analysis:\n\n",
        "⚠ Dynamic analysis unavailable. Static analysis only (no behavioral data):\n\n",
    ],
    "analyze_headers": [
        "⚠ Header reconstruction incomplete — forwarding hops stripped. Available headers only:\n\n",
        "⚠ Email gateway logs partially corrupted. Reconstructed from available fragments:\n\n",
    ],
    "correlate_alerts": [
        "⚠ Correlation engine in maintenance window. Cross-alert links unavailable for the past 2h.\n\n",
        "⚠ Alert deduplication pipeline delayed. Some correlated events may appear as separate alerts.\n\n",
    ],
    "check_asset": [
        "⚠ Asset inventory last synced 3 days ago. Current configuration may differ.\n\n",
        "⚠ CMDB lookup returned stale data — endpoint agent not checked in for 48h.\n\n",
    ],
}

_GENERIC_PARTIAL_PREFIX = "⚠ Data source temporarily degraded. Partial results shown:\n\n"

# ── Conflicting signal suffixes ────────────────────────────────────────────────

_CONFLICTING_SUFFIXES = {
    "check_reputation": [
        "\n\n[CONFLICTING] Internal threat intel: no match in our IOC database. External feeds: 1/4 vendors flagged (low confidence, possible FP).",
        "\n\n[CONFLICTING] Passive DNS shows this IP hosted a legitimate CDN 30 days ago. Could be infrastructure reuse or hijack.",
        "\n\n[CONFLICTING] Domain age: 8 days (suspicious). However, WHOIS history shows the registrant owns 40+ similar domains used for legitimate SaaS products.",
    ],
    "query_siem": [
        "\n\n[CONFLICTING] User HR record shows standard business hours activity — no prior anomalies in 180-day baseline. Behaviour today is a statistical outlier but within 2σ.",
        "\n\n[CONFLICTING] EDR telemetry for the same host shows no matching process execution. Log source discrepancy — possible agent misconfiguration.",
        "\n\n[CONFLICTING] Network flow data shows normal bandwidth profile for this user. SIEM alert threshold may be miscalibrated.",
    ],
    "analyze_payload": [
        "\n\n[CONFLICTING] Hash not found in Any.Run, Joe Sandbox, or VirusTotal (0/82). Either a zero-day or a benign unique build. Context-dependent.",
        "\n\n[CONFLICTING] Binary is signed with a valid Authenticode certificate (Microsoft root). Could be a living-off-the-land abuse or legitimate system tool.",
    ],
    "correlate_alerts": [
        "\n\n[CONFLICTING] 2 of the 4 correlated alerts are from a separate unrelated incident (INC-20260418-001, since closed as FP). Net new signals: 2.",
        "\n\n[CONFLICTING] Alert correlation engine shows similar pattern triggered by the IT team's automated vulnerability scanner last Tuesday — check scan schedule.",
    ],
    "analyze_headers": [
        "\n\n[CONFLICTING] SPF and DKIM both pass, which is unusual for phishing. Either the attacker controls the sending domain or this is a legitimate sender.",
        "\n\n[CONFLICTING] Sending IP is a known Microsoft O365 egress range. Could indicate business email compromise of a legitimate account vs external attacker.",
    ],
    "check_asset": [
        "\n\n[CONFLICTING] Badge access logs show the user was physically in a different office today. Remote session from their workstation while out-of-office could indicate compromise or VPN usage.",
        "\n\n[CONFLICTING] User's manager submitted an IT request for elevated access last week — check if this activity is related to that approved request.",
    ],
}

_GENERIC_CONFLICTING_SUFFIX = "\n\n[CONFLICTING] Secondary data source returned contradictory signal. Recommend cross-referencing with an additional investigation action."

# ── Red herring injections ─────────────────────────────────────────────────────

_RED_HERRING_INJECTIONS = [
    "\n\n[NOTE] Unrelated finding: scheduled Qualys scan running on this subnet (approved, change ticket CHG-20260419-088). May account for some anomalous network patterns.",
    "\n\n[NOTE] Host is enrolled in a pilot EDR upgrade programme — agent version mismatch between endpoint and SIEM. Some telemetry may appear inconsistent.",
    "\n\n[NOTE] User attended cybersecurity awareness training yesterday. Post-training test phishing emails were sent to this cohort — confirm if this alert relates to a test email.",
    "\n\n[NOTE] Finance month-end processing active. Large batch transfers and after-hours logins are expected until EOM. Reconcile with finance team before escalating.",
    "\n\n[NOTE] Third-party pen test is in scope for this IP range this week (see WAR-2026-04). Verify if activity matches reported test vectors.",
    "\n\n[NOTE] Recent AD migration project: some accounts temporarily assigned to wrong OUs. Check if this user's group membership reflects migration artefact.",
]


# ── Public API ─────────────────────────────────────────────────────────────────

def inject_noise(
    action_name: str,
    result: str,
    scenario_id: str,
    step_count: int,
) -> str:
    """Optionally inject ambiguity into an investigation result.

    Uses a deterministic seed derived from scenario_id + step_count so that
    the same episode always produces the same noise pattern (reproducible).

    Args:
        action_name: Name of the investigation action (e.g. 'query_siem').
        result: The original clean investigation result text.
        scenario_id: Current scenario ID (used for seeding).
        step_count: Current step count (adds per-step variation).

    Returns:
        The original result, possibly wrapped or suffixed with noise text.
        Never returns empty string — always preserves the core result.
    """
    if NOISE_LEVEL <= 0.0 or not result:
        return result

    # Deterministic RNG per (scenario, step, action) triple
    seed = hash(f"{scenario_id}:{step_count}:{action_name}") & 0x7FFFFFFF
    rng = random.Random(seed)

    if rng.random() >= NOISE_LEVEL:
        return result  # No noise this time

    # Pick noise type
    noise_type = rng.choices(
        list(_NOISE_TYPE_WEIGHTS.keys()),
        weights=list(_NOISE_TYPE_WEIGHTS.values()),
        k=1,
    )[0]

    if noise_type == "partial":
        prefixes = _PARTIAL_PREFIXES.get(action_name, [_GENERIC_PARTIAL_PREFIX])
        prefix = rng.choice(prefixes)
        return prefix + result

    elif noise_type == "conflicting":
        suffixes = _CONFLICTING_SUFFIXES.get(action_name, [_GENERIC_CONFLICTING_SUFFIX])
        suffix = rng.choice(suffixes)
        return result + suffix

    elif noise_type == "red_herring":
        injection = rng.choice(_RED_HERRING_INJECTIONS)
        return result + injection

    return result  # Fallback — no change
