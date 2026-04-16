"""Procedural scenario augmentation engine for SecOps Alert Router.

Multiplies the static scenario pool ~3× by generating varied clones of each
base scenario. Surface-level identifiers (IPs, usernames, hostnames, timestamps,
departments) are randomized while the scenario's investigation narrative, MITRE
mapping, optimal_actions, and compliance metadata are preserved unchanged.

Why this approach:
  - Agents that train on all base scenarios (~61) can memorize them after ~200
    episodes. Augmentation breaks memorization without manual authoring effort.
  - Only identifiers that appear in raw_log and alert fields are varied — the
    investigation text (the reasoning substrate) stays intact so the reward
    signal remains valid.
  - Clones inherit is_true_threat, optimal_actions, and compliance tags from
    their parent, so grading and reward shaping are unaffected.

Usage:
    from .augmentor import build_augmented_pool
    pool = build_augmented_pool(seed=42, multiplier=3)
"""

import copy
import hashlib
import random
import re
from datetime import datetime, timedelta, timezone
from typing import Optional

# ── IP space pools ──────────────────────────────────────────────────────────
# We keep RFC 5737 documentation ranges for test/synthetic data (non-routable).
# The original scenarios already use these ranges; clones stay consistent.
_INTERNAL_RANGES = [
    ("10.0.", 2, 254, 2, 254),     # 10.0.x.x
    ("10.1.", 2, 254, 2, 254),
    ("10.2.", 2, 254, 2, 254),
    ("10.10.", 2, 254, 2, 254),
    ("172.16.", 2, 254, 2, 254),
    ("172.17.", 2, 254, 2, 254),
    ("172.18.", 2, 254, 2, 254),
    ("192.168.1.", 2, 254, None, None),
    ("192.168.10.", 2, 254, None, None),
]

_EXTERNAL_RANGES = [
    ("203.0.113.", 1, 254, None, None),   # TEST-NET-3
    ("198.51.100.", 1, 254, None, None),  # TEST-NET-2
    ("198.18.", 1, 127, 1, 254),          # Benchmarking (RFC 2544)
]

_DEPARTMENTS = [
    "Finance", "Engineering", "HR", "Legal", "Marketing",
    "Sales", "Operations", "IT Infrastructure", "DevSecOps",
    "Procurement", "Executive", "Research & Development",
]

_FIRST_NAMES = [
    "alex", "blake", "casey", "drew", "elliot", "frankie",
    "grey", "hayden", "indie", "jordan", "kendall", "lane",
    "morgan", "noel", "oakley", "parker", "quinn", "reese",
    "sage", "taylor", "urban", "val", "winter", "xan",
]

_LAST_NAMES = [
    "adams", "bell", "carter", "davis", "evans", "foster",
    "garcia", "hall", "irwin", "jones", "kim", "lee",
    "miller", "nash", "ortiz", "patel", "quinn", "ross",
    "smith", "turner", "ueda", "vance", "walsh", "xu",
]

_WORKSTATION_PREFIXES = [
    "WS", "DESK", "LAPTOP", "PC", "HOST", "NODE", "CLIENT",
]

_SERVER_PREFIXES = [
    "SRV", "SVR", "APP", "DB", "WEB", "API", "SEC",
]


def _rand_internal_ip(rng: random.Random) -> str:
    prefix, a_lo, a_hi, b_lo, b_hi = rng.choice(_INTERNAL_RANGES)
    a = rng.randint(a_lo, a_hi)
    if b_lo is not None and b_hi is not None:
        b = rng.randint(b_lo, b_hi)
        return f"{prefix}{a}.{b}"
    return f"{prefix}{a}"


def _rand_external_ip(rng: random.Random) -> str:
    prefix, a_lo, a_hi, b_lo, b_hi = rng.choice(_EXTERNAL_RANGES)
    a = rng.randint(a_lo, a_hi)
    if b_lo is not None and b_hi is not None:
        b = rng.randint(b_lo, b_hi)
        return f"{prefix}{a}.{b}"
    return f"{prefix}{a}"


def _rand_username(rng: random.Random) -> str:
    first = rng.choice(_FIRST_NAMES)
    last = rng.choice(_LAST_NAMES)
    style = rng.randint(0, 2)
    if style == 0:
        return f"{first[0]}.{last}"       # e.g. j.smith
    if style == 1:
        return f"{first}.{last}"          # e.g. jordan.smith
    return f"{first}{last[:3]}"           # e.g. jordansmi


def _rand_hostname(rng: random.Random, is_server: bool = False) -> str:
    prefix = rng.choice(_SERVER_PREFIXES if is_server else _WORKSTATION_PREFIXES)
    dept_abbr = rng.choice(["FIN", "ENG", "HR", "OPS", "IT", "SEC", "MKT"])
    num = rng.randint(1, 99)
    return f"{prefix}-{dept_abbr}-{num:02d}"


def _rand_department(rng: random.Random) -> str:
    return rng.choice(_DEPARTMENTS)


def _rand_timestamp(rng: random.Random, base_iso: Optional[str] = None) -> str:
    """Return a random ISO-8601 timestamp within ±30 days of base, or a recent date."""
    if base_iso:
        try:
            base = datetime.fromisoformat(base_iso.replace("Z", "+00:00"))
        except ValueError:
            base = datetime.now(tz=timezone.utc)
    else:
        base = datetime.now(tz=timezone.utc)

    delta_days = rng.randint(-30, 0)   # always in the past
    delta_seconds = rng.randint(0, 86400)
    varied = base + timedelta(days=delta_days, seconds=delta_seconds)
    return varied.strftime("%Y-%m-%dT%H:%M:%SZ")


def _substitute_ip(text: str, old_ip: str, new_ip: str) -> str:
    """Replace exact IP occurrences, avoiding partial-match (e.g. 10.0.1.5 vs 10.0.1.50)."""
    # Escape dots for regex, use word boundaries
    escaped = re.escape(old_ip)
    return re.sub(r"\b" + escaped + r"\b", new_ip, text)


def _is_rfc1918(ip: str) -> bool:
    """Check if an IP is in RFC 1918 private ranges (10/8, 172.16/12, 192.168/16)."""
    if ip.startswith("10.") or ip.startswith("192.168."):
        return True
    if ip.startswith("172."):
        # 172.16.0.0 - 172.31.255.255
        parts = ip.split(".")
        if len(parts) >= 2:
            try:
                second = int(parts[1])
                return 16 <= second <= 31
            except ValueError:
                pass
    return False


def _is_plain_ip(value: str) -> bool:
    """Check if a string looks like a plain IPv4 address (not CIDR, not freetext)."""
    parts = value.strip().split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def _is_service_account(user: str) -> bool:
    """Check if a username is a service/system account that should not be varied."""
    lower = user.lower()
    # Explicit prefixes
    if any(lower.startswith(p) for p in ("svc-", "ci-", "devops-", "admin")):
        return True
    # Domain-prefixed accounts (DOMAIN\\account)
    if "\\" in user:
        return True
    # Accounts with no surname separator (likely system identifiers)
    if user.isupper() or user.replace("-", "").replace("_", "").isalpha() is False:
        return False
    return False


def _build_clone(base: dict, rng: random.Random, clone_index: int) -> dict:
    """Build one augmented clone of a base scenario.

    Args:
        base: Original scenario dict (will not be mutated).
        rng: Seeded RNG for reproducibility.
        clone_index: 1-based clone number (appended to the clone id).

    Returns:
        New scenario dict with varied identifiers and a derived id.
    """
    clone = copy.deepcopy(base)

    # Derive a stable clone id: e.g. "phishing-003" → "phishing-003-v2"
    clone["id"] = f"{base['id']}-v{clone_index + 1}"

    # ── Vary source IP ────────────────────────────────────────────────────────
    old_src_ip: str = base["source"].get("ip", "")
    new_src_ip = old_src_ip
    if old_src_ip and _is_plain_ip(old_src_ip):
        new_src_ip = _rand_internal_ip(rng) if _is_rfc1918(old_src_ip) else _rand_external_ip(rng)
        clone["source"]["ip"] = new_src_ip

    # ── Vary target IP ────────────────────────────────────────────────────────
    old_tgt_ip: str = base["target"].get("ip", "")
    new_tgt_ip = old_tgt_ip
    # Only vary plain IPs — skip cloud service labels, CIDR notation, freetext
    if old_tgt_ip and _is_plain_ip(old_tgt_ip):
        new_tgt_ip = _rand_internal_ip(rng) if _is_rfc1918(old_tgt_ip) else _rand_external_ip(rng)
        clone["target"]["ip"] = new_tgt_ip

    # ── Vary username ─────────────────────────────────────────────────────────
    old_user: str = base["target"].get("user", "")
    new_user = old_user
    # Only vary human-looking usernames (skip service accounts, system names, placeholders)
    if (
        old_user
        and old_user not in {"MULTIPLE", "N/A", "", "Administrator"}
        and not _is_service_account(old_user)
    ):
        new_user = _rand_username(rng)
        clone["target"]["user"] = new_user

    # ── Vary department ───────────────────────────────────────────────────────
    old_dept: str = base["target"].get("department", "")
    new_dept = old_dept
    if old_dept and old_dept not in {"MULTIPLE", "AWS", "Azure", "MULTIPLE (Finance, POS, Payments)"}:
        new_dept = _rand_department(rng)
        clone["target"]["department"] = new_dept

    # ── Vary hostname ─────────────────────────────────────────────────────────
    old_host: str = base["target"].get("host", "")
    new_host = old_host
    # Vary hostnames with dots (FQDNs), but skip cloud ARNs/S3/DC= prefixed
    # Also skip multi-host entries (contain " / ")
    if (
        old_host
        and "." in old_host
        and " / " not in old_host
        and not any(old_host.startswith(p) for p in ("s3://", "arn:", "DC="))
    ):
        is_server = any(
            kw in old_host.lower()
            for kw in ("srv", "server", "dc", "db", "sql", "app", "web", "api")
        )
        new_host = _rand_hostname(rng, is_server=is_server) + ".corp.local"
        clone["target"]["host"] = new_host

    # ── Apply substitutions to raw_log ────────────────────────────────────────
    raw = clone["raw_log"]
    if old_src_ip and new_src_ip != old_src_ip and _is_plain_ip(old_src_ip):
        raw = _substitute_ip(raw, old_src_ip, new_src_ip)
    if old_tgt_ip and new_tgt_ip != old_tgt_ip and _is_plain_ip(old_tgt_ip):
        raw = _substitute_ip(raw, old_tgt_ip, new_tgt_ip)
    if old_user and new_user != old_user:
        raw = raw.replace(old_user, new_user)
    if old_host and new_host != old_host and "." in old_host:
        raw = raw.replace(old_host, new_host)
    clone["raw_log"] = raw

    # ── Apply substitutions to alert description ──────────────────────────────
    desc = clone["alert"].get("description", "")
    if old_user and new_user != old_user:
        desc = desc.replace(old_user, new_user)
    if old_src_ip and new_src_ip != old_src_ip and _is_plain_ip(old_src_ip):
        desc = _substitute_ip(desc, old_src_ip, new_src_ip)
    if old_tgt_ip and new_tgt_ip != old_tgt_ip and _is_plain_ip(old_tgt_ip):
        desc = _substitute_ip(desc, old_tgt_ip, new_tgt_ip)
    if old_host and new_host != old_host and "." in old_host:
        desc = desc.replace(old_host, new_host)
    clone["alert"]["description"] = desc

    # ── Vary timestamp in raw_log (date-like patterns) ────────────────────────
    # Replace ISO-8601 timestamps with a shifted version to break memorization
    _ts_pattern = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})Z?")
    matches = list(_ts_pattern.finditer(clone["raw_log"]))
    if matches:
        # Pick a consistent offset for this clone so all timestamps shift together
        day_offset = rng.randint(-14, -1)
        hour_offset = rng.randint(-3, 3)
        for m in reversed(matches):  # reverse to preserve indices during replacement
            try:
                orig_dt = datetime.fromisoformat(m.group(1))
                new_dt = orig_dt + timedelta(days=day_offset, hours=hour_offset)
                new_ts = new_dt.strftime("%Y-%m-%dT%H:%M:%S") + ("Z" if m.group(0).endswith("Z") else "")
                clone["raw_log"] = clone["raw_log"][:m.start()] + new_ts + clone["raw_log"][m.end():]
            except ValueError:
                pass  # Malformed timestamp, skip

    # ── Mark as augmented (for debugging / filtering) ─────────────────────────
    clone["_augmented"] = True
    clone["_base_id"] = base["id"]

    return clone


def build_augmented_pool(
    base_scenarios: Optional[list[dict]] = None,
    seed: int = 0,
    multiplier: int = 3,
) -> list[dict]:
    """Build the full augmented scenario pool.

    For each base scenario, generates (multiplier - 1) augmented clones.
    The base scenario itself is always included unchanged as clone index 0.

    Args:
        base_scenarios: Scenario list to augment. Defaults to ALL_SCENARIOS.
        seed: RNG seed for reproducibility across server restarts.
        multiplier: Total copies per base scenario (1 = no augmentation).

    Returns:
        List of scenario dicts: all originals + all clones.
        Length = len(base_scenarios) * multiplier.
    """
    if base_scenarios is None:
        from . import ALL_SCENARIOS
        base_scenarios = ALL_SCENARIOS

    if multiplier < 1:
        raise ValueError(f"multiplier must be >= 1, got {multiplier}")

    pool: list[dict] = []

    for base in base_scenarios:
        pool.append(base)  # Original is always index 0

        for clone_idx in range(1, multiplier):
            # Per-scenario, per-clone seed: deterministic but uncorrelated.
            # Hash the scenario id + clone index to avoid seed collision.
            digest = hashlib.md5(
                f"{base['id']}:{clone_idx}:{seed}".encode()
            ).hexdigest()
            clone_seed = int(digest[:8], 16)
            rng = random.Random(clone_seed)
            clone = _build_clone(base, rng, clone_index=clone_idx)
            pool.append(clone)

    return pool


def get_pool_stats(pool: list[dict]) -> dict:
    """Return category/difficulty/threat distribution for a scenario pool.

    Args:
        pool: List of scenario dicts (originals + augmented clones).

    Returns:
        Dict with counts by category, difficulty, and threat/benign split.
    """
    stats: dict = {
        "total": len(pool),
        "originals": sum(1 for s in pool if not s.get("_augmented")),
        "augmented": sum(1 for s in pool if s.get("_augmented")),
        "true_threats": sum(1 for s in pool if s.get("is_true_threat")),
        "benign": sum(1 for s in pool if not s.get("is_true_threat")),
        "by_category": {},
        "by_difficulty": {},
    }
    for s in pool:
        cat = s.get("category", "unknown")
        diff = s.get("difficulty", "unknown")
        stats["by_category"][cat] = stats["by_category"].get(cat, 0) + 1
        stats["by_difficulty"][diff] = stats["by_difficulty"].get(diff, 0) + 1

    return stats
