"""SecOps Alert Router V2 — Inference Script.

Runs the cybersecurity incident triage RL environment with an LLM-based
agent that reads rich observation data (SIEM logs, threat intel, asset
context) and reasons about investigation/containment decisions.

Falls back to a heuristic policy if the LLM API is unavailable.
Emits structured [START]/[STEP]/[END] logs for the hackathon grader.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from secops_env.models import SecOpsAction, QueueAction
from secops_env.server.secops_environment import SecOpsEnvironment
from secops_env.server.queue_environment import QueueEnvironment
from secops_env.server.reward_engine import ACTION_NAMES, SAFE_ACTIONS
from secops_env.server.tasks import TASKS, TASK_NAMES, grade_task
from secops_env.server.investigation_engine import format_investigation_for_observation

API_BASE_URL = os.getenv("API_BASE_URL", "https://router.huggingface.co/v1")
MODEL_NAME = os.getenv("MODEL_NAME", "meta-llama/Meta-Llama-3-70B-Instruct")
HF_TOKEN = os.getenv("HF_TOKEN")

# Reward normalization for [START]/[STEP]/[END] log output
MIN_REWARD = -100.0
MAX_REWARD = 20.0


def normalize_reward(raw_reward: float) -> float:
    """Map raw reward to (0, 1), strictly exclusive."""
    normalized = (raw_reward - MIN_REWARD) / (MAX_REWARD - MIN_REWARD)
    return max(0.01, min(0.99, normalized))


# LLM client setup
llm_client = None
try:
    from openai import OpenAI
    if API_BASE_URL and MODEL_NAME:
        llm_client = OpenAI(base_url=API_BASE_URL, api_key=HF_TOKEN or "no-key")
except ImportError:
    pass


def build_llm_prompt(obs) -> str:
    """Build a rich LLM prompt from the V2 observation."""
    parts = [
        "You are a Security Operations Center (SOC) analyst AI agent.",
        "Analyze the alert below and choose the best action.",
        "",
        "=== ACTIVE ALERT ===",
        f"Rule: {obs.rule_triggered}",
        f"Severity: {obs.severity.upper()}",
        f"MITRE: {obs.mitre_tactic} ({obs.mitre_technique})",
        f"Description: {obs.alert_description}",
        f"Source: {obs.source_ip}" + (f" ({obs.source_domain})" if obs.source_domain else ""),
        f"Target: {obs.target_host} — {obs.target_user}, {obs.target_department}",
        "",
        "=== RAW LOG ===",
        obs.raw_log_snippet if obs.raw_log_snippet else "(no raw log available)",
    ]

    if obs.investigation_history:
        parts.append("")
        parts.append("=== INVESTIGATION RESULTS ===")
        parts.append(format_investigation_for_observation(obs.investigation_history))

    done_actions = set(obs.actions_taken)
    parts.extend([
        "",
        f"=== STATUS: Step {obs.time_steps_elapsed}/{obs.max_steps} ===",
        f"Actions taken: {', '.join(obs.actions_taken) if obs.actions_taken else 'None'}",
        "",
        "=== AVAILABLE ACTIONS ===",
        "Investigation:",
    ])

    inv_actions = {
        0: "analyze_headers — Examine email/packet headers for anomalies",
        1: "query_siem — Search SIEM for related security events",
        2: "check_reputation — Lookup IOC reputation (IP, domain, hash)",
        3: "check_asset — Get target host/user business context",
        4: "analyze_payload — Sandbox/static analysis of suspicious files",
        5: "correlate_alerts — Find related alerts in the last 24h",
    }
    for aid, desc in inv_actions.items():
        tag = " [DONE]" if ACTION_NAMES[aid] in done_actions else ""
        parts.append(f"  {aid}: {desc}{tag}")

    parts.extend([
        "",
        "Containment (requires 2+ investigation steps first):",
        "  6: block_source — Block source IP/domain at firewall",
        "  7: isolate_host — Quarantine affected host from network",
        "  8: disable_account — Disable compromised user account",
        "",
        "Other:",
        "  9: escalate — Escalate to senior analyst / incident response",
        "  10: resolve_benign — Mark as false positive, close alert",
        "",
        "RULES:",
        "- Investigate at least twice before containment (actions 6-8)",
        "- Higher severity = faster containment needed",
        "- Use investigation results to decide: is this a real threat?",
        "- If evidence shows malicious activity (C2, exfiltration, malware, lateral movement, credential abuse), CONTAIN immediately:",
        "    6=block_source for network-based threats, 7=isolate_host for host compromise, 8=disable_account for credential abuse",
        "- BE PARANOID ABOUT PHISHING: Mismatched reply-to addresses, suspicious domains, failed SPF/DKIM, or generic urgency often indicate REAL attacks. Do NOT brush these off as benign.",
        "- If evidence points to benign/legitimate activity confidently, resolve (10)",
        "- If evidence is ambiguous or insufficient, escalate (9)",
        "- NEVER repeat an action marked [DONE] — pick a DIFFERENT number",
        "",
        "Respond with ONLY a single number (0-10). Do NOT pick a [DONE] action.",
    ])

    return "\n".join(parts)


def _is_duplicate_investigation(action_id: int, obs) -> bool:
    """Check if an investigation action has already been taken this episode."""
    if action_id not in SAFE_ACTIONS:
        return False
    return ACTION_NAMES.get(action_id, "") in set(obs.actions_taken)


def _parse_action_from_text(text: str) -> int:
    """Extract a valid action ID (0-10) from LLM response text.

    Takes the LAST valid number found so reasoning text like
    "Based on step 2, I choose 10" correctly returns 10.
    """
    import re
    candidates = []
    for match in re.finditer(r'\b(\d+)\b', text):
        val = int(match.group(1))
        if 0 <= val <= 10:
            candidates.append(val)
    if candidates:
        return candidates[-1]
    # Fallback: no word boundaries (LLM might output "10" with no surrounding text)
    for match in re.finditer(r'(\d+)', text):
        val = int(match.group(1))
        if 0 <= val <= 10:
            candidates.append(val)
    return candidates[-1] if candidates else -1


def get_llm_action(obs) -> int:
    """Get action from LLM with duplicate-action filtering.

    If the LLM picks an already-completed investigation action, retries
    once with an explicit correction prompt. Falls back to heuristic if
    the retry also fails or returns a duplicate.
    """
    if llm_client is None:
        return get_heuristic_action(obs)
    try:
        prompt = build_llm_prompt(obs)
        messages = [{"role": "user", "content": prompt}]
        response = llm_client.chat.completions.create(
            model=MODEL_NAME, messages=messages, max_tokens=5, temperature=0.1,
        )
        text = response.choices[0].message.content.strip()
        action_id = _parse_action_from_text(text)

        if action_id < 0:
            return get_heuristic_action(obs)

        # If LLM picked a duplicate investigation, retry once with correction
        if _is_duplicate_investigation(action_id, obs):
            done_list = ", ".join(obs.actions_taken)
            messages.append({"role": "assistant", "content": text})
            messages.append({"role": "user", "content": (
                f"Action {action_id} ({ACTION_NAMES[action_id]}) is already done. "
                f"Already completed: [{done_list}]. "
                "Pick a DIFFERENT number (0-10)."
            )})
            retry = llm_client.chat.completions.create(
                model=MODEL_NAME, messages=messages, max_tokens=5, temperature=0.2,
            )
            retry_id = _parse_action_from_text(retry.choices[0].message.content.strip())
            if retry_id >= 0 and not _is_duplicate_investigation(retry_id, obs):
                return retry_id
            return get_heuristic_action(obs)

        return action_id
    except Exception:
        return get_heuristic_action(obs)


def get_heuristic_action(obs) -> int:
    """Heuristic fallback policy using weighted evidence analysis.

    Three-phase approach: gather → analyze → decide.
    Uses weighted threat/benign indicators and severity priors
    to make proportional containment decisions.
    """
    done_actions = set(obs.actions_taken)
    inv_names = {ACTION_NAMES[i] for i in SAFE_ACTIONS}
    inv_count = sum(1 for a in obs.actions_taken if a in inv_names)
    severity = obs.severity
    steps_remaining = obs.max_steps - obs.time_steps_elapsed

    # Phase 1: Gather minimum evidence (2 investigations required)
    investigation_priority = [1, 2, 0, 3, 4, 5]  # siem, reputation, headers, asset, payload, correlate
    if inv_count < 2:
        for aid in investigation_priority:
            if ACTION_NAMES[aid] not in done_actions:
                return aid

    # Phase 2: Weighted evidence analysis from investigation text
    inv_text = " ".join(entry.get("result", "") for entry in obs.investigation_history).lower()

    # Strong indicators (weight 3): definitive evidence
    strong_threat = [
        "malware", "c2 beacon", "ransomware", "exfiltration", "exploit kit",
        "cobalt strike", "mimikatz", "encoded command", "base64 -e",
        "lateral movement", "privilege escalation", "data theft",
        "command and control", "reverse shell", "credential dump",
        "dns tunneling", "pass-the-hash", "golden ticket",
    ]
    strong_benign = [
        "false positive", "legitimate business", "authorized by",
        "expected behavior", "scheduled maintenance", "known vendor",
        "no indicators of compromise", "verified safe", "approved change",
    ]

    # Medium indicators (weight 2): suggestive evidence
    medium_threat = [
        "suspicious", "anomalous", "unauthorized", "brute force",
        "phishing", "obfuscated", "fileless", "living off the land",
        "renamed binary", "unusual hours", "bulk download", "beacon",
        "encrypted channel", "non-standard port", "powershell -enc",
        "certutil", "bitsadmin", "regsvr32", "mshta",
    ]
    medium_benign = [
        "clean scan", "normal activity", "benign", "marketing email",
        "newsletter", "routine", "standard procedure", "no anomalies",
    ]

    # Weak indicators (weight 1): contextual hints
    weak_threat = [
        "flagged", "elevated", "multiple failed", "high entropy",
        "after hours", "external ip", "new process",
    ]
    weak_benign = [
        "low risk", "informational", "known pattern", "regular schedule",
    ]

    threat_score = (
        sum(3 for kw in strong_threat if kw in inv_text)
        + sum(2 for kw in medium_threat if kw in inv_text)
        + sum(1 for kw in weak_threat if kw in inv_text)
    )
    benign_score = (
        sum(3 for kw in strong_benign if kw in inv_text)
        + sum(2 for kw in medium_benign if kw in inv_text)
        + sum(1 for kw in weak_benign if kw in inv_text)
    )

    # Severity prior: higher severity alerts are more likely real threats
    severity_prior = {"medium": 0, "high": 3, "critical": 6}
    threat_score += severity_prior.get(severity, 0)

    # Phase 3: Decision with escalating decisiveness
    def _contain(sev):
        """Pick proportional containment action matching reward_engine's proportional map."""
        if sev == "critical":
            return 7  # isolate_host — proportional for critical
        elif sev == "high":
            return 7  # isolate_host — proportional for high
        return 6  # block_source — proportional for medium

    # After 4+ investigations or running out of time: must decide now
    if inv_count >= 4 or steps_remaining <= 2:
        if threat_score > benign_score:
            return _contain(severity)
        elif benign_score > threat_score + 3:
            return 10  # resolve_benign — high confidence benign
        elif threat_score > 0:
            return _contain(severity)  # lean toward containment when uncertain
        else:
            return 10  # resolve_benign

    # After 2-3 investigations: decide if evidence is clear, else investigate more
    clear_margin = 5  # need strong signal to act early
    if threat_score >= benign_score + clear_margin:
        return _contain(severity)
    elif benign_score >= threat_score + clear_margin:
        return 10  # resolve_benign

    # Evidence ambiguous — gather more
    for aid in investigation_priority:
        if ACTION_NAMES[aid] not in done_actions:
            return aid

    # All investigations exhausted — decide on balance of evidence
    if threat_score >= benign_score:
        return _contain(severity)
    return 10  # resolve_benign


def run_inference():
    """Run all tasks, emitting mandatory [START]/[STEP]/[END] stdout logs."""
    model_display = MODEL_NAME or "heuristic"

    for task_name in TASK_NAMES:
        task_config = TASKS[task_name]
        num_episodes = task_config["num_episodes"]
        max_steps = task_config["max_steps"]
        episode_results = []

        is_queue = task_name == "queue-triage"
        if is_queue:
            env = QueueEnvironment(task_name=task_name)
        else:
            env = SecOpsEnvironment(task_name=task_name, max_steps=max_steps)

        for ep in range(num_episodes):
            obs = env.reset(seed=42 + ep)

            print(f"[START] task={task_name} env=secops_env model={model_display}")

            step_rewards = []
            step_num = 0
            current_queue_slot = 0  # tracks which alert slot to work on

            step_limit = (task_config.get("max_total_steps", max_steps * 2) * 2) if is_queue else max_steps * 2
            while not obs.done and step_num < step_limit:
                if is_queue:
                    # Find the first undone slot to act on
                    queue_summary = getattr(obs, "queue_summary", []) or []
                    undone_slots = [i for i, s in enumerate(queue_summary) if not s.get("done")]
                    if undone_slots:
                        current_queue_slot = undone_slots[0]
                    # Convert active_alert dict → SecOpsObservation for LLM/heuristic
                    active_dict = getattr(obs, "active_alert", {}) or {}
                    try:
                        from secops_env.models import SecOpsObservation as _SOObs
                        llm_obs = _SOObs(**active_dict)
                    except Exception:
                        llm_obs = obs
                    action_id = get_llm_action(llm_obs)
                    action = QueueAction(action_id=action_id, alert_index=current_queue_slot)
                else:
                    action_id = get_llm_action(obs)
                    action = SecOpsAction(action_id=action_id)

                obs = env.step(action)
                step_num += 1

                action_name = ACTION_NAMES.get(action_id, "unknown")
                normalized = normalize_reward(obs.reward)
                step_rewards.append(normalized)

                error_str = "null"
                meta = (obs.metadata or {}) if not is_queue else {}
                status = meta.get("status", "")
                if status in ("duplicate_action", "procedure_violation"):
                    error_str = status

                done_str = "true" if obs.done else "false"
                print(
                    f"[STEP] step={step_num} action={action_name} "
                    f"reward={normalized:.2f} done={done_str} error={error_str}"
                )

            if is_queue:
                outcome = "queue_complete" if all(s.get("done") for s in (obs.queue_summary or [])) else "queue_timeout"
                success = outcome == "queue_complete"
                meta_reward = (obs.metadata or {}).get("cumulative_reward", obs.reward)
                inv_count = 0
            else:
                outcome = (obs.metadata or {}).get("status", "unknown")
                success = outcome in ("true_positive", "true_negative", "escalated_true_threat", "timeout_benign")
                meta_reward = (obs.metadata or {}).get("cumulative_reward", obs.reward)
                inv_count = (obs.metadata or {}).get("investigation_count", 0)

            # Queue episodes use max_total_steps (40) not per-alert max_steps (10)
            effective_max_steps = task_config.get("max_total_steps", max_steps) if is_queue else max_steps
            episode_results.append({
                "reward": meta_reward,
                "steps": step_num,
                "outcome": outcome,
                "max_steps": effective_max_steps,
                "investigation_count": inv_count,
            })

            task_score = grade_task(task_name, episode_results)

            rewards_str = ",".join(f"{r:.2f}" for r in step_rewards)
            success_str = "true" if success else "false"
            print(
                f"[END] success={success_str} steps={step_num} "
                f"score={task_score:.3f} rewards={rewards_str}"
            )

        env.close()


if __name__ == "__main__":
    run_inference()
