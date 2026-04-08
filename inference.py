"""
SecOps Alert Router — Inference Script
Meta PyTorch OpenEnv Hackathon Submission

Runs the cybersecurity incident triage RL environment (secops_env) with an
LLM-based agent. Falls back to a heuristic policy if the LLM API is
unavailable. Emits structured stdout logs in the mandatory
[START]/[STEP]/[END] key=value format required by the hackathon grader.
"""

import os
import sys

# Add project root to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from secops_env.models import SecOpsAction
from secops_env.server.secops_environment import SecOpsEnvironment
from secops_env.server.alert_generator import (
    ACTION_NAMES,
    ALERT_TYPE_NAMES,
    SEVERITY_NAMES,
)
from secops_env.server.tasks import TASKS, TASK_NAMES, grade_task

# ---------------------------------------------------------------------------
# Environment variables
# ---------------------------------------------------------------------------
API_BASE_URL = os.getenv("API_BASE_URL", "https://router.huggingface.co/v1")
MODEL_NAME = os.getenv("MODEL_NAME", "Qwen/Qwen2.5-72B-Instruct")
HF_TOKEN = os.getenv("HF_TOKEN")

# ---------------------------------------------------------------------------
# Reward normalization constants
# ---------------------------------------------------------------------------
MIN_REWARD = -50.0
MAX_REWARD = 12.0


def normalize_reward(raw_reward: float) -> float:
    """Map raw reward from [-50, +12] to [0.0, 1.0], clamped."""
    normalized = (raw_reward - MIN_REWARD) / (MAX_REWARD - MIN_REWARD)
    return max(0.0, min(1.0, normalized))


# ---------------------------------------------------------------------------
# LLM client setup
# ---------------------------------------------------------------------------
llm_client = None
try:
    from openai import OpenAI

    if API_BASE_URL and MODEL_NAME:
        llm_client = OpenAI(
            base_url=API_BASE_URL,
            api_key=HF_TOKEN or "no-key",
        )
except ImportError:
    pass


# ---------------------------------------------------------------------------
# LLM prompt & action selection
# ---------------------------------------------------------------------------
def build_llm_prompt(obs) -> str:
    """Build the LLM prompt from the current observation."""
    alert_name = ALERT_TYPE_NAMES.get(obs.alert_type, "Unknown")
    severity_name = SEVERITY_NAMES.get(obs.severity, "Unknown")
    evidence = [ACTION_NAMES[i] for i, flag in enumerate(obs.evidence_flags) if flag]
    remaining = 5 - obs.time_steps_elapsed

    return (
        "You are a Security Operations Center (SOC) analyst AI agent.\n"
        "\n"
        "Current Alert:\n"
        f"- Type: {alert_name}\n"
        f"- Severity: {severity_name}\n"
        f"- Confidence Score: {obs.confidence_score:.2f}\n"
        f"- Evidence Collected: {evidence if evidence else 'None'}\n"
        f"- Steps Remaining: {remaining}\n"
        "\n"
        "Available Actions:\n"
        "Safe (investigation):\n"
        "  0: analyze_headers - Examine email/packet headers\n"
        "  1: query_logs - Search SIEM logs for related events\n"
        "  2: verify_identity - Verify user/source identity\n"
        "  3: scope_environment - Assess affected systems scope\n"
        "\n"
        "Risky (containment - requires at least 1 investigation first):\n"
        "  4: block_ip - Block source IP address\n"
        "  5: isolate_host - Isolate affected host from network\n"
        "  6: disable_account - Disable compromised user account\n"
        "\n"
        "Resolve:\n"
        "  7: acknowledge_allow - Mark alert as benign, no action needed\n"
        "\n"
        "Rules:\n"
        "- You MUST investigate (actions 0-3) at least once before using containment (4-6)\n"
        "- Higher severity alerts need faster containment\n"
        "- If confidence is low after investigation, consider resolving as benign (7)\n"
        "- Each investigation step costs -1 reward, so don't over-investigate\n"
        "\n"
        "Respond with ONLY a single digit (0-7) representing your chosen action."
    )


def get_llm_action(obs) -> int:
    """Get action from LLM, falling back to heuristic on any failure."""
    if llm_client is None:
        return get_heuristic_action(obs)

    try:
        prompt = build_llm_prompt(obs)
        response = llm_client.chat.completions.create(
            model=MODEL_NAME,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=5,
            temperature=0.1,
        )
        text = response.choices[0].message.content.strip()
        for char in text:
            if char.isdigit() and 0 <= int(char) <= 7:
                return int(char)
        return get_heuristic_action(obs)
    except Exception:
        return get_heuristic_action(obs)


# ---------------------------------------------------------------------------
# Heuristic fallback policy
# ---------------------------------------------------------------------------
def get_heuristic_action(obs) -> int:
    """Fallback heuristic policy when LLM is unavailable."""
    evidence_count = sum(obs.evidence_flags)
    severity = obs.severity
    confidence = obs.confidence_score

    if evidence_count == 0:
        return 1  # query_logs first

    if severity == 2:  # Critical
        if confidence >= 0.15:
            return 5  # isolate_host
        elif evidence_count < 2:
            return 0  # analyze_headers
        else:
            return 5

    if severity == 1:  # High
        if evidence_count < 2:
            for i in range(4):
                if not obs.evidence_flags[i]:
                    return i
            return 4
        if confidence >= 0.30:
            return 4  # block_ip
        else:
            return 7  # acknowledge_allow

    # Medium
    if evidence_count < 2:
        for i in range(4):
            if not obs.evidence_flags[i]:
                return i
        return 7
    if confidence >= 0.25:
        return 6  # disable_account
    else:
        return 7  # acknowledge_allow


# ---------------------------------------------------------------------------
# Main inference loop
# ---------------------------------------------------------------------------
def run_inference():
    """Run all tasks, emitting mandatory [START]/[STEP]/[END] stdout logs."""
    model_display = MODEL_NAME or "heuristic"

    for task_name in TASK_NAMES:
        task_config = TASKS[task_name]
        num_episodes = task_config["num_episodes"]
        max_steps = task_config["max_steps"]
        episode_results = []

        for ep in range(num_episodes):
            env = SecOpsEnvironment(
                task_name=task_name, max_steps=max_steps, seed=42 + ep
            )
            obs = env.reset()

            print(f"[START] task={task_name} env=secops_env model={model_display}")

            step_rewards = []
            step_num = 0

            while not obs.done and step_num < max_steps * 2:
                action_id = get_llm_action(obs)
                action = SecOpsAction(action_id=action_id)
                obs = env.step(action)
                step_num += 1

                action_name = ACTION_NAMES.get(action_id, "unknown")
                normalized = normalize_reward(obs.reward)
                step_rewards.append(normalized)

                error_str = obs.metadata.get("last_action_error") or "null"
                if error_str != "null":
                    error_str = error_str.replace("\n", " ")

                done_str = "true" if obs.done else "false"
                print(
                    f"[STEP] step={step_num} action={action_name} "
                    f"reward={normalized:.2f} done={done_str} error={error_str}"
                )

            # Determine outcome
            outcome = obs.metadata.get("status", "unknown")
            success = outcome in (
                "true_positive",
                "true_positive_fast",
                "true_negative",
                "timeout_benign",
            )

            episode_results.append(
                {
                    "reward": obs.reward,
                    "steps": step_num,
                    "outcome": outcome,
                    "max_steps": max_steps,
                }
            )

            env.close()

            task_score = grade_task(task_name, episode_results)

            rewards_str = ",".join(f"{r:.2f}" for r in step_rewards)
            success_str = "true" if success else "false"
            print(
                f"[END] success={success_str} steps={step_num} "
                f"score={task_score:.3f} rewards={rewards_str}"
            )


if __name__ == "__main__":
    run_inference()
