"""FastAPI application for the SecOps Alert Triage Environment."""

import asyncio
import json
import os
from pathlib import Path
from typing import Optional

from fastapi import WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from openenv.core.env_server import create_app

from ..models import SecOpsAction, SecOpsObservation
from .secops_environment import SecOpsEnvironment
from .playbook_generator import generate_playbook
from .alert_generator import AlertGenerator
from .tasks import TASKS

# ── WebSocket broadcast state ──────────────────────────────────────────────────
_ws_clients: set[WebSocket] = set()

# ── Last completed episode — updated by BroadcastingSecOpsEnvironment ─────────
LAST_EPISODE: dict = {}

# ── Singleton environment instance — persists state across HTTP requests ───────
_ENV_INSTANCE: Optional["BroadcastingSecOpsEnvironment"] = None


async def _do_broadcast(data_str: str) -> None:
    """Push a JSON string to all connected WebSocket clients.

    Dead connections are collected and removed after each broadcast round.
    """
    dead: set[WebSocket] = set()
    for ws in _ws_clients:
        try:
            await ws.send_text(data_str)
        except Exception:
            dead.add(ws)
    _ws_clients.difference_update(dead)


def _schedule_broadcast(obs_data: dict) -> None:
    """Schedule a WebSocket broadcast from a synchronous context.

    Uses the running event loop if available (FastAPI/uvicorn async context).
    Silently no-ops if no event loop is running (e.g. during tests).
    """
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(_do_broadcast(json.dumps(obs_data, default=str)))
    except RuntimeError:
        # No running loop — skip broadcast (non-async context, e.g. tests)
        pass


class BroadcastingSecOpsEnvironment(SecOpsEnvironment):
    """SecOpsEnvironment that broadcasts state changes to WebSocket clients.

    Subclasses SecOpsEnvironment to add two side-effects:
    1. Every reset() / step() response is broadcast to connected WS clients.
    2. Every terminal step() response is captured in LAST_EPISODE for the
       /playbook endpoint.

    The core RL logic is unchanged — this class only wraps the parent methods.
    """

    def reset(self, *args, task_name: Optional[str] = None, **kwargs) -> SecOpsObservation:
        """Reset and broadcast the initial observation.

        Supports live task switching: if task_name differs from the current
        task, the alert generator is re-configured before generating the new
        scenario. This allows the dashboard task tabs to take effect at runtime
        without restarting the server.
        """
        if task_name and task_name != self._task_name:
            task_config = TASKS.get(task_name, TASKS["phishing-triage"])
            self._task_name = task_name
            self._max_steps = task_config.get("max_steps", 10)
            self._alert_gen = AlertGenerator(
                seed=kwargs.get("seed"),
                categories=task_config.get("categories"),
                difficulties=task_config.get("difficulties"),
                threat_ratio=task_config.get("threat_ratio"),
                max_steps=self._max_steps,
            )
        obs = super().reset(*args, **kwargs)
        _schedule_broadcast(obs.model_dump())
        return obs

    def step(self, action: SecOpsAction, **kwargs) -> SecOpsObservation:
        """Step, capture terminal state for playbook, and broadcast."""
        obs = super().step(action, **kwargs)

        if obs.done:
            # Capture episode data for /playbook endpoint
            LAST_EPISODE.clear()
            LAST_EPISODE.update({
                "scenario": self._scenario,
                "actions_taken": list(self._state.actions_taken),
                "investigation_history": obs.investigation_history,
                "outcome": (obs.metadata or {}).get("status", "unknown"),
                "cumulative_reward": self._state.cumulative_reward,
                "steps_taken": self._state.step_count,
            })

        _schedule_broadcast(obs.model_dump())
        return obs


# ── FastAPI app ────────────────────────────────────────────────────────────────
def _env_factory() -> BroadcastingSecOpsEnvironment:
    """Return the module-level singleton environment instance.

    OpenEnv calls the factory on every /reset and /step request. Using a
    singleton ensures episode state (step count, actions taken, scenario)
    persists across the full request-response cycle of each episode.
    """
    global _ENV_INSTANCE
    if _ENV_INSTANCE is None:
        _ENV_INSTANCE = BroadcastingSecOpsEnvironment()
    return _ENV_INSTANCE


app = create_app(
    _env_factory, SecOpsAction, SecOpsObservation,
    env_name="secops_env",
)

# Serve dashboard UI at root
_STATIC_DIR = Path(__file__).parent / "static"


@app.get("/", response_class=HTMLResponse)
async def dashboard() -> HTMLResponse:
    """Serve the SecOps SOC dashboard UI."""
    index_file = _STATIC_DIR / "index.html"
    return HTMLResponse(content=index_file.read_text(encoding="utf-8"))


@app.websocket("/ws/stream")
async def ws_stream(websocket: WebSocket) -> None:
    """WebSocket endpoint: stream all environment observations to connected clients.

    Clients connect and receive a JSON push on every reset() and step().
    Useful for watching inference.py runs live in the dashboard.
    """
    await websocket.accept()
    _ws_clients.add(websocket)
    try:
        # Keep connection alive — handle incoming pings, ignore content
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        _ws_clients.discard(websocket)
    except Exception:
        _ws_clients.discard(websocket)


@app.get("/playbook")
async def get_playbook(fmt: str = "json") -> dict:
    """Return a structured SOAR playbook for the last completed episode.

    Generates a deterministic incident response playbook from the agent's
    action trajectory. No LLM required.

    Args:
        fmt: Response format. "json" (default) returns the playbook dict.
             Other values are reserved for future Markdown support.

    Returns:
        Playbook dict or error dict if no episode has been completed yet.
    """
    if not LAST_EPISODE:
        return {"error": "No completed episode yet. Run a full episode (to done=True) first."}
    return generate_playbook(**LAST_EPISODE)


def main() -> None:
    """Entry point for direct execution via uv run or python -m."""
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)


if __name__ == "__main__":
    main()
