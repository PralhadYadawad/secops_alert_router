"""FastAPI application for the SecOps Alert Triage Environment.

Security controls are configured via environment variables:
    SECOPS_API_KEY         — Enable API key auth (unset = auth disabled)
    SECOPS_CORS_ORIGINS    — Comma-separated allowed CORS origins
    SECOPS_RATE_LIMIT      — Max requests/minute/IP (default: 60)
    SECOPS_WS_MAX_CONNS    — Max concurrent WebSocket connections (default: 50)
    SECOPS_PRODUCTION      — "true" to disable /docs and /redoc
"""

import asyncio
import json
import os
from pathlib import Path
from typing import Optional

from fastapi import HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from openenv.core.env_server import create_app

from ..models import SecOpsAction, SecOpsObservation
from .secops_environment import SecOpsEnvironment
from .playbook_generator import generate_playbook
from .alert_generator import AlertGenerator
from .tasks import TASKS, TASK_NAMES
from .logging_config import get_logger
from .security import (
    API_KEY,
    CORS_ORIGINS,
    IS_PRODUCTION,
    AuthMiddleware,
    RateLimitMiddleware,
    SecurityHeadersMiddleware,
    verify_ws_api_key,
    ws_manager,
)

logger = get_logger("app")

# ── Last completed episode — updated by BroadcastingSecOpsEnvironment ─────────
LAST_EPISODE: dict = {}

# ── Singleton environment instance — persists state across HTTP requests ───────
_ENV_INSTANCE: Optional["BroadcastingSecOpsEnvironment"] = None


async def _do_broadcast(data_str: str) -> None:
    """Push a JSON string to all connected WebSocket clients via the manager."""
    await ws_manager.broadcast(data_str)


def _schedule_broadcast(obs_data: dict) -> None:
    """Schedule a WebSocket broadcast from a synchronous context.

    Uses the running event loop if available (FastAPI/uvicorn async context).
    Silently no-ops if no event loop is running (e.g. during tests).
    """
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(_do_broadcast(json.dumps(obs_data, default=str)))
    except RuntimeError:
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
    """Return the module-level singleton environment instance."""
    global _ENV_INSTANCE
    if _ENV_INSTANCE is None:
        _ENV_INSTANCE = BroadcastingSecOpsEnvironment()
    return _ENV_INSTANCE


# Conditionally disable OpenAPI docs in production
_docs_url = None if IS_PRODUCTION else "/docs"
_redoc_url = None if IS_PRODUCTION else "/redoc"
_openapi_url = None if IS_PRODUCTION else "/openapi.json"

app = create_app(
    _env_factory, SecOpsAction, SecOpsObservation,
    env_name="secops_env",
)

# Override OpenAPI URLs in production
if IS_PRODUCTION:
    app.docs_url = None
    app.redoc_url = None
    app.openapi_url = None

# ── Middleware stack (order matters: last added = first executed) ──────────────

# 1. Security headers on every response
app.add_middleware(SecurityHeadersMiddleware)

# 2. Rate limiting per IP
app.add_middleware(RateLimitMiddleware)

# 3. CORS — only if origins are configured
if CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["X-API-Key", "Content-Type"],
    )

# 4. API key authentication (no-op if SECOPS_API_KEY is unset)
app.add_middleware(AuthMiddleware)


# ── Endpoints ─────────────────────────────────────────────────────────────────

_STATIC_DIR = Path(__file__).parent / "static"


@app.get("/health")
async def health_check() -> dict:
    """Health check endpoint for orchestrators and load balancers."""
    return {
        "status": "healthy",
        "auth_enabled": API_KEY is not None,
        "ws_connections": ws_manager.connection_count,
    }


@app.get("/", response_class=HTMLResponse)
async def dashboard() -> HTMLResponse:
    """Serve the SecOps SOC dashboard UI."""
    index_file = _STATIC_DIR / "index.html"
    return HTMLResponse(content=index_file.read_text(encoding="utf-8"))


@app.websocket("/ws/stream")
async def ws_stream(websocket: WebSocket) -> None:
    """WebSocket endpoint: stream all environment observations to connected clients.

    Security controls:
    - API key validation (via header or query param) when SECOPS_API_KEY is set
    - Connection limit enforcement via WSConnectionManager
    - Dead connection cleanup on disconnect
    """
    client_ip = websocket.client.host if websocket.client else "unknown"

    # Auth check
    if not await verify_ws_api_key(websocket):
        logger.warning("WebSocket auth failed from %s", client_ip, extra={"client_ip": client_ip})
        await websocket.close(code=4001, reason="Authentication required")
        return

    # Connection limit check
    if not ws_manager.can_accept():
        logger.warning(
            "WebSocket connection limit reached (%d), rejecting %s",
            ws_manager.connection_count, client_ip,
            extra={"client_ip": client_ip, "ws_connections": ws_manager.connection_count},
        )
        await websocket.close(code=4002, reason="Connection limit reached")
        return

    await websocket.accept()
    ws_manager.connect(websocket)
    logger.info(
        "WebSocket connected: %s (total: %d)",
        client_ip, ws_manager.connection_count,
        extra={"client_ip": client_ip, "ws_connections": ws_manager.connection_count},
    )
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        ws_manager.disconnect(websocket)
        logger.info("WebSocket disconnected: %s (total: %d)", client_ip, ws_manager.connection_count)


@app.get("/playbook")
async def get_playbook(fmt: str = "json") -> dict:
    """Return a structured SOAR playbook for the last completed episode.

    Generates a deterministic incident response playbook from the agent's
    action trajectory. No LLM required.
    """
    if not LAST_EPISODE:
        return {"error": "No completed episode yet. Run a full episode (to done=True) first."}
    return generate_playbook(**LAST_EPISODE)


# ── Input validation endpoint override ────────────────────────────────────────

@app.post("/reset")
async def validated_reset(body: dict = None) -> dict:
    """Reset with input validation on task_name.

    Rejects unrecognized task names with a 400 instead of silently
    falling back to 'phishing-triage'.
    """
    body = body or {}
    task_name = body.get("task_name")
    if task_name and task_name not in TASKS:
        logger.warning("Invalid task_name rejected: '%s'", task_name, extra={"task_name": task_name})
        raise HTTPException(
            status_code=400,
            detail=f"Unknown task_name '{task_name}'. Valid tasks: {TASK_NAMES}",
        )
    env = _env_factory()
    obs = env.reset(task_name=task_name)
    return {
        "observation": obs.model_dump(),
        "reward": 0.0,
        "done": False,
    }


logger.info(
    "SecOps server initialized: auth=%s, cors=%s, production=%s",
    "enabled" if API_KEY else "disabled",
    len(CORS_ORIGINS) > 0,
    IS_PRODUCTION,
)


def main() -> None:
    """Entry point for direct execution via uv run or python -m."""
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)


if __name__ == "__main__":
    main()
