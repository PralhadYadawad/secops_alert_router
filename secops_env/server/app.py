"""FastAPI application for the SecOps Alert Triage Environment."""

import os
from pathlib import Path

from fastapi.responses import HTMLResponse
from openenv.core.env_server import create_app

from ..models import SecOpsAction, SecOpsObservation
from .secops_environment import SecOpsEnvironment

# Create the FastAPI app
# Pass the class (factory) instead of an instance for WebSocket session support
app = create_app(
    SecOpsEnvironment, SecOpsAction, SecOpsObservation, env_name="secops_env"
)

# Serve dashboard UI at root
_STATIC_DIR = Path(__file__).parent / "static"


@app.get("/", response_class=HTMLResponse)
async def dashboard():
    """Serve the SecOps dashboard UI."""
    index_file = _STATIC_DIR / "index.html"
    return HTMLResponse(content=index_file.read_text(encoding="utf-8"))


def main():
    """Entry point for direct execution via uv run or python -m."""
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)


if __name__ == "__main__":
    main()
