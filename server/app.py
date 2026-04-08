"""FastAPI application for the SecOps Alert Triage Environment."""

import sys
import os
from pathlib import Path

# Ensure project root is on the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.responses import HTMLResponse
from openenv.core.env_server import create_app
from secops_env.models import SecOpsAction, SecOpsObservation
from secops_env.server.secops_environment import SecOpsEnvironment

app = create_app(
    SecOpsEnvironment, SecOpsAction, SecOpsObservation, env_name="secops_env"
)

# Serve dashboard UI at root
_STATIC_DIR = Path(__file__).resolve().parent.parent / "secops_env" / "server" / "static"


@app.get("/", response_class=HTMLResponse)
async def dashboard():
    """Serve the SecOps dashboard UI."""
    index_file = _STATIC_DIR / "index.html"
    return HTMLResponse(content=index_file.read_text(encoding="utf-8"))


def main():
    """Entry point for direct execution."""
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)


if __name__ == "__main__":
    main()
