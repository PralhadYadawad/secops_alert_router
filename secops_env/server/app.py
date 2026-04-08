"""FastAPI application for the SecOps Alert Triage Environment."""

from openenv.core.env_server import create_app

from ..models import SecOpsAction, SecOpsObservation
from .secops_environment import SecOpsEnvironment

# Create the FastAPI app
# Pass the class (factory) instead of an instance for WebSocket session support
app = create_app(
    SecOpsEnvironment, SecOpsAction, SecOpsObservation, env_name="secops_env"
)


def main():
    """Entry point for direct execution via uv run or python -m."""
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)


if __name__ == "__main__":
    main()
