"""FastAPI application for the SecOps Alert Triage Environment."""

import sys
import os

# Ensure project root is on the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from openenv.core.env_server import create_app
from secops_env.models import SecOpsAction, SecOpsObservation
from secops_env.server.secops_environment import SecOpsEnvironment

app = create_app(
    SecOpsEnvironment, SecOpsAction, SecOpsObservation, env_name="secops_env"
)


def main():
    """Entry point for direct execution."""
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)


if __name__ == "__main__":
    main()
