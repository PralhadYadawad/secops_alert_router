"""Re-export for openenv validator — actual app lives in secops_env.server.app."""

from secops_env.server.app import app, main

if __name__ == "__main__":
    main()
