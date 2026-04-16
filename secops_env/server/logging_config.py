"""Structured logging configuration for SecOps Alert Router.

Provides JSON-formatted log output suitable for log aggregation systems
(ELK, Datadog, CloudWatch, etc.). Falls back to human-readable format
when SECOPS_LOG_FORMAT=text.

Environment variables:
    SECOPS_LOG_LEVEL   — Logging level (default: INFO)
    SECOPS_LOG_FORMAT  — "json" (default) or "text"
"""

import json
import logging
import os
import sys
from datetime import datetime, timezone


LOG_LEVEL = os.getenv("SECOPS_LOG_LEVEL", "INFO").upper()
LOG_FORMAT = os.getenv("SECOPS_LOG_FORMAT", "json").lower()


class JSONFormatter(logging.Formatter):
    """Emit log records as single-line JSON objects."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        # Include extra fields passed via `extra={}` in log calls
        for key in ("action", "action_id", "scenario_id", "task_name",
                     "severity", "outcome", "reward", "step", "episode_id",
                     "client_ip", "ws_connections", "error"):
            if hasattr(record, key):
                log_entry[key] = getattr(record, key)

        if record.exc_info and record.exc_info[1]:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_entry, default=str)


def get_logger(name: str) -> logging.Logger:
    """Get a configured logger for the given module name.

    Idempotent: calling multiple times with the same name returns the
    same logger without adding duplicate handlers.
    """
    logger = logging.getLogger(f"secops.{name}")

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)

        if LOG_FORMAT == "json":
            handler.setFormatter(JSONFormatter())
        else:
            handler.setFormatter(logging.Formatter(
                "%(asctime)s [%(levelname)s] %(name)s — %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            ))

        logger.addHandler(handler)
        logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))
        logger.propagate = False

    return logger
