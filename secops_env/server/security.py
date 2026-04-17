"""Security middleware and utilities for SecOps Alert Router.

Provides API key authentication, rate limiting, security headers,
CORS configuration, and WebSocket connection management.

All controls are configurable via environment variables and degrade
gracefully: when no API key is set, auth is skipped so development
and testing workflows are unaffected.

Environment variables:
    SECOPS_API_KEY         — Required API key for all HTTP/WS endpoints.
                             If unset, authentication is disabled.
    SECOPS_CORS_ORIGINS    — Comma-separated allowed origins for CORS.
                             Default: "" (no CORS headers added).
    SECOPS_RATE_LIMIT      — Max requests per minute per IP. Default: 60.
    SECOPS_WS_MAX_CONNS    — Max concurrent WebSocket connections. Default: 50.
    SECOPS_PRODUCTION      — Set to "true" to disable /docs, /redoc, /openapi.json.
"""

import os
import time
from collections import defaultdict
from typing import Optional

from fastapi import HTTPException, Request, WebSocket, status
from fastapi.security import APIKeyHeader
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

# ── Configuration from environment ────────────────────────────────────────────

API_KEY: Optional[str] = os.getenv("SECOPS_API_KEY")
CORS_ORIGINS: list[str] = [
    o.strip()
    for o in os.getenv("SECOPS_CORS_ORIGINS", "").split(",")
    if o.strip()
]
RATE_LIMIT: int = int(os.getenv("SECOPS_RATE_LIMIT", "60"))
WS_MAX_CONNS: int = int(os.getenv("SECOPS_WS_MAX_CONNS", "50"))
IS_PRODUCTION: bool = os.getenv("SECOPS_PRODUCTION", "").lower() == "true"

# ── API Key Authentication ────────────────────────────────────────────────────

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def verify_api_key(request: Request) -> Optional[str]:
    """Validate the X-API-Key header if SECOPS_API_KEY is configured.

    When no API key is configured (dev/test), this is a no-op.
    When configured, missing or wrong keys raise 401/403.
    """
    if not API_KEY:
        return None  # Auth disabled — allow all requests

    key = request.headers.get("X-API-Key")
    if not key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-API-Key header",
        )
    if key != API_KEY:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid API key",
        )
    return key


async def verify_ws_api_key(websocket: WebSocket) -> bool:
    """Validate API key for WebSocket connections.

    Checks the X-API-Key header or `api_key` query parameter.
    Returns True if auth passes (or is disabled), False otherwise.
    """
    if not API_KEY:
        return True

    key = websocket.headers.get("X-API-Key") or websocket.query_params.get("api_key")
    return key == API_KEY


# ── Rate Limiter (in-memory token bucket per IP) ─────────────────────────────

class RateLimiter:
    """Simple in-memory sliding-window rate limiter.

    Tracks request timestamps per client IP and rejects requests
    that exceed the configured rate.
    """

    def __init__(self, max_requests: int = 60, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window = window_seconds
        self._requests: dict[str, list[float]] = {}
        self._last_cleanup: float = time.monotonic()
        self._cleanup_interval: float = 300.0  # auto-cleanup every 5 minutes

    def is_allowed(self, client_ip: str) -> bool:
        """Check if a request from client_ip is within the rate limit."""
        now = time.monotonic()
        window_start = now - self.window

        # Auto-cleanup stale entries periodically
        if now - self._last_cleanup > self._cleanup_interval:
            self._cleanup(now)

        # Prune old entries for this IP
        timestamps = self._requests.get(client_ip, [])
        timestamps = [t for t in timestamps if t > window_start]

        if len(timestamps) >= self.max_requests:
            self._requests[client_ip] = timestamps
            return False

        timestamps.append(now)
        self._requests[client_ip] = timestamps
        return True

    def _cleanup(self, now: float) -> None:
        """Remove stale entries to prevent memory growth."""
        window_start = now - self.window
        stale_keys = [
            ip for ip, ts in self._requests.items()
            if not ts or ts[-1] < window_start
        ]
        for key in stale_keys:
            del self._requests[key]
        self._last_cleanup = now

    def cleanup(self) -> None:
        """Public cleanup method for external callers."""
        self._cleanup(time.monotonic())


_rate_limiter = RateLimiter(max_requests=RATE_LIMIT, window_seconds=60)


# ── Security Headers Middleware ───────────────────────────────────────────────

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all HTTP responses.

    Headers added:
    - X-Content-Type-Options: nosniff
    - X-Frame-Options: DENY
    - X-XSS-Protection: 1; mode=block
    - Referrer-Policy: strict-origin-when-cross-origin
    - Content-Security-Policy: restrictive default policy
    - Permissions-Policy: restrict sensitive APIs
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=()"
        )
        # Allow HuggingFace Spaces to embed the app in its iframe
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self' ws: wss:; "
            "font-src 'self'; "
            "frame-ancestors 'self' https://*.hf.space https://huggingface.co"
        )
        return response


# ── Rate Limit Middleware ─────────────────────────────────────────────────────

class RateLimitMiddleware(BaseHTTPMiddleware):
    """Enforce per-IP rate limiting on all HTTP requests."""

    async def dispatch(self, request: Request, call_next) -> Response:
        client_ip = request.client.host if request.client else "unknown"
        if not _rate_limiter.is_allowed(client_ip):
            return Response(
                content='{"detail":"Rate limit exceeded. Try again later."}',
                status_code=429,
                media_type="application/json",
            )
        return await call_next(request)


# ── Authentication Middleware ─────────────────────────────────────────────────

class AuthMiddleware(BaseHTTPMiddleware):
    """Enforce API key authentication on all HTTP requests.

    Exempts the root dashboard ("/") and health check endpoints so the
    dashboard remains accessible. All API endpoints require auth when
    SECOPS_API_KEY is configured.
    """

    # Paths that don't require authentication
    EXEMPT_PATHS = {"/", "/health", "/docs", "/redoc", "/openapi.json"}

    async def dispatch(self, request: Request, call_next) -> Response:
        if not API_KEY:
            return await call_next(request)

        # Exempt specific paths
        if request.url.path in self.EXEMPT_PATHS:
            return await call_next(request)

        # Skip WebSocket upgrades — handled by ws_stream endpoint
        if request.headers.get("upgrade", "").lower() == "websocket":
            return await call_next(request)

        key = request.headers.get("X-API-Key")
        if not key:
            return Response(
                content='{"detail":"Missing X-API-Key header"}',
                status_code=401,
                media_type="application/json",
            )
        if key != API_KEY:
            return Response(
                content='{"detail":"Invalid API key"}',
                status_code=403,
                media_type="application/json",
            )

        return await call_next(request)


# ── WebSocket Connection Manager ──────────────────────────────────────────────

class WSConnectionManager:
    """Manage WebSocket connections with connection limits and tracking."""

    def __init__(self, max_connections: int = 50):
        self.max_connections = max_connections
        self.active_connections: set[WebSocket] = set()

    @property
    def connection_count(self) -> int:
        return len(self.active_connections)

    def can_accept(self) -> bool:
        return self.connection_count < self.max_connections

    def connect(self, websocket: WebSocket) -> None:
        self.active_connections.add(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        self.active_connections.discard(websocket)

    async def broadcast(self, data_str: str) -> None:
        """Push a JSON string to all connected clients, removing dead ones.

        Takes a snapshot of connections before iterating to avoid
        RuntimeError from set mutation during async iteration.
        """
        dead: set[WebSocket] = set()
        # Snapshot: prevents RuntimeError if connect/disconnect modifies the set
        # while we yield control at each await
        snapshot = list(self.active_connections)
        for ws in snapshot:
            try:
                await ws.send_text(data_str)
            except Exception:
                dead.add(ws)
        if dead:
            self.active_connections.difference_update(dead)


ws_manager = WSConnectionManager(max_connections=WS_MAX_CONNS)
