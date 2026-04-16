# SecOps Alert Router — Production Dockerfile
# Hardened: non-root user, pinned image, health check, minimal attack surface

FROM python:3.11-slim@sha256:4fefca94c45f0e33f2e2a76e07d3dc29aae55a6e4b1f74a506c6511278c8b1af AS base

# Prevent Python from writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install dependencies in a separate layer for caching
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY secops_env/ secops_env/
COPY inference.py .
COPY openenv.yaml .
COPY pyproject.toml .

# Create non-root user
RUN groupadd --gid 1001 secops && \
    useradd --uid 1001 --gid secops --shell /bin/false --create-home secops && \
    chown -R secops:secops /app

USER secops

EXPOSE 8000

# Health check using the /health endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

CMD ["uvicorn", "secops_env.server.app:app", "--host", "0.0.0.0", "--port", "8000"]
