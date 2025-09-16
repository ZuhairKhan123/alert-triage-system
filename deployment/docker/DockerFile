# Alert Triage System - Production Docker Image
FROM python:3.11-slim as base

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Create non-root user
RUN groupadd --gid 1000 alerttriage && \
    useradd --uid 1000 --gid alerttriage --shell /bin/bash --create-home alerttriage

# Install system dependencies
RUN apt-get update && apt-get install -y \
    --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Development stage
FROM base as development

# Install development dependencies
RUN apt-get update && apt-get install -y \
    --no-install-recommends \
    git \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt requirements-dev.txt ./
RUN pip install -r requirements-dev.txt

# Copy source code
COPY --chown=alerttriage:alerttriage . .

USER alerttriage

# Development command
CMD ["python", "src/main.py"]

# Production stage
FROM base as production

WORKDIR /app

# Copy requirements and install
COPY requirements.txt ./
RUN pip install -r requirements.txt

# Copy application code
COPY --chown=alerttriage:alerttriage src/ ./src/
COPY --chown=alerttriage:alerttriage config/ ./config/
COPY --chown=alerttriage:alerttriage data/ ./data/

# Create necessary directories
RUN mkdir -p logs && \
    chown -R alerttriage:alerttriage logs

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

USER alerttriage

# Expose ports
EXPOSE 8080 8081 9090

# Production command
CMD ["python", "src/main.py"]

# Multi-arch build stage
FROM production as multi-arch

# Support for ARM64 and AMD64
ARG TARGETPLATFORM
ARG BUILDPLATFORM

RUN echo "Building for $TARGETPLATFORM on $BUILDPLATFORM"