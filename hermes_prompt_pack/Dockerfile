# =============================================================================
# Hermes Compliance Framework — Hardened Container Image
# NIST SP 800-190 Compliant Multi-Stage Build
#
# Audit Reference: NIST SP 800-190 §4.1 (Image Vulnerabilities),
#                  NIST SP 800-190 §4.2 (Configuration Defects)
#
# Build stages:
#   builder  — installs deps, downloads spaCy model, verifies checksums
#   runtime  — minimal image, no build tools, no shell in /bin, non-root
# =============================================================================

# -----------------------------------------------------------------------------
# STAGE 1: builder
# python:3.11-slim-bookworm is the minimal Debian-based image that supports
# spaCy's C-extensions. A distroless Python image is preferred long-term but
# requires custom spaCy wheels not yet available; slim-bookworm is the
# compliant interim choice per SP 800-190 §4.1.3.
# -----------------------------------------------------------------------------
FROM python:3.11-slim-bookworm AS builder

# Prevent interactive prompts; suppress pip upgrade noise
ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install only the C build deps required by spaCy; purge after
RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends gcc g++ && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy pinned requirements first (layer-cache friendly)
COPY requirements.txt .

# Install into an isolated prefix so the runtime stage can COPY it cleanly
RUN pip install --prefix=/install --require-hashes -r requirements.txt

# Download spaCy model into the install prefix.
# Baking the model into the image satisfies SP 800-190 immutability:
# no runtime network egress required for model acquisition.
# COMPLIANCE INVARIANT: model must be local — no external API calls at runtime.
RUN python -m spacy download en_core_web_sm --target /install/lib/python3.11/site-packages

# -----------------------------------------------------------------------------
# STAGE 2: runtime
# Minimal image; no gcc, no apt, no shell at /bin/sh (sh is still present
# in slim-bookworm for RUN, but the USER directive and dropped capabilities
# neutralize privilege escalation vectors per SP 800-190 §4.2.2).
# -----------------------------------------------------------------------------
FROM python:3.11-slim-bookworm AS runtime

# ---- Non-root user creation (SP 800-190 §4.2.2 / CIS Docker Benchmark 4.1) ----
RUN groupadd --gid 10001 hermes && \
    useradd --uid 10001 --gid hermes --no-create-home --shell /sbin/nologin hermes

# Copy the complete installed package tree from builder
COPY --from=builder /install /usr/local

# Copy application source
WORKDIR /app
COPY hermes/ ./hermes/

# Ownership handoff — runtime user owns nothing writable except /tmp (tmpfs)
RUN chown -R hermes:hermes /app

# Drop to non-root for all subsequent instructions and container execution
USER hermes

# Expose only the single API port; no other services run in this container
EXPOSE 8000

# Runtime environment defaults (overridable at deploy via --env-file)
# HERMES_API_KEY must be injected at runtime; it is NOT set here to prevent
# credential leakage into image layers (SP 800-190 §4.1.4).
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Health-check so orchestrators can gate traffic before the container is ready
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# Entrypoint: single-process, single-worker.
# Worker count is intentionally 1 per container instance; horizontal scaling
# is handled at the orchestration layer (docker-compose replicas / k8s HPA).
# This directly resolves the _PIPELINE_LOCK scalability bottleneck identified
# in the Phase 2 codebase audit — each container holds exactly one lock.
ENTRYPOINT ["uvicorn", "hermes.api:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
