FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# gcc/g++ are needed to build wheels for cryptography/spacy on some
# platforms. apt lists are purged afterward to keep the layer lean.
RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends gcc g++ && \
    rm -rf /var/lib/apt/lists/*

# Non-root user for the runtime process — never run the API as root.
# The API and the gateway both run from this image as this one UID so that
# files either service creates on the shared data volume stay writable by both.
RUN groupadd --gid 10001 hermes && \
    useradd --uid 10001 --gid hermes --no-create-home --shell /sbin/nologin hermes

WORKDIR /app

COPY requirements.txt .
RUN pip install "numpy==1.26.4" && pip install -r requirements.txt
RUN python -m spacy download en_core_web_sm

# Installs the hermes and gateway packages plus the hermes-relay and
# hermes-verify console scripts.
COPY pyproject.toml README.md /build/
COPY hermes/ /build/hermes/
COPY gateway/ /build/gateway/
RUN pip install --no-deps /build && rm -rf /build

# /app/data and /app/keys must exist and be owned by the runtime user in the
# image: Docker copies this ownership into a new, empty named volume on first
# mount. Without it the volume is root-owned and SQLite cannot create files.
RUN mkdir -p /app/data /app/keys && \
    chown -R hermes:hermes /app && \
    chmod 700 /app/keys

ENV HOME=/tmp
USER hermes

EXPOSE 8787 8788

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8787/health')" || exit 1

CMD ["uvicorn", "hermes.api:app", "--host", "0.0.0.0", "--port", "8787"]
