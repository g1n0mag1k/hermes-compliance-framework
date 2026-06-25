FROM python:3.11-slim-bookworm AS builder

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends gcc g++ && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY requirements.txt .

# Install to system site-packages so spacy CLI works for model download
RUN pip install -r requirements.txt

# Download model to a known location
RUN python -m spacy download en_core_web_sm

# Copy everything to /install for runtime stage
RUN cp -r /usr/local/lib/python3.11/site-packages /install

FROM python:3.11-slim-bookworm AS runtime

RUN groupadd --gid 10001 hermes && \
    useradd --uid 10001 --gid hermes --no-create-home --shell /sbin/nologin hermes

COPY --from=builder /install /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

WORKDIR /app
COPY hermes/ ./hermes/
COPY demo.py .
COPY assets/ ./assets/
RUN chown -R hermes:hermes /app

USER hermes
EXPOSE 8000

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

ENTRYPOINT ["uvicorn", "hermes.api:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
