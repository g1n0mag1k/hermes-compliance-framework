FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends gcc g++ && \
    rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 10002 hermes-gw && \
    useradd --uid 10002 --gid hermes-gw --no-create-home --shell /sbin/nologin hermes-gw

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt
RUN python -m spacy download en_core_web_sm

COPY hermes/ ./hermes/
COPY gateway/ ./gateway/

RUN chown -R hermes-gw:hermes-gw /app

ENV HOME=/tmp
USER hermes-gw

EXPOSE 8788

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8788/gateway/health')" || exit 1

ENTRYPOINT ["uvicorn", "gateway.app:app", "--host", "0.0.0.0", "--port", "8788"]
