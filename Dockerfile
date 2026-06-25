# ── Stage 1: builder ──────────────────────────────────────────────────────
FROM python:3.12-slim AS builder
WORKDIR /build
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install --prefix=/install --no-cache-dir -r requirements.txt && \
    python -m spacy download en_core_web_sm && \
    cp -r /usr/local/lib/python3.12/dist-packages/en_core_web_sm \
          /install/lib/python3.12/site-packages/en_core_web_sm
# ── Stage 2: runtime ──────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime
# Non-root user enforcement — UID 10001
RUN groupadd --gid 10001 hermes && \
    useradd --uid 10001 --gid hermes --shell /bin/false --create-home hermes
COPY --from=builder /install /usr/local
WORKDIR /app
COPY hermes/ ./hermes/
RUN chown -R hermes:hermes /app
USER hermes
EXPOSE 8000
ENTRYPOINT ["uvicorn", "hermes.api:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
