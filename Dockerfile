# ── Stage 1: builder ──────────────────────────────────────────────────────
FROM python:3.12-slim AS builder
WORKDIR /build
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install --no-cache-dir --target=/install -r requirements.txt && \
    PYTHONPATH=/install python -m spacy download en_core_web_sm --target /install
# ── Stage 2: runtime ──────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime
RUN groupadd --gid 10001 hermes && \
    useradd --uid 10001 --gid hermes --shell /bin/false --create-home hermes
COPY --from=builder /install /usr/local/lib/python3.12/site-packages
WORKDIR /app
COPY hermes/ ./hermes/
RUN chown -R hermes:hermes /app
USER hermes
EXPOSE 8000
ENV PYTHONPATH=/usr/local/lib/python3.12/site-packages
ENTRYPOINT ["uvicorn", "hermes.api:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
