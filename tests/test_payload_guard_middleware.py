"""
Unit and integration tests for PayloadGuardMiddleware.

BEFORE: No automated coverage for ASGI payload size / JSON depth guards.
AFTER: Verifies 413/422 behavior on API and gateway apps and raw ASGI chunking.
REASON: Lock in fail-closed limits before Pydantic, spaCy, Presidio, or upstream calls.
"""

from __future__ import annotations

import json
import os
from typing import Any

import pytest
from fastapi.testclient import TestClient

from gateway.app import app as gateway_app
from hermes.api import app as hermes_app
from hermes.payload_guard_middleware import PayloadGuardMiddleware


def _nested_json(depth: int) -> bytes:
    """Build JSON with `depth` levels of object nesting (root counts as one `{`)."""
    inner: str | dict[str, Any] = "leaf"
    for _ in range(depth - 1):
        inner = {"k": inner}
    return json.dumps(inner).encode("utf-8")


@pytest.fixture
def api_client(monkeypatch):
    monkeypatch.setenv("HERMES_MAX_PAYLOAD_BYTES", "1048576")
    monkeypatch.setenv("HERMES_MAX_JSON_NESTING_DEPTH", "32")
    monkeypatch.setenv("HERMES_API_KEY", "payload-guard-test-key")
    return TestClient(hermes_app, raise_server_exceptions=False)


@pytest.fixture
def gw_client(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_MAX_PAYLOAD_BYTES", "1048576")
    monkeypatch.setenv("HERMES_MAX_JSON_NESTING_DEPTH", "32")
    monkeypatch.setenv("HERMES_DATA_DIR", str(tmp_path / "workspaces"))
    monkeypatch.setenv("HERMES_REGISTRY_DB", str(tmp_path / "workspaces" / "registry.db"))
    import hermes.workspaces as ws_mod

    ws_mod._chain_cache.clear()
    ws_mod._vault_cache.clear()
    ws_mod._DEFAULT_DATA_DIR = str(tmp_path / "workspaces")
    ws_mod._DEFAULT_REGISTRY_DB = str(tmp_path / "workspaces" / "registry.db")
    return TestClient(gateway_app, raise_server_exceptions=False)


def test_post_over_one_megabyte_returns_413(api_client):
    body = b"x" * (1_048_576 + 1)
    response = api_client.post(
        "/v1/scrub",
        content=body,
        headers={
            "X-API-Key": os.environ["HERMES_API_KEY"],
            "Content-Type": "application/json",
        },
    )
    assert response.status_code == 413
    assert response.json() == {"detail": "Payload exceeds maximum byte limit"}


def test_gateway_post_over_one_megabyte_returns_413(gw_client):
    body = b"y" * (1_048_576 + 1)
    response = gw_client.post(
        "/gateway/openai/v1/chat/completions",
        content=body,
        headers={
            "X-API-Key": "any-key",
            "Content-Type": "application/json",
        },
    )
    assert response.status_code == 413
    assert response.json() == {"detail": "Payload exceeds maximum byte limit"}


@pytest.mark.anyio
async def test_chunked_stream_over_limit_with_fake_content_length():
    seen: list[bytes] = []

    async def inner_app(scope, receive, send):
        while True:
            message = await receive()
            if message["type"] == "http.request":
                seen.append(message.get("body", b""))
                if not message.get("more_body", False):
                    break
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok", "more_body": False})

    middleware = PayloadGuardMiddleware(inner_app, max_bytes=100, max_depth=32)
    chunks = [b"a" * 60, b"b" * 60]
    chunk_index = 0
    responses: list[dict[str, Any]] = []

    async def receive():
        nonlocal chunk_index
        if chunk_index < len(chunks):
            body = chunks[chunk_index]
            chunk_index += 1
            return {
                "type": "http.request",
                "body": body,
                "more_body": chunk_index < len(chunks),
            }
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        responses.append(message)

    scope = {
        "type": "http",
        "method": "POST",
        "headers": [(b"content-length", b"10")],
    }

    await middleware(scope, receive, send)

    assert responses[0]["type"] == "http.response.start"
    assert responses[0]["status"] == 413
    assert all(r != 200 for r in responses if r.get("type") == "http.response.start")
    assert json.loads(responses[-1]["body"]) == {
        "detail": "Payload exceeds maximum byte limit"
    }


def test_fifty_level_nested_json_returns_422_before_scrub(api_client, monkeypatch):
    def _scrub_should_not_run(*_args, **_kwargs):
        raise AssertionError("scrub_payload must not run for over-deep JSON")

    monkeypatch.setattr("hermes.api.scrub_payload", _scrub_should_not_run)

    body = _nested_json(50)
    response = api_client.post(
        "/v1/scrub",
        content=body,
        headers={
            "X-API-Key": os.environ["HERMES_API_KEY"],
            "Content-Type": "application/json",
        },
    )
    assert response.status_code == 422
    assert response.json() == {"detail": "JSON nesting depth exceeds security limit"}


@pytest.mark.anyio
async def test_braces_inside_json_string_split_across_chunks_not_rejected():
    payload = b'{"note": "see {ref} for [details]"}'
    split_at = payload.index(b"{ref")
    chunk_a = payload[:split_at]
    chunk_b = payload[split_at:]

    async def inner_app(scope, receive, send):
        collected = b""
        while True:
            message = await receive()
            if message["type"] == "http.request":
                collected += message.get("body", b"")
                if not message.get("more_body", False):
                    break
        assert collected == payload
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok", "more_body": False})

    middleware = PayloadGuardMiddleware(inner_app, max_bytes=10_000, max_depth=32)
    chunks = [chunk_a, chunk_b]
    chunk_index = 0
    responses: list[dict[str, Any]] = []

    async def receive():
        nonlocal chunk_index
        if chunk_index < len(chunks):
            body = chunks[chunk_index]
            chunk_index += 1
            return {
                "type": "http.request",
                "body": body,
                "more_body": chunk_index < len(chunks),
            }
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        responses.append(message)

    scope = {"type": "http", "method": "POST", "headers": []}

    await middleware(scope, receive, send)

    assert responses[0]["status"] == 200
    assert responses[-1]["body"] == b"ok"


@pytest.mark.anyio
async def test_quote_character_split_across_chunks_preserves_string_state():
    # Split immediately after the opening quote of the string value.
    payload = b'{"note": "see {ref} for [details]"}'
    quote_split = payload.index(b'"see')
    chunk_a = payload[:quote_split]
    chunk_b = payload[quote_split:]

    async def inner_app(scope, receive, send):
        while True:
            message = await receive()
            if message["type"] == "http.request" and not message.get("more_body", False):
                break
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok", "more_body": False})

    middleware = PayloadGuardMiddleware(inner_app, max_bytes=10_000, max_depth=4)
    chunks = [chunk_a, chunk_b]
    chunk_index = 0
    responses: list[dict[str, Any]] = []

    async def receive():
        nonlocal chunk_index
        if chunk_index < len(chunks):
            body = chunks[chunk_index]
            chunk_index += 1
            return {
                "type": "http.request",
                "body": body,
                "more_body": chunk_index < len(chunks),
            }
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        responses.append(message)

    scope = {"type": "http", "method": "PATCH", "headers": []}

    await middleware(scope, receive, send)

    assert responses[0]["status"] == 200
