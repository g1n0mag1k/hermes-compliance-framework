"""
Pure ASGI payload guard: byte limits and JSON nesting depth before app parsing.

BEFORE: POST/PUT/PATCH bodies were bounded only inside individual route handlers
        (e.g. Pydantic max_length), with no shared ASGI-layer cap on size or
        nesting depth across the API and gateway.
AFTER: PayloadGuardMiddleware inspects Content-Length and streaming request chunks,
        rejecting oversize payloads (413) and excessively nested JSON (422) before
        FastAPI/Pydantic or the gateway pipeline read the full body.
REASON: Fail closed on pathological payloads at the edge without invoking spaCy,
        Presidio, or upstream provider calls.
"""

from __future__ import annotations

import json
import os
from typing import Any, Awaitable, Callable

Send = Callable[[dict[str, Any]], Awaitable[None]]
Receive = Callable[[], Awaitable[dict[str, Any]]]


class _PayloadTooLarge(Exception):
    """Raised when accumulated request body bytes exceed the configured limit."""


class _PayloadTooDeep(Exception):
    """Raised when JSON nesting depth exceeds the configured security limit."""


class _RequestPayloadTracker:
    """Per-request byte and JSON depth scanner state (persists across receive chunks)."""

    __slots__ = (
        "max_bytes",
        "max_depth",
        "total_bytes",
        "depth",
        "in_string",
        "escape_next",
        "violation",
    )

    def __init__(self, max_bytes: int, max_depth: int) -> None:
        self.max_bytes = max_bytes
        self.max_depth = max_depth
        self.total_bytes = 0
        self.depth = 0
        self.in_string = False
        self.escape_next = False
        self.violation: _PayloadTooLarge | _PayloadTooDeep | None = None

    def feed(self, chunk: bytes) -> None:
        self.total_bytes += len(chunk)
        if self.total_bytes > self.max_bytes:
            raise _PayloadTooLarge()

        for byte in chunk:
            if self.in_string:
                if self.escape_next:
                    self.escape_next = False
                    continue
                if byte == ord("\\"):
                    self.escape_next = True
                elif byte == ord('"'):
                    self.in_string = False
                continue

            if byte == ord('"'):
                self.in_string = True
            elif byte in (ord("{"), ord("[")):
                self.depth += 1
                if self.depth > self.max_depth:
                    raise _PayloadTooDeep()
            elif byte in (ord("}"), ord("]")):
                if self.depth > 0:
                    self.depth -= 1


def _header_bytes(scope: dict[str, Any], name: bytes) -> bytes | None:
    for key, value in scope.get("headers") or []:
        if key.lower() == name:
            return value
    return None


def _parse_content_length(scope: dict[str, Any]) -> int | None:
    raw = _header_bytes(scope, b"content-length")
    if raw is None:
        return None
    try:
        return int(raw.decode("latin-1").strip())
    except ValueError:
        return None


async def _send_json_response(send: Send, status: int, detail: str) -> None:
    body = json.dumps({"detail": detail}).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body, "more_body": False})


class PayloadGuardMiddleware:
    """ASGI middleware enforcing payload size and JSON nesting depth limits."""

    def __init__(
        self,
        app: Callable[..., Awaitable[None]],
        max_bytes: int | None = None,
        max_depth: int | None = None,
    ) -> None:
        self.app = app
        if max_bytes is None:
            max_bytes = int(os.environ.get("HERMES_MAX_PAYLOAD_BYTES", "1048576"))
        if max_depth is None:
            max_depth = int(os.environ.get("HERMES_MAX_JSON_NESTING_DEPTH", "32"))
        self.max_bytes = max_bytes
        self.max_depth = max_depth

    async def __call__(self, scope: dict[str, Any], receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        method = (scope.get("method") or "").upper()
        if method not in ("POST", "PUT", "PATCH"):
            await self.app(scope, receive, send)
            return

        content_length = _parse_content_length(scope)
        if content_length is not None and content_length > self.max_bytes:
            await _send_json_response(
                send, 413, "Payload exceeds maximum byte limit"
            )
            return

        tracker = _RequestPayloadTracker(self.max_bytes, self.max_depth)
        response_started = False
        guard_response_sent = False

        async def _emit_guard_response(violation: Exception) -> None:
            nonlocal response_started, guard_response_sent
            if response_started or guard_response_sent:
                return
            if isinstance(violation, _PayloadTooLarge):
                await _send_json_response(
                    send, 413, "Payload exceeds maximum byte limit"
                )
            elif isinstance(violation, _PayloadTooDeep):
                await _send_json_response(
                    send, 422, "JSON nesting depth exceeds security limit"
                )
            else:
                return
            response_started = True
            guard_response_sent = True

        async def send_wrapper(message: dict[str, Any]) -> None:
            nonlocal response_started
            if tracker.violation and message.get("type") == "http.response.start":
                await _emit_guard_response(tracker.violation)
                return
            if guard_response_sent and message.get("type") == "http.response.body":
                return
            if message.get("type") == "http.response.start":
                response_started = True
            await send(message)

        async def wrapped_receive() -> dict[str, Any]:
            message = await receive()
            if message.get("type") == "http.request":
                body = message.get("body", b"")
                if body:
                    try:
                        tracker.feed(body)
                    except (_PayloadTooLarge, _PayloadTooDeep) as exc:
                        tracker.violation = exc
                        raise
            return message

        try:
            await self.app(scope, wrapped_receive, send_wrapper)
        except (_PayloadTooLarge, _PayloadTooDeep) as exc:
            if not tracker.violation:
                tracker.violation = exc
            if not response_started:
                await _emit_guard_response(tracker.violation)
        else:
            if tracker.violation and not response_started:
                await _emit_guard_response(tracker.violation)
