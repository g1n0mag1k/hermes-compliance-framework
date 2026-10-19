"""
Drata Demo Evidence Harness
===========================
This file demonstrates the Hermes → Drata evidence flow using a
deterministic in-process mock. It makes no network calls and uses
no real Drata credentials.

LIVE DRATA STATUS: NOT VALIDATED
These tests prove only that Hermes handles the evidence flow
correctly against a mock. They do NOT prove that Drata accepts
the payload, honors X-Idempotency-Key, or that credentials are
correct.
"""

from __future__ import annotations

import json
import re
import socket
import urllib.error
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any, Self

import httpx
import pytest
from fastapi.testclient import TestClient

import gateway.app as gateway_app
import gateway.evidence as gateway_evidence
import gateway.evidence_export.dispatch as dispatch_module
import gateway.policy as gateway_policy
from gateway.app import app
from gateway.evidence_export import outbox
from gateway.evidence_export.drata_connector import DrataConnector
from gateway.evidence_export.event import _FORBIDDEN_FIELD_NAMES, EvidenceEvent
from gateway.evidence_export.exporters import (
    DRATA_API_KEY_ENV,
    DRATA_CCT_URL_ENV,
    WEBHOOK_AUTH_HEADER_ENV,
    WEBHOOK_AUTH_VALUE_ENV,
    WEBHOOK_URL_ENV,
)
from gateway.evidence_export.outbox import (
    DuplicateEventError,
    OutboxStatus,
    enqueue_event,
    flush_outbox,
    get_outbox_row,
    list_outbox_rows,
)
from gateway.pipeline import GatewayPipeline, GatewayRequest, GatewayResponse
from gateway.policy import Policy, clear_workspace_policy, set_workspace_policy
from hermes.receipts.v2.verifier import verify_receipt
from hermes.workspaces import create_workspace

DEMO_PROMPT = "Patient John Smith, SSN 123-45-6789"
PHI_VALUES = ("John Smith", "123-45-6789", "John", "Smith", "Patient John Smith")
# The prompt's "SSN" label as a standalone word. Category identifiers such as
# HIPAA_SSN are metadata the evidence contract is required to carry.
SSN_LABEL_RE = re.compile(r"(?<![A-Za-z0-9_])SSN(?![A-Za-z0-9_])")

# Fake, non-routable values (.invalid is reserved by RFC 2606). Never real Drata.
DEMO_CCT_URL = "https://drata-mock.invalid/demo/records"
DEMO_API_KEY = "demo-fake-key-not-a-real-credential"
CREDENTIAL_VALUES = (DEMO_API_KEY, DEMO_CCT_URL, "drata-mock.invalid", "Bearer")

DEMO_POLICY = Policy(
    policy_id="DRATA_DEMO_BLOCK",
    policy_version="1.0.0",
    text_action="BLOCK",
    binary_action="BLOCK",
    on_detector_error="BLOCK",
    on_parse_error="BLOCK",
    approved_providers=["openai", "azure_openai", "anthropic"],
)


class _MockDrataResponse:
    def __init__(self, status: int) -> None:
        self.status = status

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


class MockDrataServer:
    """
    In-process stand-in for the Drata CCT endpoint. Installed in place of
    urllib.request.urlopen (the transport DrataConnector uses), so no socket
    is opened. Records each POST's headers and body; the Authorization value
    is never stored, only whether it was present.
    """

    def __init__(self, status: int = 200) -> None:
        self.status = status
        self.requests: list[dict[str, Any]] = []

    def __call__(self, req, timeout: float | None = None):
        headers = {name.lower(): value for name, value in req.header_items()}
        authorization_present = headers.pop("authorization", None) is not None
        raw_body = req.data.decode("utf-8")
        self.requests.append(
            {
                "method": req.get_method(),
                "headers": headers,
                "authorization_present": authorization_present,
                "raw_body": raw_body,
                "body": json.loads(raw_body),
            }
        )
        if 200 <= self.status < 300:
            return _MockDrataResponse(self.status)
        raise urllib.error.HTTPError(req.full_url, self.status, "mock drata error", {}, None)  # type: ignore[arg-type]

    @property
    def idempotency_keys(self) -> list[str]:
        return [r["headers"].get("x-idempotency-key") for r in self.requests]


# -------------------------------------------------------------------------
# Fixtures
# -------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def isolated_demo_env(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_DATA_DIR", str(tmp_path / "workspaces"))
    monkeypatch.setenv("HERMES_REGISTRY_DB", str(tmp_path / "workspaces" / "registry.db"))
    for name in (WEBHOOK_URL_ENV, WEBHOOK_AUTH_HEADER_ENV, WEBHOOK_AUTH_VALUE_ENV):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv(DRATA_CCT_URL_ENV, DEMO_CCT_URL)
    monkeypatch.setenv(DRATA_API_KEY_ENV, DEMO_API_KEY)
    monkeypatch.setattr("gateway.evidence_export.exporters.time.sleep", lambda _s: None)

    import hermes.workspaces as ws_mod

    ws_mod._chain_cache.clear()
    ws_mod._vault_cache.clear()
    monkeypatch.setattr(ws_mod, "_DEFAULT_DATA_DIR", str(tmp_path / "workspaces"))
    monkeypatch.setattr(ws_mod, "_DEFAULT_REGISTRY_DB", str(tmp_path / "workspaces" / "registry.db"))
    gateway_evidence.reset_v2_chains()
    gateway_policy._workspace_policies.clear()
    gateway_policy.reload_policy()
    yield


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def _refuse(*args, **kwargs):
        raise AssertionError("Drata demo harness attempted a real network connection")

    monkeypatch.setattr(socket, "create_connection", _refuse)
    monkeypatch.setattr(socket.socket, "connect", _refuse)
    monkeypatch.setattr(socket.socket, "connect_ex", _refuse)


@pytest.fixture()
def mock_drata(monkeypatch) -> MockDrataServer:
    server = MockDrataServer(status=200)
    monkeypatch.setattr("urllib.request.urlopen", server)
    return server


@pytest.fixture()
def upstream(monkeypatch) -> list[dict]:
    """Mock AI provider. BLOCK decisions must leave this list empty."""
    monkeypatch.setenv("HERMES_OPENAI_API_KEY", "test-openai-key")
    received: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        received.append({"url": str(request.url), "body": request.content.decode("utf-8")})
        return httpx.Response(200, json={"id": "chatcmpl-demo", "choices": []})

    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(
        gateway_app,
        "_pipeline",
        GatewayPipeline(client_factory=lambda: httpx.Client(transport=transport)),
    )
    return received


@pytest.fixture()
def demo(upstream, mock_drata, monkeypatch):
    ws, api_key = create_workspace("drata-demo-ws", "Drata Demo", "demo@test.com")
    set_workspace_policy(ws.workspace_id, DEMO_POLICY)
    ctx = SimpleNamespace(
        ws=ws,
        api_key=api_key,
        upstream=upstream,
        mock=mock_drata,
        events=[],
        drata_requests_at_enqueue=[],
        results=[],
    )

    real_enqueue = dispatch_module.enqueue_event

    def _spy_enqueue(event: EvidenceEvent, **kwargs: Any) -> None:
        ctx.events.append(event)
        ctx.drata_requests_at_enqueue.append(len(mock_drata.requests))
        real_enqueue(event, **kwargs)

    monkeypatch.setattr(dispatch_module, "enqueue_event", _spy_enqueue)
    yield ctx
    clear_workspace_policy(ws.workspace_id)


# -------------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------------


def _openai_chat(content: str) -> dict:
    return {"model": "gpt-4o", "messages": [{"role": "user", "content": content}]}


def _send_gateway_request(ctx) -> GatewayResponse:
    return gateway_app._pipeline.process(
        GatewayRequest(
            workspace_id=ctx.ws.workspace_id,
            provider_id="openai",
            method="POST",
            path="/v1/chat/completions",
            query_string="",
            headers={"content-type": "application/json"},
            body_bytes=json.dumps(_openai_chat(DEMO_PROMPT)).encode("utf-8"),
            content_type="application/json",
        ),
        ctx.ws,
    )


def _assert_no_phi(text: str) -> None:
    for value in PHI_VALUES:
        assert value not in text, f"PHI value {value!r} leaked"
    assert DEMO_PROMPT not in text
    assert not SSN_LABEL_RE.search(text), "standalone 'SSN' label leaked"


def _assert_no_credentials(text: str) -> None:
    for value in CREDENTIAL_VALUES:
        assert value not in text, f"credential material {value!r} leaked"


def _row(ctx, index: int) -> dict:  # type: ignore[return-value]
    return get_outbox_row(ctx.events[index].event_id)


def _later(days: int = 1) -> datetime:
    return datetime.now(UTC) + timedelta(days=days)


# -------------------------------------------------------------------------
# Demo steps (each builds on the previous ones)
# -------------------------------------------------------------------------


def step1_phi_detection_and_block(ctx) -> None:
    result = _send_gateway_request(ctx)
    ctx.results.append(result)

    assert result.decision.decision == "BLOCK"
    assert result.receipt.payload["decision"] == "BLOCK"
    assert "HIPAA_SSN" in result.receipt.payload["phi_categories_detected"]

    assert result.receipt.payload["forwarded"] is False
    assert result.upstream_response is None
    assert ctx.upstream == [], "upstream AI provider was contacted on BLOCK"

    assert result.receipt_persistence_failed is False
    assert result.receipt.cose_sign1_bytes
    stored = gateway_evidence.get_gateway_receipt(ctx.ws, result.receipt.receipt_digest)
    assert stored is not None
    assert stored["payload"]["decision"] == "BLOCK"
    public_pem = gateway_evidence._get_gateway_signer().public_key_manifest()["public_key_pem"]
    verification = verify_receipt(result.receipt.cose_sign1_bytes, public_pem)
    assert verification.signature_valid, verification.errors


def step2_evidence_event_is_phi_safe(ctx) -> None:
    assert len(ctx.events) == 1
    event = ctx.events[0]
    receipt = ctx.results[0].receipt
    serialized = event.serialize()
    record_json = json.dumps(DrataConnector.build_drata_record(event), sort_keys=True)

    for text in (serialized, record_json):
        _assert_no_phi(text)
        assert "chatcmpl-demo" not in text
    assert not set(event.to_dict()) & _FORBIDDEN_FIELD_NAMES
    event.assert_phi_safe()

    assert event.decision == "BLOCK"
    assert DrataConnector.build_drata_record(event)["gateway_decision"] == "BLOCK"
    assert event.upstream_contacted is False
    assert event.phi_categories_detected
    assert "HIPAA_SSN" in event.phi_categories_detected
    assert event.receipt_id and event.receipt_id == receipt.receipt_id
    assert event.receipt_digest == receipt.receipt_digest
    assert event.event_id


def step3_outbox_enqueue(ctx) -> None:
    event = ctx.events[0]
    assert ctx.drata_requests_at_enqueue == [0], "event was not queued before Drata was called"
    assert ctx.mock.requests == []

    rows = list_outbox_rows(ctx.ws.workspace_id)
    assert len(rows) == 1
    row = rows[0]
    assert row["event_id"] == event.event_id
    assert row["status"] == OutboxStatus.PENDING.value
    assert row["attempt_count"] == 0
    assert row["last_error"] is None
    assert EvidenceEvent.model_validate_json(row["evidence_payload"]) == event

    row_json = json.dumps(row)
    raw_db = outbox.outbox_db_path().read_bytes().decode("latin-1")
    for text in (row_json, raw_db):
        _assert_no_phi(text)
        _assert_no_credentials(text)


def step4_mock_drata_acceptance(ctx) -> None:
    event = ctx.events[0]
    ctx.mock.status = 200

    counts = flush_outbox(ctx.ws.workspace_id)

    assert counts == {"exported": 1, "retry_scheduled": 0, "dead_lettered": 0}
    assert _row(ctx, 0)["status"] == OutboxStatus.EXPORTED.value
    assert len(ctx.mock.requests) == 1
    request = ctx.mock.requests[0]
    assert request["method"] == "POST"
    assert set(request["body"]) == {"data"}
    assert isinstance(request["body"]["data"], dict)
    assert request["body"]["data"]["event_id"] == event.event_id
    assert request["body"]["data"]["gateway_decision"] == "BLOCK"
    assert request["body"]["data"]["upstream_contacted"] is False
    assert request["headers"]["x-idempotency-key"] == event.event_id
    assert request["authorization_present"] is True
    assert "authorization" not in request["headers"]
    _assert_no_phi(request["raw_body"])
    _assert_no_credentials(request["raw_body"])
    _assert_no_credentials(json.dumps(ctx.mock.requests))


def step5_idempotency(ctx) -> None:
    event = ctx.events[0]

    with pytest.raises(DuplicateEventError):
        enqueue_event(event)

    counts = flush_outbox(ctx.ws.workspace_id, now=_later(1))

    assert counts == {"exported": 0, "retry_scheduled": 0, "dead_lettered": 0}
    assert len(ctx.mock.requests) == 1, "Drata received a second request for the same event"
    rows = list_outbox_rows(ctx.ws.workspace_id)
    assert [r["event_id"] for r in rows] == [event.event_id]
    assert rows[0]["status"] == OutboxStatus.EXPORTED.value


def step6_drata_failure_enforcement_unaffected(ctx) -> None:
    requests_before = len(ctx.mock.requests)
    result = _send_gateway_request(ctx)
    ctx.results.append(result)

    # The gateway response is complete; Drata has not been called for it.
    assert result.decision.decision == "BLOCK"
    assert len(ctx.mock.requests) == requests_before
    assert len(ctx.events) == 2
    assert ctx.drata_requests_at_enqueue[1] == requests_before
    second_id = ctx.events[1].event_id
    assert second_id != ctx.events[0].event_id
    assert _row(ctx, 1)["status"] == OutboxStatus.PENDING.value
    assert _row(ctx, 1)["attempt_count"] == 0

    ctx.mock.status = 503
    flushed_at = datetime.now(UTC)
    counts = flush_outbox(ctx.ws.workspace_id, now=flushed_at)

    assert counts == {"exported": 0, "retry_scheduled": 1, "dead_lettered": 0}
    row = _row(ctx, 1)
    assert row["status"] == OutboxStatus.PENDING.value
    assert row["attempt_count"] == 1
    assert row["last_error"] == "HTTP 503"
    assert datetime.fromisoformat(row["next_attempt_at"]) > flushed_at
    failed_attempts = ctx.mock.requests[requests_before:]
    assert failed_attempts, "flush did not attempt Drata"
    assert {r["headers"]["x-idempotency-key"] for r in failed_attempts} == {second_id}

    for original in ctx.results:
        assert original.decision.decision == "BLOCK"
        stored = gateway_evidence.get_gateway_receipt(ctx.ws, original.receipt.receipt_digest)
        assert stored["payload"]["decision"] == "BLOCK"  # type: ignore[index]
        assert stored["payload"]["forwarded"] is False  # type: ignore[index]
    assert _row(ctx, 0)["status"] == OutboxStatus.EXPORTED.value
    assert ctx.upstream == []


def step7_retry_uses_same_event_id(ctx) -> None:
    second_id = ctx.events[1].event_id
    retry_at = datetime.fromisoformat(_row(ctx, 1)["next_attempt_at"])
    ctx.mock.status = 200
    requests_before = len(ctx.mock.requests)

    assert flush_outbox(ctx.ws.workspace_id, now=retry_at - timedelta(seconds=1))["exported"] == 0
    assert len(ctx.mock.requests) == requests_before, "retry fired before its scheduled time"

    counts = flush_outbox(ctx.ws.workspace_id, now=retry_at)

    assert counts == {"exported": 1, "retry_scheduled": 0, "dead_lettered": 0}
    row = _row(ctx, 1)
    assert row["status"] == OutboxStatus.EXPORTED.value
    assert row["attempt_count"] == 2
    assert len(ctx.mock.requests) == requests_before + 1
    retry = ctx.mock.requests[-1]
    assert retry["headers"]["x-idempotency-key"] == second_id
    assert retry["body"]["data"]["event_id"] == second_id
    _assert_no_phi(retry["raw_body"])

    assert len(ctx.events) == 2, "a new EvidenceEvent was built for the retry"
    event_ids = {e.event_id for e in ctx.events}
    rows = list_outbox_rows(ctx.ws.workspace_id)
    assert {r["event_id"] for r in rows} == event_ids
    assert all(r["status"] == OutboxStatus.EXPORTED.value for r in rows)
    assert set(ctx.mock.idempotency_keys) == event_ids


DEMO_STEPS = (
    step1_phi_detection_and_block,
    step2_evidence_event_is_phi_safe,
    step3_outbox_enqueue,
    step4_mock_drata_acceptance,
    step5_idempotency,
    step6_drata_failure_enforcement_unaffected,
    step7_retry_uses_same_event_id,
)


def _run_through(ctx, last_step: int) -> None:
    for step in DEMO_STEPS[:last_step]:
        step(ctx)


# -------------------------------------------------------------------------
# Tests
# -------------------------------------------------------------------------


def test_step1_phi_detection_and_block(demo):
    _run_through(demo, 1)


def test_step2_evidence_event_is_phi_safe(demo):
    _run_through(demo, 2)


def test_step3_outbox_enqueue_before_drata_call(demo):
    _run_through(demo, 3)


def test_step4_mock_drata_acceptance(demo):
    _run_through(demo, 4)


def test_step5_idempotency_duplicate_rejected_no_resend(demo):
    _run_through(demo, 5)


def test_step6_drata_503_leaves_enforcement_unaffected(demo):
    _run_through(demo, 6)


def test_step7_retry_reuses_original_event_id(demo):
    _run_through(demo, 7)


def test_drata_demo_full_flow_in_order(demo):
    _run_through(demo, len(DEMO_STEPS))
    assert len(demo.events) == 2
    assert demo.upstream == []


def test_gateway_http_block_unaffected_by_drata_503(demo):
    demo.mock.status = 503
    client = TestClient(app)

    response = client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": demo.api_key},
        json=_openai_chat(DEMO_PROMPT),
    )

    assert response.status_code == 403
    body = response.json()
    assert body["error"]["code"] == "phi_detected"
    _assert_no_phi(response.text)
    assert demo.upstream == []
    stored = gateway_evidence.get_gateway_receipt(demo.ws, body["receipt_digest"])
    assert stored["payload"]["decision"] == "BLOCK"
    assert stored["payload"]["forwarded"] is False
    # The background flush ran after the response and hit the 503.
    assert demo.mock.requests
    rows = list_outbox_rows(demo.ws.workspace_id)
    assert len(rows) == 1
    assert rows[0]["status"] == OutboxStatus.PENDING.value
    assert rows[0]["last_error"] == "HTTP 503"
