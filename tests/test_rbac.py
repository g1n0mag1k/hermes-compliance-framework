"""
tests/test_rbac.py — Workspace role-based access control for config endpoints.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from hermes.api import DrataConfigState, app
from hermes.drata_state import get_drata_config_state
from hermes.workspaces import create_workspace


@pytest.fixture(autouse=True)
def isolated_workspace_registry(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_DATA_DIR", str(tmp_path / "workspaces"))
    monkeypatch.setenv(
        "HERMES_REGISTRY_DB",
        str(tmp_path / "workspaces" / "registry.db"),
    )

    import hermes.workspaces as ws_mod

    ws_mod._chain_cache.clear()
    ws_mod._vault_cache.clear()
    ws_mod._DEFAULT_DATA_DIR = str(tmp_path / "workspaces")
    ws_mod._DEFAULT_REGISTRY_DB = str(tmp_path / "workspaces" / "registry.db")
    yield


@pytest.fixture()
def client():
    return TestClient(app)


def test_msp_admin_can_access_config_endpoint(client):
    _, api_key = create_workspace(
        "rbac-admin-01",
        "Admin Workspace",
        "admin@test.com",
        role="msp_admin",
    )
    response = client.post(
        "/api/v1/sentry/config",
        headers={"X-API-Key": api_key},
    )
    assert response.status_code == 501
    assert response.json()["detail"] == "sentry.config.not_implemented"


def test_client_readonly_blocked_from_config_endpoint(client):
    _, api_key = create_workspace(
        "rbac-readonly-01",
        "Readonly Workspace",
        "ro@test.com",
        role="client_readonly",
    )
    response = client.post(
        "/api/v1/sentry/config",
        headers={"X-API-Key": api_key},
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "Insufficient permissions"


# -------------------------------------------------------------------------
# /api/v1/drata/config — honest state, no fake success
# -------------------------------------------------------------------------

DRATA_TEST_URL = "https://drata.example.invalid/cct/secret-connection-123"
DRATA_TEST_KEY = "drata-secret-key-must-not-leak"


@pytest.fixture()
def clear_drata_env(monkeypatch):
    monkeypatch.delenv("HERMES_DRATA_CCT_URL", raising=False)
    monkeypatch.delenv("HERMES_DRATA_API_KEY", raising=False)


def _admin_key(workspace_id="rbac-drata-admin"):
    _, api_key = create_workspace(
        workspace_id, "Drata Admin", "drata@test.com", role="msp_admin"
    )
    return api_key


def test_drata_config_not_configured_when_env_unset(client, clear_drata_env):
    response = client.post(
        "/api/v1/drata/config", headers={"X-API-Key": _admin_key()}
    )
    assert response.status_code == 501
    body = response.json()
    assert body["status"] == "not_implemented"
    assert body["state"] == "NOT_CONFIGURED"
    assert body["cct_url_configured"] is False
    assert body["api_key_configured"] is False
    assert body["connection_tested"] is False


def test_drata_config_configured_when_env_set(client, clear_drata_env, monkeypatch):
    monkeypatch.setenv("HERMES_DRATA_CCT_URL", DRATA_TEST_URL)
    monkeypatch.setenv("HERMES_DRATA_API_KEY", DRATA_TEST_KEY)
    response = client.post(
        "/api/v1/drata/config", headers={"X-API-Key": _admin_key()}
    )
    assert response.status_code == 501
    body = response.json()
    assert body["state"] == "CONFIGURED"
    assert body["cct_url_configured"] is True
    assert body["api_key_configured"] is True
    assert body["connection_tested"] is False


def test_drata_config_api_key_alone_is_not_configured(client, clear_drata_env, monkeypatch):
    monkeypatch.setenv("HERMES_DRATA_API_KEY", DRATA_TEST_KEY)
    response = client.post(
        "/api/v1/drata/config", headers={"X-API-Key": _admin_key()}
    )
    assert response.json()["state"] == "NOT_CONFIGURED"
    assert response.json()["api_key_configured"] is True


@pytest.mark.parametrize("configured", [False, True])
def test_drata_config_never_returns_fake_updated(client, clear_drata_env, monkeypatch, configured):
    if configured:
        monkeypatch.setenv("HERMES_DRATA_CCT_URL", DRATA_TEST_URL)
    response = client.post(
        "/api/v1/drata/config", headers={"X-API-Key": _admin_key()}
    )
    assert not (200 <= response.status_code < 300)
    assert response.json() != {"status": "updated"}
    assert response.json()["status"] != "updated"


def test_drata_config_does_not_contact_network(client, clear_drata_env, monkeypatch):
    monkeypatch.setenv("HERMES_DRATA_CCT_URL", DRATA_TEST_URL)
    monkeypatch.setenv("HERMES_DRATA_API_KEY", DRATA_TEST_KEY)
    with patch("urllib.request.urlopen") as mock_urlopen:
        client.post("/api/v1/drata/config", headers={"X-API-Key": _admin_key()})
    mock_urlopen.assert_not_called()


def test_drata_config_response_contains_no_credentials(client, clear_drata_env, monkeypatch, caplog):
    monkeypatch.setenv("HERMES_DRATA_CCT_URL", DRATA_TEST_URL)
    monkeypatch.setenv("HERMES_DRATA_API_KEY", DRATA_TEST_KEY)
    with caplog.at_level(logging.DEBUG):
        response = client.post(
            "/api/v1/drata/config", headers={"X-API-Key": _admin_key()}
        )
    raw = response.text
    assert DRATA_TEST_KEY not in raw
    assert DRATA_TEST_URL not in raw
    assert "secret-connection-123" not in raw
    for header_value in response.headers.values():
        assert DRATA_TEST_KEY not in header_value
    assert DRATA_TEST_KEY not in caplog.text


def test_drata_config_msp_tech_allowed(client, clear_drata_env):
    _, api_key = create_workspace(
        "rbac-drata-tech", "Drata Tech", "tech@test.com", role="msp_tech"
    )
    response = client.post("/api/v1/drata/config", headers={"X-API-Key": api_key})
    assert response.status_code == 501
    assert response.json()["state"] == "NOT_CONFIGURED"


def test_drata_config_client_readonly_blocked(client, clear_drata_env, monkeypatch):
    monkeypatch.setenv("HERMES_DRATA_CCT_URL", DRATA_TEST_URL)
    _, api_key = create_workspace(
        "rbac-drata-readonly", "Drata RO", "ro-drata@test.com", role="client_readonly"
    )
    response = client.post("/api/v1/drata/config", headers={"X-API-Key": api_key})
    assert response.status_code == 403
    assert response.json()["detail"] == "Insufficient permissions"
    assert "state" not in response.json()


def test_drata_config_invalid_api_key_rejected(client, clear_drata_env):
    response = client.post(
        "/api/v1/drata/config", headers={"X-API-Key": "not-a-real-key"}
    )
    assert response.status_code == 401


def test_drata_config_missing_api_key_rejected(client, clear_drata_env):
    response = client.post("/api/v1/drata/config")
    assert response.status_code == 422


def test_get_drata_config_state_transitions(clear_drata_env, monkeypatch):
    assert get_drata_config_state() is DrataConfigState.NOT_CONFIGURED
    assert get_drata_config_state(True) is DrataConfigState.NOT_CONFIGURED
    assert get_drata_config_state(False) is DrataConfigState.NOT_CONFIGURED

    monkeypatch.setenv("HERMES_DRATA_CCT_URL", DRATA_TEST_URL)
    assert get_drata_config_state() is DrataConfigState.CONFIG_INVALID
    assert get_drata_config_state(True) is DrataConfigState.CONFIG_INVALID

    monkeypatch.setenv("HERMES_DRATA_API_KEY", DRATA_TEST_KEY)
    assert get_drata_config_state() is DrataConfigState.CONFIGURED
    assert get_drata_config_state(False) is DrataConfigState.CONNECTION_TEST_FAILED
    assert get_drata_config_state(True) is DrataConfigState.CONNECTION_TEST_SUCCEEDED


def test_drata_config_http_url_is_config_invalid(client, clear_drata_env, monkeypatch, caplog):
    insecure_url = "http://drata.example.invalid/cct/secret-connection-123"
    monkeypatch.setenv("HERMES_DRATA_CCT_URL", insecure_url)
    monkeypatch.setenv("HERMES_DRATA_API_KEY", DRATA_TEST_KEY)
    with caplog.at_level(logging.DEBUG):
        response = client.post(
            "/api/v1/drata/config", headers={"X-API-Key": _admin_key()}
        )
    assert response.status_code == 501
    body = response.json()
    assert body["state"] == "CONFIG_INVALID"
    assert "https" in body["reason"]
    assert body["cct_url_configured"] is True
    assert body["live_validated"] is False
    assert body["connection_tested"] is False
    for secret in (insecure_url, "secret-connection-123", DRATA_TEST_KEY):
        assert secret not in response.text
        assert secret not in caplog.text


def test_drata_config_malformed_url_is_config_invalid(client, clear_drata_env, monkeypatch):
    monkeypatch.setenv("HERMES_DRATA_CCT_URL", "not a url")
    monkeypatch.setenv("HERMES_DRATA_API_KEY", DRATA_TEST_KEY)
    response = client.post(
        "/api/v1/drata/config", headers={"X-API-Key": _admin_key()}
    )
    assert response.status_code == 501
    assert response.json()["state"] == "CONFIG_INVALID"
    assert "not a url" not in response.text


def test_drata_config_url_without_api_key_is_config_invalid(client, clear_drata_env, monkeypatch):
    monkeypatch.setenv("HERMES_DRATA_CCT_URL", DRATA_TEST_URL)
    response = client.post(
        "/api/v1/drata/config", headers={"X-API-Key": _admin_key()}
    )
    assert response.status_code == 501
    body = response.json()
    assert body["state"] == "CONFIG_INVALID"
    assert body["cct_url_configured"] is True
    assert body["api_key_configured"] is False
    assert "HERMES_DRATA_API_KEY" in body["reason"]


def test_drata_config_configured_never_claims_live_validation(client, clear_drata_env, monkeypatch):
    monkeypatch.setenv("HERMES_DRATA_CCT_URL", DRATA_TEST_URL)
    monkeypatch.setenv("HERMES_DRATA_API_KEY", DRATA_TEST_KEY)
    with patch("urllib.request.urlopen") as mock_urlopen:
        response = client.post(
            "/api/v1/drata/config", headers={"X-API-Key": _admin_key()}
        )
    mock_urlopen.assert_not_called()
    assert response.status_code == 501
    body = response.json()
    assert body["state"] == "CONFIGURED"
    assert body["live_validated"] is False
    assert "does NOT prove" in body["reason"]
    assert body["state"] not in ("CONNECTION_SUCCESS", "CONNECTION_TEST_SUCCEEDED")


# -------------------------------------------------------------------------
# GET /v1/integrations/drata/status — local-state-only integration status
# -------------------------------------------------------------------------

DRATA_STATUS_PATH = "/v1/integrations/drata/status"
DRATA_STATUS_FIELDS = {
    "configured",
    "connection_state",
    "live_validated",
    "transport",
    "events_pending",
    "events_exported",
    "events_dead_letter",
    "last_exported_at",
    "last_error",
    "partner_connection",
}
OUTBOX_FIELDS = (
    "events_pending",
    "events_exported",
    "events_dead_letter",
    "last_exported_at",
    "last_error",
)


def _outbox_event(event_id, workspace_id):
    from gateway.evidence_export.event import EvidenceEvent

    return EvidenceEvent(
        event_id=event_id,
        transaction_id=f"gw_{event_id}",
        workspace_id=workspace_id,
        timestamp="2026-09-24T12:00:00+00:00",
        gateway_version="1.0.0",
        upstream_provider="openai",
        endpoint_path="/v1/chat/completions",
        decision="BLOCK",
        policy_id="HIPAA_PRODUCTION_BLOCK",
        policy_version="1.0.0",
        policy_digest="abc123digest",
        phi_categories_detected=["HIPAA_SSN"],
        phi_categories_redacted=[],
        content_types_inspected=["application/json"],
        content_types_not_inspected=[],
        detector_states={"HIPAA_SSN": "ran_clean"},
        upstream_contacted=False,
        all_detectors_clean=True,
        receipt_id=f"rcpt-{event_id}",
        receipt_digest=f"digest-{event_id}",
        gateway_sequence=0,
        signature_algorithm="EdDSA",
        cose_sign1_hex="aabbcc",
    )


def _enqueue_and_flush(event_id, workspace_id, post_result):
    from gateway.evidence_export.outbox import enqueue_event, flush_outbox

    enqueue_event(_outbox_event(event_id, workspace_id))
    with patch("gateway.evidence_export.exporters._post_json", return_value=post_result):
        flush_outbox(workspace_id)


@pytest.fixture()
def drata_env(clear_drata_env, monkeypatch):
    monkeypatch.setenv("HERMES_DRATA_CCT_URL", DRATA_TEST_URL)
    monkeypatch.setenv("HERMES_DRATA_API_KEY", DRATA_TEST_KEY)


def _get_status(client, api_key):
    response = client.get(DRATA_STATUS_PATH, headers={"X-API-Key": api_key})
    assert response.status_code == 200
    body = response.json()
    assert set(body) == DRATA_STATUS_FIELDS
    return body


def test_drata_status_not_configured(client, clear_drata_env):
    body = _get_status(client, _admin_key())
    assert body == {
        "configured": False,
        "connection_state": "NOT_CONFIGURED",
        "live_validated": False,
        "transport": "CCT",
        "events_pending": 0,
        "events_exported": 0,
        "events_dead_letter": 0,
        "last_exported_at": None,
        "last_error": None,
        "partner_connection": False,
    }


def test_drata_status_configured_with_https_url(client, drata_env):
    with patch("urllib.request.urlopen") as mock_urlopen:
        body = _get_status(client, _admin_key())
    mock_urlopen.assert_not_called()
    assert body["configured"] is True
    assert body["connection_state"] == "CONFIGURED"
    assert body["live_validated"] is False
    assert body["transport"] == "CCT"


@pytest.mark.parametrize(
    "url,api_key",
    [
        ("http://drata.example.invalid/cct/secret-connection-123", DRATA_TEST_KEY),
        ("not a url", DRATA_TEST_KEY),
        (DRATA_TEST_URL, None),
    ],
)
def test_drata_status_config_invalid(client, clear_drata_env, monkeypatch, url, api_key):
    monkeypatch.setenv("HERMES_DRATA_CCT_URL", url)
    if api_key:
        monkeypatch.setenv("HERMES_DRATA_API_KEY", api_key)
    body = _get_status(client, _admin_key())
    assert body["configured"] is True
    assert body["connection_state"] == "CONFIG_INVALID"
    assert body["live_validated"] is False
    assert url not in json.dumps(body)


def test_drata_status_outbox_counts_match_outbox_state(client, drata_env):
    from gateway.evidence_export.outbox import enqueue_event, list_outbox_rows

    ws_id = "rbac-drata-admin"
    api_key = _admin_key(ws_id)
    _enqueue_and_flush("evt-exported-1", ws_id, (True, 1, None))
    _enqueue_and_flush("evt-exported-2", ws_id, (True, 1, None))
    _enqueue_and_flush("evt-dead-1", ws_id, (False, 1, "HTTP 401"))
    _enqueue_and_flush("evt-retry-1", ws_id, (False, 3, "HTTP 503"))
    enqueue_event(_outbox_event("evt-queued-1", ws_id))

    rows = {r["event_id"]: r["status"] for r in list_outbox_rows(ws_id)}
    assert rows == {
        "evt-exported-1": "EXPORTED",
        "evt-exported-2": "EXPORTED",
        "evt-dead-1": "DEAD_LETTER",
        "evt-retry-1": "PENDING",
        "evt-queued-1": "PENDING",
    }

    body = _get_status(client, api_key)
    assert body["events_pending"] == 2
    assert body["events_exported"] == 2
    assert body["events_dead_letter"] == 1
    assert body["last_error"] == "HTTP 503"
    exported_at = datetime.fromisoformat(body["last_exported_at"])
    assert exported_at.tzinfo is not None
    assert abs(datetime.now(UTC) - exported_at) < timedelta(minutes=5)


def test_drata_status_outbox_counts_scoped_to_caller_workspace(client, drata_env):
    api_key = _admin_key("rbac-drata-ws-a")
    _enqueue_and_flush("evt-other-ws", "rbac-drata-ws-b", (False, 1, "HTTP 401"))
    _enqueue_and_flush("evt-other-ws-2", "rbac-drata-ws-b", (True, 1, None))

    body = _get_status(client, api_key)
    assert body["events_pending"] == 0
    assert body["events_exported"] == 0
    assert body["events_dead_letter"] == 0
    assert body["last_exported_at"] is None
    assert body["last_error"] is None


def test_drata_status_last_error_null_when_no_error(client, drata_env):
    from gateway.evidence_export.outbox import enqueue_event

    ws_id = "rbac-drata-admin"
    api_key = _admin_key(ws_id)
    _enqueue_and_flush("evt-ok-1", ws_id, (True, 1, None))
    enqueue_event(_outbox_event("evt-queued-1", ws_id))

    body = _get_status(client, api_key)
    assert body["last_error"] is None
    assert body["events_exported"] == 1
    assert body["events_pending"] == 1


def test_drata_status_last_error_cleared_after_successful_retry(client, drata_env):
    from gateway.evidence_export.outbox import flush_outbox

    ws_id = "rbac-drata-admin"
    api_key = _admin_key(ws_id)
    _enqueue_and_flush("evt-retry-ok", ws_id, (False, 3, "HTTP 503"))
    assert _get_status(client, api_key)["last_error"] == "HTTP 503"

    later = datetime.now(UTC) + timedelta(days=1)
    with patch("gateway.evidence_export.exporters._post_json", return_value=(True, 1, None)):
        flush_outbox(ws_id, now=later)

    body = _get_status(client, api_key)
    assert body["last_error"] is None
    assert body["events_pending"] == 0
    assert body["events_exported"] == 1
    assert body["last_exported_at"] == later.isoformat()


def test_drata_status_last_error_never_contains_credentials(client, drata_env, monkeypatch, caplog):
    from gateway.evidence_export import outbox
    from gateway.evidence_export.drata_connector import DrataConnector

    ws_id = "rbac-drata-admin"
    api_key = _admin_key(ws_id)
    leaked = (
        f"POST {DRATA_TEST_URL} failed: Authorization: Bearer {DRATA_TEST_KEY} "
        "api_key=sk-live-0123456789abcdefghij host drata.example.invalid:443"
    )

    def _leaky(self, event):
        raise RuntimeError(leaked)

    monkeypatch.setattr(DrataConnector, "send_evidence", _leaky)
    outbox.enqueue_event(_outbox_event("evt-leak-1", ws_id))
    outbox.flush_outbox(ws_id)

    # A row written unsanitized (e.g. by an older build) is re-sanitized on read.
    outbox.enqueue_event(_outbox_event("evt-leak-2", ws_id))
    conn = outbox._connect()
    try:
        conn.execute(
            "UPDATE evidence_outbox SET last_error = ? WHERE event_id = ?",
            (leaked, "evt-leak-2"),
        )
    finally:
        conn.close()

    with caplog.at_level(logging.DEBUG):
        response = client.get(DRATA_STATUS_PATH, headers={"X-API-Key": api_key})
    assert response.status_code == 200
    body = response.json()
    assert body["last_error"]
    for secret in (
        DRATA_TEST_KEY,
        DRATA_TEST_URL,
        "secret-connection-123",
        "drata.example.invalid",
        "sk-live-0123456789abcdefghij",
        "https://",
    ):
        assert secret not in body["last_error"]
        assert secret not in response.text
        assert secret not in caplog.text


@pytest.mark.parametrize(
    "url,api_key",
    [
        (None, None),
        (DRATA_TEST_URL, DRATA_TEST_KEY),
        (DRATA_TEST_URL, None),
        ("http://drata.example.invalid/cct", DRATA_TEST_KEY),
    ],
)
def test_drata_status_live_validated_always_false(client, clear_drata_env, monkeypatch, url, api_key):
    if url:
        monkeypatch.setenv("HERMES_DRATA_CCT_URL", url)
    if api_key:
        monkeypatch.setenv("HERMES_DRATA_API_KEY", api_key)
    ws_id = "rbac-drata-admin"
    key = _admin_key(ws_id)
    if url and api_key and url.startswith("https://"):
        _enqueue_and_flush("evt-live-1", ws_id, (True, 1, None))
    body = _get_status(client, key)
    assert body["live_validated"] is False
    assert body["connection_state"] not in (
        "CONNECTION_SUCCESS",
        "CONNECTION_TEST_SUCCEEDED",
        "CONNECTED",
    )


@pytest.mark.parametrize("configured", [False, True])
def test_drata_status_partner_connection_always_false(client, clear_drata_env, monkeypatch, configured):
    if configured:
        monkeypatch.setenv("HERMES_DRATA_CCT_URL", DRATA_TEST_URL)
        monkeypatch.setenv("HERMES_DRATA_API_KEY", DRATA_TEST_KEY)
    body = _get_status(client, _admin_key())
    assert body["partner_connection"] is False


def test_drata_status_msp_tech_allowed(client, drata_env):
    _, api_key = create_workspace(
        "rbac-status-tech", "Status Tech", "status-tech@test.com", role="msp_tech"
    )
    assert _get_status(client, api_key)["connection_state"] == "CONFIGURED"


def test_drata_status_client_readonly_forbidden(client, drata_env):
    _, api_key = create_workspace(
        "rbac-status-ro", "Status RO", "status-ro@test.com", role="client_readonly"
    )
    response = client.get(DRATA_STATUS_PATH, headers={"X-API-Key": api_key})
    assert response.status_code == 403
    assert response.json() == {"detail": "Insufficient permissions"}


def test_drata_status_invalid_api_key_rejected(client, drata_env):
    response = client.get(DRATA_STATUS_PATH, headers={"X-API-Key": "not-a-real-key"})
    assert response.status_code == 401


def test_drata_status_outbox_query_failure_returns_partial_response(client, drata_env, monkeypatch):
    import gateway.evidence_export.outbox as outbox_mod

    def _boom(workspace_id):
        raise RuntimeError(f"database locked at {DRATA_TEST_URL} key {DRATA_TEST_KEY}")

    monkeypatch.setattr(outbox_mod, "outbox_stats", _boom)
    response = client.get(DRATA_STATUS_PATH, headers={"X-API-Key": _admin_key()})
    assert response.status_code == 200
    body = response.json()
    assert body["configured"] is True
    assert body["connection_state"] == "CONFIGURED"
    assert body["live_validated"] is False
    assert body["partner_connection"] is False
    for field in OUTBOX_FIELDS:
        assert body[field] is None
    assert DRATA_TEST_KEY not in response.text


def test_drata_status_unreadable_outbox_db_returns_partial_response(
    client, drata_env, monkeypatch, tmp_path
):
    import gateway.evidence_export.outbox as outbox_mod

    unreadable = tmp_path / "outbox-is-a-directory"
    unreadable.mkdir()
    monkeypatch.setattr(outbox_mod, "outbox_db_path", lambda: unreadable)
    body = _get_status(client, _admin_key())
    assert body["connection_state"] == "CONFIGURED"
    for field in OUTBOX_FIELDS:
        assert body[field] is None


def test_drata_status_does_not_contact_network(client, drata_env):
    ws_id = "rbac-drata-admin"
    api_key = _admin_key(ws_id)
    from gateway.evidence_export.outbox import enqueue_event

    enqueue_event(_outbox_event("evt-queued-net", ws_id))
    with patch("urllib.request.urlopen") as mock_urlopen, patch(
        "gateway.evidence_export.exporters._post_json"
    ) as mock_post, patch("socket.create_connection") as mock_socket:
        body = _get_status(client, api_key)
    mock_urlopen.assert_not_called()
    mock_post.assert_not_called()
    mock_socket.assert_not_called()
    assert body["events_pending"] == 1


def test_drata_status_response_contains_no_credentials(client, drata_env, caplog):
    with caplog.at_level(logging.DEBUG):
        response = client.get(DRATA_STATUS_PATH, headers={"X-API-Key": _admin_key()})
    for secret in (DRATA_TEST_KEY, DRATA_TEST_URL, "secret-connection-123", "drata.example.invalid"):
        assert secret not in response.text
        assert secret not in caplog.text
        for header_value in response.headers.values():
            assert secret not in header_value


def test_drata_config_endpoint_still_available_after_status_endpoint(client, drata_env):
    response = client.post("/api/v1/drata/config", headers={"X-API-Key": _admin_key()})
    assert response.status_code == 501
    assert response.json()["state"] == "CONFIGURED"
