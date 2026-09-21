"""Tests for gateway.evidence_export.dispatch.dispatch_psa_ticket."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from gateway.credentials import CredentialManager
from gateway.evidence_export.dispatch import dispatch_psa_ticket


@pytest.fixture()
def manager(tmp_path) -> CredentialManager:
    return CredentialManager(db_path=str(tmp_path / "psa_credentials.db"))


def _run(coro):
    return asyncio.run(coro)


def test_dispatch_halopsa_posts_correct_payload(manager: CredentialManager) -> None:
    manager.set_psa_config(
        tenant_id="tenant-halo",
        psa_type="halopsa",
        base_url="https://halo.example.com",
        api_token="halo-secret",
    )

    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = None
    mock_client.post = AsyncMock(return_value=MagicMock())

    with patch(
        "gateway.evidence_export.dispatch.CredentialManager",
        return_value=manager,
    ), patch(
        "gateway.evidence_export.dispatch.httpx.AsyncClient",
        return_value=mock_client,
    ):
        _run(
            dispatch_psa_ticket(
                "tenant-halo",
                "HIPAA_SSN",
                "https://evidence.example/run-1",
            )
        )

    mock_client.post.assert_awaited_once()
    args, kwargs = mock_client.post.await_args
    assert args[0] == "https://halo.example.com/api/Tickets"
    assert kwargs["json"] == {
        "summary": "Hermes Relay Drift Detected: HIPAA_SSN",
        "details": "Audit evidence: https://evidence.example/run-1",
        "client_id": "tenant-halo",
        "tickettype_id": 1,
    }
    assert kwargs["headers"]["Authorization"] == "Bearer halo-secret"


def test_dispatch_connectwise_posts_correct_payload(manager: CredentialManager) -> None:
    manager.set_psa_config(
        tenant_id="tenant-cw",
        psa_type="connectwise",
        base_url="https://cw.example.com",
        api_token="cw-basic-token",
        client_id="cw-client-id",
    )

    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = None
    mock_client.post = AsyncMock(return_value=MagicMock())

    with patch(
        "gateway.evidence_export.dispatch.CredentialManager",
        return_value=manager,
    ), patch(
        "gateway.evidence_export.dispatch.httpx.AsyncClient",
        return_value=mock_client,
    ):
        _run(
            dispatch_psa_ticket(
                "tenant-cw",
                "HIPAA_PHI_EMAIL",
                "https://evidence.example/run-2",
            )
        )

    mock_client.post.assert_awaited_once()
    args, kwargs = mock_client.post.await_args
    assert args[0] == (
        "https://cw.example.com/v4_6_release/apis/3.0/service/tickets"
    )
    assert kwargs["json"] == {
        "summary": "Hermes Relay Alert: HIPAA_PHI_EMAIL Drift",
        "company": {"identifier": "tenant-cw"},
        "initialDescription": "Audit evidence: https://evidence.example/run-2",
        "recordType": "ServiceTicket",
    }
    assert kwargs["headers"]["Authorization"] == "Basic cw-basic-token"
    assert kwargs["headers"]["clientId"] == "cw-client-id"


def test_dispatch_no_config_returns_silently(manager: CredentialManager) -> None:
    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = None
    mock_client.post = AsyncMock()

    with patch(
        "gateway.evidence_export.dispatch.CredentialManager",
        return_value=manager,
    ), patch(
        "gateway.evidence_export.dispatch.httpx.AsyncClient",
        return_value=mock_client,
    ):
        _run(
            dispatch_psa_ticket(
                "no-such-tenant",
                "HIPAA_SSN",
                "https://evidence.example/none",
            )
        )

    mock_client.post.assert_not_called()


def test_dispatch_never_raises_on_network_failure(manager: CredentialManager) -> None:
    manager.set_psa_config(
        tenant_id="tenant-fail",
        psa_type="halopsa",
        base_url="https://halo.example.com",
        api_token="tok",
    )

    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = None
    mock_client.post = AsyncMock(
        side_effect=httpx.ConnectError("connection refused")
    )

    with patch(
        "gateway.evidence_export.dispatch.CredentialManager",
        return_value=manager,
    ), patch(
        "gateway.evidence_export.dispatch.httpx.AsyncClient",
        return_value=mock_client,
    ):
        _run(
            dispatch_psa_ticket(
                "tenant-fail",
                "HIPAA_SSN",
                "https://evidence.example/fail",
            )
        )
