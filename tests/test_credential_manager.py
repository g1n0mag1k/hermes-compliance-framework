"""Tests for gateway.credentials.CredentialManager."""

from __future__ import annotations

import pytest

from gateway.credentials import CredentialManager


@pytest.fixture()
def manager(tmp_path) -> CredentialManager:
    return CredentialManager(db_path=str(tmp_path / "psa_credentials.db"))


def test_set_and_get_psa_config(manager: CredentialManager) -> None:
    manager.set_psa_config(
        tenant_id="tenant-a",
        psa_type="halopsa",
        base_url="https://psa.example.com",
        api_token="token-123",
        client_id="client-xyz",
    )
    config = manager.get_psa_config("tenant-a")
    assert config == {
        "psa_type": "halopsa",
        "base_url": "https://psa.example.com",
        "api_token": "token-123",
        "client_id": "client-xyz",
    }


def test_get_missing_returns_none(manager: CredentialManager) -> None:
    assert manager.get_psa_config("never-configured") is None


def test_delete_psa_config(manager: CredentialManager) -> None:
    manager.set_psa_config(
        tenant_id="tenant-del",
        psa_type="connectwise",
        base_url="https://cw.example.com",
        api_token="tok",
    )
    manager.delete_psa_config("tenant-del")
    assert manager.get_psa_config("tenant-del") is None


def test_update_overwrites_existing(manager: CredentialManager) -> None:
    manager.set_psa_config(
        tenant_id="tenant-upd",
        psa_type="halopsa",
        base_url="https://old.example.com",
        api_token="old-token",
        client_id="old-client",
    )
    manager.set_psa_config(
        tenant_id="tenant-upd",
        psa_type="connectwise",
        base_url="https://new.example.com",
        api_token="new-token",
        client_id="new-client",
    )
    config = manager.get_psa_config("tenant-upd")
    assert config == {
        "psa_type": "connectwise",
        "base_url": "https://new.example.com",
        "api_token": "new-token",
        "client_id": "new-client",
    }


def test_halopsa_and_connectwise_both_valid(manager: CredentialManager) -> None:
    manager.set_psa_config(
        tenant_id="tenant-halo",
        psa_type="halopsa",
        base_url="https://halo.example.com",
        api_token="halo-token",
    )
    manager.set_psa_config(
        tenant_id="tenant-cw",
        psa_type="connectwise",
        base_url="https://cw.example.com",
        api_token="cw-token",
        client_id="cw-client",
    )
    halo = manager.get_psa_config("tenant-halo")
    cw = manager.get_psa_config("tenant-cw")
    assert halo is not None and halo["psa_type"] == "halopsa"
    assert cw is not None and cw["psa_type"] == "connectwise"
    assert cw["client_id"] == "cw-client"
