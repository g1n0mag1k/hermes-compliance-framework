"""Unit tests for production hard-fail on missing crypto keys."""
import pytest

from hermes.attestation import _load_signing_key
from hermes.vault import _load_vault_key


def test_signing_key_raises_in_production_when_unset(monkeypatch):
    monkeypatch.setenv("HERMES_ENV", "production")
    monkeypatch.delenv("HERMES_SIGNING_KEY", raising=False)
    with pytest.raises(RuntimeError, match="HERMES_SIGNING_KEY"):
        _load_signing_key()


def test_vault_key_raises_in_production_when_unset(monkeypatch):
    monkeypatch.setenv("HERMES_ENV", "production")
    monkeypatch.delenv("HERMES_VAULT_KEY", raising=False)
    with pytest.raises(RuntimeError, match="HERMES_VAULT_KEY"):
        _load_vault_key()


def test_signing_key_raises_in_production_when_invalid(monkeypatch):
    monkeypatch.setenv("HERMES_ENV", "production")
    monkeypatch.setenv("HERMES_SIGNING_KEY", "not-valid-hex")
    with pytest.raises(RuntimeError, match="HERMES_SIGNING_KEY"):
        _load_signing_key()


def test_vault_key_raises_in_production_when_invalid(monkeypatch):
    monkeypatch.setenv("HERMES_ENV", "production")
    monkeypatch.setenv("HERMES_VAULT_KEY", "abcd")  # 2 bytes, not 32
    with pytest.raises(RuntimeError, match="HERMES_VAULT_KEY"):
        _load_vault_key()


def test_signing_key_warns_and_falls_back_in_development(monkeypatch):
    monkeypatch.setenv("HERMES_ENV", "development")
    monkeypatch.delenv("HERMES_SIGNING_KEY", raising=False)
    with pytest.warns(UserWarning, match="HERMES_SIGNING_KEY not set"):
        key = _load_signing_key()
    assert isinstance(key, bytes)
    assert len(key) == 32


def test_vault_key_warns_and_falls_back_in_development(monkeypatch):
    monkeypatch.setenv("HERMES_ENV", "development")
    monkeypatch.delenv("HERMES_VAULT_KEY", raising=False)
    with pytest.warns(UserWarning, match="HERMES_VAULT_KEY not set"):
        key = _load_vault_key()
    assert isinstance(key, bytes)
    assert len(key) == 32


def test_vault_key_rejects_wrong_length_in_development(monkeypatch):
    monkeypatch.setenv("HERMES_ENV", "development")
    monkeypatch.setenv("HERMES_VAULT_KEY", "abcd")  # 2 bytes, not 32
    with pytest.raises(ValueError, match="exactly 64 hex characters"):
        _load_vault_key()
