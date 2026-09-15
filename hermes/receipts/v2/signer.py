"""Signer protocol for Hermes Relay V2 receipt signing."""

from __future__ import annotations

from typing import Protocol, TypedDict


class KeyManifest(TypedDict):
    key_id: str
    algorithm: str  # "ES256" or "EdDSA"
    public_key_spki_sha256: str
    public_key_pem: str
    valid_from: str  # ISO 8601
    valid_until: str | None
    status: str  # "active" | "rotated" | "revoked"
    purpose: str  # "receipt-signing"


class Signer(Protocol):
    @property
    def key_id(self) -> bytes: ...

    @property
    def cose_algorithm(self) -> int: ...

    def public_key_manifest(self) -> KeyManifest: ...

    def sign_cose_sig_structure(self, message: bytes) -> bytes: ...
