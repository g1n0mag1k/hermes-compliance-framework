"""RFC 8785 JSON Canonicalization Scheme for Hermes Relay V2 receipts.

Produces deterministic UTF-8 bytes suitable for domain-separated hashing and
Merkle tree construction. Uses the ``jcs`` library for JCS serialization and
enforces strict I-JSON constraints (no NaN/Infinity, no duplicate keys,
UTF-8 only) before canonicalization.
"""

from __future__ import annotations

import hashlib
import math
from typing import Any, Mapping

import jcs

# Domain separator for receipt content digests (NUL-terminated ASCII label).
_RECEIPT_DOMAIN = b"HERMES-RECEIPT-V2\0"

# Merkle domain prefixes (RFC 6962-style leaf/node separation).
_MERKLE_LEAF_PREFIX = b"\x00"
_MERKLE_NODE_PREFIX = b"\x01"


class CanonicalizationError(ValueError):
    """Raised when a payload violates I-JSON / JCS constraints."""


def _reject_duplicate_keys(pairs: list[tuple[Any, Any]]) -> dict:
    """object_pairs_hook that rejects duplicate JSON object member names."""
    seen: set[Any] = set()
    out: dict = {}
    for key, value in pairs:
        if key in seen:
            raise CanonicalizationError(f"Duplicate object key: {key!r}")
        seen.add(key)
        out[key] = value
    return out


def _validate_ijson(value: Any, *, path: str = "$") -> None:
    """Recursively enforce I-JSON constraints on a Python value tree."""
    if isinstance(value, Mapping):
        keys = list(value.keys())
        if len(keys) != len(set(keys)):
            raise CanonicalizationError(f"Duplicate object keys at {path}")
        for key in keys:
            if not isinstance(key, str):
                raise CanonicalizationError(
                    f"Non-string object key at {path}: {key!r}"
                )
            _validate_ijson(value[key], path=f"{path}.{key}")
        return

    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_ijson(item, path=f"{path}[{index}]")
        return

    if isinstance(value, bool) or value is None or isinstance(value, str):
        return

    if isinstance(value, int) and not isinstance(value, bool):
        return

    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise CanonicalizationError(
                f"Non-finite number rejected at {path}: {value!r}"
            )
        return

    raise CanonicalizationError(
        f"Unsupported JSON type at {path}: {type(value).__name__}"
    )


def canonicalize(payload: dict) -> bytes:
    """Return RFC 8785 (JCS) canonical UTF-8 bytes for ``payload``.

    Properties are sorted recursively. NaN, Infinity, and duplicate keys are
    rejected. Output is always UTF-8 ``bytes``.
    """
    if not isinstance(payload, dict):
        raise CanonicalizationError(
            f"payload must be a dict, got {type(payload).__name__}"
        )

    _validate_ijson(payload)

    try:
        canonical = jcs.canonicalize(payload)
    except ValueError as exc:
        raise CanonicalizationError(str(exc)) from exc

    if isinstance(canonical, str):
        return canonical.encode("utf-8")
    if not isinstance(canonical, (bytes, bytearray)):
        raise CanonicalizationError(
            f"jcs.canonicalize returned unexpected type: {type(canonical).__name__}"
        )
    return bytes(canonical)


def receipt_digest(payload: dict) -> bytes:
    """SHA-256 digest of a domain-separated canonical receipt payload.

    ``receipt_digest(payload) = SHA-256("HERMES-RECEIPT-V2\\0" + canonicalize(payload))``
    """
    return hashlib.sha256(_RECEIPT_DOMAIN + canonicalize(payload)).digest()


def merkle_leaf(digest: bytes) -> bytes:
    """Hash a Merkle leaf: ``SHA-256(0x00 || digest)``."""
    if not isinstance(digest, (bytes, bytearray)):
        raise TypeError("digest must be bytes")
    return hashlib.sha256(_MERKLE_LEAF_PREFIX + bytes(digest)).digest()


def merkle_node(left: bytes, right: bytes) -> bytes:
    """Hash a Merkle internal node: ``SHA-256(0x01 || left || right)``."""
    if not isinstance(left, (bytes, bytearray)) or not isinstance(
        right, (bytes, bytearray)
    ):
        raise TypeError("left and right must be bytes")
    return hashlib.sha256(
        _MERKLE_NODE_PREFIX + bytes(left) + bytes(right)
    ).digest()


# Re-export for callers that need duplicate-key-safe JSON object construction.
reject_duplicate_keys = _reject_duplicate_keys
