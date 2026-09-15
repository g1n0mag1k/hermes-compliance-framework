"""
hermes/receipts/v2/canonical.py — RFC 8785 JSON Canonicalization for V2 receipts.

Implements:
  - RFC 8785 JCS canonicalization via the `jcs` library
  - Domain-separated receipt_digest (SHA-256 with "HERMES-RECEIPT-V2\0" prefix)
  - Merkle leaf and node hash functions with anti-second-preimage prefixes

All functions are pure — no I/O, no randomness, no external state.
"""

import hashlib
import math
from typing import Any

import jcs as _jcs

# Domain separator for receipt digests — prevents cross-context hash collisions
_RECEIPT_DOMAIN = b"HERMES-RECEIPT-V2\x00"

# Merkle tree hash prefixes per RFC 6962 / RFC 9162
_MERKLE_LEAF_PREFIX = b"\x00"
_MERKLE_NODE_PREFIX = b"\x01"

# Algorithms that are never permitted in V2 receipts
_BLOCKED_ALGORITHMS = {"HS256", "HS384", "HS512", "none"}


def canonicalize(payload: dict) -> bytes:
    """
    Return the RFC 8785 JCS canonical UTF-8 encoding of `payload`.

    Raises:
        ValueError: if payload contains NaN, Infinity, or duplicate keys
        TypeError:  if payload contains non-serializable types
    """
    _validate_payload(payload)
    return _jcs.canonicalize(payload)


def receipt_digest(payload: dict) -> bytes:
    """
    Domain-separated SHA-256 digest over the canonical payload.

    digest = SHA-256("HERMES-RECEIPT-V2\\0" || canonicalize(payload))

    The domain prefix prevents a receipt digest from being confused with
    any other SHA-256 hash in the system (Merkle nodes, checkpoint digests,
    database exports, etc.).
    """
    canonical_bytes = canonicalize(payload)
    h = hashlib.sha256()
    h.update(_RECEIPT_DOMAIN)
    h.update(canonical_bytes)
    return h.digest()


def receipt_digest_hex(payload: dict) -> str:
    """Hex-encoded receipt_digest — convenience wrapper."""
    return receipt_digest(payload).hex()


def merkle_leaf(digest: bytes) -> bytes:
    """
    Hash a single receipt digest as a Merkle tree leaf node.

    leaf = SHA-256(0x00 || digest)

    The 0x00 prefix prevents second-preimage attacks where an attacker
    crafts an internal node that collides with a leaf.
    """
    h = hashlib.sha256()
    h.update(_MERKLE_LEAF_PREFIX)
    h.update(digest)
    return h.digest()


def merkle_node(left: bytes, right: bytes) -> bytes:
    """
    Hash two child digests into a Merkle tree internal node.

    node = SHA-256(0x01 || left || right)

    The 0x01 prefix is distinct from the leaf prefix — prevents
    a leaf from being substituted for an internal node.
    """
    h = hashlib.sha256()
    h.update(_MERKLE_NODE_PREFIX)
    h.update(left)
    h.update(right)
    return h.digest()


def build_merkle_root(digests: list[bytes]) -> bytes:
    """
    Build a Merkle root over a list of receipt digests.

    Each digest is first wrapped as a leaf, then paired bottom-up.
    Odd trees duplicate the last node at each level (RFC 6962 §2.1).

    Raises:
        ValueError: if digests is empty
    """
    if not digests:
        raise ValueError("Cannot build Merkle root over empty digest list")

    leaves = [merkle_leaf(d) for d in digests]

    # Bottom-up reduction
    level = leaves
    while len(level) > 1:
        next_level = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else level[i]
            next_level.append(merkle_node(left, right))
        level = next_level

    return level[0]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _validate_payload(payload: Any, _path: str = "") -> None:
    """
    Recursively validate that payload is safe to canonicalize.

    Rejects:
    - NaN and Infinity float values (not valid JSON per RFC 8259)
    - Duplicate dict keys (jcs library may silently drop one)
    - Non-string dict keys
    """
    if isinstance(payload, float):
        if math.isnan(payload) or math.isinf(payload):
            raise ValueError(
                f"Payload contains non-finite float at {_path!r}: {payload!r}. "
                "NaN and Infinity are not valid JSON values (RFC 8259 §6)."
            )
    elif isinstance(payload, dict):
        keys = list(payload.keys())
        if len(keys) != len(set(keys)):
            seen = set()
            for k in keys:
                if k in seen:
                    raise ValueError(
                        f"Duplicate key {k!r} in payload at {_path!r}. "
                        "RFC 8785 requires unique keys."
                    )
                seen.add(k)
        for k, v in payload.items():
            if not isinstance(k, str):
                raise TypeError(
                    f"Dict key {k!r} at {_path!r} must be str, not {type(k).__name__}."
                )
            _validate_payload(v, _path=f"{_path}.{k}" if _path else k)
    elif isinstance(payload, list):
        for i, item in enumerate(payload):
            _validate_payload(item, _path=f"{_path}[{i}]")
