"""Golden tests for Hermes Relay V2 RFC 8785 canonicalization."""

from __future__ import annotations

import hashlib

import pytest

from hermes.receipts.v2.canonical import (
    CanonicalizationError,
    canonicalize,
    merkle_leaf,
    merkle_node,
    receipt_digest,
)

# ---------------------------------------------------------------------------
# Golden vectors — pinned expected UTF-8 bytes / digests
# ---------------------------------------------------------------------------

# RFC 8785 sorts object members lexicographically by key.
GOLDEN_PAYLOAD = {
    "b": 2,
    "a": 1,
    "nested": {"z": True, "m": None, "a": [3, 1, "x"]},
}
GOLDEN_CANONICAL = (
    b'{"a":1,"b":2,"nested":{"a":[3,1,"x"],"m":null,"z":true}}'
)

# receipt_digest = SHA-256(b"HERMES-RECEIPT-V2\0" + GOLDEN_CANONICAL)
_DOMAIN = b"HERMES-RECEIPT-V2\0"
GOLDEN_RECEIPT_DIGEST = bytes.fromhex(
    "881d4d99515bde538b89dae53ea2cf918247b1546f6f1ab6deb6b4479a600b1f"
)

# Distinct Merkle prefixes must not collide for the same child material.
_CHILD = bytes.fromhex(
    "6f566ddeda89ff9d7355d639c8cfe968ea9fb0cd40b157616dd178e82fd4c25c"
)
GOLDEN_MERKLE_LEAF = bytes.fromhex(
    "6a9f07bcef50508986a9a8eb561f63c095b9b16557ba3923e8981655b4e4d29f"
)
GOLDEN_MERKLE_NODE = bytes.fromhex(
    "b6f2ffdcaad570a5e12dc301c813616a167d4a81a71416e4a59fbcc9c48c2d63"
)


class TestCanonicalizeDeterminism:
    def test_identical_input_identical_bytes(self):
        first = canonicalize(GOLDEN_PAYLOAD)
        second = canonicalize(dict(GOLDEN_PAYLOAD))
        assert first == second == GOLDEN_CANONICAL

    def test_property_order_does_not_affect_output(self):
        reordered = {
            "nested": {"a": [3, 1, "x"], "m": None, "z": True},
            "a": 1,
            "b": 2,
        }
        assert canonicalize(reordered) == GOLDEN_CANONICAL
        assert canonicalize(reordered) == canonicalize(GOLDEN_PAYLOAD)

    def test_nested_property_order_independent(self):
        a = {"outer": {"k2": 2, "k1": 1}}
        b = {"outer": {"k1": 1, "k2": 2}}
        assert canonicalize(a) == canonicalize(b) == b'{"outer":{"k1":1,"k2":2}}'

    def test_utf8_bytes_only(self):
        out = canonicalize({"msg": "café", "emoji": "🔐"})
        assert isinstance(out, bytes)
        assert out.decode("utf-8") == out.decode("utf-8")  # round-trip
        assert out == b'{"emoji":"\xf0\x9f\x94\x90","msg":"caf\xc3\xa9"}'


class TestIJSONRejection:
    def test_rejects_nan(self):
        with pytest.raises(CanonicalizationError, match="Non-finite|nan|NaN"):
            canonicalize({"x": float("nan")})

    def test_rejects_positive_infinity(self):
        with pytest.raises(CanonicalizationError, match="Non-finite|inf|Inf"):
            canonicalize({"x": float("inf")})

    def test_rejects_negative_infinity(self):
        with pytest.raises(CanonicalizationError, match="Non-finite|inf|Inf"):
            canonicalize({"x": float("-inf")})

    def test_rejects_nested_nan(self):
        with pytest.raises(CanonicalizationError):
            canonicalize({"ok": 1, "deep": {"vals": [1.0, float("nan")]}})

    def test_rejects_non_dict_payload(self):
        with pytest.raises(CanonicalizationError, match="dict"):
            canonicalize([1, 2, 3])  # type: ignore[arg-type]

    def test_rejects_duplicate_keys_via_mapping_hook(self):
        # Simulate a mapping that reports duplicate keys through .keys().
        class DupMap(dict):
            def keys(self):
                return ["a", "a"]

            def __getitem__(self, key):
                return 1

        with pytest.raises(CanonicalizationError, match="[Dd]uplicate"):
            canonicalize(DupMap())


class TestReceiptDigestDomainSeparator:
    def test_domain_separator_prefix_applied(self):
        digest = receipt_digest(GOLDEN_PAYLOAD)
        assert digest == GOLDEN_RECEIPT_DIGEST
        assert len(digest) == 32

        # Explicit formula check — domain label must be present.
        bare = hashlib.sha256(GOLDEN_CANONICAL).digest()
        assert digest != bare
        assert digest == hashlib.sha256(_DOMAIN + GOLDEN_CANONICAL).digest()

    def test_domain_separator_bytes_are_exact(self):
        assert _DOMAIN == b"HERMES-RECEIPT-V2\0"
        assert _DOMAIN.endswith(b"\0")
        assert _DOMAIN.startswith(b"HERMES-RECEIPT-V2")

    def test_digest_stable_across_key_order(self):
        a = {"z": 1, "a": 2}
        b = {"a": 2, "z": 1}
        assert receipt_digest(a) == receipt_digest(b)


class TestMerklePrefixes:
    def test_leaf_prefix_golden(self):
        assert merkle_leaf(_CHILD) == GOLDEN_MERKLE_LEAF

    def test_node_prefix_golden(self):
        assert merkle_node(_CHILD, _CHILD) == GOLDEN_MERKLE_NODE

    def test_leaf_and_node_prefixes_are_distinct(self):
        leaf = merkle_leaf(_CHILD)
        # Same payload bytes under the other prefix must differ.
        node_like = hashlib.sha256(b"\x01" + _CHILD).digest()
        assert leaf != node_like
        assert merkle_leaf(_CHILD) != merkle_node(_CHILD, _CHILD)

    def test_leaf_uses_0x00_prefix(self):
        digest = b"\x11" * 32
        assert merkle_leaf(digest) == hashlib.sha256(b"\x00" + digest).digest()

    def test_node_uses_0x01_prefix(self):
        left = b"\x22" * 32
        right = b"\x33" * 32
        assert merkle_node(left, right) == hashlib.sha256(
            b"\x01" + left + right
        ).digest()

    def test_leaf_node_collision_resistance_smoke(self):
        """0x00||d must never equal 0x01||L||R for equal-length digest inputs
        under SHA-256 in these fixtures — prefixes are cryptographically
        domain-separated.
        """
        d = hashlib.sha256(b"x").digest()
        assert merkle_leaf(d) != merkle_node(d, d)
        assert merkle_leaf(d) != merkle_node(d[:16], d[16:])
