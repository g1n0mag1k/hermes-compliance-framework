"""
tests/v2/test_canonical.py — RFC 8785 canonicalization tests with golden vectors.
"""

import hashlib
import pytest

from hermes.receipts.v2.canonical import (
    canonicalize,
    receipt_digest,
    receipt_digest_hex,
    merkle_leaf,
    merkle_node,
    build_merkle_root,
)


# ---------------------------------------------------------------------------
# Canonicalize golden vectors
# ---------------------------------------------------------------------------

class TestCanonicalize:
    def test_simple_object(self):
        result = canonicalize({"b": 2, "a": 1})
        assert result == b'{"a":1,"b":2}'

    def test_property_order_irrelevant(self):
        a = canonicalize({"z": 3, "a": 1, "m": 2})
        b = canonicalize({"m": 2, "z": 3, "a": 1})
        c = canonicalize({"a": 1, "m": 2, "z": 3})
        assert a == b == c

    def test_identical_input_identical_output(self):
        payload = {"event": "scan", "version": 2, "tags": ["phi", "hipaa"]}
        assert canonicalize(payload) == canonicalize(payload)

    def test_unicode_strings(self):
        # RFC 8785 requires Unicode characters to be preserved, not escaped
        result = canonicalize({"key": "café"})
        assert "café".encode("utf-8") in result

    def test_nested_object_sorted(self):
        result = canonicalize({"outer": {"z": 1, "a": 2}})
        assert result == b'{"outer":{"a":2,"z":1}}'

    def test_array_order_preserved(self):
        result = canonicalize({"arr": [3, 1, 2]})
        assert result == b'{"arr":[3,1,2]}'

    def test_boolean_values(self):
        result = canonicalize({"t": True, "f": False})
        assert result == b'{"f":false,"t":true}'

    def test_null_value(self):
        result = canonicalize({"x": None})
        assert result == b'{"x":null}'

    def test_empty_dict(self):
        result = canonicalize({})
        assert result == b'{}'

    def test_rejects_nan(self):
        with pytest.raises(ValueError, match="NaN"):
            canonicalize({"x": float("nan")})

    def test_rejects_positive_infinity(self):
        with pytest.raises(ValueError, match="Infinity"):
            canonicalize({"x": float("inf")})

    def test_rejects_negative_infinity(self):
        with pytest.raises(ValueError, match="Infinity"):
            canonicalize({"x": float("-inf")})

    def test_rejects_duplicate_keys(self):
        # Python dicts can't have literal duplicate keys, but we can test
        # the validator with a constructed scenario via a subclass
        # The validator itself is sound — test with nested structure
        with pytest.raises(ValueError, match="Duplicate key"):
            from hermes.receipts.v2.canonical import _validate_payload
            _validate_payload({"a": 1}, "")  # valid
            # Simulate duplicate detection by calling with a list of keys
            class FakeDict(dict):
                def keys(self):
                    return ["a", "a"]
            _validate_payload(FakeDict([("a", 1)]), "")

    def test_returns_bytes(self):
        result = canonicalize({"x": 1})
        assert isinstance(result, bytes)

    def test_utf8_output(self):
        result = canonicalize({"hello": "world"})
        result.decode("utf-8")  # must not raise


# ---------------------------------------------------------------------------
# receipt_digest tests
# ---------------------------------------------------------------------------

class TestReceiptDigest:
    def test_returns_bytes(self):
        d = receipt_digest({"x": 1})
        assert isinstance(d, bytes)
        assert len(d) == 32  # SHA-256

    def test_domain_separator_applied(self):
        payload = {"event": "test"}
        canonical = b'{"event":"test"}'

        # Without domain prefix
        raw = hashlib.sha256(canonical).digest()
        # With domain prefix
        from_function = receipt_digest(payload)

        assert raw != from_function  # domain separator changes the result

    def test_domain_separator_prefix(self):
        """Verify the exact domain separator is prepended."""
        payload = {"event": "test"}
        canonical = b'{"event":"test"}'
        domain = b"HERMES-RECEIPT-V2\x00"

        expected = hashlib.sha256(domain + canonical).digest()
        assert receipt_digest(payload) == expected

    def test_deterministic(self):
        payload = {"a": 1, "b": [1, 2, 3]}
        assert receipt_digest(payload) == receipt_digest(payload)

    def test_different_payloads_different_digests(self):
        d1 = receipt_digest({"x": 1})
        d2 = receipt_digest({"x": 2})
        assert d1 != d2

    def test_hex_wrapper(self):
        payload = {"x": 1}
        hex_d = receipt_digest_hex(payload)
        assert isinstance(hex_d, str)
        assert len(hex_d) == 64
        assert bytes.fromhex(hex_d) == receipt_digest(payload)


# ---------------------------------------------------------------------------
# Merkle tests
# ---------------------------------------------------------------------------

class TestMerkle:
    def test_leaf_prefix_distinct_from_node(self):
        data = b"x" * 32
        leaf = merkle_leaf(data)
        # node with same data in both slots uses 0x01 prefix
        node = merkle_node(data, data)
        assert leaf != node

    def test_leaf_deterministic(self):
        d = b"a" * 32
        assert merkle_leaf(d) == merkle_leaf(d)

    def test_node_deterministic(self):
        l = b"a" * 32
        r = b"b" * 32
        assert merkle_node(l, r) == merkle_node(l, r)

    def test_node_not_commutative(self):
        """Left-right order must matter."""
        l = b"a" * 32
        r = b"b" * 32
        assert merkle_node(l, r) != merkle_node(r, l)

    def test_leaf_format(self):
        data = b"x" * 32
        expected = hashlib.sha256(b"\x00" + data).digest()
        assert merkle_leaf(data) == expected

    def test_node_format(self):
        l = b"a" * 32
        r = b"b" * 32
        expected = hashlib.sha256(b"\x01" + l + r).digest()
        assert merkle_node(l, r) == expected

    def test_build_root_single(self):
        d = b"a" * 32
        root = build_merkle_root([d])
        assert root == merkle_leaf(d)

    def test_build_root_two(self):
        d1 = b"a" * 32
        d2 = b"b" * 32
        root = build_merkle_root([d1, d2])
        expected = merkle_node(merkle_leaf(d1), merkle_leaf(d2))
        assert root == expected

    def test_build_root_empty_raises(self):
        with pytest.raises(ValueError, match="empty"):
            build_merkle_root([])

    def test_build_root_deterministic(self):
        digests = [bytes([i]) * 32 for i in range(5)]
        assert build_merkle_root(digests) == build_merkle_root(digests)

    def test_build_root_different_inputs_different_roots(self):
        d1 = [b"a" * 32, b"b" * 32]
        d2 = [b"a" * 32, b"c" * 32]
        assert build_merkle_root(d1) != build_merkle_root(d2)

    def test_build_root_odd_count_stable(self):
        """Three digests should not raise — last leaf is duplicated."""
        digests = [bytes([i]) * 32 for i in range(3)]
        root = build_merkle_root(digests)
        assert isinstance(root, bytes)
        assert len(root) == 32
