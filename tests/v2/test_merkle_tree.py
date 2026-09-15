"""
tests/v2/test_merkle_tree.py — RFC 9162 Merkle tree tests.
"""

import hashlib
import pytest

from hermes.receipts.v2.canonical import merkle_leaf, merkle_node
from hermes.receipts.v2.merkle_tree import (
    MerkleTree,
    InclusionProof,
    ConsistencyProof,
    _compute_root,
    _inclusion_path,
    _recompute_root_from_inclusion,
)


def _digest(i: int) -> bytes:
    """Generate a deterministic 32-byte test digest."""
    return hashlib.sha256(f"receipt-{i}".encode()).digest()


class TestMerkleTreeBasics:
    def test_empty_tree_size_zero(self):
        t = MerkleTree()
        assert t.size == 0

    def test_append_returns_index(self):
        t = MerkleTree()
        assert t.append(_digest(0)) == 0
        assert t.append(_digest(1)) == 1

    def test_append_hex(self):
        t = MerkleTree()
        idx = t.append_hex(_digest(0).hex())
        assert idx == 0

    def test_size_tracks_appends(self):
        t = MerkleTree()
        for i in range(7):
            t.append(_digest(i))
        assert t.size == 7

    def test_root_single_leaf(self):
        t = MerkleTree()
        d = _digest(0)
        t.append(d)
        assert t.root() == merkle_leaf(d)

    def test_root_two_leaves(self):
        t = MerkleTree()
        d0, d1 = _digest(0), _digest(1)
        t.append(d0)
        t.append(d1)
        expected = merkle_node(merkle_leaf(d0), merkle_leaf(d1))
        assert t.root() == expected

    def test_root_empty_raises(self):
        with pytest.raises(ValueError, match="empty"):
            MerkleTree().root()

    def test_root_hex_is_64_chars(self):
        t = MerkleTree()
        t.append(_digest(0))
        assert len(t.root_hex()) == 64

    def test_root_at_prefix(self):
        t = MerkleTree()
        for i in range(5):
            t.append(_digest(i))
        root_at_3 = t.root_at(3)
        # Independently compute root of first 3
        t2 = MerkleTree()
        for i in range(3):
            t2.append(_digest(i))
        assert root_at_3 == t2.root()

    def test_root_at_invalid_raises(self):
        t = MerkleTree()
        for i in range(3):
            t.append(_digest(i))
        with pytest.raises(ValueError):
            t.root_at(0)
        with pytest.raises(ValueError):
            t.root_at(4)

    def test_append_wrong_length_raises(self):
        t = MerkleTree()
        with pytest.raises(ValueError, match="32 bytes"):
            t.append(b"too short")

    def test_deterministic_root(self):
        t1, t2 = MerkleTree(), MerkleTree()
        for i in range(4):
            t1.append(_digest(i))
            t2.append(_digest(i))
        assert t1.root() == t2.root()

    def test_different_digests_different_root(self):
        t1, t2 = MerkleTree(), MerkleTree()
        t1.append(_digest(0))
        t2.append(_digest(1))
        assert t1.root() != t2.root()


class TestInclusionProofs:
    @pytest.fixture
    def tree_5(self):
        t = MerkleTree()
        for i in range(5):
            t.append(_digest(i))
        return t

    def test_inclusion_proof_returns_proof(self, tree_5):
        proof = tree_5.inclusion_proof(0)
        assert isinstance(proof, InclusionProof)

    def test_inclusion_proof_all_leaves(self, tree_5):
        root = tree_5.root()
        for i in range(tree_5.size):
            proof = tree_5.inclusion_proof(i)
            assert proof.verify(root), f"Inclusion proof failed for leaf {i}"

    def test_inclusion_proof_invalid_index(self, tree_5):
        with pytest.raises(IndexError):
            tree_5.inclusion_proof(5)
        with pytest.raises(IndexError):
            tree_5.inclusion_proof(-1)

    def test_inclusion_proof_to_dict(self, tree_5):
        d = tree_5.inclusion_proof(0).to_dict()
        assert "leaf_index" in d
        assert "leaf_hash" in d
        assert "path" in d
        assert "tree_size" in d
        assert "tree_root" in d

    def test_inclusion_proof_wrong_root_fails(self, tree_5):
        proof = tree_5.inclusion_proof(0)
        wrong_root = b"\xff" * 32
        assert not proof.verify(wrong_root)

    def test_inclusion_proof_single_leaf_tree(self):
        t = MerkleTree()
        t.append(_digest(0))
        proof = t.inclusion_proof(0)
        assert proof.verify()

    def test_inclusion_proof_power_of_two(self):
        t = MerkleTree()
        for i in range(8):
            t.append(_digest(i))
        root = t.root()
        for i in range(8):
            assert t.inclusion_proof(i).verify(root)


class TestConsistencyProofs:
    @pytest.fixture
    def tree_10(self):
        t = MerkleTree()
        for i in range(10):
            t.append(_digest(i))
        return t

    def test_consistency_proof_returns_proof(self, tree_10):
        proof = tree_10.consistency_proof(5)
        assert isinstance(proof, ConsistencyProof)

    def test_consistency_proof_has_correct_sizes(self, tree_10):
        proof = tree_10.consistency_proof(5)
        assert proof.old_size == 5
        assert proof.new_size == 10

    def test_consistency_proof_roots_match(self, tree_10):
        proof = tree_10.consistency_proof(5)
        assert proof.old_root == tree_10.root_at(5)
        assert proof.new_root == tree_10.root()

    def test_consistency_proof_invalid_old_size(self, tree_10):
        with pytest.raises(ValueError):
            tree_10.consistency_proof(0)
        with pytest.raises(ValueError):
            tree_10.consistency_proof(10)
        with pytest.raises(ValueError):
            tree_10.consistency_proof(11)

    def test_consistency_proof_to_dict(self, tree_10):
        d = tree_10.consistency_proof(3).to_dict()
        assert "old_size" in d
        assert "new_size" in d
        assert "old_root" in d
        assert "new_root" in d
        assert "path" in d

    def test_consistency_proof_detects_appended_entries(self):
        """Tree grows by appending — proof should verify."""
        t = MerkleTree()
        for i in range(4):
            t.append(_digest(i))
        old_root = t.root()

        for i in range(4, 8):
            t.append(_digest(i))

        proof = t.consistency_proof(4)
        assert proof.old_root == old_root
        assert proof.verify(old_root, t.root())

    def test_forked_tree_different_root(self):
        """A tree that rewrites a leaf produces a different root."""
        t1, t2 = MerkleTree(), MerkleTree()
        for i in range(4):
            t1.append(_digest(i))
        # t2 has the same first 3 leaves but different 4th
        for i in range(3):
            t2.append(_digest(i))
        t2.append(_digest(99))  # different leaf

        assert t1.root_at(3) == t2.root_at(3)  # first 3 are the same
        assert t1.root() != t2.root()           # but full roots differ
