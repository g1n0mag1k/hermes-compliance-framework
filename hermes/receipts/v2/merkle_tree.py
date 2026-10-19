"""
hermes/receipts/v2/merkle_tree.py — RFC 9162-style Merkle tree for receipt digests.

Builds an append-only Merkle tree over receipt digests and produces:
  - Inclusion proofs: prove a specific receipt is in the tree
  - Consistency proofs: prove tree[n] is a prefix of tree[m] (no rewriting)
  - The current Merkle root and tree size

This is the foundation for signed checkpoints. The tree is in-memory;
persistence is handled by the caller (write receipt batches to WORM storage).

Hash functions follow RFC 9162 §2.1 (same as RFC 6962):
  leaf(data)        = SHA-256(0x00 || data)
  node(left, right) = SHA-256(0x01 || left || right)

These are re-exported from canonical.py for consistency.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from hermes.receipts.v2.canonical import merkle_leaf, merkle_node


@dataclass
class MerkleTree:
    """
    Append-only Merkle tree over receipt digests.

    Entries are raw receipt_digest bytes (32-byte SHA-256).
    The tree is stored as a flat list of leaves; the root is
    recomputed on demand via _compute_root().

    This implementation follows RFC 9162 §2.1:
      - Leaves: SHA-256(0x00 || digest)
      - Nodes:  SHA-256(0x01 || left || right)
      - MTH(D[n]) is defined recursively by splitting at the largest
        power of two strictly less than n (RFC 9162 §2.1.1).
        This differs from Bitcoin-style trees that duplicate the last
        node on odd-length levels.

    Thread safety: not thread-safe. Wrap in a lock if shared.
    """

    _leaves: list[bytes] = field(default_factory=list)

    def append(self, receipt_digest: bytes) -> int:
        """
        Add a receipt digest to the tree.

        Args:
            receipt_digest: 32-byte receipt digest (from canonical.receipt_digest()).

        Returns:
            Zero-indexed position (leaf index) of the appended entry.

        Raises:
            ValueError: if receipt_digest is not exactly 32 bytes.
        """
        if len(receipt_digest) != 32:
            raise ValueError(
                f"receipt_digest must be 32 bytes, got {len(receipt_digest)}"
            )
        self._leaves.append(receipt_digest)
        return len(self._leaves) - 1

    def append_hex(self, receipt_digest_hex: str) -> int:
        """Convenience: append a hex-encoded receipt digest."""
        return self.append(bytes.fromhex(receipt_digest_hex))

    @property
    def size(self) -> int:
        """Number of leaves in the tree."""
        return len(self._leaves)

    def root(self) -> bytes:
        """
        Compute and return the current Merkle root.

        Raises:
            ValueError: if the tree is empty.
        """
        if not self._leaves:
            raise ValueError("Cannot compute root of empty Merkle tree.")
        return _compute_root([merkle_leaf(d) for d in self._leaves])

    def root_hex(self) -> str:
        """Hex-encoded Merkle root."""
        return self.root().hex()

    def root_at(self, size: int) -> bytes:
        """
        Compute the Merkle root for the first `size` leaves.

        Used in consistency proofs to reconstruct an older tree state.

        Raises:
            ValueError: if size <= 0 or size > self.size.
        """
        if size <= 0 or size > self.size:
            raise ValueError(
                f"size must be in [1, {self.size}], got {size}"
            )
        return _compute_root([merkle_leaf(d) for d in self._leaves[:size]])

    # ------------------------------------------------------------------
    # Inclusion proof
    # ------------------------------------------------------------------

    def inclusion_proof(self, leaf_index: int) -> InclusionProof:
        """
        Generate an inclusion proof for the leaf at `leaf_index`.

        The proof is a list of sibling hashes from leaf to root.
        A verifier recomputes the root by combining the leaf hash
        with each sibling in order.

        Args:
            leaf_index: Zero-indexed position of the leaf.

        Returns:
            InclusionProof containing the leaf hash, sibling path, and tree size.

        Raises:
            IndexError: if leaf_index is out of range.
        """
        if leaf_index < 0 or leaf_index >= self.size:
            raise IndexError(
                f"leaf_index {leaf_index} out of range [0, {self.size - 1}]"
            )

        leaf_hash = merkle_leaf(self._leaves[leaf_index])
        path = _inclusion_path(
            [merkle_leaf(d) for d in self._leaves], leaf_index
        )

        return InclusionProof(
            leaf_index=leaf_index,
            leaf_hash=leaf_hash,
            path=path,
            tree_size=self.size,
            tree_root=self.root(),
        )

    # ------------------------------------------------------------------
    # Consistency proof
    # ------------------------------------------------------------------

    def consistency_proof(self, old_size: int) -> ConsistencyProof:
        """
        Generate a consistency proof that tree[old_size] is a prefix of tree[self.size].

        A verifier holding an old root (computed over old_size leaves) can
        confirm it is consistent with a new root (over self.size leaves)
        without seeing any leaf data — only the proof hashes.

        Args:
            old_size: Size of the older tree snapshot to prove consistency with.

        Returns:
            ConsistencyProof.

        Raises:
            ValueError: if old_size >= self.size or old_size <= 0.
        """
        if old_size <= 0 or old_size >= self.size:
            raise ValueError(
                f"old_size must be in [1, {self.size - 1}], got {old_size}"
            )

        old_root = self.root_at(old_size)
        new_root = self.root()
        path = _consistency_path(
            [merkle_leaf(d) for d in self._leaves], old_size, self.size
        )

        return ConsistencyProof(
            old_size=old_size,
            new_size=self.size,
            old_root=old_root,
            new_root=new_root,
            path=path,
        )


# ------------------------------------------------------------------
# Proof dataclasses
# ------------------------------------------------------------------

@dataclass(frozen=True)
class InclusionProof:
    """
    Proof that a specific receipt digest is included in a Merkle tree.

    Verify by calling verify().
    """
    leaf_index: int
    leaf_hash: bytes        # SHA-256(0x00 || receipt_digest)
    path: list[bytes]       # sibling hashes from leaf to root
    tree_size: int
    tree_root: bytes

    def verify(self, expected_root: bytes | None = None) -> bool:
        """
        Verify this inclusion proof.

        Args:
            expected_root: Root to verify against. Defaults to self.tree_root.

        Returns:
            True if the proof is valid, False otherwise.
        """
        root_to_check = expected_root if expected_root is not None else self.tree_root
        computed = _recompute_root_from_inclusion(
            self.leaf_hash, self.leaf_index, self.path, self.tree_size
        )
        return computed == root_to_check

    def to_dict(self) -> dict:
        return {
            "leaf_index": self.leaf_index,
            "leaf_hash": self.leaf_hash.hex(),
            "path": [h.hex() for h in self.path],
            "tree_size": self.tree_size,
            "tree_root": self.tree_root.hex(),
        }


@dataclass(frozen=True)
class ConsistencyProof:
    """
    Proof that tree[old_size] is a prefix of tree[new_size].

    Proves the log has only been appended to — no rewriting occurred.
    Verify by calling verify().
    """
    old_size: int
    new_size: int
    old_root: bytes
    new_root: bytes
    path: list[bytes]

    def verify(
        self,
        expected_old_root: bytes | None = None,
        expected_new_root: bytes | None = None,
    ) -> bool:
        """
        Verify this consistency proof.

        Args:
            expected_old_root: Old root to verify against. Defaults to self.old_root.
            expected_new_root: New root to verify against. Defaults to self.new_root.

        Returns:
            True if the proof is valid, False otherwise.
        """
        old_root = expected_old_root if expected_old_root is not None else self.old_root
        new_root = expected_new_root if expected_new_root is not None else self.new_root
        return _verify_consistency(
            self.old_size, self.new_size, old_root, new_root, self.path
        )

    def to_dict(self) -> dict:
        return {
            "old_size": self.old_size,
            "new_size": self.new_size,
            "old_root": self.old_root.hex(),
            "new_root": self.new_root.hex(),
            "path": [h.hex() for h in self.path],
        }


# ------------------------------------------------------------------
# Internal tree algorithms
# ------------------------------------------------------------------

def _compute_root(leaf_hashes: list[bytes]) -> bytes:
    """
    RFC 9162 §2.1.1 Merkle Tree Hash (MTH) — recursive power-of-two split.

    MTH({d(0)}) = SHA-256(0x00 || d(0))
    MTH(D[n])   = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))
    where k is the largest power of two strictly less than n.

    This is NOT the Bitcoin/duplicate-last style; unbalanced trees are
    handled by splitting recursively, never by padding.
    """
    n = len(leaf_hashes)
    if n == 0:
        raise ValueError("Empty leaf list")
    if n == 1:
        return leaf_hashes[0]
    # Largest power of two strictly less than n
    k = 1
    while k < n:
        k <<= 1
    k >>= 1
    return merkle_node(
        _compute_root(leaf_hashes[:k]),
        _compute_root(leaf_hashes[k:]),
    )


def _inclusion_path(leaf_hashes: list[bytes], index: int) -> list[bytes]:
    """
    RFC 9162 §2.1.3 — compute the inclusion proof PATH(m, D[n]).

    PATH(m, {d(0)}) = {}
    PATH(m, D[n])   = PATH(m, D[0:k]) + [MTH(D[k:n])]   if m < k
                    = PATH(m-k, D[k:n]) + [MTH(D[0:k])]  if m >= k
    where k is the largest power of two strictly less than n.

    Returns the list of sibling hashes from leaf to root.
    Unlike Bitcoin-style trees, there is no duplicate-last padding.
    """
    n = len(leaf_hashes)
    if n == 1:
        return []
    # Largest power of two strictly less than n
    k = 1
    while k < n:
        k <<= 1
    k >>= 1
    if index < k:
        return _inclusion_path(leaf_hashes[:k], index) + [_compute_root(leaf_hashes[k:])]
    else:
        return _inclusion_path(leaf_hashes[k:], index - k) + [_compute_root(leaf_hashes[:k])]


def _recompute_root_from_inclusion(
    leaf_hash: bytes, index: int, path: list[bytes], tree_size: int
) -> bytes:
    """
    Recompute the Merkle root from an RFC 9162 §2.1.3 inclusion proof.

    Mirrors the recursive split used by _inclusion_path: at each level we
    know which subtree contains the leaf (left if index < k, right otherwise),
    so we know whether the path sibling goes on the right or left.
    """
    node = leaf_hash
    n = tree_size
    idx = index
    for sibling in path:
        # Largest power of two strictly less than n
        k = 1
        while k < n:
            k <<= 1
        k >>= 1
        if idx < k:
            # Leaf is in left subtree; sibling is right subtree root
            node = merkle_node(node, sibling)
            n = k
        else:
            # Leaf is in right subtree; sibling is left subtree root
            node = merkle_node(sibling, node)
            idx -= k
            n = n - k
    return node


def _consistency_path(
    leaf_hashes: list[bytes], old_size: int, new_size: int
) -> list[bytes]:
    """
    RFC 9162 §2.1.4 — compute consistency proof path (PROOF(m, n)).
    """
    if old_size == new_size:
        return []
    k = 1
    while k < new_size:
        k <<= 1
    k >>= 1  # largest power of 2 strictly less than new_size

    if old_size <= k:
        sub = _consistency_path(leaf_hashes[:k], old_size, k)
        right_root = _compute_root(leaf_hashes[k:new_size])
        return sub + [right_root]
    else:
        sub = _consistency_path(
            leaf_hashes[k:new_size], old_size - k, new_size - k
        )
        left_root = _compute_root(leaf_hashes[:k])
        return [left_root] + sub


def _verify_consistency(
    old_size: int,
    new_size: int,
    old_root: bytes,
    new_root: bytes,
    path: list[bytes],
) -> bool:
    """
    RFC 9162 §2.1.4.2 — verify a consistency proof between two tree heads.
    """
    if old_size > new_size:
        return False
    if old_size == new_size:
        return old_root == new_root and not path
    if old_size == 0:
        return False
    if not path:
        return False

    if old_size & (old_size - 1) == 0:
        first_elem, rest = old_root, path
    else:
        first_elem, rest = path[0], path[1:]

    fn = old_size - 1
    sn = new_size - 1

    while fn & 1:
        fn >>= 1
        sn >>= 1

    fr = first_elem
    sr = first_elem

    for sibling in rest:
        if sn == 0:
            return False
        if (fn & 1) or fn == sn:
            fr = merkle_node(sibling, fr)
            sr = merkle_node(sibling, sr)
            if not (fn & 1):
                while not (fn & 1) and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = merkle_node(sr, sibling)
        fn >>= 1
        sn >>= 1

    return fr == old_root and sr == new_root and sn == 0
