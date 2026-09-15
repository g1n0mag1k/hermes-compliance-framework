"""
tests/v2/test_key_store.py — Encrypted KeyStore tests.
"""

import os
import pytest

from hermes.receipts.v2.key_store import KeyStore
from hermes.receipts.v2.software_signer import SoftwareSignerEd25519, SoftwareSignerES256

PASSPHRASE = b"test-passphrase-not-for-production"
WRONG_PASSPHRASE = b"definitely-wrong"


@pytest.fixture
def store_path(tmp_path):
    return tmp_path / "test.keystore"


class TestKeyStoreCreate:
    def test_creates_file(self, store_path):
        KeyStore.create(store_path, PASSPHRASE)
        assert store_path.exists()

    def test_file_permissions_600(self, store_path):
        KeyStore.create(store_path, PASSPHRASE)
        mode = oct(os.stat(store_path).st_mode)[-3:]
        assert mode == "600"

    def test_raises_if_file_exists(self, store_path):
        KeyStore.create(store_path, PASSPHRASE)
        with pytest.raises(FileExistsError):
            KeyStore.create(store_path, PASSPHRASE)

    def test_returns_store_instance(self, store_path):
        store = KeyStore.create(store_path, PASSPHRASE)
        assert isinstance(store, KeyStore)

    def test_key_id_accessible_without_decrypt(self, store_path):
        store = KeyStore.create(store_path, PASSPHRASE)
        assert len(store.key_id) == 16  # 8 bytes = 16 hex chars

    def test_algorithm_ed25519_default(self, store_path):
        store = KeyStore.create(store_path, PASSPHRASE)
        assert store.algorithm == "EdDSA"

    def test_algorithm_es256(self, tmp_path):
        p = tmp_path / "es256.keystore"
        store = KeyStore.create(p, PASSPHRASE, algorithm="ES256")
        assert store.algorithm == "ES256"

    def test_invalid_algorithm_raises(self, store_path):
        with pytest.raises(ValueError, match="Unsupported"):
            KeyStore.create(store_path, PASSPHRASE, algorithm="HMAC")


class TestKeyStoreOpen:
    def test_open_loads_correct_key_id(self, store_path):
        created = KeyStore.create(store_path, PASSPHRASE)
        loaded = KeyStore.open(store_path, PASSPHRASE)
        assert created.key_id == loaded.key_id

    def test_open_wrong_passphrase_raises(self, store_path):
        KeyStore.create(store_path, PASSPHRASE)
        with pytest.raises(ValueError, match="[Ww]rong passphrase|[Cc]orrupt"):
            KeyStore.open(store_path, WRONG_PASSPHRASE)

    def test_open_missing_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            KeyStore.open(tmp_path / "nonexistent.keystore", PASSPHRASE)

    def test_open_corrupt_file_raises(self, store_path):
        store_path.write_text("not json at all")
        with pytest.raises(ValueError):
            KeyStore.open(store_path, PASSPHRASE)


class TestKeyStoreLoadSigner:
    def test_load_signer_ed25519(self, store_path):
        KeyStore.create(store_path, PASSPHRASE)
        store = KeyStore.open(store_path, PASSPHRASE)
        signer = store.load_signer()
        assert isinstance(signer, SoftwareSignerEd25519)

    def test_load_signer_es256(self, tmp_path):
        p = tmp_path / "es256.keystore"
        KeyStore.create(p, PASSPHRASE, algorithm="ES256")
        store = KeyStore.open(p, PASSPHRASE)
        signer = store.load_signer()
        assert isinstance(signer, SoftwareSignerES256)

    def test_signer_can_sign(self, store_path):
        KeyStore.create(store_path, PASSPHRASE)
        store = KeyStore.open(store_path, PASSPHRASE)
        signer = store.load_signer()
        sig = signer.sign_cose_sig_structure(b"test message bytes")
        assert isinstance(sig, bytes)
        assert len(sig) == 64  # Ed25519

    def test_signer_key_id_matches_store(self, store_path):
        created = KeyStore.create(store_path, PASSPHRASE)
        store = KeyStore.open(store_path, PASSPHRASE)
        signer = store.load_signer()
        assert signer.key_id.hex() == created.key_id

    def test_load_signer_with_explicit_passphrase(self, store_path):
        """load_signer() should also accept an explicit passphrase arg."""
        KeyStore.create(store_path, PASSPHRASE)
        # Load without caching passphrase
        import json
        data = json.loads(store_path.read_text())
        from hermes.receipts.v2.key_store import KeyStore as KS
        import base64
        store = KS(
            _path=store_path,
            _algorithm=data["algorithm"],
            _salt=base64.b64decode(data["salt"]),
            _nonce=base64.b64decode(data["nonce"]),
            _ciphertext=base64.b64decode(data["ciphertext"]),
            _iterations=data["iterations"],
            _key_id_hex=data["key_id"],
            _lock=__import__("threading").Lock(),
        )
        signer = store.load_signer(passphrase=PASSPHRASE)
        assert isinstance(signer, SoftwareSignerEd25519)

    def test_load_signer_no_passphrase_raises(self, store_path):
        KeyStore.create(store_path, PASSPHRASE)
        import json, base64, threading
        data = json.loads(store_path.read_text())
        store = KeyStore(
            _path=store_path,
            _algorithm=data["algorithm"],
            _salt=base64.b64decode(data["salt"]),
            _nonce=base64.b64decode(data["nonce"]),
            _ciphertext=base64.b64decode(data["ciphertext"]),
            _iterations=data["iterations"],
            _key_id_hex=data["key_id"],
            _lock=threading.Lock(),
        )
        with pytest.raises(RuntimeError, match="[Nn]o passphrase"):
            store.load_signer()


class TestKeyStoreFileFormat:
    def test_file_is_valid_json(self, store_path):
        import json
        KeyStore.create(store_path, PASSPHRASE)
        data = json.loads(store_path.read_text())
        assert data["format_version"] == 1
        assert "algorithm" in data
        assert "salt" in data
        assert "nonce" in data
        assert "ciphertext" in data
        assert "key_id" in data

    def test_private_key_not_in_plaintext(self, store_path):
        KeyStore.create(store_path, PASSPHRASE)
        raw = store_path.read_text()
        assert "BEGIN" not in raw  # no PEM header in plaintext
        assert "PRIVATE" not in raw

    def test_two_creates_produce_different_ciphertexts(self, tmp_path):
        p1 = tmp_path / "a.keystore"
        p2 = tmp_path / "b.keystore"
        KeyStore.create(p1, PASSPHRASE)
        KeyStore.create(p2, PASSPHRASE)
        import json
        d1 = json.loads(p1.read_text())
        d2 = json.loads(p2.read_text())
        # Different keys → different ciphertexts, different key_ids
        assert d1["ciphertext"] != d2["ciphertext"]
        assert d1["key_id"] != d2["key_id"]
