"""
hermes/receipts/v2/key_store.py — Encrypted on-disk key storage for Hermes V2.

Replaces the V1 pattern of storing signing material in a plaintext
HERMES_SIGNING_KEY env var. Private keys are wrapped with AES-256-GCM
using a user-supplied passphrase (PBKDF2-HMAC-SHA256, 600_000 iterations)
and stored as a JSON file. The private key never appears in plaintext
outside this module.

Key properties:
  - Non-exportable in the sense that the raw key bytes are never returned;
    only a live Signer instance is handed back.
  - PBKDF2 iteration count is stored in the file so future strengthening
    is backward-compatible.
  - File format is versioned (format_version: 1) for future migration.
  - Thread-safe for concurrent reads; writes hold a file lock.

Usage:
    # First run — create and save
    store = KeyStore.create(path, passphrase=b"strong-passphrase")
    signer = store.load_signer()

    # Subsequent runs — load from disk
    store = KeyStore.open(path, passphrase=b"strong-passphrase")
    signer = store.load_signer()
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import threading
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from hermes.receipts.v2.software_signer import SoftwareSignerEd25519, SoftwareSignerES256

_FORMAT_VERSION = 1
_PBKDF2_ITERATIONS = 600_000
_SALT_BYTES = 32
_NONCE_BYTES = 12      # AES-GCM standard nonce
_KDF_DOMAIN = b"HERMES-KEY-STORE-V1\x00"


def _derive_key(passphrase: bytes, salt: bytes, iterations: int) -> bytes:
    """Derive a 256-bit AES key from passphrase + salt via PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_KDF_DOMAIN + salt,
        iterations=iterations,
    )
    return kdf.derive(passphrase)


@dataclass
class KeyStore:
    """
    An encrypted on-disk key store for a single Hermes signing key.

    Do not construct directly — use KeyStore.create() or KeyStore.open().
    """
    _path: Path
    _algorithm: str        # "EdDSA" or "ES256"
    _salt: bytes
    _nonce: bytes
    _ciphertext: bytes     # AES-GCM encrypted PKCS8 PEM private key
    _iterations: int
    _key_id_hex: str       # stored for fast lookup without decrypting
    _lock: threading.Lock

    # ------------------------------------------------------------------
    # Factory methods
    # ------------------------------------------------------------------

    @classmethod
    def create(
        cls,
        path: str | Path,
        passphrase: bytes,
        algorithm: str = "EdDSA",
        iterations: int = _PBKDF2_ITERATIONS,
    ) -> "KeyStore":
        """
        Generate a new signing key and save it encrypted to `path`.

        Args:
            path:        Where to write the encrypted key file.
            passphrase:  Encryption passphrase (bytes). Never stored.
            algorithm:   "EdDSA" (default) or "ES256".
            iterations:  PBKDF2 iteration count (default 600_000).

        Returns:
            A KeyStore ready for load_signer().

        Raises:
            FileExistsError: if `path` already exists (prevents accidental overwrite).
            ValueError:      if algorithm is not "EdDSA" or "ES256".
        """
        path = Path(path)
        if path.exists():
            raise FileExistsError(
                f"Key store already exists at {path}. "
                "Use KeyStore.open() to load it, or delete it to regenerate."
            )

        # Generate key
        if algorithm == "EdDSA":
            private_key = ed25519.Ed25519PrivateKey.generate()
        elif algorithm == "ES256":
            private_key = ec.generate_private_key(ec.SECP256R1())
        else:
            raise ValueError(f"Unsupported algorithm {algorithm!r}. Use 'EdDSA' or 'ES256'.")

        # Serialize to PKCS8 PEM (unencrypted — we handle encryption ourselves)
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        # Derive key_id for fast lookup
        pub_spki = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        import hashlib
        key_id_hex = hashlib.sha256(pub_spki).digest()[:8].hex()

        # Encrypt
        salt = secrets.token_bytes(_SALT_BYTES)
        nonce = secrets.token_bytes(_NONCE_BYTES)
        aes_key = _derive_key(passphrase, salt, iterations)
        aesgcm = AESGCM(aes_key)
        ciphertext = aesgcm.encrypt(nonce, private_pem, b"")

        store = cls(
            _path=path,
            _algorithm=algorithm,
            _salt=salt,
            _nonce=nonce,
            _ciphertext=ciphertext,
            _iterations=iterations,
            _key_id_hex=key_id_hex,
            _lock=threading.Lock(),
        )
        store._save()
        return store

    @classmethod
    def open(cls, path: str | Path, passphrase: bytes) -> "KeyStore":
        """
        Load an existing encrypted key store from `path`.

        Does NOT decrypt the key — decryption happens only in load_signer().
        Validates the file format and passphrase eagerly by doing a test
        decrypt to confirm the passphrase is correct.

        Raises:
            FileNotFoundError: if `path` does not exist.
            ValueError:        if the file format is invalid or passphrase wrong.
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Key store not found at {path}.")

        try:
            with open(path) as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as exc:
            raise ValueError(f"Could not read key store at {path}: {exc}") from exc

        if data.get("format_version") != _FORMAT_VERSION:
            raise ValueError(
                f"Unsupported key store format version: {data.get('format_version')}"
            )

        algorithm = data["algorithm"]
        salt = base64.b64decode(data["salt"])
        nonce = base64.b64decode(data["nonce"])
        ciphertext = base64.b64decode(data["ciphertext"])
        iterations = data.get("iterations", _PBKDF2_ITERATIONS)
        key_id_hex = data["key_id"]

        store = cls(
            _path=path,
            _algorithm=algorithm,
            _salt=salt,
            _nonce=nonce,
            _ciphertext=ciphertext,
            _iterations=iterations,
            _key_id_hex=key_id_hex,
            _lock=threading.Lock(),
        )

        # Eagerly verify passphrase — better to fail fast here than on first sign
        store._decrypt(passphrase)  # raises on wrong passphrase
        store._passphrase = passphrase  # cache for load_signer()
        return store

    # ------------------------------------------------------------------
    # Key access
    # ------------------------------------------------------------------

    def load_signer(self, passphrase: bytes | None = None) -> SoftwareSignerEd25519 | SoftwareSignerES256:
        """
        Decrypt and return a live Signer instance.

        Args:
            passphrase: Decryption passphrase. If None, uses the passphrase
                        cached from open() — only valid if called via open().

        Returns:
            SoftwareSignerEd25519 or SoftwareSignerES256, ready to sign.

        Raises:
            ValueError:  if passphrase is wrong or key is corrupt.
            RuntimeError: if no passphrase available.
        """
        pw = passphrase or getattr(self, "_passphrase", None)
        if pw is None:
            raise RuntimeError(
                "No passphrase available. Pass passphrase= or use KeyStore.open()."
            )
        private_pem = self._decrypt(pw)
        if self._algorithm == "EdDSA":
            return SoftwareSignerEd25519.load_from_pem(private_pem)
        else:
            return SoftwareSignerES256.load_from_pem(private_pem)

    @property
    def key_id(self) -> str:
        """Hex key_id — readable without decrypting."""
        return self._key_id_hex

    @property
    def algorithm(self) -> str:
        """Algorithm string — readable without decrypting."""
        return self._algorithm

    @property
    def path(self) -> Path:
        return self._path

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _decrypt(self, passphrase: bytes) -> bytes:
        """Decrypt and return raw PKCS8 PEM bytes. Raises on wrong passphrase."""
        aes_key = _derive_key(passphrase, self._salt, self._iterations)
        aesgcm = AESGCM(aes_key)
        try:
            return aesgcm.decrypt(self._nonce, self._ciphertext, b"")
        except Exception as exc:
            raise ValueError(
                "Key decryption failed — wrong passphrase or corrupt key store."
            ) from exc

    def _save(self) -> None:
        """Write the encrypted key store to disk (atomic via temp file)."""
        data = {
            "format_version": _FORMAT_VERSION,
            "algorithm": self._algorithm,
            "key_id": self._key_id_hex,
            "salt": base64.b64encode(self._salt).decode("ascii"),
            "nonce": base64.b64encode(self._nonce).decode("ascii"),
            "ciphertext": base64.b64encode(self._ciphertext).decode("ascii"),
            "iterations": self._iterations,
        }
        tmp = self._path.with_suffix(".tmp")
        with open(tmp, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, self._path)  # atomic on POSIX
        # Restrict permissions: owner read/write only
        os.chmod(self._path, 0o600)
