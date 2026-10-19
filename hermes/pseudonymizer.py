"""Insurance broker workflow: deterministic PHI pseudonymization with reversible linkage."""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime
from pathlib import Path

import pandas as pd

from hermes.vault import VAULT_KEY, _aesgcm_decrypt, _aesgcm_encrypt


def _is_missing_phi_value(value: object) -> bool:
    if value is None:
        return True
    if isinstance(value, str) and value == "":
        return True
    try:
        return bool(pd.isna(value))
    except (TypeError, ValueError):
        return False


def _coded_identifier(column: str, value: object) -> str:
    digest = hmac.new(
        VAULT_KEY,
        f"{column}:{value}".encode(),
        hashlib.sha256,
    ).hexdigest()[:8]
    return f"CLIENT_{digest}"


class Pseudonymizer:
    def __init__(self, phi_columns: list[str]) -> None:
        """phi_columns: column names to pseudonymize"""
        self._phi_columns = list(phi_columns)

    def pseudonymize(
        self,
        df: pd.DataFrame,
        transaction_id: str,
    ) -> tuple[pd.DataFrame, dict[str, dict]]:
        """
        Returns (coded_df, linkage_table).

        coded_df: copy of df where every value in phi_columns is
          replaced with a coded identifier:
            "CLIENT_" + hmac.new(VAULT_KEY,
                f"{col}:{value}".encode(),
                hashlib.sha256).hexdigest()[:8]

        linkage_table: dict mapping each coded identifier to:
            {
                "column": str,
                "original": str,
                "transaction_id": str,
                "coded_at": str,   # ISO 8601 UTC
            }

        Rules:
        - Non-PHI columns copied unchanged
        - Empty string, NaN, None in PHI columns: left as-is, not coded
        - Same (col, value) always produces the same coded identifier
          (HMAC keyed to VAULT_KEY is deterministic)
        """
        coded_df = df.copy()
        linkage_table: dict[str, dict] = {}
        coded_at = datetime.now(UTC).isoformat()

        for col in self._phi_columns:
            if col not in coded_df.columns:
                continue
            for idx in coded_df.index:
                value = coded_df.at[idx, col]
                if _is_missing_phi_value(value):
                    continue
                code = _coded_identifier(col, value)
                coded_df.at[idx, col] = code
                if code not in linkage_table:
                    linkage_table[code] = {
                        "column": col,
                        "original": str(value),
                        "transaction_id": transaction_id,
                        "coded_at": coded_at,
                    }

        return coded_df, linkage_table

    def reassociate(
        self,
        coded_df: pd.DataFrame,
        linkage_table: dict[str, dict],
    ) -> pd.DataFrame:
        """
        Replace coded identifiers in phi_columns with original values.
        Codes not found in linkage_table: left unchanged (not an error).
        Returns new DataFrame — does not modify coded_df in place.
        """
        restored = coded_df.copy()
        for col in self._phi_columns:
            if col not in restored.columns:
                continue
            for idx in restored.index:
                value = restored.at[idx, col]
                if not isinstance(value, str):
                    continue
                entry = linkage_table.get(value)
                if entry is None:
                    continue
                restored.at[idx, col] = entry["original"]
        return restored

    def export_linkage_table(
        self,
        linkage_table: dict[str, dict],
        output_path: str | Path,
    ) -> None:
        """
        Write linkage table as AES-256-GCM encrypted JSON.
        Use VAULT_KEY and _aesgcm_encrypt from hermes.vault.
        File format: hex(nonce || ciphertext || tag) as UTF-8 text.
        Raises FileExistsError if output_path already exists.
        """
        path = Path(output_path)
        if path.exists():
            raise FileExistsError(path)
        json_str = json.dumps(linkage_table)
        encrypted_hex = _aesgcm_encrypt(json_str, VAULT_KEY)
        path.write_text(encrypted_hex, encoding="utf-8")

    @staticmethod
    def load_linkage_table(input_path: str | Path) -> dict[str, dict]:
        """
        Decrypt and return a linkage table from export_linkage_table().
        Use _aesgcm_decrypt from hermes.vault.
        Raises FileNotFoundError if input_path does not exist.
        """
        path = Path(input_path)
        if not path.exists():
            raise FileNotFoundError(path)
        ciphertext_hex = path.read_text(encoding="utf-8")
        json_str = _aesgcm_decrypt(ciphertext_hex, VAULT_KEY)
        return json.loads(json_str)
