import os
import sqlite3
import threading
from pathlib import Path

from gateway.providers import Provider

CLIENT_AUTH_HEADERS_TO_STRIP = {"authorization", "x-api-key", "api-key"}

VALID_PSA_TYPES = frozenset({"halopsa", "connectwise"})
DEFAULT_PSA_DB_PATH = str(Path.home() / ".hermes" / "psa_credentials.db")


def strip_client_auth_headers(headers: dict[str, str]) -> dict[str, str]:
    """Remove all client auth headers case-insensitively."""
    return {
        k: v
        for k, v in headers.items()
        if k.lower() not in CLIENT_AUTH_HEADERS_TO_STRIP
    }


def inject_provider_credentials(headers: dict[str, str], provider: Provider) -> dict[str, str]:
    """Inject gateway-managed provider credentials into request headers."""
    credential = os.environ.get(provider.credential_env)
    if not credential:
        raise RuntimeError(
            f"Provider credential env var {provider.credential_env!r} is not set"
        )

    result = dict(headers)
    result[provider.auth_header] = f"{provider.auth_prefix}{credential}"
    for key, value in provider.extra_headers.items():
        result[key] = value
    return result


class CredentialManager:
    """Store and retrieve per-tenant PSA configuration in SQLite."""

    def __init__(self, db_path: str | None = None) -> None:
        self._db_path = db_path or DEFAULT_PSA_DB_PATH
        self._lock = threading.Lock()
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self._db_path, check_same_thread=False)

    def _init_db(self) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS psa_credentials (
                        tenant_id TEXT PRIMARY KEY,
                        psa_type TEXT NOT NULL,
                        base_url TEXT NOT NULL,
                        api_token TEXT NOT NULL,
                        client_id TEXT NOT NULL DEFAULT ''
                    )
                    """
                )
                conn.commit()
            finally:
                conn.close()

    def set_psa_config(
        self,
        tenant_id: str,
        psa_type: str,
        base_url: str,
        api_token: str,
        client_id: str = "",
    ) -> None:
        if psa_type not in VALID_PSA_TYPES:
            raise ValueError(
                f"psa_type must be one of {sorted(VALID_PSA_TYPES)}, got {psa_type!r}"
            )
        with self._lock:
            conn = self._connect()
            try:
                with conn:
                    conn.execute(
                        """
                        INSERT INTO psa_credentials
                            (tenant_id, psa_type, base_url, api_token, client_id)
                        VALUES (?, ?, ?, ?, ?)
                        ON CONFLICT(tenant_id) DO UPDATE SET
                            psa_type = excluded.psa_type,
                            base_url = excluded.base_url,
                            api_token = excluded.api_token,
                            client_id = excluded.client_id
                        """,
                        (tenant_id, psa_type, base_url, api_token, client_id),
                    )
            finally:
                conn.close()

    def get_psa_config(self, tenant_id: str) -> dict | None:
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    """
                    SELECT psa_type, base_url, api_token, client_id
                    FROM psa_credentials
                    WHERE tenant_id = ?
                    """,
                    (tenant_id,),
                ).fetchone()
            finally:
                conn.close()

        if row is None:
            return None
        return {
            "psa_type": row[0],
            "base_url": row[1],
            "api_token": row[2],
            "client_id": row[3],
        }

    def delete_psa_config(self, tenant_id: str) -> None:
        with self._lock:
            conn = self._connect()
            try:
                with conn:
                    conn.execute(
                        "DELETE FROM psa_credentials WHERE tenant_id = ?",
                        (tenant_id,),
                    )
            finally:
                conn.close()
