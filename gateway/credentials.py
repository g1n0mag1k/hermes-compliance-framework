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


# ---------------------------------------------------------------------------
# Per-workspace AI provider credentials (multi-tenant)
# ---------------------------------------------------------------------------
#
# A parent organization can give each child workspace its own OpenAI / Anthropic / Azure
# OpenAI credential so usage and billing stay separated per client. When a
# workspace has no stored credential, the gateway falls back to the
# deployment-wide env var (provider.credential_env) exactly as before.
#
# Credentials are encrypted at rest with AES-256-GCM using a per-workspace key
# derived from HERMES_VAULT_KEY (hermes.tenant_keys.workspace_credential_key).
# Raw credentials are never returned by any API and never logged.

_AZURE_ALLOWED_HOST_SUFFIXES = (".openai.azure.com", ".cognitiveservices.azure.com")


def _provider_credentials_db_path() -> str:
    from hermes.workspaces import _data_dir

    return os.environ.get(
        "HERMES_PROVIDER_CREDENTIALS_DB",
        str(_data_dir() / "provider_credentials.db"),
    )


def validate_provider_base_url(provider_id: str, base_url: str | None) -> str | None:
    """Validate a per-workspace upstream base URL. Only Azure OpenAI accepts one.

    Restricting the host prevents a tenant from pointing the gateway (and the
    credential it injects) at an arbitrary server.
    """
    from urllib.parse import urlsplit

    if base_url is None or base_url == "":
        return None
    if provider_id != "azure_openai":
        raise ValueError(
            f"base_url can only be set for azure_openai, not {provider_id!r}"
        )
    parts = urlsplit(base_url)
    host = (parts.hostname or "").lower()
    if parts.scheme != "https":
        raise ValueError("azure_openai base_url must use https")
    if not host.endswith(_AZURE_ALLOWED_HOST_SUFFIXES):
        raise ValueError(
            "azure_openai base_url host must end with one of "
            f"{list(_AZURE_ALLOWED_HOST_SUFFIXES)}"
        )
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ValueError("azure_openai base_url must not contain credentials, query or fragment")
    if parts.path not in ("", "/"):
        raise ValueError("azure_openai base_url must not contain a path")
    if parts.port not in (None, 443):
        raise ValueError("azure_openai base_url must use the default https port")
    return f"https://{host}"


class ProviderCredentialStore:
    """SQLite store of per-workspace AI provider credentials (encrypted)."""

    def __init__(self, db_path: str | None = None) -> None:
        self._db_path = db_path or _provider_credentials_db_path()
        self._lock = threading.Lock()
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            conn = self._connect()
            try:
                with conn:
                    conn.execute(
                        """
                        CREATE TABLE IF NOT EXISTS provider_credentials (
                            workspace_id         TEXT NOT NULL,
                            provider_id          TEXT NOT NULL,
                            encrypted_credential TEXT NOT NULL,
                            base_url             TEXT,
                            updated_at           TEXT NOT NULL,
                            PRIMARY KEY (workspace_id, provider_id)
                        )
                        """
                    )
            finally:
                conn.close()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self._db_path, check_same_thread=False)

    @staticmethod
    def _check_provider(provider_id: str) -> None:
        from gateway.providers import PROVIDER_REGISTRY

        if provider_id not in PROVIDER_REGISTRY:
            raise ValueError(
                f"Unknown provider {provider_id!r}. Allowed: {sorted(PROVIDER_REGISTRY)}"
            )

    def set_credential(
        self,
        workspace_id: str,
        provider_id: str,
        credential: str,
        base_url: str | None = None,
    ) -> None:
        from datetime import UTC, datetime

        from hermes.tenant_keys import workspace_credential_key
        from hermes.vault import _aesgcm_encrypt

        self._check_provider(provider_id)
        if not credential or not credential.strip():
            raise ValueError("credential must be a non-empty string")
        if any(c in credential for c in "\r\n"):
            raise ValueError("credential must not contain newlines")
        normalized_url = validate_provider_base_url(provider_id, base_url)
        encrypted = _aesgcm_encrypt(credential, workspace_credential_key(workspace_id))
        with self._lock:
            conn = self._connect()
            try:
                with conn:
                    conn.execute(
                        """
                        INSERT INTO provider_credentials
                            (workspace_id, provider_id, encrypted_credential,
                             base_url, updated_at)
                        VALUES (?, ?, ?, ?, ?)
                        ON CONFLICT(workspace_id, provider_id) DO UPDATE SET
                            encrypted_credential = excluded.encrypted_credential,
                            base_url = excluded.base_url,
                            updated_at = excluded.updated_at
                        """,
                        (
                            workspace_id,
                            provider_id,
                            encrypted,
                            normalized_url,
                            datetime.now(UTC).isoformat(),
                        ),
                    )
            finally:
                conn.close()

    def get_credential(
        self, workspace_id: str, provider_id: str
    ) -> tuple[str, str | None] | None:
        """Return (credential, base_url) for the workspace, or None if unset."""
        from hermes.tenant_keys import workspace_credential_key
        from hermes.vault import _aesgcm_decrypt

        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT encrypted_credential, base_url FROM provider_credentials "
                    "WHERE workspace_id = ? AND provider_id = ?",
                    (workspace_id, provider_id),
                ).fetchone()
            finally:
                conn.close()
        if row is None:
            return None
        try:
            credential = _aesgcm_decrypt(row[0], workspace_credential_key(workspace_id))
        except Exception as exc:
            # Fail closed: never fall back to the shared key when a tenant's own
            # credential exists but cannot be decrypted (key rotated / tampered).
            raise RuntimeError(
                f"Stored {provider_id} credential for workspace {workspace_id!r} "
                "could not be decrypted"
            ) from exc
        return credential, row[1]

    def list_configured(self, workspace_id: str) -> list[dict]:
        """Metadata only (provider_id, base_url, updated_at). Never the credential."""
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT provider_id, base_url, updated_at FROM provider_credentials "
                    "WHERE workspace_id = ? ORDER BY provider_id",
                    (workspace_id,),
                ).fetchall()
            finally:
                conn.close()
        return [
            {"provider_id": r[0], "base_url": r[1], "updated_at": r[2]} for r in rows
        ]

    def delete_credential(self, workspace_id: str, provider_id: str) -> bool:
        with self._lock:
            conn = self._connect()
            try:
                with conn:
                    cur = conn.execute(
                        "DELETE FROM provider_credentials "
                        "WHERE workspace_id = ? AND provider_id = ?",
                        (workspace_id, provider_id),
                    )
            finally:
                conn.close()
        return cur.rowcount > 0


_store_cache: dict[str, ProviderCredentialStore] = {}
_store_cache_lock = threading.Lock()


def _default_store() -> ProviderCredentialStore:
    """One store per resolved DB path, so the hot path doesn't re-run DDL."""
    path = _provider_credentials_db_path()
    with _store_cache_lock:
        store = _store_cache.get(path)
        if store is None:
            store = ProviderCredentialStore(db_path=path)
            _store_cache[path] = store
        return store


def resolve_upstream_for_workspace(
    headers: dict[str, str],
    provider: Provider,
    workspace_id: str,
    store: ProviderCredentialStore | None = None,
) -> tuple[dict[str, str], str]:
    """
    Inject the credential for (workspace, provider) and return
    (headers, upstream_base_url).

    Uses the workspace's stored credential when one exists; otherwise falls
    back to inject_provider_credentials() and provider.effective_base_url()
    (the deployment-wide env vars), preserving single-tenant behavior.
    Raises RuntimeError when no credential is available (gateway fails closed).
    """
    stored = (store or _default_store()).get_credential(
        workspace_id, provider.provider_id
    )
    if stored is None:
        return inject_provider_credentials(headers, provider), provider.effective_base_url()

    credential, base_url = stored
    result = dict(headers)
    result[provider.auth_header] = f"{provider.auth_prefix}{credential}"
    for key, value in provider.extra_headers.items():
        result[key] = value
    upstream_base = base_url or provider.effective_base_url()
    if not upstream_base:
        raise RuntimeError(
            f"No upstream base URL configured for provider {provider.provider_id!r} "
            f"in workspace {workspace_id!r}"
        )
    return result, upstream_base
