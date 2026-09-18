import os

from gateway.providers import Provider

CLIENT_AUTH_HEADERS_TO_STRIP = {"authorization", "x-api-key", "api-key"}


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
