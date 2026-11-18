import os
from dataclasses import dataclass


@dataclass
class Provider:
    provider_id: str
    base_url: str
    allowed_path_prefixes: list[str]
    auth_header: str
    auth_prefix: str
    credential_env: str
    tls_required: bool
    extra_headers: dict[str, str]

    def effective_base_url(self) -> str:
        if self.provider_id == "azure_openai":
            return os.environ.get("HERMES_AZURE_OPENAI_ENDPOINT", self.base_url)
        return self.base_url


PROVIDER_REGISTRY: dict[str, Provider] = {
    "openai": Provider(
        provider_id="openai",
        base_url="https://api.openai.com",
        allowed_path_prefixes=[
            "/v1/chat/completions",
            "/v1/assistants",
            "/v1/threads",
            "/v1/audio/transcriptions",
            "/v1/embeddings",
        ],
        auth_header="Authorization",
        auth_prefix="Bearer ",
        credential_env="HERMES_OPENAI_API_KEY",
        tls_required=True,
        extra_headers={},
    ),
    "azure_openai": Provider(
        provider_id="azure_openai",
        base_url="",
        allowed_path_prefixes=["/openai/deployments/", "/openai/v1/"],
        auth_header="api-key",
        auth_prefix="",
        credential_env="HERMES_AZURE_OPENAI_KEY",
        tls_required=True,
        extra_headers={},
    ),
    "anthropic": Provider(
        provider_id="anthropic",
        base_url="https://api.anthropic.com",
        allowed_path_prefixes=["/v1/messages", "/v1/messages/batches"],
        auth_header="x-api-key",
        auth_prefix="",
        credential_env="HERMES_ANTHROPIC_API_KEY",
        tls_required=True,
        extra_headers={
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
    ),
}


def resolve_provider(provider_id: str) -> Provider:
    if provider_id not in PROVIDER_REGISTRY:
        raise ValueError(
            f"Unknown provider: {provider_id!r}. Allowed: {list(PROVIDER_REGISTRY)}"
        )
    return PROVIDER_REGISTRY[provider_id]


def validate_path(provider: Provider, path: str) -> bool:
    """True iff `path` is a sub-path of one of the provider's allow-listed
    endpoints, with no `.`/`..` segments. A raw string-prefix check alone is
    not enough: "/v1/chat/completions/..%2F..%2Ffiles" (URL-decoded to
    "/v1/chat/completions/../../files" by the time it reaches this
    function) starts with the allowed prefix as a string, but resolves to
    "/files" — well outside it — once a client or upstream server
    normalizes the path. A legitimate request to these endpoints never
    needs a dot-segment, so reject outright rather than trying to resolve
    and recheck the normalized path."""
    segments = path.split("/")
    if "." in segments or ".." in segments:
        return False
    return any(path.startswith(p) for p in provider.allowed_path_prefixes)
