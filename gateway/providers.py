from dataclasses import dataclass
import os


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
    return any(path.startswith(p) for p in provider.allowed_path_prefixes)
