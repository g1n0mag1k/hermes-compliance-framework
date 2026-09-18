STRIP_PREFIXES = (
    "openai-",
    "x-openai-",
    "anthropic-",
    "x-anthropic-",
    "anthropic-ratelimit-",
    "x-ms-",
    "x-azure-",
    "azureml-",
    "x-ratelimit-",
    "cf-",
    "x-envoy-",
    "access-control-",
)

STRIP_EXACT = frozenset({
    "apim-request-id",
    "request-id",
    "x-request-id",
    "x-should-retry",
    "server",
    "via",
    "set-cookie",
    "alt-svc",
    "report-to",
    "nel",
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "www-authenticate",
    "content-length",
})


def filter_response_headers(headers: dict[str, str], gateway_request_id: str) -> dict[str, str]:
    """Strip provider-identifying headers and add gateway request id."""
    filtered: dict[str, str] = {}
    for key, value in headers.items():
        lower = key.lower()
        if lower in STRIP_EXACT:
            continue
        if any(lower.startswith(prefix) for prefix in STRIP_PREFIXES):
            continue
        filtered[key] = value
    filtered["x-gateway-request-id"] = gateway_request_id
    return filtered
