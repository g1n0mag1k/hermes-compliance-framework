"""
hermes/drata_state.py — Drata configuration state machine.

Dependency-free so both the Hermes API and the gateway Drata connector can
derive state from the same definition.
"""
import os
from enum import Enum
from typing import Optional, Tuple
from urllib.parse import urlsplit

DRATA_CCT_URL_ENV_VAR = "HERMES_DRATA_CCT_URL"
DRATA_API_KEY_ENV_VAR = "HERMES_DRATA_API_KEY"


class DrataConfigState(str, Enum):
    NOT_CONFIGURED = "NOT_CONFIGURED"
    CONFIGURED = "CONFIGURED"
    CONFIG_INVALID = "CONFIG_INVALID"
    CONNECTION_TEST_FAILED = "CONNECTION_TEST_FAILED"
    CONNECTION_TEST_SUCCEEDED = "CONNECTION_TEST_SUCCEEDED"


class DrataConnectionState(str, Enum):
    """Result states for DrataConnector.test_connection()."""

    NOT_CONFIGURED = "NOT_CONFIGURED"
    CONFIGURED = "CONFIGURED"
    CONFIG_INVALID = "CONFIG_INVALID"
    # Reserved for a future live check. No verified read-only Drata endpoint
    # exists, so nothing in this repository returns these two states.
    CONNECTION_SUCCESS = "CONNECTION_SUCCESS"
    CONNECTION_FAILED = "CONNECTION_FAILED"
    UNSUPPORTED = "UNSUPPORTED"


# Reason strings are shown in API responses and the dashboard. They name env
# vars only and must never include the configured URL or API key.
NOT_CONFIGURED_REASON = f"{DRATA_CCT_URL_ENV_VAR} is not set."
URL_MALFORMED_REASON = (
    f"{DRATA_CCT_URL_ENV_VAR} is set but is not a well-formed absolute URL."
)
URL_NOT_HTTPS_REASON = (
    f"{DRATA_CCT_URL_ENV_VAR} is set but does not use https://. Drata "
    "credentials and evidence are never sent over an insecure transport."
)
API_KEY_MISSING_REASON = (
    f"{DRATA_CCT_URL_ENV_VAR} is set but {DRATA_API_KEY_ENV_VAR} is not set."
)
CONFIGURED_REASON = (
    f"Structural check passed: {DRATA_CCT_URL_ENV_VAR} uses https and "
    f"{DRATA_API_KEY_ENV_VAR} is present. No network call was made; this does "
    "NOT prove Drata accepts these credentials or this URL."
)


def is_https_url(url: str) -> bool:
    try:
        return urlsplit(url).scheme == "https"
    except ValueError:
        return False


def _is_well_formed_url(url: str) -> bool:
    # Validates the exact value the connector will POST to, so surrounding
    # whitespace counts as malformed rather than being silently stripped.
    if any(ch.isspace() for ch in url):
        return False
    try:
        parts = urlsplit(url)
        parts.port  # raises ValueError on a non-numeric or out-of-range port
    except ValueError:
        return False
    return bool(parts.scheme) and bool(parts.hostname)


def check_drata_config() -> Tuple[DrataConnectionState, str]:
    """
    Structural, offline check of the Drata CCT configuration.

    Returns NOT_CONFIGURED, CONFIG_INVALID, or CONFIGURED with a reason safe to
    display. Makes no network call and never reads credentials into the reason.
    """
    url = os.environ.get(DRATA_CCT_URL_ENV_VAR)
    if not url:
        return DrataConnectionState.NOT_CONFIGURED, NOT_CONFIGURED_REASON
    if not _is_well_formed_url(url):
        return DrataConnectionState.CONFIG_INVALID, URL_MALFORMED_REASON
    if not is_https_url(url):
        return DrataConnectionState.CONFIG_INVALID, URL_NOT_HTTPS_REASON
    if not os.environ.get(DRATA_API_KEY_ENV_VAR):
        return DrataConnectionState.CONFIG_INVALID, API_KEY_MISSING_REASON
    return DrataConnectionState.CONFIGURED, CONFIGURED_REASON


def get_drata_config_state(connection_test_passed: Optional[bool] = None) -> DrataConfigState:
    """
    Derive the Drata configuration state from the environment.

    connection_test_passed must be None unless a connection test actually
    ran. No Drata connection test exists in this repository, so production
    callers always pass None and can never reach a CONNECTION_TEST_* state.
    """
    structural_state, _ = check_drata_config()
    if structural_state is DrataConnectionState.NOT_CONFIGURED:
        return DrataConfigState.NOT_CONFIGURED
    if structural_state is DrataConnectionState.CONFIG_INVALID:
        return DrataConfigState.CONFIG_INVALID
    if connection_test_passed is None:
        return DrataConfigState.CONFIGURED
    if connection_test_passed:
        return DrataConfigState.CONNECTION_TEST_SUCCEEDED
    return DrataConfigState.CONNECTION_TEST_FAILED
