"""
hermes/drata_state.py — Drata configuration state machine.

Dependency-free so both the Hermes API and the gateway Drata connector can
derive state from the same definition.
"""
import os
from enum import Enum
from typing import Optional

DRATA_CCT_URL_ENV_VAR = "HERMES_DRATA_CCT_URL"
DRATA_API_KEY_ENV_VAR = "HERMES_DRATA_API_KEY"


class DrataConfigState(str, Enum):
    NOT_CONFIGURED = "NOT_CONFIGURED"
    CONFIGURED = "CONFIGURED"
    CONNECTION_TEST_FAILED = "CONNECTION_TEST_FAILED"
    CONNECTION_TEST_SUCCEEDED = "CONNECTION_TEST_SUCCEEDED"


def get_drata_config_state(connection_test_passed: Optional[bool] = None) -> DrataConfigState:
    """
    Derive the Drata configuration state from the environment.

    connection_test_passed must be None unless a connection test actually
    ran. No Drata connection test exists in this repository, so production
    callers always pass None and can never reach a CONNECTION_TEST_* state.
    """
    if not os.environ.get(DRATA_CCT_URL_ENV_VAR):
        return DrataConfigState.NOT_CONFIGURED
    if connection_test_passed is None:
        return DrataConfigState.CONFIGURED
    if connection_test_passed:
        return DrataConfigState.CONNECTION_TEST_SUCCEEDED
    return DrataConfigState.CONNECTION_TEST_FAILED
