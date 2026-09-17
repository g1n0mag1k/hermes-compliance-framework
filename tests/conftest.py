"""Pytest session-wide setup.

Runs before any test module (and therefore before `hermes.attestation` is
first imported), which matters because `hermes/attestation.py` opens
HERMES_DB_PATH — defaulting to "hermes_chain.db" in the working directory —
at *import* time, to build the module-level ATTESTATION_CHAIN singleton.
Without this, running the test suite would create (and progressively grow)
a real SQLite file in the repo's working directory on every run.

Individual tests that exercise persistence directly (test_attestation.py)
pass their own db_path explicitly via pytest's tmp_path fixture and are
unaffected by this default.

The same pattern is applied for HERMES_CANARY_DB_PATH so importing
`hermes.auditor` never writes hermes_canary.db into the working directory.

Workspace registry is also pointed at a temp directory so the multi-tenant
model never writes registry.db into the repo during test runs.
"""
import os
import tempfile

_TEST_DB_DIR = tempfile.mkdtemp(prefix="hermes_test_singleton_db_")
os.environ.setdefault("HERMES_DB_PATH", os.path.join(_TEST_DB_DIR, "singleton_hermes_chain.db"))
os.environ.setdefault(
    "HERMES_CANARY_DB_PATH",
    os.path.join(_TEST_DB_DIR, "singleton_hermes_canary.db"),
)
# Workspace registry isolation — prevents test quota from accumulating in repo
os.environ.setdefault("HERMES_DATA_DIR", os.path.join(_TEST_DB_DIR, "workspaces"))
os.environ.setdefault(
    "HERMES_REGISTRY_DB",
    os.path.join(_TEST_DB_DIR, "workspaces", "registry.db"),
)
