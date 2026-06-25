import os
import pytest
from fastapi.testclient import TestClient
from hermes.api import app
os.environ.setdefault("HERMES_API_KEY", "unit-test-key")
@pytest.fixture
def client():
    return TestClient(app)
@pytest.fixture
def auth_headers():
    return {"x-api-key": "unit-test-key"}
