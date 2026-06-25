import os
import pytest
from fastapi.testclient import TestClient
from hermes.api import app
os.environ.setdefault("HERMES_API_KEY", "unit-test-key")
client = TestClient(app)
headers = {"x-api-key": "unit-test-key"}
def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "operational"
def test_scrub_endpoint_ssn():
    response = client.post("/v1/scrub", json={"payload": "SSN: 123-45-6789"}, headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert "[REDACTED_SSN]" in data["clean_text"]
    assert data["audit_log"]["flags_triggered"]["HIPAA_SSN"] >= 1
def test_scrub_endpoint_pan():
    response = client.post("/v1/scrub", json={"payload": "Card: 4111111111111111"}, headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert "[REDACTED_PAN]" in data["clean_text"]
    assert data["audit_log"]["flags_triggered"]["PCI_PAN"] >= 1
def test_scrub_endpoint_unauthorized():
    response = client.post("/v1/scrub", json={"payload": "test"}, headers={"x-api-key": "wrong"})
    assert response.status_code == 401
