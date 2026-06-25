import os
from fastapi.testclient import TestClient
from hermes.api import app

os.environ.setdefault("HERMES_API_KEY", "unit-test-key")

client = TestClient(app)

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "operational"

def test_unauthorized_access_blocked():
    """Ensure payloads are rejected without the correct MSP tenant key."""
    response = client.post("/v1/scrub", json={"payload": "Test"})
    assert response.status_code == 422
    
    response = client.post(
        "/v1/scrub", 
        headers={"X-API-Key": "invalid_key"}, 
        json={"payload": "Test"}
    )
    assert response.status_code == 401

def test_successful_payload_scrub():
    """Verify end-to-end routing through the REST layer."""
    test_payload = "Patient SSN is 123-45-6789. Card 4242424242424242 charged."
    response = client.post(
        "/v1/scrub",
        headers={"X-API-Key": os.environ["HERMES_API_KEY"]},
        json={"payload": test_payload}
    )
    
    assert response.status_code == 200
    data = response.json()
    
    assert "[REDACTED_SSN]" in data["clean_text"]
    assert "[REDACTED_PAN]" in data["clean_text"]
    assert "123-45-6789" not in data["clean_text"]
    
    assert "audit_log" in data
    assert data["audit_log"]["flags_triggered"]["HIPAA_SSN"] == 1
    assert data["audit_log"]["flags_triggered"]["PCI_PAN"] == 1
