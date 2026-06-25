import os
import uuid
from fastapi import FastAPI, Header, HTTPException, Depends
from pydantic import BaseModel
from hermes.classifier import scrub_payload, ScrubberResult

# -------------------------------------------------------------------------
# API APPLICATION & CONFIGURATION
# -------------------------------------------------------------------------
app = FastAPI(
    title="Hermes Compliance API",
    description="Zero-Data-Retention PHI/PII Redaction Layer for MSPs",
    version="1.0.0"
)

# -------------------------------------------------------------------------
# SCHEMAS & AUTHENTICATION
# -------------------------------------------------------------------------
# The expected tenant API key is sourced from the environment so that no
# credential is committed to source control (set HERMES_API_KEY at deploy).
API_KEY_ENV_VAR = "HERMES_API_KEY"

class ScrubRequest(BaseModel):
    payload: str

def verify_api_key(x_api_key: str = Header(...)):
    """Simulates multi-tenant RMM authentication for the TenHats pilot."""
    expected_key = os.environ.get(API_KEY_ENV_VAR)
    if not expected_key or x_api_key != expected_key:
        raise HTTPException(status_code=401, detail="Unauthorized: Invalid or missing API Key")
    return x_api_key

# -------------------------------------------------------------------------
# ENDPOINTS
# -------------------------------------------------------------------------
@app.get("/health", tags=["System"])
def health_check():
    """Load balancer ping endpoint."""
    return {"status": "operational", "compliance_mode": "enforced", "version": "1.0.0"}

@app.post(
    "/v1/scrub",
    response_model=ScrubberResult,
    tags=["Pipeline"],
    dependencies=[Depends(verify_api_key)],
)
def scrub_endpoint(request: ScrubRequest):
    """
    Synchronous endpoint execution. FastAPI delegates this to a 
    background threadpool to cleanly respect our _PIPELINE_LOCK.
    """
    txn_id = f"txn_api_{uuid.uuid4().hex[:12]}"
    result = scrub_payload(transaction_id=txn_id, text=request.payload)
    return result
