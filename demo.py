import streamlit as st
import uuid
from hermes.classifier import scrub_payload

# -------------------------------------------------------------------------
# MSP DEMO UI: TenHats Proof of Concept
# -------------------------------------------------------------------------
st.set_page_config(page_title="Hermes | Compliance Scrubber", layout="wide")

st.title("Hermes Compliance Framework")
st.markdown("**Enterprise PII/PHI Redaction Layer — Zero-Data-Retention Architecture**")
st.divider()

st.subheader("Simulated MSP Ingress Payload")
sample_text = "Patient SSN is 123-45-6789. Dr. Brian Strong reviewed the file with card 4242424242424242 on October 12th, 2026. The invalid clinical ID 4242424242424243 was bypassed."

user_input = st.text_area("Raw Text Input (Unredacted)", value=sample_text, height=100)

if st.button("Execute Deterministic Redaction", type="primary"):
    txn_id = f"txn_{uuid.uuid4().hex[:8]}"
    result = scrub_payload(transaction_id=txn_id, text=user_input)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.success("Sanitized Egress Payload (Safe for LLM Routing)")
        st.text_area("Cleaned Text", value=result.clean_text, height=200, disabled=True)
        
    with col2:
        st.info("Cryptographic Audit Log (SOC 2 / HIPAA Evidence)")
        st.json(result.audit_log.model_dump())
        
    st.divider()
    
    m1, m2 = st.columns(2)
    m1.metric(label="Total Rule Hits", value=sum(result.audit_log.flags_triggered.values()))
    m2.metric(label="Characters Redacted", value=result.audit_log.original_char_count - result.audit_log.redacted_char_count)
