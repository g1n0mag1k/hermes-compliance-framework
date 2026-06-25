import re
import spacy
import threading
from pydantic import BaseModel, Field
from typing import Dict, List

# -------------------------------------------------------------------------
# COMPLIANCE INVARIANT: Model must be local. No external API calls permitted.
# -------------------------------------------------------------------------
try:
    nlp = spacy.load("en_core_web_sm")
except OSError:
    raise RuntimeError(
        "CRITICAL AUDIT FAILURE: Local spaCy model 'en_core_web_sm' missing. "
        "Run: python -m spacy download en_core_web_sm"
    )

# -------------------------------------------------------------------------
# DETERMINISTIC REGEX PATTERNS
# -------------------------------------------------------------------------
REGEX_SSN = re.compile(r'\b(?!(?:000|666|9\d{2}))([0-8]\d{2})-(?!00)(\d{2})-(?!0000)(\d{4})\b')
REGEX_PAN = re.compile(r'\b(?:\d[ -]*?){13,19}\b')

# -------------------------------------------------------------------------
# AUDIT SCHEMAS
# -------------------------------------------------------------------------
class RedactionAuditLog(BaseModel):
    transaction_id: str = Field(..., description="Unique thread-safe transaction ID")
    original_char_count: int
    redacted_char_count: int
    flags_triggered: Dict[str, int] = Field(default_factory=dict, description="Count of rule hits")
    
class ScrubberResult(BaseModel):
    clean_text: str
    audit_log: RedactionAuditLog

# -------------------------------------------------------------------------
# DETERMINISTIC VALIDATORS
# -------------------------------------------------------------------------
def validate_luhn_checksum(pan_candidate: str) -> bool:
    digits = [int(c) for c in pan_candidate if c.isdigit()]
    if not digits or not (13 <= len(digits) <= 19):
        return False
    
    checksum = 0
    reverse_digits = digits[::-1]
    
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
        
    return checksum % 10 == 0

# -------------------------------------------------------------------------
# GLOBAL THREAD LOCK & ORCHESTRATOR
# -------------------------------------------------------------------------
_PIPELINE_LOCK = threading.Lock()

def scrub_payload(transaction_id: str, text: str) -> ScrubberResult:
    original_char_count = len(text)
    flags: Dict[str, int] = {}
    clean_text = text

    # 1. REGEX PASSES
    def ssn_replacer(_match):
        flags['HIPAA_SSN'] = flags.get('HIPAA_SSN', 0) + 1
        return "[REDACTED_SSN]"
    
    clean_text = REGEX_SSN.sub(ssn_replacer, clean_text)

    def pan_replacer(match):
        candidate = match.group(0)
        clean_candidate = "".join(c for c in candidate if c.isdigit())
        if validate_luhn_checksum(clean_candidate):
            flags['PCI_PAN'] = flags.get('PCI_PAN', 0) + 1
            return "[REDACTED_PAN]"
        return candidate

    clean_text = REGEX_PAN.sub(pan_replacer, clean_text)
    
    # 2. NER PASS (Thread-Locked)
    with _PIPELINE_LOCK:
        doc = nlp(clean_text)
        
    spans_to_redact = []
    for ent in doc.ents:
        # Prevent NER from re-classifying previously injected redaction tags
        if ent.label_ in {"PERSON", "DATE", "ORG"} and "REDACTED" not in ent.text:
            spans_to_redact.append((ent.start_char, ent.end_char, ent.label_))
    
    spans_to_redact.sort(key=lambda x: x[0], reverse=True)
    for start, end, label in spans_to_redact:
        clean_text = clean_text[:start] + f"[REDACTED_{label}]" + clean_text[end:]
        flags[f'HIPAA_PHI_{label}'] = flags.get(f'HIPAA_PHI_{label}', 0) + 1

    # 3. AUDIT PAYLOAD
    audit_log = RedactionAuditLog(
        transaction_id=transaction_id,
        original_char_count=original_char_count,
        redacted_char_count=len(clean_text),
        flags_triggered=flags
    )

    return ScrubberResult(clean_text=clean_text, audit_log=audit_log)
