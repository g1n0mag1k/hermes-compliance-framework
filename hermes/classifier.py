import re
import spacy
import threading
from pydantic import BaseModel, Field
from typing import Dict, List, Optional, Set, Tuple
from presidio_analyzer import AnalyzerEngine

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
# 45 CFR §164.514(b)(2)(i) Safe Harbor identifier citations
# -------------------------------------------------------------------------
CFR_CITATION_MAP = {
    "HIPAA_PHI_PERSON": "45 CFR §164.514(b)(2)(i)(A)",
    "HIPAA_PHI_DATE": "45 CFR §164.514(b)(2)(i)(C)",
    "HIPAA_PHI_PHONE": "45 CFR §164.514(b)(2)(i)(D)",
    "HIPAA_PHI_EMAIL": "45 CFR §164.514(b)(2)(i)(F)",
    "HIPAA_SSN": "45 CFR §164.514(b)(2)(i)(G)",
    "HIPAA_PHI_URL": "45 CFR §164.514(b)(2)(i)(N)",
    "HIPAA_PHI_IP": "45 CFR §164.514(b)(2)(i)(O)",
    "HIPAA_PHI_ADDRESS": "45 CFR §164.514(b)(2)(i)(B)",
    "PCI_PAN": "PCI-DSS (not a HIPAA Safe Harbor identifier)",
}

# -------------------------------------------------------------------------
# DETERMINISTIC REGEX PATTERNS
# -------------------------------------------------------------------------
REGEX_SSN = re.compile(r'\b(?!(?:000|666|9\d{2}))([0-8]\d{2})-(?!00)(\d{2})-(?!0000)(\d{4})\b')
REGEX_PAN = re.compile(r'\b(?:\d[ -]*?){13,19}\b')

# -------------------------------------------------------------------------
# PRESIDIO ENTITY MAPPING
# -------------------------------------------------------------------------
PRESIDIO_ENTITY_TYPES = [
    "PHONE_NUMBER",
    "EMAIL_ADDRESS",
    "URL",
    "IP_ADDRESS",
    "US_BANK_NUMBER",
    "LOCATION",
]

PRESIDIO_FLAG_MAP = {
    "PHONE_NUMBER": ("HIPAA_PHI_PHONE", "PHONE"),
    "EMAIL_ADDRESS": ("HIPAA_PHI_EMAIL", "EMAIL"),
    "URL": ("HIPAA_PHI_URL", "URL"),
    "IP_ADDRESS": ("HIPAA_PHI_IP", "IP"),
    "US_BANK_NUMBER": ("HIPAA_PHI_BANK_NUMBER", "BANK_NUMBER"),
    "LOCATION": ("HIPAA_PHI_ADDRESS", "ADDRESS"),
}

SPACY_FLAG_MAP = {
    "PERSON": ("HIPAA_PHI_PERSON", "PERSON"),
    "DATE": ("HIPAA_PHI_DATE", "DATE"),
    "ORG": ("HIPAA_PHI_ORG", "ORG"),
}

# -------------------------------------------------------------------------
# AUDIT SCHEMAS
# -------------------------------------------------------------------------
class FlagEntry(BaseModel):
    count: int
    cfr_citation: Optional[str] = None


class RedactionAuditLog(BaseModel):
    transaction_id: str = Field(..., description="Unique thread-safe transaction ID")
    original_char_count: int
    redacted_char_count: int
    flags_triggered: Dict[str, FlagEntry] = Field(
        default_factory=dict,
        description="Per-flag detection counts with regulatory citations",
    )


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
# PRESIDIO DETECTION
# -------------------------------------------------------------------------
_presidio_analyzer: Optional[AnalyzerEngine] = None
_PIPELINE_LOCK = threading.Lock()


def _get_presidio_analyzer() -> AnalyzerEngine:
    global _presidio_analyzer
    if _presidio_analyzer is None:
        _presidio_analyzer = AnalyzerEngine()
    return _presidio_analyzer


def detect_with_presidio(text: str) -> List[Dict]:
    """Run Presidio AnalyzerEngine and return detected entities for configured categories."""
    with _PIPELINE_LOCK:
        analyzer = _get_presidio_analyzer()
        results = analyzer.analyze(
            text=text,
            language="en",
            entities=PRESIDIO_ENTITY_TYPES,
        )

    entities: List[Dict] = []
    for result in results:
        mapping = PRESIDIO_FLAG_MAP.get(result.entity_type)
        if mapping is None:
            continue
        flag_name, placeholder = mapping
        span_text = text[result.start:result.end]
        if "REDACTED" in span_text:
            continue
        entities.append(
            {
                "start": result.start,
                "end": result.end,
                "entity_type": result.entity_type,
                "flag": flag_name,
                "placeholder": placeholder,
                "text": span_text,
            }
        )
    return entities


# -------------------------------------------------------------------------
# SPAN OVERLAP RESOLUTION
# -------------------------------------------------------------------------
def _increment_flag(flags: Dict[str, FlagEntry], flag_name: str) -> None:
    if flag_name in flags:
        flags[flag_name].count += 1
    else:
        flags[flag_name] = FlagEntry(
            count=1,
            cfr_citation=CFR_CITATION_MAP.get(flag_name),
        )


PLACEHOLDER_PRIORITY = {
    "PHONE": 90,
    "EMAIL": 90,
    "URL": 90,
    "IP": 90,
    "ADDRESS": 85,
    "BANK_NUMBER": 85,
    "PERSON": 80,
    "DATE": 80,
    "ORG": 70,
}


def _preferred_placeholder(current: str, candidate: str) -> str:
    if PLACEHOLDER_PRIORITY.get(candidate, 0) > PLACEHOLDER_PRIORITY.get(current, 0):
        return candidate
    return current


def _spans_overlap(start_a: int, end_a: int, start_b: int, end_b: int) -> bool:
    return start_a < end_b and start_b < end_a


def _span_fully_contains(
    outer_start: int,
    outer_end: int,
    inner_start: int,
    inner_end: int,
) -> bool:
    return outer_start <= inner_start and inner_end <= outer_end


def _merge_flag_sets(
    prev_start: int,
    prev_end: int,
    prev_flags: Set[str],
    start: int,
    end: int,
    flag_names: Set[str],
) -> Set[str]:
    """Union overlapping span flags, suppressing URL hits inside email spans."""
    merged_flags = prev_flags | flag_names
    if "HIPAA_PHI_EMAIL" not in merged_flags or "HIPAA_PHI_URL" not in merged_flags:
        return merged_flags

    if (
        "HIPAA_PHI_EMAIL" in prev_flags
        and "HIPAA_PHI_URL" in flag_names
        and _span_fully_contains(prev_start, prev_end, start, end)
    ):
        merged_flags.discard("HIPAA_PHI_URL")
    elif (
        "HIPAA_PHI_EMAIL" in flag_names
        and "HIPAA_PHI_URL" in prev_flags
        and _span_fully_contains(start, end, prev_start, prev_end)
    ):
        merged_flags.discard("HIPAA_PHI_URL")

    return merged_flags


def _merge_overlapping_spans(
    spans: List[Tuple[int, int, Set[str], str]],
) -> List[Tuple[int, int, Set[str], str]]:
    """Merge overlapping character spans so each region is redacted exactly once."""
    if not spans:
        return []

    sorted_spans = sorted(spans, key=lambda item: (item[0], -(item[1] - item[0])))
    merged: List[Tuple[int, int, Set[str], str]] = []

    for start, end, flag_names, placeholder in sorted_spans:
        if merged and _spans_overlap(merged[-1][0], merged[-1][1], start, end):
            prev_start, prev_end, prev_flags, prev_placeholder = merged[-1]
            merged[-1] = (
                min(prev_start, start),
                max(prev_end, end),
                _merge_flag_sets(prev_start, prev_end, prev_flags, start, end, flag_names),
                _preferred_placeholder(prev_placeholder, placeholder),
            )
        else:
            merged.append((start, end, set(flag_names), placeholder))

    return merged


def _collect_spacy_spans(text: str) -> List[Tuple[int, int, Set[str], str]]:
    with _PIPELINE_LOCK:
        doc = nlp(text)

    spans: List[Tuple[int, int, Set[str], str]] = []
    for ent in doc.ents:
        mapping = SPACY_FLAG_MAP.get(ent.label_)
        if mapping is None or "REDACTED" in ent.text:
            continue
        flag_name, placeholder = mapping
        spans.append((ent.start_char, ent.end_char, {flag_name}, placeholder))
    return spans


def _collect_presidio_spans(text: str) -> List[Tuple[int, int, Set[str], str]]:
    spans: List[Tuple[int, int, Set[str], str]] = []
    for entity in detect_with_presidio(text):
        spans.append(
            (
                entity["start"],
                entity["end"],
                {entity["flag"]},
                entity["placeholder"],
            )
        )
    return spans


def _apply_span_redactions(
    text: str,
    spans: List[Tuple[int, int, Set[str], str]],
    flags: Dict[str, FlagEntry],
) -> str:
    merged_spans = _merge_overlapping_spans(spans)
    merged_spans.sort(key=lambda item: item[0], reverse=True)

    clean_text = text
    for start, end, flag_names, placeholder in merged_spans:
        for flag_name in flag_names:
            _increment_flag(flags, flag_name)
        clean_text = clean_text[:start] + f"[REDACTED_{placeholder}]" + clean_text[end:]

    return clean_text


# -------------------------------------------------------------------------
# GLOBAL THREAD LOCK & ORCHESTRATOR
# -------------------------------------------------------------------------
def scrub_payload(transaction_id: str, text: str) -> ScrubberResult:
    original_char_count = len(text)
    flags: Dict[str, FlagEntry] = {}
    clean_text = text

    # 1. REGEX PASSES
    def ssn_replacer(_match):
        _increment_flag(flags, "HIPAA_SSN")
        return "[REDACTED_SSN]"

    clean_text = REGEX_SSN.sub(ssn_replacer, clean_text)

    def pan_replacer(match):
        candidate = match.group(0)
        clean_candidate = "".join(c for c in candidate if c.isdigit())
        if validate_luhn_checksum(clean_candidate):
            _increment_flag(flags, "PCI_PAN")
            return "[REDACTED_PAN]"
        return candidate

    clean_text = REGEX_PAN.sub(pan_replacer, clean_text)

    # 2. NER + PRESIDIO PASSES (merged span redaction — no duplicate overlaps)
    entity_spans = _collect_spacy_spans(clean_text)
    entity_spans.extend(_collect_presidio_spans(clean_text))
    clean_text = _apply_span_redactions(clean_text, entity_spans, flags)

    # 3. AUDIT PAYLOAD
    audit_log = RedactionAuditLog(
        transaction_id=transaction_id,
        original_char_count=original_char_count,
        redacted_char_count=len(clean_text),
        flags_triggered=flags,
    )

    return ScrubberResult(clean_text=clean_text, audit_log=audit_log)
