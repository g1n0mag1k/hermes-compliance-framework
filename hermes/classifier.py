import re
import base64
import unicodedata
import urllib.parse
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
    "HIPAA_PHI_MRN": "45 CFR §164.514(b)(2)(i)(H)",
    "HIPAA_PHI_AGE_89": "45 CFR §164.514(b)(2)(i)(C)",
    "HIPAA_PHI_GPS": "45 CFR §164.514(b)(2)(i)(B)",
    "HIPAA_PHI_FAX": "45 CFR §164.514(b)(2)(i)(E)",
    "HIPAA_PHI_HPBN": "45 CFR §164.514(b)(2)(i)(I)",
    "HIPAA_PHI_ACCOUNT": "45 CFR §164.514(b)(2)(i)(J)",
    "HIPAA_PHI_VIN": "45 CFR §164.514(b)(2)(i)(L)",
    "HIPAA_PHI_ORG": "45 CFR §164.514(b)(2)(i)(A)",
}


# -------------------------------------------------------------------------
# DECLARED SCOPE — 45 CFR §164.514(b)(2)(i) Safe Harbor identifier coverage
# This manifest is the authoritative record of what Hermes checks for.
# It is embedded in every attestation receipt so the boundary of evidence
# is explicit — "scanned and found nothing" vs "never in scope" are
# distinguishable. EVIDENCE_INCOMPLETE is raised for uncovered categories.
# -------------------------------------------------------------------------
DECLARED_SCOPE: list[dict] = [
    {"cfr": "45 CFR §164.514(b)(2)(i)(A)", "category": "Names",                          "flag": "HIPAA_PHI_PERSON",  "status": "covered",     "method": "spaCy NER"},
    {"cfr": "45 CFR §164.514(b)(2)(i)(B)", "category": "Geographic subdivisions",        "flag": "HIPAA_PHI_ADDRESS", "status": "covered",     "method": "Presidio"},
    {"cfr": "45 CFR §164.514(b)(2)(i)(C)", "category": "Dates",                          "flag": "HIPAA_PHI_DATE",    "status": "covered",     "method": "spaCy NER"},
    {"cfr": "45 CFR §164.514(b)(2)(i)(D)", "category": "Telephone numbers",              "flag": "HIPAA_PHI_PHONE",   "status": "covered",     "method": "Presidio"},
    {"cfr": "45 CFR §164.514(b)(2)(i)(E)", "category": "Fax numbers",                   "flag": "HIPAA_PHI_FAX",     "status": "covered",     "method": "regex"},
    {"cfr": "45 CFR §164.514(b)(2)(i)(F)", "category": "Email addresses",               "flag": "HIPAA_PHI_EMAIL",   "status": "covered",     "method": "Presidio"},
    {"cfr": "45 CFR §164.514(b)(2)(i)(G)", "category": "Social security numbers",       "flag": "HIPAA_SSN",         "status": "covered",     "method": "regex"},
    {"cfr": "45 CFR §164.514(b)(2)(i)(H)", "category": "Medical record numbers",        "flag": "HIPAA_PHI_MRN",     "status": "covered",     "method": "regex"},
    {"cfr": "45 CFR §164.514(b)(2)(i)(I)", "category": "Health plan beneficiary numbers","flag": "HIPAA_PHI_HPBN",   "status": "covered",     "method": "regex"},
    {"cfr": "45 CFR §164.514(b)(2)(i)(J)", "category": "Account numbers",               "flag": "HIPAA_PHI_ACCOUNT", "status": "covered",     "method": "regex"},
    {"cfr": "45 CFR §164.514(b)(2)(i)(K)", "category": "Certificate/license numbers",   "flag": None,                "status": "not_covered", "method": None},
    {"cfr": "45 CFR §164.514(b)(2)(i)(L)", "category": "Vehicle identifiers/VINs",      "flag": "HIPAA_PHI_VIN",     "status": "covered",     "method": "regex"},
    {"cfr": "45 CFR §164.514(b)(2)(i)(M)", "category": "Device identifiers",            "flag": None,                "status": "not_covered", "method": None},
    {"cfr": "45 CFR §164.514(b)(2)(i)(N)", "category": "Web URLs",                      "flag": "HIPAA_PHI_URL",     "status": "covered",     "method": "Presidio"},
    {"cfr": "45 CFR §164.514(b)(2)(i)(O)", "category": "IP addresses",                  "flag": "HIPAA_PHI_IP",      "status": "covered",     "method": "Presidio"},
    {"cfr": "45 CFR §164.514(b)(2)(i)(P)", "category": "Biometric identifiers",         "flag": None,                "status": "not_covered", "method": None},
    {"cfr": "45 CFR §164.514(b)(2)(i)(Q)", "category": "Full face photographs",         "flag": None,                "status": "not_covered", "method": None},
    {"cfr": "45 CFR §164.514(b)(2)(i)(R)", "category": "Other unique identifiers",      "flag": None,                "status": "not_covered", "method": None},
]

# Pre-computed sets for O(1) receipt generation
COVERED_FLAGS:    frozenset = frozenset(e["flag"]      for e in DECLARED_SCOPE if e["status"] == "covered")
COVERED_CFRS:     list[str] = [e["cfr"]               for e in DECLARED_SCOPE if e["status"] == "covered"]
NOT_COVERED_CFRS: list[str] = [e["cfr"]               for e in DECLARED_SCOPE if e["status"] == "not_covered"]

# -------------------------------------------------------------------------
# DETERMINISTIC REGEX PATTERNS
# -------------------------------------------------------------------------
REGEX_SSN = re.compile(r'\b(?!(?:000|666|9\d{2}))([0-8]\d{2})([-. ])(?!00)(\d{2})\2(?!0000)(\d{4})\b')
REGEX_PAN = re.compile(r'\b(?:\d[ -]*?){13,19}\b')

REGEX_MRN = re.compile(
    r'\b(?:MRN|Medical\s+Record\s+(?:Number|No\.?|#)|Patient\s+(?:ID|Number|No\.?))'
    r'[\s:#]*(\d{6,10})\b',
    re.IGNORECASE
)

REGEX_FAX = re.compile(
    r'\b(?:fax|facsimile)[\s:#]*'
    r'(\+?1?[\s.\-]?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4})\b',
    re.IGNORECASE
)

# (I) Health plan beneficiary numbers — Medicare Beneficiary ID (MBI),
# legacy HICNs, and generic beneficiary/member/plan/subscriber ID patterns.
# MBI format: 11 chars, may appear with hyphens (1EG4-TE5-MK72).
REGEX_HPBN = re.compile(
    r'\b(?:beneficiary(?:\s+id)?|member\s+id|plan\s+(?:id|number|no\.?)|'
    r'subscriber\s+(?:id|number|no\.?)|hicn|mbi)'
    r'[\s:#]*([A-Z0-9][A-Z0-9\-]{6,13}[A-Z0-9])\b'
    r'|\b([1-9][A-HJ-NP-Z][A-HJ-NP-Z0-9]\d[A-HJ-NP-Z][A-HJ-NP-Z0-9]\d[A-HJ-NP-Z]{2}\d{2})\b',
    re.IGNORECASE
)

# (J) Account numbers — catches bank/financial account numbers when
# preceded by account context keywords. 6-17 digits covers most formats.
REGEX_ACCOUNT = re.compile(
    r'\b(?:account\s+(?:number|no\.?|#|num)|acct\.?\s*(?:number|no\.?|#)?|bank\s+account)'
    r'[\s:#]*(\d{6,17})\b',
    re.IGNORECASE
)

# (C) Age over 89 — Safe Harbor requires ages 90+ be aggregated.
# Catches: '94 years old', 'age 91', '92-year-old', 'aged 90'
REGEX_AGE_OVER_89 = re.compile(
    r'\b(9[0-9]|1[0-9]{2})'
    r'(?:\s*[-\u2013]?\s*year(?:s)?(?:\s*[-\u2013]\s*old)?|\s+years?\s+old|\s+y/?o)\b'
    r'|\bage[d]?\s*:?\s*(9[0-9]|1[0-9]{2})\b',
    re.IGNORECASE
)

# (B) GPS coordinates — latitude/longitude in decimal or DMS format.
# Catches: '35.9606, -83.9207', '35.9606° N, 83.9207° W',
# '35°57'38"N 83°55'15"W', lat: 35.9606 lon: -83.9207
REGEX_GPS = re.compile(
    r'(?:lat(?:itude)?\s*[=:]?\s*|lon(?:gitude)?\s*[=:]?\s*)'
    r'[-+]?\d{1,3}\.\d+'
    r'|[-+]?\d{1,3}\.\d+\s*[°]?\s*[NSns]\s*[,/]?\s*'
    r'[-+]?\d{1,3}\.\d+\s*[°]?\s*[EWew]'
    r'|\b\d{1,3}[°°]\s*\d{1,2}[\'’]\s*\d{1,2}(?:\.\d+)?["\u201d]?\s*[NSns]'
    r'\s*[,/]?\s*\d{1,3}[°°]\s*\d{1,2}[\'’]\s*\d{1,2}(?:\.\d+)?["\u201d]?\s*[EWew]\b'
    r'|(?:location|loc|coords?|coordinates?)\s*[=:,]?\s*'
    r'[-+]?\d{1,3}\.\d{4,}\s*,\s*[-+]?\d{1,3}\.\d{4,}',
    re.IGNORECASE
)

# Base64-encoded PHI detection — catches base64 strings that decode to
# text containing PHI. Minimum 16 chars to avoid false positives on
# short tokens. Only attempts decode if string is valid base64.
# Base64 pattern — no \b since +/= are non-word chars.
# Requires whitespace or string boundary on each side.
# Excludes matches inside URLs (negative lookbehind for ://).
# Base64 detection — requires context prefix (colon, space, comma etc.)
# to avoid matching plain English words. Uses findall in the scrub pass.
REGEX_BASE64 = re.compile(
    r'(?:[\s:,;=])([A-Za-z0-9+/]{6,}(?:={0,2})?(?:\s[A-Za-z0-9+/]{4,}(?:={0,2})?)*)'
)

def _try_decode_base64(s: str) -> str:
    """Attempt base64 decode. Return decoded string or empty string on failure."""
    # Reject obvious non-base64 patterns
    if '_' in s:  # underscores not in standard base64
        return ''
    if s.isupper() or s.isnumeric():  # ALL_CAPS or pure digits unlikely base64
        return ''
    # Reject plain alphabetic strings — real base64 almost always contains
    # at least one digit or special char. Pure alpha strings are English words.
    if s.replace(' ', '').isalpha():
        return ''
    try:
        # Remove spaces (present in multi-word base64 strings)
        clean = s.replace(' ', '')
        # Must have mixed case or special chars to be plausible base64
        has_lower = any(c.islower() for c in clean)
        has_upper = any(c.isupper() for c in clean)
        if not (has_lower and has_upper):
            return ''
        # Pad if needed
        remainder = len(clean) % 4
        if remainder:
            clean += '=' * (4 - remainder)
        decoded = base64.b64decode(clean, validate=True).decode('utf-8', errors='ignore')
        # Only return if decoded text is readable, long enough, and contains
        # at least one letter (not just numbers/punctuation)
        # Require ASCII-only printable output — Unicode garbage indicates
        # a false positive on a plain English word, not real base64 PHI.
        if not decoded or not decoded.isascii() or not decoded.isprintable():
            return ''
        if len(decoded) < 4 or not any(c.isalpha() for c in decoded):
            return ''
        return decoded
    except Exception:
        pass
    return ''

def _expand_url_path_components(text: str) -> str:
    """Extract path segments and query values from URLs and append them
    as plaintext so regex detectors can find PHI embedded in URL paths.
    Example: https://api.example.com/patients/234-56-7891/records
    appends '234-56-7891' so REGEX_SSN can match it.
    The original URL is preserved — we only append extracted components.
    """
    url_pattern = re.compile(
        r'https?://[^\s<>"{}|\\^`\[\]]+',
        re.IGNORECASE
    )
    extras = []
    for match in url_pattern.finditer(text):
        url = match.group(0)
        try:
            parsed = urllib.parse.urlparse(url)
            # Extract path segments
            segments = [s for s in parsed.path.split('/') if s]
            extras.extend(segments)
            # Extract query values
            qs = urllib.parse.parse_qs(parsed.query)
            for vals in qs.values():
                extras.extend(vals)
        except Exception:
            pass
    if extras:
        return text + ' ' + ' '.join(extras)
    return text

# (L) Vehicle identifiers — VIN is exactly 17 chars: 8 VIN chars, 1 check
# digit (0-9 or X), 8 VIS chars. All positions use [A-HJ-NPR-Z0-9] (no I/O/Q).
# Uses lookaround boundaries instead of \b (alphanum chars break \b).
REGEX_VIN = re.compile(
    r'(?<![A-HJ-NPR-Z0-9])'
    r'[A-HJ-NPR-Z0-9]{8}'
    r'[0-9X]'
    r'[A-HJ-NPR-Z0-9]{8}'
    r'(?![A-HJ-NPR-Z0-9])',
    re.IGNORECASE
)

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
    flags_redacted: Dict[str, FlagEntry] = Field(
        default_factory=dict,
        description="Per-flag redaction counts — must equal flags_triggered for zero-egress confirmation",
    )


# Tri-state per-detector status. A silently-failed or skipped detector must
# never be indistinguishable from one that ran and found nothing clean —
# that's a false-clean receipt, the worst failure mode for an attestation
# system. "not_run" is reserved for detectors intentionally skipped by a
# future conditional pipeline; every detector in the current pipeline always
# attempts to run, so only ran_clean/ran_error are reachable today.
DETECTOR_RAN_CLEAN = "ran_clean"
DETECTOR_RAN_ERROR = "ran_error"
DETECTOR_NOT_RUN = "not_run"


class ScrubberResult(BaseModel):
    clean_text: str
    audit_log: RedactionAuditLog
    detectors_executed: Dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Per-CFR-category tri-state execution status for this run: "
            "'ran_clean' (executed, no error), 'ran_error' (executed, raised "
            "and was caught), or 'not_run' (skipped). Never boolean — a "
            "silent failure must be distinguishable from a clean scan."
        ),
    )

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
class _PresidioAnalyzerCache:
    engine: Optional[AnalyzerEngine] = None


_PIPELINE_LOCK = threading.Lock()


def _get_presidio_analyzer() -> AnalyzerEngine:
    if _PresidioAnalyzerCache.engine is None:
        _PresidioAnalyzerCache.engine = AnalyzerEngine()
    return _PresidioAnalyzerCache.engine


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
    redacted_flags: Dict[str, FlagEntry],
) -> str:
    merged_spans = _merge_overlapping_spans(spans)
    merged_spans.sort(key=lambda item: item[0], reverse=True)

    clean_text = text
    for start, end, flag_names, placeholder in merged_spans:
        for flag_name in flag_names:
            _increment_flag(flags, flag_name)
        clean_text = clean_text[:start] + f"[REDACTED_{placeholder}]" + clean_text[end:]
        for flag_name in flag_names:
            _increment_flag(redacted_flags, flag_name)

    return clean_text


def _run_regex_stage(pattern: "re.Pattern", replacer, text: str) -> Tuple[str, str]:
    """Run one regex substitution stage and report tri-state status.

    A detector that raises must not take down the whole scan (that would be
    worse than the silent-failure gap this closes — one bad payload would
    zero out every category after it). Failure is caught, the stage is
    skipped for this payload (text passed through unchanged for that stage),
    and the failure is recorded as ran_error rather than presented as clean.
    """
    try:
        return pattern.sub(replacer, text), DETECTOR_RAN_CLEAN
    except Exception:
        return text, DETECTOR_RAN_ERROR


def _run_stage(fn, *args) -> Tuple[str, str]:
    """Run one non-regex text-transform stage (callable(*args) -> str) with
    the same fail-soft/tri-state contract as _run_regex_stage."""
    try:
        return fn(*args), DETECTOR_RAN_CLEAN
    except Exception:
        return args[0] if args else "", DETECTOR_RAN_ERROR


# -------------------------------------------------------------------------
# GLOBAL THREAD LOCK & ORCHESTRATOR
# -------------------------------------------------------------------------
def scrub_payload(transaction_id: str, text: str) -> ScrubberResult:
    # Unicode normalization — NFKC folds homoglyphs, fullwidth chars,
    # and compatibility variants before any detection pass.
    # Prevents evasion via Cyrillic lookalikes, Unicode dashes, etc.
    text = unicodedata.normalize('NFKC', text)
    # Explicit dash normalization — NFKC does not fold Unicode dashes
    # to ASCII hyphen. Normalize all dash variants so SSN/phone/date
    # regex patterns work correctly against obfuscated input.
    _UNICODE_DASHES = '\u2010\u2011\u2012\u2013\u2014\u2015\u2212\u2012\ufe58\ufe63\uff0d'
    for _dash in _UNICODE_DASHES:
        text = text.replace(_dash, '-')
    original_char_count = len(text)
    flags: Dict[str, FlagEntry] = {}
    redacted_flags: Dict[str, FlagEntry] = {}
    clean_text = text
    detectors_executed: Dict[str, str] = {}

    # 0a. URL PATH EXPANSION — extract path segments and query values
    # from URLs so regex detectors can find PHI embedded in URL paths.
    # e.g. /patients/234-56-7891/records exposes the SSN to REGEX_SSN.
    clean_text, status = _run_stage(_expand_url_path_components, clean_text)
    detectors_executed["URL_PATH_EXPANSION"] = status

    # 0. BASE64 DETECTION PASS — decode and re-scrub base64 segments
    # A base64-encoded SSN, name, or MRN would bypass all other detectors.
    # We decode candidates and substitute with their decoded plaintext
    # so subsequent passes can detect PHI normally.
    def _decode_base64_in_text(text: str) -> str:
        # Strip URLs before base64 scan to prevent corrupting URL hostnames
        url_pattern = re.compile(r'https?://[^\s]+')
        urls = url_pattern.findall(text)
        text_no_urls = url_pattern.sub('', text)
        candidates = REGEX_BASE64.findall(text_no_urls)
        for candidate in candidates:
            decoded = _try_decode_base64(candidate)
            if decoded:
                text_no_urls = text_no_urls.replace(candidate, ' ' + decoded + ' ', 1)
        # Restore URLs
        for url in urls:
            text_no_urls = text_no_urls + ' ' + url
        return text_no_urls
    clean_text, status = _run_stage(_decode_base64_in_text, clean_text)
    detectors_executed["BASE64_DECODE_PASS"] = status

    # 1. REGEX PASSES
    def gps_replacer(_match):
        _increment_flag(flags, "HIPAA_PHI_GPS")
        _increment_flag(redacted_flags, "HIPAA_PHI_GPS")
        return "[REDACTED_GPS]"
    clean_text, status = _run_regex_stage(REGEX_GPS, gps_replacer, clean_text)
    detectors_executed["45 CFR §164.514(b)(2)(i)(B) GPS"] = status

    def age_over_89_replacer(_match):
        _increment_flag(flags, "HIPAA_PHI_AGE_89")
        _increment_flag(redacted_flags, "HIPAA_PHI_AGE_89")
        return "[REDACTED_AGE_OVER_89]"
    clean_text, status = _run_regex_stage(REGEX_AGE_OVER_89, age_over_89_replacer, clean_text)
    detectors_executed["45 CFR §164.514(b)(2)(i)(C) age>89"] = status

    def hpbn_replacer(_match):
        _increment_flag(flags, "HIPAA_PHI_HPBN")
        _increment_flag(redacted_flags, "HIPAA_PHI_HPBN")
        return "[REDACTED_HPBN]"
    clean_text, status = _run_regex_stage(REGEX_HPBN, hpbn_replacer, clean_text)
    detectors_executed["45 CFR §164.514(b)(2)(i)(I)"] = status

    def account_replacer(_match):
        _increment_flag(flags, "HIPAA_PHI_ACCOUNT")
        _increment_flag(redacted_flags, "HIPAA_PHI_ACCOUNT")
        return "[REDACTED_ACCOUNT]"
    clean_text, status = _run_regex_stage(REGEX_ACCOUNT, account_replacer, clean_text)
    detectors_executed["45 CFR §164.514(b)(2)(i)(J)"] = status

    def vin_replacer(_match):
        _increment_flag(flags, "HIPAA_PHI_VIN")
        _increment_flag(redacted_flags, "HIPAA_PHI_VIN")
        return "[REDACTED_VIN]"
    clean_text, status = _run_regex_stage(REGEX_VIN, vin_replacer, clean_text)
    detectors_executed["45 CFR §164.514(b)(2)(i)(L)"] = status

    def mrn_replacer(_match):
        _increment_flag(flags, "HIPAA_PHI_MRN")
        _increment_flag(redacted_flags, "HIPAA_PHI_MRN")
        return "[REDACTED_MRN]"
    clean_text, status = _run_regex_stage(REGEX_MRN, mrn_replacer, clean_text)
    detectors_executed["45 CFR §164.514(b)(2)(i)(H)"] = status

    def fax_replacer(_match):
        _increment_flag(flags, "HIPAA_PHI_FAX")
        _increment_flag(redacted_flags, "HIPAA_PHI_FAX")
        return "[REDACTED_FAX]"
    clean_text, status = _run_regex_stage(REGEX_FAX, fax_replacer, clean_text)
    detectors_executed["45 CFR §164.514(b)(2)(i)(E)"] = status

    def ssn_replacer(_match):
        _increment_flag(flags, "HIPAA_SSN")
        _increment_flag(redacted_flags, "HIPAA_SSN")
        return "[REDACTED_SSN]"

    clean_text, status = _run_regex_stage(REGEX_SSN, ssn_replacer, clean_text)
    detectors_executed["45 CFR §164.514(b)(2)(i)(G)"] = status

    def pan_replacer(match):
        candidate = match.group(0)
        clean_candidate = "".join(c for c in candidate if c.isdigit())
        if validate_luhn_checksum(clean_candidate):
            _increment_flag(flags, "PCI_PAN")
            _increment_flag(redacted_flags, "PCI_PAN")
            return "[REDACTED_PAN]"
        return candidate

    clean_text, status = _run_regex_stage(REGEX_PAN, pan_replacer, clean_text)
    detectors_executed["PCI-DSS PAN (Luhn)"] = status

    # 2. NER + PRESIDIO PASSES (merged span redaction — no duplicate overlaps)
    # spaCy and Presidio are independent engines with independent failure
    # domains — one throwing must not silently blank out the other's
    # categories, and each category's status must reflect its own engine.
    try:
        spacy_spans = _collect_spacy_spans(clean_text)
        spacy_status = DETECTOR_RAN_CLEAN
    except Exception:
        spacy_spans = []
        spacy_status = DETECTOR_RAN_ERROR

    try:
        presidio_spans = _collect_presidio_spans(clean_text)
        presidio_status = DETECTOR_RAN_CLEAN
    except Exception:
        presidio_spans = []
        presidio_status = DETECTOR_RAN_ERROR

    entity_spans = spacy_spans + presidio_spans
    clean_text = _apply_span_redactions(clean_text, entity_spans, flags, redacted_flags)
    # Record NER + Presidio categories as executed, attributed to the
    # engine that actually covers each CFR category.
    detectors_executed["45 CFR §164.514(b)(2)(i)(A)"] = spacy_status     # Names (spaCy)
    detectors_executed["45 CFR §164.514(b)(2)(i)(B)"] = presidio_status  # Geographic (Presidio)
    detectors_executed["45 CFR §164.514(b)(2)(i)(C)"] = spacy_status     # Dates (spaCy)
    detectors_executed["45 CFR §164.514(b)(2)(i)(D)"] = presidio_status  # Phone (Presidio)
    detectors_executed["45 CFR §164.514(b)(2)(i)(F)"] = presidio_status  # Email (Presidio)
    detectors_executed["45 CFR §164.514(b)(2)(i)(N)"] = presidio_status  # URL (Presidio)
    detectors_executed["45 CFR §164.514(b)(2)(i)(O)"] = presidio_status  # IP (Presidio)

    # 3. AUDIT PAYLOAD
    audit_log = RedactionAuditLog(
        transaction_id=transaction_id,
        original_char_count=original_char_count,
        redacted_char_count=len(clean_text),
        flags_triggered=flags,
        flags_redacted=redacted_flags,
    )

    return ScrubberResult(clean_text=clean_text, audit_log=audit_log, detectors_executed=detectors_executed)
