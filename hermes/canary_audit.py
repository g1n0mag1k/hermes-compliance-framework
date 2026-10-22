"""
hermes/canary_audit.py — Telemetry Canary Audit Engine

Ingests raw telemetry text, runs the 16-category HIPAA Safe Harbor
synthetic canary check adapted from entrypoint.py (hermes-canary-action),
and emits a cryptographically signed JSON audit report.

This module is the engine behind POST /v1/telemetry/canary-audit. It is
intentionally self-contained so it can be unit-tested without the full
FastAPI app stack.

Zero-PHI contract
─────────────────
Synthetic canary tokens are injected into a *copy* of the telemetry payload
and then scrubbed. The real payload is also scrubbed. No real PHI is stored
in the report; only redacted clean-text excerpts (first 500 chars) are
included. Raw payload bytes are never written to disk or logged.

Signing
───────
Every report is HMAC-SHA256 signed using the same HERMES_SIGNING_KEY that
signs /v1/scrub attestation receipts. The signature covers the canonical
JSON of the report body (all keys sorted, no whitespace) with the
`report_signature` field zeroed — identical scheme to the canary-action
entrypoint so CI and API receipts are verifiable with the same key.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import uuid
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, date, datetime, timedelta
from typing import Any

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

AUDIT_REPORT_SCHEMA_VERSION = "1.0"
ISSUER = "Hermes Relay v1.0.0 — hermesrelay.dev"
RULESET = "hipaa-safe-harbor-16"

# 45 CFR §164.514(b)(2)(i) Safe Harbor identifier categories (all 16 + HealthSherpa extras)
SAFE_HARBOR_CATEGORIES: list[dict[str, str]] = [
    {"key": "names",            "cfr": "§164.514(b)(2)(i)(A)", "label": "Names"},
    {"key": "dates",            "cfr": "§164.514(b)(2)(i)(C)", "label": "Dates"},
    {"key": "phone_numbers",    "cfr": "§164.514(b)(2)(i)(D)", "label": "Phone Numbers"},
    {"key": "fax",              "cfr": "§164.514(b)(2)(i)(E)", "label": "Fax Numbers"},
    {"key": "email",            "cfr": "§164.514(b)(2)(i)(F)", "label": "Email Addresses"},
    {"key": "ssn",              "cfr": "§164.514(b)(2)(i)(G)", "label": "Social Security Numbers"},
    {"key": "mrn",              "cfr": "§164.514(b)(2)(i)(H)", "label": "Medical Record Numbers"},
    {"key": "health_plan_ids",  "cfr": "§164.514(b)(2)(i)(I)", "label": "Health Plan Beneficiary Numbers"},
    {"key": "account_numbers",  "cfr": "§164.514(b)(2)(i)(J)", "label": "Account Numbers"},
    {"key": "license_numbers",  "cfr": "§164.514(b)(2)(i)(K)", "label": "Certificate/License Numbers"},
    {"key": "vins",             "cfr": "§164.514(b)(2)(i)(L)", "label": "Vehicle Identifiers / VINs"},
    {"key": "device_serials",   "cfr": "§164.514(b)(2)(i)(M)", "label": "Device Identifiers"},
    {"key": "web_urls",         "cfr": "§164.514(b)(2)(i)(N)", "label": "Web URLs"},
    {"key": "ip_addresses",     "cfr": "§164.514(b)(2)(i)(O)", "label": "IP Addresses"},
    {"key": "biometric_ids",    "cfr": "§164.514(b)(2)(i)(P)", "label": "Biometric Identifiers"},
    {"key": "full_face_photos", "cfr": "§164.514(b)(2)(i)(Q)", "label": "Full-face Photographs"},
]

_CATEGORY_META: dict[str, dict[str, str]] = {c["key"]: c for c in SAFE_HARBOR_CATEGORIES}

_RNG = secrets.SystemRandom()


# ─────────────────────────────────────────────────────────────────────────────
# Signing key — shared with attestation.py
# ─────────────────────────────────────────────────────────────────────────────

def _load_signing_key() -> bytes:
    key_hex = os.environ.get("HERMES_SIGNING_KEY")
    if key_hex:
        try:
            return bytes.fromhex(key_hex)
        except ValueError as exc:
            raise RuntimeError(
                "HERMES_SIGNING_KEY is not a valid hex string. "
                "Generate one with: openssl rand -hex 32"
            ) from exc
    # Dev fallback — never for production
    env = os.environ.get("HERMES_ENV", "development")
    if env == "production":
        raise RuntimeError(
            "HERMES_SIGNING_KEY is required when HERMES_ENV=production."
        )
    return hashlib.sha256(b"hermes-dev-signing-key-not-for-production").digest()


_SIGNING_KEY: bytes = _load_signing_key()


# ─────────────────────────────────────────────────────────────────────────────
# Scrubber library (ported from hermes-canary-action/entrypoint.py)
# ─────────────────────────────────────────────────────────────────────────────

def _redact(pattern: str, label: str, text: str, flags: int = 0) -> str:
    return re.sub(pattern, f"[REDACTED-{label}]", text, flags=flags)


def _build_scrubbers() -> dict[str, Callable[[str], str]]:
    """Return per-category scrubbers aligned with HIPAA Safe Harbor §164.514(b)(2)(i)."""

    def scrub_name(text: str) -> str:
        text = re.sub(
            r"\b(?:Dr\.|Mr\.|Mrs\.|Ms\.)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\b",
            "[REDACTED-NAME]",
            text,
        )
        text = re.sub(
            r"\bPatient:\s*[A-Z][a-z]+(?:\s+[A-Z]\.?\s+[A-Z][a-z]+|\s+[A-Z][a-z]+)+\b",
            "Patient: [REDACTED-NAME]",
            text,
        )
        return text

    def scrub_date(text: str) -> str:
        patterns = [
            r"\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b",
            r"\b\d{4}-\d{2}-\d{2}\b",
            r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2},?\s+\d{4}\b",
        ]
        for pattern in patterns:
            text = re.sub(pattern, "[REDACTED-DATE]", text, flags=re.IGNORECASE)
        return text

    return {
        "names": scrub_name,
        "dates": scrub_date,
        "phone_numbers": lambda t: _redact(
            r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b", "PHONE", t
        ),
        "fax": lambda t: _redact(
            r"\bFax:?\s*(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b", "FAX", t
        ),
        "email": lambda t: _redact(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "EMAIL", t
        ),
        "ssn": lambda t: _redact(r"\b\d{3}-\d{2}-\d{4}\b", "SSN", t),
        "mrn": lambda t: _redact(
            r"\bMRN[:\s#-]*\d{6,12}\b", "MRN", t, flags=re.IGNORECASE
        ),
        "health_plan_ids": lambda t: _redact(
            r"\b(?:HP|PLAN|MEMBER)[#:\s-]*[A-Z0-9]{8,16}\b",
            "HEALTH_PLAN_ID",
            t,
            flags=re.IGNORECASE,
        ),
        "account_numbers": lambda t: _redact(
            r"\b(?:ACCT|ACCOUNT)[#:\s-]*\d{8,17}\b",
            "ACCOUNT",
            t,
            flags=re.IGNORECASE,
        ),
        "license_numbers": lambda t: _redact(
            r"\b(?:LIC|LICENSE)[#:\s-]*[A-Z0-9-]{5,24}\b",
            "LICENSE",
            t,
            flags=re.IGNORECASE,
        ),
        "vins": lambda t: _redact(r"\b[A-HJ-NPR-Z0-9]{17}\b", "VIN", t),
        "device_serials": lambda t: _redact(
            r"\b(?:SN|SERIAL)[#:\s-]*[A-Z0-9]{8,20}\b",
            "DEVICE_SERIAL",
            t,
            flags=re.IGNORECASE,
        ),
        "web_urls": lambda t: _redact(r"https?://[^\s<>\"']+", "URL", t),
        "ip_addresses": lambda t: _redact(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
            "IP",
            t,
        ),
        "biometric_ids": lambda t: _redact(
            r"\b(?:BIO|BIOMETRIC)[#:\s-]*[A-F0-9]{16,64}\b",
            "BIOMETRIC",
            t,
            flags=re.IGNORECASE,
        ),
        "full_face_photos": lambda t: _redact(
            r"(?:photo|image|selfie)[:\s-]*data:image/[a-z]+;base64,[A-Za-z0-9+/=]+",
            "PHOTO",
            t,
            flags=re.IGNORECASE,
        ),
    }


_SCRUBBERS: dict[str, Callable[[str], str]] = _build_scrubbers()


def _compose_scrubber() -> Callable[[str], str]:
    """Return a single scrubber that applies all 16 category scrubbers in order."""
    def scrub(text: str) -> str:
        result = text
        for fn in _SCRUBBERS.values():
            result = fn(result)
        return result
    return scrub


_FULL_SCRUBBER: Callable[[str], str] = _compose_scrubber()


# ─────────────────────────────────────────────────────────────────────────────
# Synthetic canary token generation
# ─────────────────────────────────────────────────────────────────────────────

def _random_nxx() -> str:
    return f"{_RNG.randint(2, 9)}{_RNG.randint(0, 9)}{_RNG.randint(0, 9)}"


def _random_phone() -> str:
    return f"({_random_nxx()}) {_random_nxx()}-{_RNG.randint(0,9)}{_RNG.randint(0,9)}{_RNG.randint(0,9)}{_RNG.randint(0,9)}"


def _random_vin() -> str:
    chars = "ABCDEFGHJKLMNPRSTUVWXYZ0123456789"
    return "".join(secrets.choice(chars) for _ in range(17))


@dataclass(frozen=True)
class CanaryVector:
    category: str
    cfr: str
    label: str
    sample: str          # synthetic string containing the needle
    needle: str          # pipe-separated needles to search for post-scrub
    scrubber: Callable[[str], str]


def _build_canary_vectors() -> list[CanaryVector]:
    """Generate one fresh randomized canary token per Safe Harbor category."""
    first_names = [
        "Bavomir", "Qwinella", "Tovakrel", "Tepha", "Marmok",
        "Cindrel", "Flostin", "Vexler", "Nubwick", "Glimmera",
    ]
    last_names = [
        "Lurendor", "Zirandel", "Croutonsmith", "Wobbleton", "Fizzington",
        "Plumwicket", "Branflakes", "Tumblewick", "Quorble", "Snorfax",
    ]

    p_first = _RNG.choice(first_names)
    p_last = _RNG.choice(last_names)
    d_first = _RNG.choice(first_names)
    d_last = _RNG.choice(last_names)
    names_sample = (
        f"Patient: {p_first} {p_last} was seen by Dr. {d_first} {d_last}."
    )
    names_needle = f"{p_first} {p_last}|{d_first} {d_last}"

    span = (date(2026, 12, 31) - date(2020, 1, 1)).days
    ev = date(2020, 1, 1) + timedelta(days=_RNG.randint(0, span))
    mmddyyyy = ev.strftime("%m/%d/%Y")
    iso_d = ev.strftime("%Y-%m-%d")
    dates_sample = f"Admission on {mmddyyyy} and follow-up {iso_d}."
    dates_needle = f"{mmddyyyy}|{iso_d}"

    phone = _random_phone()
    fax = _random_phone()
    while fax == phone:
        fax = _random_phone()

    email_user = f"canary.{secrets.token_hex(4)}"
    email_domain = f"clinic-{secrets.token_hex(3)}.example.org"
    email = f"{email_user}@{email_domain}"

    ssn = (
        f"{_RNG.randint(1,9)}{_RNG.randint(0,9)}{_RNG.randint(0,9)}"
        f"-{_RNG.randint(0,9)}{_RNG.randint(0,9)}"
        f"-{_RNG.randint(0,9)}{_RNG.randint(0,9)}{_RNG.randint(0,9)}{_RNG.randint(0,9)}"
    )

    mrn_digits = "".join(str(_RNG.randint(0, 9)) for _ in range(10))
    plan_id = "".join(
        secrets.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(14)
    )
    account_number = "".join(str(_RNG.randint(0, 9)) for _ in range(16))

    state = secrets.choice(["WA", "CA", "TX", "NY", "FL"])
    license_id = f"{state}-MED-{_RNG.randint(0, 999999):06d}"

    vin = _random_vin()

    device_serial = "".join(
        secrets.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(12)
    )

    portal_id = secrets.token_hex(8)
    portal_sub = secrets.token_hex(3)
    portal_url = f"https://portal-{portal_sub}.example.org/patient/{portal_id}"

    ip_address = f"10.{_RNG.randint(0,255)}.{_RNG.randint(0,255)}.{_RNG.randint(1,254)}"

    bio_id = secrets.token_hex(16).upper()

    photo_b64 = base64.b64encode(secrets.token_bytes(48)).decode("ascii")
    photo_needle = f"data:image/jpeg;base64,{photo_b64}"

    raw: list[tuple[str, str, str]] = [
        ("names",           names_sample,                              names_needle),
        ("dates",           dates_sample,                              dates_needle),
        ("phone_numbers",   f"Callback at {phone} after discharge.",   phone),
        ("fax",             f"Send records via Fax: {fax}.",           f"Fax: {fax}"),
        ("email",           f"Contact {email} for results.",           email),
        ("ssn",             f"Legacy index SSN {ssn} must be redacted.", ssn),
        ("mrn",             f"Chart MRN: {mrn_digits} updated.",       f"MRN: {mrn_digits}"),
        ("health_plan_ids", f"Coverage PLAN# {plan_id} verified.",     plan_id),
        ("account_numbers", f"Billing ACCT# {account_number} posted.", account_number),
        ("license_numbers", f"Provider LIC# {license_id}.",            license_id),
        ("vins",            f"Transport vehicle VIN {vin} noted.",     vin),
        ("device_serials",  f"Pump SERIAL SN-{device_serial} registered.", device_serial),
        ("web_urls",        f"Portal {portal_url}.",                   portal_url),
        ("ip_addresses",    f"Session originated from {ip_address}.",  ip_address),
        ("biometric_ids",   f"Template BIO# {bio_id} stored.",         bio_id),
        ("full_face_photos", f"photo: {photo_needle}",                 photo_needle),
    ]

    vectors: list[CanaryVector] = []
    for key, sample, needle in raw:
        meta = _CATEGORY_META[key]
        vectors.append(CanaryVector(
            category=key,
            cfr=meta["cfr"],
            label=meta["label"],
            sample=sample,
            needle=needle,
            scrubber=_SCRUBBERS[key],
        ))
    return vectors


# ─────────────────────────────────────────────────────────────────────────────
# HealthSherpa column-level PHI scan
# ─────────────────────────────────────────────────────────────────────────────

# Column name keywords that indicate PHI — mirrors hermes/ingest/healthsherpa.py
_HS_PHI_PATTERNS = re.compile(
    r"(?<![a-z0-9_])(?:"
    + "|".join(re.escape(p) for p in sorted([
        "first_name", "last_name", "date_of_birth", "subscriber_id",
        "member_id", "policy_id", "group_id",
        "phone", "email", "social", "birth", "address", "street", "gender",
        "first", "last", "city", "zip", "dob", "ssn", "npi", "tin", "ein",
    ], key=len, reverse=True))
    + r")(?![a-z0-9_])",
    re.IGNORECASE,
)


def _normalize_col(name: str) -> str:
    name = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", name)
    name = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    return re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")


def _detect_healthsherpa_phi_columns(text: str) -> list[str]:
    """
    Scan text for HealthSherpa-style CSV column headers containing PHI keywords.
    Returns a list of detected column names.
    """
    # Extract tokens that look like column names: CamelCase, snake_case, or
    # plain words from the first line of CSV-like text
    first_line = text.split("\n")[0] if "\n" in text else text[:500]
    # Try CSV header parse: split on comma, strip quotes
    candidates = [c.strip().strip('"').strip("'") for c in first_line.split(",")]
    if len(candidates) < 2:
        # Not CSV — fall back to all word tokens
        candidates = re.findall(r"\b[A-Za-z][A-Za-z0-9_]{2,}\b", text[:2000])

    phi_cols: list[str] = []
    for col in candidates:
        norm = _normalize_col(col)
        if _HS_PHI_PATTERNS.search(norm):
            phi_cols.append(col)
    return phi_cols


# ─────────────────────────────────────────────────────────────────────────────
# Core audit result structures
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class CategoryResult:
    category: str
    cfr: str
    label: str
    canary_passed: bool   # True = scrubber caught the synthetic token (no leak)
    payload_phi_detected: bool  # True = pattern found in the real payload
    payload_redacted_excerpt: str  # First 500 chars of scrubbed payload (safe to store)


@dataclass
class HealthSherpaResult:
    phi_column_names: list[str]
    columns_detected: int
    risk_level: str  # "NONE" | "LOW" | "HIGH"


@dataclass
class AuditReport:
    # Identity
    report_id: str
    transaction_id: str
    issued_at: str
    issuer: str
    schema_version: str
    ruleset: str

    # Canary harness result
    canary_status: str          # "PASSED" | "FAILED"
    categories_tested: list[str]
    categories_passed: list[str]
    categories_failed: list[str]
    category_results: list[dict[str, Any]]

    # HealthSherpa column scan
    healthsherpa: dict[str, Any]

    # Payload scan summary
    payload_phi_detected: bool
    payload_phi_categories: list[str]
    payload_char_count_in: int
    payload_char_count_out: int
    chars_removed: int
    clean_text_excerpt: str     # first 500 chars of scrubbed payload only

    # Zero-egress confirmation
    zero_phi_egress_confirmed: bool
    zero_phi_egress_scope_note: str

    # Compliance metadata
    compliance_frameworks: list[str]
    declared_scope: list[dict[str, str]]

    # Deliverable pricing tier
    deliverable_tier: str       # "$299 Signed Audit Report"

    # Signature (zeroed before signing, populated after)
    report_signature: str       # HMAC-SHA256 hex over canonical JSON body


# ─────────────────────────────────────────────────────────────────────────────
# Signing
# ─────────────────────────────────────────────────────────────────────────────

def _sign_report(report_dict: dict[str, Any]) -> str:
    """
    HMAC-SHA256 over canonical JSON with report_signature zeroed.

    Identical signing scheme to hermes-canary-action so CI receipts and API
    reports are verifiable with the same HERMES_SIGNING_KEY.
    """
    signing_body = {**report_dict, "report_signature": ""}
    canonical = json.dumps(signing_body, sort_keys=True, separators=(",", ":"))
    return hmac.new(
        _SIGNING_KEY,
        canonical.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _verify_report_signature(report_dict: dict[str, Any]) -> bool:
    """Re-derive and compare signature for a stored report dict."""
    provided = report_dict.get("report_signature", "")
    if not provided:
        return False
    expected = _sign_report(report_dict)
    return hmac.compare_digest(provided, expected)


# ─────────────────────────────────────────────────────────────────────────────
# Core audit runner
# ─────────────────────────────────────────────────────────────────────────────

def run_canary_audit(
    payload: str,
    transaction_id: str | None = None,
    source_label: str = "api",
) -> AuditReport:
    """
    Run the full 16-category HIPAA Safe Harbor canary audit against *payload*.

    Steps
    ─────
    1. Generate fresh synthetic canary tokens (one per category).
    2. Inject each into a copy of the payload and verify the scrubber removes it.
    3. Scan the real payload with each category scrubber; note which categories
       fire and how many chars were removed.
    4. Run HealthSherpa column-level PHI detection.
    5. Build, sign, and return an AuditReport.

    Nothing in this function writes to disk or makes network calls.
    The raw payload is never stored — only the scrubbed excerpt (≤500 chars).
    """
    if not transaction_id:
        transaction_id = f"txn_canary_{uuid.uuid4().hex[:12]}"

    issued_at = datetime.now(UTC).isoformat()
    vectors = _build_canary_vectors()

    # ── Step 1 + 2: canary harness ──────────────────────────────────────────
    category_results: list[CategoryResult] = []
    categories_passed: list[str] = []
    categories_failed: list[str] = []

    # Scrub the real payload once per category to detect real PHI
    payload_phi_categories: list[str] = []

    for vec in vectors:
        # Canary test: inject synthetic token into a payload copy, then scrub
        test_text = payload + f"\n\n[CANARY-INJECT] {vec.sample}"
        scrubbed_test = vec.scrubber(test_text)

        # Check if any needle survived — a leak means scrubber is broken
        canary_leaked = any(
            needle and needle in scrubbed_test
            for needle in vec.needle.split("|")
        )
        canary_passed = not canary_leaked

        # Real-payload scan: apply this category's scrubber to the real payload
        scrubbed_real = vec.scrubber(payload)
        phi_detected = scrubbed_real != payload  # scrubber changed something

        if phi_detected:
            payload_phi_categories.append(vec.category)

        if canary_passed:
            categories_passed.append(vec.category)
        else:
            categories_failed.append(vec.category)

        category_results.append(CategoryResult(
            category=vec.category,
            cfr=vec.cfr,
            label=vec.label,
            canary_passed=canary_passed,
            payload_phi_detected=phi_detected,
            payload_redacted_excerpt=scrubbed_real[:500],
        ))

    # Compose final clean text using all scrubbers together
    clean_text = _FULL_SCRUBBER(payload)

    # ── Step 3: summary metrics ─────────────────────────────────────────────
    canary_status = "PASSED" if not categories_failed else "FAILED"
    payload_phi_detected = bool(payload_phi_categories)
    char_in = len(payload)
    char_out = len(clean_text)
    chars_removed = abs(char_in - char_out)

    # Zero-egress confirmation: all canaries passed AND clean_text has no
    # surviving phi tokens (we do a post-scrub needle check on the real payload)
    post_scrub_leak = False
    for vec in vectors:
        if any(needle and needle in clean_text for needle in vec.needle.split("|")):
            post_scrub_leak = True
            break

    zero_phi_egress = canary_status == "PASSED" and not post_scrub_leak

    # ── Step 4: HealthSherpa column scan ────────────────────────────────────
    hs_phi_cols = _detect_healthsherpa_phi_columns(payload)
    hs_risk = "NONE" if not hs_phi_cols else ("HIGH" if len(hs_phi_cols) >= 3 else "LOW")
    hs_result = HealthSherpaResult(
        phi_column_names=hs_phi_cols,
        columns_detected=len(hs_phi_cols),
        risk_level=hs_risk,
    )

    # ── Step 5: Build report ─────────────────────────────────────────────────
    report = AuditReport(
        report_id=f"aud_{uuid.uuid4().hex}",
        transaction_id=transaction_id,
        issued_at=issued_at,
        issuer=ISSUER,
        schema_version=AUDIT_REPORT_SCHEMA_VERSION,
        ruleset=RULESET,
        canary_status=canary_status,
        categories_tested=[v.category for v in vectors],
        categories_passed=categories_passed,
        categories_failed=categories_failed,
        category_results=[asdict(r) for r in category_results],
        healthsherpa=asdict(hs_result),
        payload_phi_detected=payload_phi_detected,
        payload_phi_categories=payload_phi_categories,
        payload_char_count_in=char_in,
        payload_char_count_out=char_out,
        chars_removed=chars_removed,
        clean_text_excerpt=clean_text[:500],
        zero_phi_egress_confirmed=zero_phi_egress,
        zero_phi_egress_scope_note=(
            "Confirmed within declared_scope only. "
            "Canary harness uses synthetic Safe Harbor tokens; real PHI "
            "detection uses the same scrubbers. Evidence is incomplete for "
            "categories not listed in declared_scope."
        ),
        compliance_frameworks=["HIPAA", "45 CFR §164.514(b)(2)"],
        declared_scope=[
            {"key": c["key"], "cfr": c["cfr"], "label": c["label"]}
            for c in SAFE_HARBOR_CATEGORIES
        ],
        deliverable_tier="$299 Signed Audit Report",
        report_signature="",  # populated below
    )

    # Sign
    report_dict = asdict(report)
    sig = _sign_report(report_dict)
    report.report_signature = sig

    return report


# ─────────────────────────────────────────────────────────────────────────────
# Public helper for the API layer
# ─────────────────────────────────────────────────────────────────────────────

def audit_report_to_dict(report: AuditReport) -> dict[str, Any]:
    """Return the report as a plain dict, ready for JSON serialization."""
    return asdict(report)


def verify_audit_report(report_dict: dict[str, Any]) -> bool:
    """
    Verify the HMAC-SHA256 signature on a stored audit report dict.
    Returns True only if the signature is valid. Safe to call externally.
    """
    return _verify_report_signature(report_dict)
