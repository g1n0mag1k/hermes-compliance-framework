"""Pre-process evasions without NFKC, and keep detector offsets aligned.

The blanket ``unicodedata.normalize('NFKC', text)`` call formerly at the
top of ``_scrub_payload_impl`` rewrote clinical superscripts (``10⁶`` →
``106``) and does not fold cross-script confusables. These tests lock the
replacement: strip format/control characters, fold fullwidth ASCII 1:1,
and fold mixed-script homoglyphs only inside mixed tokens.
"""

import inspect
import unicodedata

import pytest

from hermes import classifier
from hermes.classifier import nlp, sanitize_and_fold_evasions, scrub_payload

_CLINICAL = "WBC 10\u2076/\u03bcL, \u03b2-blocker prescribed"
_TELEMETRY_KEYS = ("format_chars_stripped", "mixed_script_homoglyphs_folded")


def _assert_clinical_preserved(text: str) -> None:
    assert "10\u2076" in text
    assert "\u03bcL" in text
    assert "\u03b2" in text
    assert "106" not in text


def test_zero_width_ssn_stripped_and_redacted() -> None:
    """A zero-width character inside an SSN is removed before the regex stage."""
    raw = "id 123\u200b-45-6789 ok"
    sanitized, meta = sanitize_and_fold_evasions(raw)

    assert sanitized == "id 123-45-6789 ok"
    assert meta["format_chars_stripped"] == 1
    assert meta["mixed_script_homoglyphs_folded"] == 0
    assert "\u200b" not in sanitized

    result = scrub_payload("tx_zw_ssn", raw)
    plain = scrub_payload("tx_zw_ssn_plain", sanitized)

    assert result.clean_text == "id [REDACTED_SSN] ok"
    assert result.clean_text == plain.clean_text
    assert "123-45-6789" not in result.clean_text
    assert "\u200b" not in result.clean_text
    assert result.audit_log.flags_triggered["HIPAA_SSN"].count == 1


@pytest.mark.parametrize(
    "invisible",
    [
        "\u200b",
        "\u200c",
        "\u200d",
        "\ufeff",
        "\u00ad",
        "\u202a",
        "\u202b",
        "\u202c",
        "\u202d",
        "\u202e",
        "\u2066",
        "\u2067",
        "\u2068",
        "\u2069",
        "\x00",
        "\x1b",
        "\x7f",
        "\x85",
    ],
)
def test_format_and_control_characters_are_stripped(invisible: str) -> None:
    raw = f"123{invisible}-45-6789"
    sanitized, meta = sanitize_and_fold_evasions(raw)
    assert sanitized == "123-45-6789"
    assert meta["format_chars_stripped"] == 1
    assert invisible not in sanitized


def test_newline_tab_and_cr_are_preserved() -> None:
    raw = "line\n\tkeep\r"
    sanitized, meta = sanitize_and_fold_evasions(raw)
    assert sanitized == raw
    assert meta == {
        "format_chars_stripped": 0,
        "mixed_script_homoglyphs_folded": 0,
    }


def test_fullwidth_ascii_folds_one_to_one_and_ssn_redacts() -> None:
    fullwidth = "\uff11\uff12\uff13-\uff14\uff15-\uff16\uff17\uff18\uff19"
    sanitized, meta = sanitize_and_fold_evasions(fullwidth)
    assert sanitized == "123-45-6789"
    assert len(sanitized) == len(fullwidth)
    assert meta["mixed_script_homoglyphs_folded"] == 0
    assert meta["format_chars_stripped"] == 0

    result = scrub_payload("tx_fullwidth_ssn", f"id {fullwidth} ok")
    assert result.clean_text == "id [REDACTED_SSN] ok"


def test_mixed_script_homoglyph_name_and_id_redacted_at_exact_boundaries() -> None:
    """Cyrillic lookalikes fold 1:1, then redaction spans match the Latin twin.

    ``Pt Ѕmіth`` folds to ``Pt Smith`` and the person span is exactly
    ``Smith``. ``МRN-994812`` folds to ``MRN-994812``. REGEX_MRN does not
    treat ``-`` as a separator, and the NER span on this sentence covers
    exactly that identifier (redacted as an organization). Neighboring
    words stay put because each confusable is replaced by one character.
    """
    name = "\u0405m\u0456th"  # Ѕmіth — Cyrillic DZE + Cyrillic i
    identifier = "\u041cRN-994812"  # Cyrillic EM
    payload = f"Pt {name} presented. {identifier} assigned."
    plain = "Pt Smith presented. MRN-994812 assigned."

    sanitized, meta = sanitize_and_fold_evasions(payload)
    assert sanitized == plain
    assert len(sanitized) == len(payload)
    assert meta["format_chars_stripped"] == 0
    assert meta["mixed_script_homoglyphs_folded"] == 3

    name_at = payload.index(name)
    id_at = payload.index(identifier)
    assert sanitized[name_at : name_at + len(name)] == "Smith"
    assert sanitized[id_at : id_at + len(identifier)] == "MRN-994812"
    assert plain.index("Smith") == name_at
    assert plain.index("MRN-994812") == id_at

    homoglyph = scrub_payload("tx_homoglyph_bounds", payload)
    latin = scrub_payload("tx_homoglyph_bounds_plain", plain)

    assert homoglyph.clean_text == latin.clean_text
    assert homoglyph.clean_text == (
        "Pt [REDACTED_PERSON] presented. [REDACTED_ORG] assigned."
    )
    assert "Smith" not in homoglyph.clean_text
    assert "MRN-994812" not in homoglyph.clean_text
    assert name not in homoglyph.clean_text
    assert "\u041c" not in homoglyph.clean_text
    assert homoglyph.clean_text.startswith("Pt ")
    assert " presented. " in homoglyph.clean_text
    assert homoglyph.clean_text.endswith(" assigned.")
    assert homoglyph.audit_log.flags_triggered["HIPAA_PHI_PERSON"].count == 1


def test_pure_non_latin_and_clinical_symbols_are_not_folded() -> None:
    samples = [
        "\u0418\u0432\u0430\u043d\u043e\u0432",  # Иванов — pure Cyrillic
        "\u03b1",  # α
        "\u03b2-blocker",
        "\u03bcg",  # μg
        "\u03bcL",  # μL
        "\u03b12",  # α2, digit mixed with non-confusable Greek
        "10\u2076",  # 10⁶
        "\ufb01",  # ﬁ must stay one character
        "\u2153",  # ⅓ must stay one character
    ]
    for sample in samples:
        sanitized, meta = sanitize_and_fold_evasions(sample)
        assert sanitized == sample, repr(sample)
        assert len(sanitized) == len(sample), repr(sample)
        assert meta["mixed_script_homoglyphs_folded"] == 0
        assert set(meta) == set(_TELEMETRY_KEYS)


def test_clinical_superscripts_survive_and_old_nfkc_fails() -> None:
    """NFKC corrupts this lab value; the pre-processor and scrub must not.

    The assertion helper is applied to the old NFKC output first, and that
    call must fail. That is the pre-fix behavior this change removes.
    """
    nfkc = unicodedata.normalize("NFKC", _CLINICAL)
    assert nfkc == "WBC 106/\u03bcL, \u03b2-blocker prescribed"
    with pytest.raises(AssertionError):
        _assert_clinical_preserved(nfkc)

    sanitized, meta = sanitize_and_fold_evasions(_CLINICAL)
    assert sanitized == _CLINICAL
    assert meta["format_chars_stripped"] == 0
    assert meta["mixed_script_homoglyphs_folded"] == 0
    _assert_clinical_preserved(sanitized)

    result = scrub_payload("tx_clinical_superscript", _CLINICAL)
    _assert_clinical_preserved(result.clean_text)
    assert "\u03bcL" in result.clean_text
    assert "\u03b2-blocker" in result.clean_text
    assert "10\u2076" in result.clean_text

    impl_source = inspect.getsource(classifier._scrub_payload_impl)
    assert "unicodedata.normalize" not in impl_source
    assert "NFKC" not in impl_source
    assert "sanitize_and_fold_evasions" in impl_source


def test_en_dash_date_and_ssn_still_redacted_without_nfkc() -> None:
    """Dash folding still runs after NFKC is gone, so an en-dash date redacts.

    spaCy tags ``2020-01-15`` as a date and does not tag the en-dash form.
    Redaction of that date is proof the Unicode dash loop still executes.
    """
    text = "Admitted 2020\u201301\u201315 SSN 123-45-6789."
    raw_labels = {(ent.text, ent.label_) for ent in nlp(text).ents}
    assert ("2020\u201301\u201315", "DATE") not in raw_labels

    folded = text.replace("\u2013", "-")
    folded_labels = {(ent.text, ent.label_) for ent in nlp(folded).ents}
    assert ("2020-01-15", "DATE") in folded_labels

    result = scrub_payload("tx_endash_date", text)
    assert "\u2013" not in result.clean_text
    assert "2020-01-15" not in result.clean_text
    assert "2020\u201301\u201315" not in result.clean_text
    assert "123-45-6789" not in result.clean_text
    assert "[REDACTED_DATE]" in result.clean_text
    assert "[REDACTED_SSN]" in result.clean_text
    assert result.clean_text.startswith("Admitted ")
    assert result.audit_log.flags_triggered["HIPAA_PHI_DATE"].count >= 1
    assert result.audit_log.flags_triggered["HIPAA_SSN"].count == 1
