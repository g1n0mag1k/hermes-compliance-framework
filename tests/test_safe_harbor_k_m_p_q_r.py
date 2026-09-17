import os

os.environ.setdefault("HERMES_ENV", "development")

from hermes.classifier import DECLARED_SCOPE, scrub_payload


def _flags(result):
    return result.audit_log.flags_triggered


class TestCategoryK:
    def test_dea_valid_detected(self):
        result = scrub_payload("tx_dea_valid", "DEA: AB1234563")
        assert "HIPAA_PHI_CERT_LICENSE" in _flags(result)

    def test_dea_invalid_not_detected(self):
        result = scrub_payload("tx_dea_invalid", "DEA: AB1234560")
        assert "HIPAA_PHI_CERT_LICENSE" not in _flags(result)

    def test_npi_valid_detected(self):
        result = scrub_payload("tx_npi_valid", "NPI: 1234567893")
        assert "HIPAA_PHI_NPI" in _flags(result)

    def test_state_license_with_context(self):
        result = scrub_payload("tx_state_lic", "license no: CA12345")
        assert "HIPAA_PHI_STATE_LICENSE" in _flags(result)

    def test_state_license_no_context(self):
        result = scrub_payload("tx_state_no_ctx", "CA12345")
        assert "HIPAA_PHI_STATE_LICENSE" not in _flags(result)


class TestCategoryM:
    def test_gs1_udi_detected(self):
        result = scrub_payload("tx_gs1", "(01)00855361005016(21)S12345")
        assert "HIPAA_PHI_DEVICE_ID" in _flags(result)

    def test_udi_serial_detected(self):
        result = scrub_payload("tx_serial", "(21)XYZ789012")
        assert "HIPAA_PHI_DEVICE_ID" in _flags(result)

    def test_hibcc_detected(self):
        result = scrub_payload("tx_hibcc", "+H123PARTNO123456/$$420S123456")
        assert "HIPAA_PHI_DEVICE_ID" in _flags(result)

    def test_iccbba_detected(self):
        result = scrub_payload("tx_iccbba", "=A999999999999999B")
        assert "HIPAA_PHI_DEVICE_ID" in _flags(result)

    def test_gtin14_valid_with_context(self):
        result = scrub_payload("tx_gtin_valid", "device GTIN: 00855361005016")
        assert "HIPAA_PHI_DEVICE_ID" in _flags(result)

    def test_gtin14_invalid_not_detected(self):
        result = scrub_payload("tx_gtin_invalid", "device GTIN: 00855361005010")
        assert "HIPAA_PHI_DEVICE_ID" not in _flags(result)


class TestCategoryP:
    def test_fingerprint_word_detected(self):
        result = scrub_payload("tx_fp", "patient fingerprint on file")
        assert "HIPAA_PHI_BIOMETRIC_REF" in _flags(result)

    def test_voiceprint_detected(self):
        result = scrub_payload("tx_voice", "voiceprint authentication required")
        assert "HIPAA_PHI_BIOMETRIC_REF" in _flags(result)

    def test_biometric_file_detected(self):
        result = scrub_payload("tx_bio_file", "scan stored as patient.wsq")
        assert "HIPAA_PHI_BIOMETRIC_REF" in _flags(result)

    def test_p_content_channel_not_run(self):
        result = scrub_payload("tx_p_content", "no biometric content here")
        assert result.detectors_executed["45 CFR §164.514(b)(2)(i)(P) content"] == "not_run"


class TestCategoryQ:
    def test_image_filename_detected(self):
        result = scrub_payload("tx_img_file", "see patient_photo.jpg for reference")
        assert "HIPAA_PHI_IMAGE_REF" in _flags(result)

    def test_base64_image_detected(self):
        result = scrub_payload("tx_img_b64", "data:image/jpeg;base64," + "A" * 50)
        assert "HIPAA_PHI_IMAGE_REF" in _flags(result)

    def test_q_content_channel_not_run(self):
        result = scrub_payload("tx_q_content", "no image content here")
        assert result.detectors_executed["45 CFR §164.514(b)(2)(i)(Q) content"] == "not_run"


class TestCategoryR:
    def test_nct_trial_detected(self):
        result = scrub_payload("tx_nct", "enrolled in NCT12345678")
        assert "HIPAA_PHI_TRIAL_ID" in _flags(result)

    def test_nct_wrong_length_not_detected(self):
        result = scrub_payload("tx_nct_bad", "NCT1234567")
        assert "HIPAA_PHI_TRIAL_ID" not in _flags(result)

    def test_enc_code_detected(self):
        result = scrub_payload("tx_enc", "encounter ENC-789012")
        assert "HIPAA_PHI_UNIQUE_CODE" in _flags(result)

    def test_spec_code_detected(self):
        result = scrub_payload("tx_spec", "specimen SPEC_445521")
        assert "HIPAA_PHI_UNIQUE_CODE" in _flags(result)


class TestDeclaredScopeCoverage:
    def test_declared_scope_18_categories(self):
        assert len(DECLARED_SCOPE) == 18

    def test_all_18_have_status(self):
        assert all(
            e["status"] in ("covered", "reference_only", "not_covered")
            for e in DECLARED_SCOPE
        )

    def test_no_not_covered_remains(self):
        assert not any(e["status"] == "not_covered" for e in DECLARED_SCOPE)
