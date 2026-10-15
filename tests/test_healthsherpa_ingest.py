import pandas as pd
import pytest

from hermes.ingest.healthsherpa import PHI_COLUMN_PATTERNS, HealthSherpaIngester


def _write(tmp_path, text, name="export.csv"):
    p = tmp_path / name
    p.write_text(text)
    return p


class TestLoad:
    def test_accepts_str_and_path(self, tmp_path):
        p = _write(tmp_path, "a,b\n1,2\n")
        assert HealthSherpaIngester(p).load().shape == (1, 2)
        assert HealthSherpaIngester(str(p)).load().shape == (1, 2)

    def test_strips_column_names(self, tmp_path):
        p = _write(tmp_path, "  First Name , Zip Code\t\nAnn,02134\n")
        df = HealthSherpaIngester(p).load()
        assert list(df.columns) == ["First Name", "Zip Code"]

    def test_preserves_raw_values(self, tmp_path):
        p = _write(tmp_path, "zip,ssn,note\n02134,001-23-4567,\n")
        df = HealthSherpaIngester(p).load()
        assert df.loc[0, "zip"] == "02134"
        assert df.loc[0, "ssn"] == "001-23-4567"
        assert df.loc[0, "note"] == ""

    def test_missing_file(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            HealthSherpaIngester(tmp_path / "nope.csv").load()

    def test_header_only_csv(self, tmp_path):
        p = _write(tmp_path, "first_name,last_name\n")
        with pytest.raises(ValueError, match="^CSV has no rows$"):
            HealthSherpaIngester(p).load()

    def test_zero_byte_csv(self, tmp_path):
        p = _write(tmp_path, "")
        with pytest.raises(ValueError, match="^CSV has no rows$"):
            HealthSherpaIngester(p).load()


class TestIdentifyPhiColumns:
    def test_patterns_constant_is_lowercase_and_complete(self):
        expected = {
            "name", "first", "last", "ssn", "social", "dob", "birth",
            "date_of_birth", "address", "street", "city", "zip", "phone",
            "email", "member_id", "subscriber_id", "policy_id", "group_id",
            "npi", "tin", "ein", "gender",
        }
        assert set(PHI_COLUMN_PATTERNS) == expected
        assert all(p == p.lower() for p in PHI_COLUMN_PATTERNS)

    @pytest.mark.parametrize("pattern", PHI_COLUMN_PATTERNS)
    def test_every_pattern_matches_itself_case_insensitively(self, pattern):
        ing = HealthSherpaIngester("unused.csv")
        for col in (pattern, pattern.upper(), pattern.title()):
            assert ing.identify_phi_columns(pd.DataFrame(columns=[col])) == [col]

    def test_real_world_header_variants_preserve_casing(self):
        cols = [
            "First Name", "LastName", "SSN", "Social Security #", "DOB",
            "Date of Birth", "Address1", "Street Address", "City", "ZIPCode",
            "Phone Number", "Email", "Member ID", "subscriber-id", "PolicyID",
            "Group_ID", "Agent NPI", "TIN", "EIN", "Gender",
        ]
        ing = HealthSherpaIngester("unused.csv")
        assert ing.identify_phi_columns(pd.DataFrame(columns=cols)) == cols

    def test_non_phi_columns_not_matched(self):
        cols = [
            "Plan Type", "Premium", "Setting", "Reinstated", "Destination",
            "Status", "Effective Date", "Carrier",
        ]
        ing = HealthSherpaIngester("unused.csv")
        assert ing.identify_phi_columns(pd.DataFrame(columns=cols)) == []

    def test_mixed_returns_only_phi_in_order(self):
        df = pd.DataFrame(columns=["Premium", "Email", "Carrier", "DOB"])
        assert HealthSherpaIngester("x.csv").identify_phi_columns(df) == ["Email", "DOB"]

    def test_no_columns_returns_empty_list(self):
        assert HealthSherpaIngester("x.csv").identify_phi_columns(pd.DataFrame()) == []


class TestValidate:
    def test_valid(self):
        df = pd.DataFrame({"a": [1]})
        assert HealthSherpaIngester("x.csv").validate(df) is None

    def test_no_rows(self):
        with pytest.raises(ValueError, match="^DataFrame has no rows$"):
            HealthSherpaIngester("x.csv").validate(pd.DataFrame(columns=["a"]))

    def test_fully_empty_reports_no_rows(self):
        with pytest.raises(ValueError, match="^DataFrame has no rows$"):
            HealthSherpaIngester("x.csv").validate(pd.DataFrame())

    def test_no_columns(self):
        df = pd.DataFrame(index=[0, 1])
        with pytest.raises(ValueError, match="^DataFrame has no columns$"):
            HealthSherpaIngester("x.csv").validate(df)


def test_module_has_no_hermes_imports():
    import inspect

    import hermes.ingest.healthsherpa as mod

    src = inspect.getsource(mod)
    assert "import hermes" not in src and "from hermes" not in src
