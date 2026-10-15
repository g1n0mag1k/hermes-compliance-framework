"""Tests for Pseudonymizer and HealthSherpaIngester (synthetic PHI only)."""

from __future__ import annotations

import io

import pandas as pd
import pytest

from hermes.ingest.healthsherpa import HealthSherpaIngester
from hermes.pseudonymizer import Pseudonymizer


def _sample_broker_csv() -> str:
    return (
        "First Name,Last Name,SSN,DOB,Premium,Carrier\n"
        "Test_Name_A,Test_Name_B,000-00-0001,1900-01-01,100.00,Acme Health\n"
        "Test_Name_C,Test_Name_D,000-00-0002,1900-01-02,200.00,Acme Health\n"
    )


def test_phi_columns_identified_correctly(tmp_path):
    csv_path = tmp_path / "test.csv"
    csv_path.write_text(_sample_broker_csv(), encoding="utf-8")
    df = HealthSherpaIngester(csv_path).load()
    phi = HealthSherpaIngester(csv_path).identify_phi_columns(df)
    assert phi == ["First Name", "Last Name", "SSN", "DOB"]


def test_pseudonymize_replaces_phi_columns():
    df = pd.DataFrame(
        {
            "first_name": ["Test_Name_A"],
            "ssn": ["000-00-0001"],
            "premium": ["100.00"],
        }
    )
    pseudo = Pseudonymizer(["first_name", "ssn"])
    coded_df, linkage = pseudo.pseudonymize(df, transaction_id="txn-1")
    assert coded_df.loc[0, "first_name"].startswith("CLIENT_")
    assert coded_df.loc[0, "ssn"].startswith("CLIENT_")
    assert coded_df.loc[0, "first_name"] != "Test_Name_A"
    assert coded_df.loc[0, "ssn"] != "000-00-0001"
    assert len(linkage) == 2


def test_pseudonymize_leaves_non_phi_columns_unchanged():
    df = pd.DataFrame(
        {
            "first_name": ["Test_Name_A"],
            "premium": ["100.00"],
            "carrier": ["Acme Health"],
        }
    )
    pseudo = Pseudonymizer(["first_name"])
    coded_df, _ = pseudo.pseudonymize(df, transaction_id="txn-2")
    assert coded_df.loc[0, "premium"] == "100.00"
    assert coded_df.loc[0, "carrier"] == "Acme Health"


def test_pseudonymize_deterministic_same_input_same_code():
    df = pd.DataFrame({"ssn": ["000-00-0001", "000-00-0001"]})
    pseudo = Pseudonymizer(["ssn"])
    coded_df, linkage = pseudo.pseudonymize(df, transaction_id="txn-3")
    assert coded_df.loc[0, "ssn"] == coded_df.loc[1, "ssn"]
    assert len(linkage) == 1


def test_pseudonymize_empty_and_nan_values_unchanged():
    df = pd.DataFrame(
        {
            "first_name": ["", None, "Test_Name_A"],
            "ssn": [pd.NA, "", "000-00-0001"],
        }
    )
    pseudo = Pseudonymizer(["first_name", "ssn"])
    coded_df, linkage = pseudo.pseudonymize(df, transaction_id="txn-4")
    assert coded_df.loc[0, "first_name"] == ""
    assert pd.isna(coded_df.loc[1, "first_name"])
    assert pd.isna(coded_df.loc[0, "ssn"])
    assert coded_df.loc[1, "ssn"] == ""
    assert coded_df.loc[2, "first_name"].startswith("CLIENT_")
    assert len(linkage) == 2


def test_reassociate_restores_original_values():
    df = pd.DataFrame(
        {
            "first_name": ["Test_Name_A", "Test_Name_B"],
            "dob": ["1900-01-01", "1900-01-02"],
        }
    )
    pseudo = Pseudonymizer(["first_name", "dob"])
    coded_df, linkage = pseudo.pseudonymize(df, transaction_id="txn-5")
    restored = pseudo.reassociate(coded_df, linkage)
    assert restored.loc[0, "first_name"] == "Test_Name_A"
    assert restored.loc[1, "first_name"] == "Test_Name_B"
    assert restored.loc[0, "dob"] == "1900-01-01"
    assert restored.loc[1, "dob"] == "1900-01-02"
    assert not coded_df.equals(restored)


def test_reassociate_unknown_codes_left_unchanged():
    unknown_code = "CLIENT_not_in_linkage"
    coded_df = pd.DataFrame({"first_name": [unknown_code]})
    pseudo = Pseudonymizer(["first_name"])
    restored = pseudo.reassociate(coded_df, {})
    assert restored.loc[0, "first_name"] == unknown_code


def test_export_and_load_linkage_table_roundtrip(tmp_path):
    df = pd.DataFrame(
        {
            "first_name": ["Test_Name_A", "Test_Name_B", "Test_Name_C"],
            "ssn": ["000-00-0001", "000-00-0002", "000-00-0003"],
        }
    )
    pseudo = Pseudonymizer(["first_name", "ssn"])
    _, linkage = pseudo.pseudonymize(df, transaction_id="txn-roundtrip")
    out_path = tmp_path / "linkage.enc"
    pseudo.export_linkage_table(linkage, out_path)
    loaded = Pseudonymizer.load_linkage_table(out_path)
    assert loaded == linkage
    for code, entry in linkage.items():
        assert loaded[code] == entry
        assert loaded[code]["original"] == entry["original"]
        assert loaded[code]["column"] == entry["column"]
        assert loaded[code]["transaction_id"] == entry["transaction_id"]
        assert loaded[code]["coded_at"] == entry["coded_at"]


def test_export_raises_if_file_exists(tmp_path):
    out_path = tmp_path / "linkage.enc"
    out_path.write_text("existing", encoding="utf-8")
    pseudo = Pseudonymizer(["first_name"])
    with pytest.raises(FileExistsError):
        pseudo.export_linkage_table({}, out_path)


def test_load_raises_if_file_not_found(tmp_path):
    missing = tmp_path / "missing.enc"
    with pytest.raises(FileNotFoundError):
        Pseudonymizer.load_linkage_table(missing)


def test_healthsherpa_ingester_load_valid_csv(tmp_path):
    csv_path = tmp_path / "test.csv"
    buffer = io.StringIO(_sample_broker_csv())
    csv_path.write_text(buffer.getvalue(), encoding="utf-8")
    df = HealthSherpaIngester(csv_path).load()
    assert len(df) == 2
    assert df.loc[0, "First Name"] == "Test_Name_A"
    assert df.loc[0, "SSN"] == "000-00-0001"
    assert df.loc[0, "DOB"] == "1900-01-01"


def test_healthsherpa_ingester_raises_on_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        HealthSherpaIngester(tmp_path / "test.csv").load()


def test_healthsherpa_ingester_raises_on_empty_csv(tmp_path):
    csv_path = tmp_path / "test.csv"
    csv_path.write_text("first_name,last_name\n", encoding="utf-8")
    with pytest.raises(ValueError, match="^CSV has no rows$"):
        HealthSherpaIngester(csv_path).load()


def test_healthsherpa_validate_raises_on_empty_df():
    ingester = HealthSherpaIngester("unused.csv")
    with pytest.raises(ValueError, match="^DataFrame has no rows$"):
        ingester.validate(pd.DataFrame(columns=["first_name", "premium"]))
