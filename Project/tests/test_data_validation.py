import io

import pandas as pd
import pytest

from data_validator import read_csv_upload, validate_records
from detector import analyze_records, build_report


def test_missing_columns_and_blank_values_are_reported():
    result = analyze_records(pd.DataFrame([{"id": "r1", "alg": "", "iv": ""}]))
    assert result["validation"].missing_columns == ["key_id"]
    assert "Missing algorithm metadata" in set(result["findings"]["finding"])
    assert "Missing key identity" in set(result["findings"]["finding"])
    assert "Missing nonce/IV" in set(result["findings"]["finding"])


def test_exact_duplicate_rows_removed_and_reported():
    validation = validate_records(pd.DataFrame([
        {"record_id": "r1", "algorithm": "AES-GCM", "key_id": "k", "nonce": "n"},
        {"record_id": "r1", "algorithm": "AES-GCM", "key_id": "k", "nonce": "n"},
    ]))
    assert len(validation.records) == 1
    assert validation.duplicate_rows_removed == 1


def test_empty_dataset_is_supported():
    result = analyze_records(pd.DataFrame())
    assert result["summary"]["records_analyzed"] == 0
    assert result["findings"].empty
    assert "The dataset contains no records." in result["validation"].messages


def test_normal_records_have_no_findings():
    result = analyze_records(pd.DataFrame([
        {"record_id": "r1", "algorithm": "AES-GCM", "key_id": "k1", "nonce": "n1",
         "public_key_fingerprint": "fp1", "key_type": "RSA", "key_size_bits": "2048"},
        {"record_id": "r2", "algorithm": "AES-GCM", "key_id": "k2", "nonce": "n1",
         "public_key_fingerprint": "fp2", "key_type": "RSA", "key_size_bits": "3072"},
    ]))
    assert result["findings"].empty


def test_report_contains_source_count_findings_and_limits():
    analysis = analyze_records(pd.DataFrame([
        {"record_id": "r1", "algorithm": "AES-GCM", "key_id": "k", "nonce": "n"},
        {"record_id": "r2", "algorithm": "AES-GCM", "key_id": "k", "nonce": "n"},
    ]), source="synthetic demonstration")
    report = build_report(analysis)
    assert report["dataset_source"].eq("synthetic demonstration").all()
    assert report["records_analyzed"].eq(2).all()
    assert report["finding"].str.contains("Repeated nonce").any()
    assert report["limitations"].str.contains("cannot be proven").all()
    assert report["repeated_nonce_contexts"].eq(1).all()
    assert report["repeated_public_key_fingerprints"].eq(0).all()


def test_csv_parser_rejects_malformed_rows():
    with pytest.raises(ValueError, match="Could not read this CSV"):
        read_csv_upload(io.StringIO("record_id,algorithm\nr1,AES-GCM,extra\n"))
