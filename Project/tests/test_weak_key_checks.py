import pandas as pd

from detector import analyze_records


def test_repeated_public_key_fingerprint_is_reported():
    data = pd.DataFrame([
        {"record_id": "r1", "public_key_fingerprint": "fingerprint-1"},
        {"record_id": "r2", "public_key_fingerprint": "fingerprint-1"},
    ])
    result = analyze_records(data)
    repeated = result["findings"].query("finding == 'Repeated public-key fingerprint'")
    assert set(repeated["record_id"]) == {"r1", "r2"}
    assert result["summary"]["repeated_public_key_fingerprints"] == 1


def test_rsa_below_threshold_is_flagged_but_at_threshold_is_not():
    data = pd.DataFrame([
        {"record_id": "small", "key_type": "RSA", "key_size_bits": "1024"},
        {"record_id": "ok", "key_type": "RSA", "key_size_bits": "2048"},
    ])
    result = analyze_records(data)
    weak = result["findings"].query("finding == 'RSA key below screening threshold'")
    assert list(weak["record_id"]) == ["small"]
    assert result["summary"]["weak_key_indicators"] == 1


def test_malformed_size_and_missing_fingerprint_are_distinct_findings():
    result = analyze_records(pd.DataFrame([
        {"record_id": "r1", "key_type": "RSA", "key_size_bits": "not-a-size"},
    ]))
    findings = set(result["findings"]["finding"])
    assert "Missing or malformed RSA key size" in findings
    assert "Missing public-key fingerprint" in findings


def test_malformed_fingerprint_format_is_reported():
    result = analyze_records(pd.DataFrame([
        {"record_id": "r1", "public_key_fingerprint": "bad fingerprint"},
    ]))
    assert "Malformed public-key fingerprint" in set(result["findings"]["finding"])


def test_repeated_generation_indicator_is_not_proof_of_weak_randomness():
    result = analyze_records(pd.DataFrame([
        {"record_id": "r1", "generation_output_fingerprint": "output-1"},
        {"record_id": "r2", "generation_output_fingerprint": "output-1"},
    ]))
    assert result["summary"]["weak_key_indicators"] == 2
    details = result["findings"].query(
        "finding == 'Repeated key-generation output indicator'"
    )["details"].iloc[0]
    assert "does not prove weak randomness" in details
