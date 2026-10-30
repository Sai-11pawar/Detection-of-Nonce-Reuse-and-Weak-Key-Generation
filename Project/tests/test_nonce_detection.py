import pandas as pd

from detector import analyze_records


def records(rows):
    return pd.DataFrame(rows)


def test_repeated_nonce_same_algorithm_and_key_is_reported():
    result = analyze_records(records([
        {"record_id": "r1", "algorithm": "AES-GCM", "key_id": "key-a", "nonce": "ab12"},
        {"record_id": "r2", "algorithm": "aes-gcm", "key_id": "key-a", "nonce": "ab12"},
    ]))
    repeated = result["findings"].query("finding == 'Repeated nonce/IV in key context'")
    assert set(repeated["record_id"]) == {"r1", "r2"}
    assert result["summary"]["repeated_nonce_contexts"] == 1


def test_same_nonce_across_different_keys_is_not_reported_as_reuse():
    result = analyze_records(records([
        {"record_id": "r1", "algorithm": "AES-GCM", "key_id": "key-a", "nonce": "ab12"},
        {"record_id": "r2", "algorithm": "AES-GCM", "key_id": "key-b", "nonce": "ab12"},
    ]))
    assert "Repeated nonce/IV in key context" not in set(result["findings"]["finding"])
    assert result["summary"]["repeated_nonce_contexts"] == 0


def test_public_key_fingerprint_can_supply_key_context():
    result = analyze_records(records([
        {"record_id": "r1", "algorithm": "AES-GCM", "public_key_fingerprint": "fp-a", "nonce": "ab12"},
        {"record_id": "r2", "algorithm": "AES-GCM", "public_key_fingerprint": "fp-a", "nonce": "ab12"},
    ]))
    assert "Repeated nonce/IV in key context" in set(result["findings"]["finding"])
    assert "Missing key identity" not in set(result["findings"]["finding"])


def test_nonce_comparison_does_not_fold_case_without_encoding_metadata():
    result = analyze_records(records([
        {"record_id": "r1", "algorithm": "AES-GCM", "key_id": "key-a", "nonce": "Ab12"},
        {"record_id": "r2", "algorithm": "AES-GCM", "key_id": "key-a", "nonce": "ab12"},
    ]))
    assert "Repeated nonce/IV in key context" not in set(result["findings"]["finding"])


def test_unsupported_algorithm_is_reported_not_nonce_checked():
    result = analyze_records(records([
        {"record_id": "r1", "algorithm": "made-up", "key_id": "key-a", "nonce": "ab12"},
        {"record_id": "r2", "algorithm": "made-up", "key_id": "key-a", "nonce": "ab12"},
    ]))
    assert "Unsupported algorithm metadata" in set(result["findings"]["finding"])
    assert "Repeated nonce/IV in key context" not in set(result["findings"]["finding"])
