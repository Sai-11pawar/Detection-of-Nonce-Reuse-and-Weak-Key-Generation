"""Defensive checks for cryptographic metadata records."""

from __future__ import annotations

import pandas as pd

from data_validator import validate_records


SUPPORTED_ALGORITHMS = {
    "aes-gcm",
    "aes-ccm",
    "chacha20-poly1305",
    "rsa",
    "ecdsa",
    "ed25519",
    "x25519",
}


def analyze_records(
    records: pd.DataFrame,
    *,
    source: str = "uploaded",
    min_rsa_bits: int = 2048,
) -> dict:
    """Validate records and return findings, summary, and analysis context."""
    validation = validate_records(records)
    data = validation.records.copy()
    findings: list[dict] = []

    for _, row in data.iterrows():
        record_id = _value(row, "record_id") or "(record ID missing)"
        algorithm = _value(row, "algorithm")
        if algorithm and algorithm.casefold() not in SUPPORTED_ALGORITHMS:
            findings.append(_finding(
                record_id, "Unsupported algorithm metadata",
                f"'{algorithm}' is not in the educational algorithm list; nonce requirements were not assessed.",
                "Review algorithm metadata",
            ))

        key_id = _value(row, "key_id") or _value(row, "public_key_fingerprint")
        nonce = _value(row, "nonce")
        if not algorithm:
            findings.append(_finding(record_id, "Missing algorithm metadata",
                                     "Nonce reuse could not be checked for this record.",
                                     "Supply the algorithm name"))
        if not key_id:
            findings.append(_finding(record_id, "Missing key identity",
                                     "Nonce reuse could not be grouped into a key context.",
                                     "Supply a non-secret key identifier or public-key fingerprint"))
        if not nonce:
            findings.append(_finding(record_id, "Missing nonce/IV",
                                     "This record was not eligible for nonce reuse comparison.",
                                     "Supply the nonce or IV metadata"))

    data["_key_context"] = data.apply(
        lambda row: _value(row, "key_id") or _value(row, "public_key_fingerprint"), axis=1
    )
    eligible = data[
        data["algorithm"].fillna("").astype(str).str.strip().ne("")
        & data["_key_context"].ne("")
        & data["nonce"].fillna("").astype(str).str.strip().ne("")
        & data["algorithm"].fillna("").astype(str).str.strip().str.casefold().isin(SUPPORTED_ALGORITHMS)
    ].copy()
    eligible["_algorithm_context"] = eligible["algorithm"].str.strip().str.casefold()
    eligible["_nonce_context"] = eligible["nonce"].str.strip()

    for (algorithm, key_id, nonce), group in eligible.groupby(
        ["_algorithm_context", "_key_context", "_nonce_context"], dropna=False, sort=False
    ):
        if len(group) < 2:
            continue
        ids = _record_ids(group)
        detail = (
            f"Nonce/IV repeats {len(group)} times for algorithm '{algorithm}' "
            f"and key identifier '{key_id}'. A repeat is a review indicator, "
            "not proof of compromise."
        )
        for record_id in ids:
            findings.append(_finding(record_id, "Repeated nonce/IV in key context", detail,
                                     "Verify algorithm requirements and investigate authorized records"))

    fingerprints = data.copy()
    fingerprints["_fingerprint_context"] = fingerprints["public_key_fingerprint"].map(
        lambda value: str(value).strip() if _present(value) else ""
    )
    fingerprints = fingerprints[fingerprints["_fingerprint_context"].ne("")]
    for _, row in data.iterrows():
        fingerprint = _value(row, "public_key_fingerprint")
        if fingerprint and any(character.isspace() or ord(character) < 32 for character in fingerprint):
            findings.append(_finding(
                _value(row, "record_id") or "(record ID missing)",
                "Malformed public-key fingerprint",
                "Fingerprint metadata contains internal whitespace or control characters.",
                "Check the fingerprint's source and provide a stable non-secret identifier",
            ))
    for fingerprint, group in fingerprints.groupby("_fingerprint_context", sort=False):
        if len(group) < 2:
            continue
        ids = _record_ids(group)
        for record_id in ids:
            findings.append(_finding(
                record_id, "Repeated public-key fingerprint",
                f"Public-key fingerprint '{fingerprint}' appears in {len(group)} records. "
                "This can be expected when a key is reused; it does not prove weak randomness.",
                "Confirm whether the shared key is expected",
            ))

    for _, row in data.iterrows():
        record_id = _value(row, "record_id") or "(record ID missing)"
        key_type = _value(row, "key_type")
        key_size = _parse_key_size(row.get("key_size_bits"))
        if key_type.casefold() == "rsa":
            if key_size is None:
                findings.append(_finding(record_id, "Missing or malformed RSA key size",
                                         "RSA key size was absent or was not a positive whole number.",
                                         "Provide key_size_bits from an authorized inventory"))
            elif key_size < min_rsa_bits:
                findings.append(_finding(
                    record_id, "RSA key below screening threshold",
                    f"RSA key size is {key_size} bits, below the configured educational "
                    f"screening threshold of {min_rsa_bits} bits.",
                    "Review the key against your organization's current policy",
                ))
        elif key_type and key_size is None and _present(row.get("key_size_bits")):
            findings.append(_finding(record_id, "Malformed key-size metadata",
                                     "Key size must be a positive whole number.",
                                     "Correct or remove the malformed key size"))

        if key_type and not _value(row, "public_key_fingerprint"):
            findings.append(_finding(record_id, "Missing public-key fingerprint",
                                     "Public-key repetition could not be checked for this record.",
                                     "Provide a fingerprint, not the public key material"))

        generation_output = row.get("generation_output_fingerprint")
        if _present(generation_output):
            output_key = str(generation_output).strip()
            matches = data[
                data["generation_output_fingerprint"].map(
                    lambda value: _present(value) and str(value).strip() == output_key
                )
            ]
            if len(matches) > 1:
                findings.append(_finding(
                    record_id, "Repeated key-generation output indicator",
                    f"The supplied non-secret generation-output indicator appears in "
                    f"{len(matches)} records. This repetition alone does not prove weak randomness.",
                    "Validate the field's meaning and investigate the generator using authorized evidence",
                ))

    findings_frame = pd.DataFrame(
        findings, columns=["record_id", "finding", "details", "recommended_action"]
    )
    summary = {
        "records_analyzed": len(data),
        "repeated_nonce_contexts": int(
            sum(
                1
                for _, group in eligible.groupby(
                    ["_algorithm_context", "_key_context", "_nonce_context"], sort=False
                )
                if len(group) > 1
            )
        ),
        "repeated_public_key_fingerprints": int(
            sum(1 for _, group in fingerprints.groupby("_fingerprint_context", sort=False) if len(group) > 1)
        ),
        "weak_key_indicators": int(
            findings_frame["finding"].isin(
                ["RSA key below screening threshold", "Repeated key-generation output indicator"]
            ).sum()
        ) if not findings_frame.empty else 0,
        "finding_count": len(findings_frame),
        "duplicate_rows_removed": validation.duplicate_rows_removed,
    }
    checks = [
        "Nonce/IV repeats grouped by case-insensitive algorithm label and exact trimmed key/nonce values",
        "Repeated non-secret public-key fingerprints",
        f"RSA key-size screening (minimum {min_rsa_bits} bits)",
        "Missing or malformed metadata and unsupported algorithm labels",
        "Repeated supplied key-generation output indicators, if present",
    ]
    return {
        "source": source,
        "records": data,
        "findings": findings_frame,
        "summary": summary,
        "checks": checks,
        "validation": validation,
        "min_rsa_bits": min_rsa_bits,
    }


def build_report(analysis: dict) -> pd.DataFrame:
    """Create a downloadable CSV with dataset context on every report row."""
    findings = analysis["findings"]
    summary = analysis["summary"]
    if findings.empty:
        findings = pd.DataFrame([{
            "record_id": "",
            "finding": "No findings from available metadata",
            "details": "This does not prove that the system is secure or that no issue exists.",
            "recommended_action": "Review coverage and limitations before drawing conclusions",
        }])
    report = findings.copy()
    report.insert(0, "dataset_source", analysis["source"])
    report.insert(1, "records_analyzed", summary["records_analyzed"])
    report.insert(2, "checks_performed", "; ".join(analysis["checks"]))
    report.insert(3, "duplicate_rows_removed", summary["duplicate_rows_removed"])
    report.insert(4, "repeated_nonce_contexts", summary["repeated_nonce_contexts"])
    report.insert(5, "repeated_public_key_fingerprints",
                  summary["repeated_public_key_fingerprints"])
    report.insert(6, "weak_key_indicators", summary["weak_key_indicators"])
    report.insert(7, "limitations",
                  "Metadata-only screening; findings require context and authorized verification. "
                  "Weak randomness cannot be proven from these fields alone.")
    return report


def _finding(record_id: str, name: str, details: str, action: str) -> dict:
    return {
        "record_id": record_id,
        "finding": name,
        "details": details,
        "recommended_action": action,
    }


def _record_ids(group: pd.DataFrame) -> list[str]:
    return [
        _value(row, "record_id") or "(record ID missing)"
        for _, row in group.iterrows()
    ]


def _value(row: pd.Series, column: str) -> str:
    value = row.get(column)
    return str(value).strip() if _present(value) else ""


def _present(value: object) -> bool:
    if value is None:
        return False
    try:
        if pd.isna(value):
            return False
    except (TypeError, ValueError):
        pass
    return str(value).strip() != ""


def _parse_key_size(value: object) -> int | None:
    if not _present(value):
        return None
    try:
        parsed = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None
