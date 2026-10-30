"""CSV loading and normalization for cryptographic metadata."""

from __future__ import annotations

import csv
import io
from dataclasses import dataclass

import pandas as pd


ALIASES = {
    "algorithm": ("algorithm", "alg"),
    "key_id": ("key_id", "key_identifier", "keyid"),
    "nonce": ("nonce", "iv", "initialization_vector"),
    "record_id": ("record_id", "record_identifier", "id"),
    "public_key_fingerprint": ("public_key_fingerprint", "key_fingerprint", "fingerprint"),
    "key_type": ("key_type", "public_key_type"),
    "key_size_bits": ("key_size_bits", "key_size", "bits"),
    "generation_output_fingerprint": ("generation_output_fingerprint",),
}


@dataclass
class ValidationResult:
    records: pd.DataFrame
    messages: list[str]
    duplicate_rows_removed: int
    missing_columns: list[str]


def validate_records(records: pd.DataFrame) -> ValidationResult:
    """Normalize supported header aliases and report data quality issues."""
    if not isinstance(records, pd.DataFrame):
        raise TypeError("Records must be provided as a pandas DataFrame.")

    normalized = records.copy()
    normalized.columns = [str(column).strip().casefold() for column in normalized.columns]
    for canonical, aliases in ALIASES.items():
        if canonical not in normalized.columns:
            alias = next((name for name in aliases if name in normalized.columns), None)
            if alias:
                normalized = normalized.rename(columns={alias: canonical})

    messages: list[str] = []
    required = ("algorithm", "key_id", "nonce", "record_id")
    missing = [column for column in required if column not in normalized.columns]
    if missing:
        messages.append("Missing columns: " + ", ".join(missing))
    for column in ALIASES:
        if column not in normalized.columns:
            normalized[column] = pd.NA
        normalized[column] = normalized[column].astype("string")

    duplicate_count = int(normalized.duplicated().sum())
    if duplicate_count:
        normalized = normalized.drop_duplicates().reset_index(drop=True)
        messages.append(f"Removed {duplicate_count} exact duplicate row(s) for analysis.")

    if normalized.empty:
        messages.append("The dataset contains no records.")
    for column in required:
        if column in normalized and normalized[column].isna().all():
            messages.append(f"Column '{column}' has no populated values.")

    return ValidationResult(normalized, messages, duplicate_count, missing)


def read_csv_upload(uploaded_file) -> pd.DataFrame:
    """Read an uploaded CSV without modifying its original file."""
    position = uploaded_file.tell() if hasattr(uploaded_file, "tell") else None
    try:
        raw = uploaded_file.read()
        if position is not None and hasattr(uploaded_file, "seek"):
            uploaded_file.seek(position)
        text = raw.decode("utf-8-sig") if isinstance(raw, bytes) else raw
        if not isinstance(text, str):
            raise ValueError("CSV input must be text or UTF-8 encoded bytes.")
        rows = csv.reader(io.StringIO(text, newline=""), strict=True)
        header = next(rows, None)
        if header is None:
            raise ValueError("The CSV file is empty.")
        for line_number, row in enumerate(rows, start=2):
            if row and len(row) != len(header):
                raise ValueError(
                    f"Row {line_number} has {len(row)} fields; expected {len(header)}."
                )
        return pd.read_csv(io.StringIO(text), dtype=str, keep_default_na=False)
    except (csv.Error, pd.errors.EmptyDataError, pd.errors.ParserError, UnicodeDecodeError, ValueError) as error:
        if position is not None and hasattr(uploaded_file, "seek"):
            uploaded_file.seek(position)
        raise ValueError(f"Could not read this CSV: {error}") from error
