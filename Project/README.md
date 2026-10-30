# Detection of Nonce Reuse and Weak Key Generation in Deployed Systems

An educational, offline dashboard that screens **cryptographic metadata** for possible nonce/IV reuse and weak-key indicators. It is intended for college demonstrations and authorized defensive analysis. It does not scan systems, decrypt data, collect secret keys, or send uploaded files to an external service.

> **Interpret results carefully:** a finding is a review lead, not proof that a system is compromised. A missing finding is not proof of security. The bundled sample is fictional demonstration data, not evidence from deployed systems.

## What the project explains and checks

- A **nonce** (number used once) is intended for one use within a particular cryptographic context. Reuse can undermine security in some schemes, but the relevant rule depends on the algorithm, mode, key, and usage.
- An **initialization vector (IV)** initializes some encryption modes. Its uniqueness or unpredictability requirements depend on the construction; an IV is not automatically a secret.
- Nonce/IV comparison uses the **algorithm + key identifier + nonce** context. Algorithm labels are case-insensitive; key identifiers and nonce strings are compared exactly after trimming outer whitespace. This avoids assuming unknown nonce encodings are case-insensitive. A repeat under a different key is not grouped as the same context. Records missing one of those values are not eligible for this comparison.
- A **public-key fingerprint** is an identifier derived from public-key data. A repeated fingerprint may be normal key reuse or duplicate inventory records; it is not equivalent to weak randomness.
- **RSA key size** is the bit length of the RSA modulus. The default 2048-bit threshold is a simple educational screening setting, not a guarantee or a complete security policy.
- **Weak randomness** is a generator problem that may make key material predictable. These metadata checks cannot prove it. Repeated generation-output indicators are flagged only as a lead and require validation of what the field means.

The current educational algorithm list recognizes AES-GCM, AES-CCM, ChaCha20-Poly1305, RSA, ECDSA, Ed25519, X25519, and `unknown` as labels. Unknown labels are reported and are not nonce-checked. Recognition does not mean all algorithm-specific usage rules are implemented.

## Project structure

```text
app.py
detector.py
data_validator.py
requirements.txt
run_project.bat
sample_data/
  synthetic_crypto_records.csv
tests/
  test_nonce_detection.py
  test_weak_key_checks.py
  test_data_validation.py
reports/
```

## Architecture and data flow

1. The user uploads a CSV or loads the clearly marked fictional sample.
2. `data_validator.py` normalizes known header aliases, removes exact duplicate rows for analysis, and reports missing fields/data.
3. `detector.py` groups nonces by algorithm, key identifier, and nonce; checks public-key fingerprint repeats, RSA key sizes, and supplied repeated generation-output indicators.
4. The Streamlit app presents findings, data-source labels, summary metrics, and a chart derived from the selected dataset.
5. The user downloads a CSV report with findings and limitations.

The original upload is not modified. The app analyzes records in the local process. Do not include private keys, passwords, access tokens, or other secret material.

## Input CSV format

Recommended columns:

| Column | Required for | Example |
|---|---|---|
| `record_id` | Identifying affected records | `record-001` |
| `algorithm` | Nonce context | `AES-GCM` |
| `key_id` | Non-secret key context identifier | `service-key-A` |
| `nonce` | Nonce/IV comparison | `0011aabb` |
| `public_key_fingerprint` | Repeated public key check | `sha256:...` |
| `key_type` | RSA key-size check | `RSA` |
| `key_size_bits` | RSA key-size check | `2048` |
| `generation_output_fingerprint` | Optional repeated output indicator | `inventory-label-42` |

The minimum nonce check needs `algorithm`, a non-secret `key_id` (or `public_key_fingerprint` as the key-context identifier), and `nonce`. The app accepts these aliases: `alg`; `key_identifier`/`keyid`; `iv`/`initialization_vector`; `record_identifier`/`id`; `key_fingerprint`/`fingerprint`; `public_key_type`; and `key_size`/`bits`. Header matching is case-insensitive. Unsupported algorithms are identified rather than silently treated as supported.

The bundled `sample_data/synthetic_crypto_records.csv` includes a repeated nonce in one key context, a nonce repeated across different keys (not flagged as same-context reuse), a repeated public-key fingerprint, a small RSA key, normal examples, and missing/malformed metadata. Every row is fictional.

## Install and run on Windows

1. Install Python 3.10 or newer from [python.org](https://www.python.org/downloads/). Select **Add Python to PATH** during setup.
2. Open this folder in VS Code / File Explorer.
3. Double-click `run_project.bat`. On first launch it creates `.venv`, installs the packages, and starts Streamlit. Keep the terminal window open.
4. Open **http://localhost:8501** in your browser.
5. Select **Upload Dataset**, choose **Load synthetic example**, and click **Analyze selected dataset**.
6. Explore **Nonce Reuse Analysis**, **Weak Key Checks**, and **Results**. Download the report from Results.

The first run needs internet access to install packages from the Python package index. Analysis itself is offline. Troubleshooting: confirm Python 3.10+ is installed; reopen a terminal after changing PATH; check that package installation succeeded; or run the commands below manually. The batch file keeps its window open and prints an error message on failure.

### Create a Windows desktop shortcut

Right-click `run_project.bat` in File Explorer and choose **Show more options → Create shortcut** (or **Send to → Desktop (create shortcut)**). Rename the shortcut if desired. Its target should remain the project batch file; keep the project folder in place.

## Run tests

From PowerShell in the project directory:

```powershell
py -3.10 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pytest -q
```

If PowerShell blocks activation, skip activation and run `.\.venv\Scripts\python.exe -m pytest -q`.

## How to interpret results

- **Repeated nonce/IV in key context:** the same normalized value occurs more than once for the same algorithm and key identifier. Confirm that records are comparable, the algorithm's rules, and whether repetition was permitted. Repeated values across distinct key identifiers are not flagged as same-context reuse.
- **Repeated public-key fingerprint:** the same public-key identifier appears multiple times. This can be routine reuse or duplicate data.
- **Malformed public-key fingerprint:** obvious internal whitespace or control characters are identified; fingerprint formats are not comprehensively validated because formats vary.
- **RSA key below threshold:** the supplied key size is lower than the currently selected threshold. Investigate using your organization's policies and approved cryptographic guidance.
- **Missing/malformed metadata:** one or more checks may be incomplete. These are data-quality findings, not cryptographic vulnerabilities by themselves.
- **Repeated generation output indicator:** the supplied label repeats. First confirm what it represents. This is not proof of weak randomness.
- **No findings:** only means that these implemented checks found no matching pattern in these records. It does not establish that the system is secure.
- Exact duplicate rows are excluded from analysis and counted. Missing columns and unsupported algorithm names are surfaced in the interface.

## Limitations and future improvements

This tool does not inspect ciphertext, infer algorithm modes from traffic, validate all algorithm-specific nonce rules, assess private keys, establish key provenance, or prove randomness quality. Real authorized datasets should be gathered under the system owner's approval, reviewed to remove secrets and personal data, and interpreted by qualified cryptography/security staff. Future work could add reviewed algorithm-specific policies, richer provenance, and safe integrations with authorized inventory exports.

## Technologies

Python, Streamlit, Pandas, CSV, and Pytest. No paid APIs, database, authentication service, or external analysis service is used.
