from __future__ import annotations

from pathlib import Path

import pandas as pd
import streamlit as st

from data_validator import read_csv_upload
from detector import analyze_records, build_report


st.set_page_config(page_title="Crypto Metadata Safety Check", page_icon="🔐", layout="wide")
st.markdown(
    """
    <style>
    .stApp { background: #071321; color: #e7f1f7; }
    [data-testid="stSidebar"] { background: #0b1d2c; }
    h1, h2, h3 { color: #e8f7ff; }
    .intro { color: #b7cbd8; font-size: 1.05rem; }
    .notice { background: #102b3b; border-left: 4px solid #31d4d0; padding: 0.8rem 1rem; border-radius: 6px; }
    div[data-testid="stMetric"] { background: #102536; border: 1px solid #1c4655; padding: 1rem; border-radius: 10px; }
    .stButton button, .stDownloadButton button { border-radius: 7px; }
    </style>
    """,
    unsafe_allow_html=True,
)

SAMPLE_PATH = Path(__file__).parent / "sample_data" / "synthetic_crypto_records.csv"
PAGES = ["Overview", "Upload Dataset", "Nonce Reuse Analysis", "Weak Key Checks", "Results"]


def _source_notice() -> None:
    source = st.session_state.source
    if source and source.startswith("synthetic"):
        st.warning(
            f"SIMULATED DEMONSTRATION DATA — {source}. These are fictional examples, "
            "not findings from deployed systems."
        )
    elif source:
        st.info(f"Analysis source: {source}. Results describe only the supplied records.")


def _analysis_table(finding_names) -> None:
    analysis = st.session_state.analysis
    if analysis is None:
        st.info("Load data and analyze it to view findings here.")
        return
    _source_notice()
    names = [finding_names] if isinstance(finding_names, str) else finding_names
    subset = analysis["findings"][analysis["findings"]["finding"].isin(names)]
    if subset.empty:
        st.success("No matching findings in the available metadata, or the required fields were not supplied.")
    else:
        st.dataframe(subset, use_container_width=True, hide_index=True)


st.sidebar.title("🔐 Crypto Safety Check")
page = st.sidebar.radio("Navigate", PAGES)
st.sidebar.caption("Offline metadata analysis • No secrets needed")

if "records" not in st.session_state:
    st.session_state.records = None
    st.session_state.source = None
    st.session_state.analysis = None

st.title("Detection of Nonce Reuse and Weak Key Generation")
st.markdown(
    '<p class="intro">A beginner-friendly, offline screening tool for authorized cryptographic metadata. '
    "It does not scan systems, collect secret keys, or prove compromise.</p>",
    unsafe_allow_html=True,
)

if page == "Overview":
    st.markdown(
        '<div class="notice"><b>Important:</b> A flagged record is a lead for authorized review, not proof '
        "that a system is vulnerable. Synthetic examples are fictional and clearly marked.</div>",
        unsafe_allow_html=True,
    )
    st.subheader("What this project checks")
    st.write(
        "- **Nonce/IV reuse:** same value repeated for the same algorithm and key identifier.\n"
        "- **Public-key metadata:** repeated fingerprints and RSA sizes below a configurable educational threshold.\n"
        "- **Data quality:** missing, malformed, duplicate, or unsupported metadata."
    )
    st.info("Start in **Upload Dataset** to load the fictional demo or your authorized CSV, then run the analysis.")

elif page == "Upload Dataset":
    st.subheader("Choose a metadata CSV")
    st.caption("Use metadata only. Do not include private keys, passwords, access tokens, or other secrets.")
    uploaded = st.file_uploader("Upload CSV", type=["csv"])
    col_a, col_b = st.columns(2)
    with col_a:
        if st.button("Load synthetic example", type="secondary"):
            try:
                st.session_state.records = pd.read_csv(SAMPLE_PATH, dtype=str, keep_default_na=False)
                st.session_state.source = "synthetic demonstration (fictional)"
                st.session_state.analysis = None
                st.success("Synthetic demonstration dataset loaded. It is not real deployment data.")
            except (OSError, pd.errors.ParserError, UnicodeDecodeError) as error:
                st.error(f"Could not load the bundled synthetic dataset: {error}")
    with col_b:
        if st.button("Reset dataset"):
            st.session_state.records = None
            st.session_state.source = None
            st.session_state.analysis = None
            st.rerun()
    if uploaded is not None and st.button("Use uploaded dataset"):
        try:
            st.session_state.records = read_csv_upload(uploaded)
            st.session_state.source = f"uploaded: {uploaded.name}"
            st.session_state.analysis = None
            st.success("CSV loaded locally. The original uploaded file is not changed or sent anywhere.")
        except ValueError as error:
            st.error(str(error))
    if st.session_state.records is not None:
        _source_notice()
        st.write(f"Loaded {len(st.session_state.records)} raw records.")
        st.dataframe(st.session_state.records.head(20), use_container_width=True)
        threshold = st.number_input("RSA screening threshold (bits)", min_value=1024, max_value=8192,
                                    value=2048, step=256)
        if st.button("Analyze selected dataset", type="primary"):
            st.session_state.analysis = analyze_records(
                st.session_state.records, source=st.session_state.source, min_rsa_bits=threshold
            )
            st.success("Analysis complete. Findings describe supplied metadata only.")

elif page == "Nonce Reuse Analysis":
    st.subheader("Nonce and initialization vector review")
    st.write(
        "A **nonce** (number used once) is a value intended for one use in a particular cryptographic context. "
        "An **initialization vector (IV)** is a value used to initialize some encryption modes; its required "
        "uniqueness or unpredictability depends on the algorithm and mode."
    )
    st.write("This tool groups by algorithm + key identifier + nonce. Repeated values across different keys "
             "are not counted as a repeated nonce context.")
    _analysis_table("Repeated nonce/IV in key context")

elif page == "Weak Key Checks":
    st.subheader("Key-generation indicators")
    st.write(
        "A **public-key fingerprint** is a short identifier derived from public key data; repeating one may "
        "simply mean the same key was recorded more than once. **RSA key size** is the number of bits in the "
        "modulus. The default 2048-bit threshold is an educational screening value, not a complete policy."
    )
    st.warning("Repeated keys, small key sizes, and weak randomness are different claims. These metadata "
               "checks do not prove that a random-number generator was weak.")
    st.write(
        "**Weak randomness** means key material may be predictable because the random-number "
        "generator or its inputs were inadequate. Proving this generally requires reliable "
        "generator evidence; repeated public keys or output labels alone are not proof."
    )
    _analysis_table(["Repeated public-key fingerprint", "RSA key below screening threshold",
                    "Repeated key-generation output indicator", "Missing or malformed RSA key size",
                    "Missing public-key fingerprint"])

elif page == "Results":
    st.subheader("Analysis results and report")
    analysis = st.session_state.analysis
    if analysis is None:
        st.info("Load a dataset and click **Analyze selected dataset** first.")
    else:
        _source_notice()
        summary = analysis["summary"]
        columns = st.columns(4)
        labels = [
            ("Records analyzed", summary["records_analyzed"]),
            ("Repeated nonce contexts", summary["repeated_nonce_contexts"]),
            ("Repeated public-key fingerprints", summary["repeated_public_key_fingerprints"]),
            ("Weak-key indicators", summary["weak_key_indicators"]),
        ]
        for column, (label, value) in zip(columns, labels):
            column.metric(label, value)
        st.caption(f"Exact duplicate rows excluded from checks: {summary['duplicate_rows_removed']}")
        if analysis["findings"].empty:
            st.success("No findings from the available metadata. This does not prove the dataset or system is secure.")
        else:
            st.dataframe(analysis["findings"], use_container_width=True, hide_index=True)
        st.subheader("Findings in this dataset")
        counts = analysis["findings"]["finding"].value_counts()
        st.bar_chart(counts, color="#31d4d0")
        st.subheader("Checks performed")
        for item in analysis["checks"]:
            st.write(f"- {item}")
        validation = analysis["validation"]
        for message in validation.messages:
            st.warning(message)
        report = build_report(analysis)
        st.download_button(
            "Download findings report (CSV)", report.to_csv(index=False).encode("utf-8"),
            file_name="crypto_metadata_analysis_report.csv", mime="text/csv",
        )
        st.caption("The report includes source, record count, checks, findings, limitations, and recommended actions.")
