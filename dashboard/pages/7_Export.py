import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import streamlit as st
from dashboard import api_client

st.set_page_config(page_title="Forensic Export — VidProof", layout="wide")
st.title("Forensic Export")
st.caption(
    "Generates a self-contained zip package that can be verified independently "
    "by any investigator using only standard tools (OpenSSL, Python 3)."
)

# Evidence selection
try:
    evidence_list = api_client.list_evidence()
    evidence_ids = [e["evidenceId"] for e in evidence_list] if evidence_list else []
except Exception:
    evidence_ids = []

if evidence_ids:
    evidence_id = st.selectbox("Evidence ID", evidence_ids)
else:
    evidence_id = st.text_input("Evidence ID", placeholder="ev-001")

st.divider()

export_clicked = st.button("Generate Export Package", type="primary", disabled=not evidence_id)

if export_clicked and evidence_id:
    with st.spinner("Building forensic package…"):
        try:
            zip_bytes = api_client.export_evidence(evidence_id.strip())
        except Exception as exc:
            st.error(f"Export failed: {exc}")
            st.stop()

    size_kb = len(zip_bytes) / 1024
    st.success(f"Package ready — {size_kb:.1f} KB", icon="📦")

    st.download_button(
        label="Download .zip",
        data=zip_bytes,
        file_name=f"{evidence_id}.zip",
        mime="application/zip",
        type="primary",
    )

    st.divider()
    st.subheader("Package Contents")
    st.markdown(f"""
| Path | Contents |
|---|---|
| `evidence/{evidence_id}.enc` | AES-256-GCM encrypted video (ciphertext only) |
| `metadata/evidence.json` | Immutable evidence record — hashes, signature, timestamps |
| `metadata/camera.json` | Enrolled camera record — Ed25519 public key |
| `metadata/verification-results/` | All verification runs for this evidence item |
| `tsa/token.tsr` | RFC 3161 timestamp token (if captured) |
| `fabric-history.json` | Hyperledger Fabric custody history (if Fabric is running) |
| `MANIFEST.json` | SHA-256 hashes of every file in this package |
| `VERIFY_INSTRUCTIONS.md` | Step-by-step independent verification guide |
""")

    st.info(
        "The recipient can verify the package without VidProof installed — "
        "the VERIFY_INSTRUCTIONS.md inside the zip contains all commands needed.",
        icon="ℹ️",
    )
