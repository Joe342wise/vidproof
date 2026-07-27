import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import streamlit as st
import pandas as pd
from dashboard import api_client

st.set_page_config(page_title="Evidence — VidProof", layout="wide")
st.title("Evidence")

# ---------------------------------------------------------------------------
# Capture form
# ---------------------------------------------------------------------------
with st.expander("Capture new evidence", expanded=False):
    with st.form("capture_form"):
        camera_id = st.text_input("Camera ID", placeholder="cam-001")
        evidence_id = st.text_input("Evidence ID (optional, auto-generated if blank)", placeholder="ev-001")
        uploaded = st.file_uploader("Video file", type=["mp4", "avi", "mkv", "mov", "bin"])
        submitted = st.form_submit_button("Capture")

    if submitted:
        if not camera_id:
            st.error("Camera ID is required.")
        elif uploaded is None:
            st.error("Please upload a video file.")
        else:
            with st.spinner("Encrypting and capturing…"):
                try:
                    result = api_client.capture_evidence(
                        camera_id=camera_id.strip(),
                        video_bytes=uploaded.read(),
                        filename=uploaded.name,
                        evidence_id=evidence_id.strip() or None,
                    )
                    if result.get("ok"):
                        st.success(f"Evidence captured: **{result['evidenceId']}**")
                        st.code(
                            f"Plaintext hash:      {result['plaintextHash']}\n"
                            f"Encrypted file hash: {result['encryptedFileHash']}\n"
                            f"Object URI:          {result['objectUri']}"
                        )
                    else:
                        st.error(result.get("detail", "Capture failed"))
                except Exception as exc:
                    st.error(f"Error: {exc}")

# ---------------------------------------------------------------------------
# Evidence list
# ---------------------------------------------------------------------------
st.subheader("Evidence Records")

if st.button("Refresh"):
    st.rerun()

try:
    items = api_client.list_evidence()
    if not items:
        st.info("No evidence captured yet.")
    else:
        display_cols = ["evidenceId", "cameraId", "captureTimestamp", "encryptedFileHash"]
        available = [c for c in display_cols if c in items[0]]
        df = pd.DataFrame(items)[available]
        df.columns = [c.replace("Id", " ID").replace("Timestamp", " Time") for c in available]
        st.dataframe(df, use_container_width=True, hide_index=True)
except Exception as exc:
    st.error(f"Could not load evidence: {exc}")
