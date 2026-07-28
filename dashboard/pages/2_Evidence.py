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
# Verification status helper
# ---------------------------------------------------------------------------

@st.cache_data(ttl=30)
def _verification_status(evidence_id: str) -> str:
    try:
        results = api_client.list_verification_results(evidence_id)
        if not results:
            return "Not yet checked"
        latest = max(results, key=lambda r: r.get("verifiedAt", ""))
        return "Verified" if latest["primaryDecision"] == "PASS" else "Failed"
    except Exception:
        return "Unknown"


_BADGE_STYLE = {
    "Verified":       "background:#1a7a3a;color:#fff;padding:2px 8px;border-radius:4px;font-size:0.85em",
    "Failed":         "background:#b91c1c;color:#fff;padding:2px 8px;border-radius:4px;font-size:0.85em",
    "Not yet checked":"background:#475569;color:#fff;padding:2px 8px;border-radius:4px;font-size:0.85em",
    "Unknown":        "background:#78350f;color:#fff;padding:2px 8px;border-radius:4px;font-size:0.85em",
}


# ---------------------------------------------------------------------------
# Evidence list
# ---------------------------------------------------------------------------
st.subheader("Evidence Records")

col_refresh, col_clear = st.columns([1, 5])
with col_refresh:
    if st.button("Refresh"):
        st.cache_data.clear()
        st.rerun()

try:
    items = api_client.list_evidence()
    if not items:
        st.info("No evidence captured yet.")
    else:
        display_cols = ["evidenceId", "cameraId", "captureTimestamp", "encryptedFileHash"]
        available = [c for c in display_cols if c in items[0]]
        df = pd.DataFrame(items)[available].copy()
        df.columns = [c.replace("Id", " ID").replace("Timestamp", " Time") for c in available]

        # Build verification status column
        statuses = [_verification_status(item["evidenceId"]) for item in items]

        # Render as an HTML table with badges
        rows_html = ""
        for (_, row), status in zip(df.iterrows(), statuses):
            badge_style = _BADGE_STYLE.get(status, _BADGE_STYLE["Unknown"])
            badge = f'<span style="{badge_style}">{status}</span>'
            cells = "".join(f"<td style='padding:6px 12px'>{v}</td>" for v in row)
            rows_html += f"<tr>{cells}<td style='padding:6px 12px'>{badge}</td></tr>"

        header_cells = "".join(
            f"<th style='padding:6px 12px;text-align:left;border-bottom:1px solid #334155'>{c}</th>"
            for c in list(df.columns) + ["Verification Status"]
        )
        table_html = f"""
        <div style="overflow-x:auto">
        <table style="width:100%;border-collapse:collapse;font-size:0.9em">
          <thead><tr style="background:#1e293b">{header_cells}</tr></thead>
          <tbody>{rows_html}</tbody>
        </table>
        </div>
        """
        st.markdown(table_html, unsafe_allow_html=True)

except Exception as exc:
    st.error(f"Could not load evidence: {exc}")
