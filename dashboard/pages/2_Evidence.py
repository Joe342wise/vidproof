import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from datetime import datetime, timezone

import pandas as pd
import streamlit as st
from dashboard import api_client

st.set_page_config(page_title="Evidence — VidProof", layout="wide")
st.title("Evidence")

# ---------------------------------------------------------------------------
# Capture form
# ---------------------------------------------------------------------------
with st.expander("Capture new evidence", expanded=False):
    with st.form("capture_form"):
        camera_id = st.text_input("Camera ID", placeholder="cam-001")
        evidence_id_input = st.text_input("Evidence ID (optional, auto-generated if blank)", placeholder="ev-001")
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
                        evidence_id=evidence_id_input.strip() or None,
                    )
                    if result.get("ok"):
                        st.success(f"Evidence captured: **{result['evidenceId']}**")
                        st.code(
                            f"Plaintext hash:      {result['plaintextHash']}\n"
                            f"Encrypted file hash: {result['encryptedFileHash']}\n"
                            f"Object URI:          {result['objectUri']}"
                        )
                        st.cache_data.clear()
                    else:
                        st.error(result.get("detail", "Capture failed"))
                except Exception as exc:
                    st.error(f"Error: {exc}")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

@st.cache_data(ttl=30)
def _load_items() -> list[dict]:
    return api_client.list_evidence()


@st.cache_data(ttl=30)
def _verification_status(evidence_id: str) -> str:
    try:
        results = api_client.list_verification_results(evidence_id)
        if not results:
            return "Not checked"
        latest = max(results, key=lambda r: r.get("verifiedAt", ""))
        return "Verified" if latest["primaryDecision"] == "PASS" else "Failed"
    except Exception:
        return "Unknown"


def _fmt_ts(ts: str) -> str:
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return ts


_BADGE = {
    "Verified":   ("#1a7a3a", "#fff"),
    "Failed":     ("#b91c1c", "#fff"),
    "Not checked":("#475569", "#fff"),
    "Unknown":    ("#78350f", "#fff"),
}


def _badge(status: str) -> str:
    bg, fg = _BADGE.get(status, ("#334155", "#fff"))
    return (
        f'<span style="background:{bg};color:{fg};padding:2px 9px;'
        f'border-radius:4px;font-size:0.82em;font-weight:600">{status}</span>'
    )


def _fabric_chip(tx: str) -> str:
    if tx:
        return '<span style="color:#4ade80;font-weight:600">✓</span>'
    return '<span style="color:#475569">—</span>'


# ---------------------------------------------------------------------------
# Load + status
# ---------------------------------------------------------------------------
st.subheader("Evidence Records")

col_ref, _ = st.columns([1, 7])
with col_ref:
    if st.button("Refresh", use_container_width=True):
        st.cache_data.clear()
        st.rerun()

try:
    items = _load_items()
except Exception as exc:
    st.error(f"Could not load evidence: {exc}")
    st.stop()

if not items:
    st.info("No evidence captured yet.")
    st.stop()

# Fetch statuses (cached per item)
with st.spinner("Loading verification statuses…"):
    statuses = {item["evidenceId"]: _verification_status(item["evidenceId"]) for item in items}

# ---------------------------------------------------------------------------
# Controls — search / filter / sort
# ---------------------------------------------------------------------------
c_search, c_status, c_sort, c_dir = st.columns([3, 2, 2, 1])

with c_search:
    search = st.text_input(
        "Search",
        placeholder="Evidence ID or Camera ID…",
        label_visibility="collapsed",
    ).strip().lower()

with c_status:
    status_options = ["All statuses", "Verified", "Failed", "Not checked"]
    status_filter = st.selectbox("Status", status_options, label_visibility="collapsed")

with c_sort:
    sort_options = {
        "Newest first":  ("captureTimestamp", True),
        "Oldest first":  ("captureTimestamp", False),
        "Camera ID":     ("cameraId", False),
        "Evidence ID":   ("evidenceId", False),
        "Status":        ("_status", False),
    }
    sort_choice = st.selectbox("Sort by", list(sort_options.keys()), label_visibility="collapsed")

with c_dir:
    # Flip button for the chosen sort
    flip = st.checkbox("↑", value=False, help="Reverse sort order")

sort_key, sort_desc = sort_options[sort_choice]
if flip:
    sort_desc = not sort_desc

# ---------------------------------------------------------------------------
# Apply filters
# ---------------------------------------------------------------------------
rows = []
for item in items:
    eid  = item.get("evidenceId", "")
    cam  = item.get("cameraId", "")
    ts   = item.get("captureTimestamp", "")
    fhash = item.get("encryptedFileHash", "")
    tx   = item.get("fabricTxId", "")
    st   = statuses.get(eid, "Unknown")

    if search and search not in eid.lower() and search not in cam.lower():
        continue
    if status_filter != "All statuses" and st != status_filter:
        continue

    rows.append({
        "evidenceId": eid,
        "cameraId": cam,
        "captureTimestamp": ts,
        "encryptedFileHash": fhash,
        "fabricTxId": tx,
        "_status": st,
    })

# Sort
rows.sort(key=lambda r: r.get(sort_key, ""), reverse=sort_desc)

n_total    = len(items)
n_filtered = len(rows)

if n_filtered == 0:
    st.info(
        f"No blocks match the current filter. "
        f"({n_total} total record{'s' if n_total != 1 else ''})"
    )
    st.stop()

st.caption(
    f"Showing **{n_filtered}** of **{n_total}** block{'s' if n_total != 1 else ''}"
    + (f" · filtered by status: *{status_filter}*" if status_filter != "All statuses" else "")
    + (f" · search: *{search}*" if search else "")
)

# ---------------------------------------------------------------------------
# Table
# ---------------------------------------------------------------------------
header_cells = "".join(
    f"<th style='padding:7px 12px;text-align:left;border-bottom:1px solid #334155;"
    f"white-space:nowrap;font-size:0.8em;text-transform:uppercase;"
    f"letter-spacing:0.06em;color:#94a3b8'>{h}</th>"
    for h in ["Evidence ID", "Camera", "Captured", "Enc File Hash", "Fabric", "Status"]
)

rows_html = ""
for row in rows:
    eid_cell   = f'<span style="font-family:monospace;font-size:0.85em">{row["evidenceId"]}</span>'
    hash_short = row["encryptedFileHash"][:16] + "…" if row["encryptedFileHash"] else "—"
    hash_cell  = f'<span style="font-family:monospace;font-size:0.82em;color:#94a3b8" title="{row["encryptedFileHash"]}">{hash_short}</span>'
    rows_html += (
        "<tr style='border-bottom:1px solid #1e293b'>"
        f"<td style='padding:7px 12px'>{eid_cell}</td>"
        f"<td style='padding:7px 12px;font-size:0.88em'>{row['cameraId']}</td>"
        f"<td style='padding:7px 12px;font-size:0.88em;white-space:nowrap'>{_fmt_ts(row['captureTimestamp'])}</td>"
        f"<td style='padding:7px 12px'>{hash_cell}</td>"
        f"<td style='padding:7px 12px;text-align:center'>{_fabric_chip(row['fabricTxId'])}</td>"
        f"<td style='padding:7px 12px'>{_badge(row['_status'])}</td>"
        "</tr>"
    )

st.markdown(
    f"""<div style="overflow-x:auto;margin-bottom:1rem">
    <table style="width:100%;border-collapse:collapse;font-size:0.9em">
      <thead><tr style="background:#0f172a">{header_cells}</tr></thead>
      <tbody>{rows_html}</tbody>
    </table></div>""",
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# Export selection
# ---------------------------------------------------------------------------
st.divider()
filtered_ids = [r["evidenceId"] for r in rows]

selected_ids = st.multiselect(
    "Select blocks to export",
    options=filtered_ids,
    placeholder="Choose one or more evidence blocks…",
)

if st.button(
    f"Export {len(selected_ids)} selected" if selected_ids else "Export Selected",
    type="primary",
    disabled=len(selected_ids) == 0,
    help="Select at least one block above to enable export.",
):
    st.session_state.export_preselected = selected_ids
    st.switch_page("pages/7_Export.py")
