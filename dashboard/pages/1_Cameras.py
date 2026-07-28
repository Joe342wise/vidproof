import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from datetime import datetime, timezone, timedelta
import streamlit as st
from dashboard import api_client

st.set_page_config(page_title="Cameras — VidProof", layout="wide")
st.title("Cameras")

# ---------------------------------------------------------------------------
# Enroll form
# ---------------------------------------------------------------------------
with st.expander("Enroll a new camera", expanded=False):
    with st.form("enroll_form"):
        camera_id_in = st.text_input("Camera ID", placeholder="cam-001")
        device_serial = st.text_input("Device Serial", placeholder="SN123456")
        operator_id = st.text_input("Operator ID", placeholder="alice")
        owner_public_key = st.text_area(
            "Owner Public Key (base64 X25519)",
            placeholder="Paste base64-encoded X25519 public key here",
            height=80,
        )
        submitted = st.form_submit_button("Enroll")

    if submitted:
        if not all([camera_id_in, device_serial, operator_id, owner_public_key]):
            st.error("All fields are required.")
        else:
            with st.spinner("Enrolling…"):
                try:
                    result = api_client.enroll_camera(
                        camera_id=camera_id_in.strip(),
                        device_serial=device_serial.strip(),
                        operator_id=operator_id.strip(),
                        owner_public_key=owner_public_key.strip(),
                    )
                    if result.get("ok"):
                        st.success(f"Enrolled **{result['cameraId']}**")
                        st.info(f"Private key: `{result['privateKeyPath']}`")
                        st.info(f"Camera record: `{result['cameraJsonPath']}`")
                    else:
                        st.error(result.get("detail", "Enrollment failed"))
                except Exception as exc:
                    st.error(f"Error: {exc}")

# ---------------------------------------------------------------------------
# Data load
# ---------------------------------------------------------------------------

@st.cache_data(ttl=20)
def _load_cameras():
    return api_client.list_cameras()

@st.cache_data(ttl=20)
def _load_evidence():
    return api_client.list_evidence()


col_title, col_btn = st.columns([6, 1])
with col_title:
    st.subheader("Enrolled Cameras")
with col_btn:
    if st.button("Refresh", use_container_width=True):
        st.cache_data.clear()
        st.rerun()

try:
    cameras = _load_cameras()
except Exception as exc:
    st.error(f"Could not reach backend: {exc}")
    st.stop()

if not cameras:
    st.info("No cameras enrolled yet. Use the form above to enroll one.")
    st.stop()

try:
    all_evidence = _load_evidence()
except Exception:
    all_evidence = []

# ---------------------------------------------------------------------------
# Per-camera stats
# ---------------------------------------------------------------------------

def _camera_stats(camera_id: str) -> dict:
    """Count evidence blocks and find the most recent capture for this camera."""
    blocks = [e for e in all_evidence if e.get("cameraId") == camera_id]
    if not blocks:
        return {"count": 0, "last_ts": None}
    timestamps = [e.get("captureTimestamp", "") for e in blocks if e.get("captureTimestamp")]
    last_ts = max(timestamps) if timestamps else None
    return {"count": len(blocks), "last_ts": last_ts}


def _status(last_ts: str | None) -> tuple[str, str, str]:
    """Return (label, colour, dot) for the status badge."""
    if last_ts is None:
        return "Off", "#475569", "⚫"
    try:
        ts = datetime.fromisoformat(last_ts.replace("Z", "+00:00"))
    except ValueError:
        return "Off", "#475569", "⚫"
    age = datetime.now(timezone.utc) - ts
    if age < timedelta(minutes=5):
        return "Recording", "#16a34a", "🟢"
    return "Off", "#475569", "⚫"


def _fmt_ts(ts: str | None) -> str:
    if not ts:
        return "never"
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except ValueError:
        return ts


# ---------------------------------------------------------------------------
# Card HTML
# ---------------------------------------------------------------------------

_CARD_CSS = """
<style>
.vp-card {
  border: 1px solid #334155;
  border-radius: 10px;
  padding: 20px 24px;
  background: #0f172a;
  font-family: sans-serif;
  color: #e2e8f0;
  height: 100%;
}
.vp-card-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 14px;
}
.vp-camera-id {
  font-size: 1.35em;
  font-weight: 700;
  color: #f1f5f9;
  word-break: break-all;
}
.vp-status-badge {
  font-size: 0.8em;
  font-weight: 600;
  padding: 3px 10px;
  border-radius: 99px;
  white-space: nowrap;
  margin-top: 4px;
}
.vp-block-count {
  font-size: 2.4em;
  font-weight: 800;
  color: #38bdf8;
  line-height: 1;
  margin: 10px 0 4px;
}
.vp-block-label {
  font-size: 0.78em;
  color: #94a3b8;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  margin-bottom: 14px;
}
.vp-meta {
  font-size: 0.82em;
  color: #94a3b8;
  line-height: 1.7;
  border-top: 1px solid #1e293b;
  padding-top: 12px;
  margin-top: 4px;
}
.vp-meta strong { color: #cbd5e1; }
</style>
"""

st.markdown(_CARD_CSS, unsafe_allow_html=True)


def _card_html(cam: dict, stats: dict) -> str:
    label, colour, _dot = _status(stats["last_ts"])
    badge_bg = {"Recording": "#14532d", "Off": "#1e293b", "Error": "#450a0a"}.get(label, "#1e293b")

    enrolled = _fmt_ts(cam.get("enrollmentTimestamp"))
    last_block = _fmt_ts(stats["last_ts"])

    return f"""
<div class="vp-card">
  <div class="vp-card-header">
    <div class="vp-camera-id">{cam.get('cameraId', '—')}</div>
    <span class="vp-status-badge" style="background:{badge_bg};color:{colour};border:1px solid {colour}">
      {label}
    </span>
  </div>
  <div class="vp-block-count">{stats['count']}</div>
  <div class="vp-block-label">blocks received</div>
  <div class="vp-meta">
    <strong>Serial:</strong> {cam.get('deviceSerial', '—')}<br>
    <strong>Operator:</strong> {cam.get('operatorId', '—')}<br>
    <strong>Last block:</strong> {last_block}<br>
    <strong>Enrolled:</strong> {enrolled}<br>
    <strong>Policy:</strong> {cam.get('authorizationPolicy', '—')}
  </div>
</div>
"""


# ---------------------------------------------------------------------------
# Render cards — 2 per row
# ---------------------------------------------------------------------------

COLS_PER_ROW = 2

for row_start in range(0, len(cameras), COLS_PER_ROW):
    row_cameras = cameras[row_start: row_start + COLS_PER_ROW]
    cols = st.columns(COLS_PER_ROW, gap="medium")
    for col, cam in zip(cols, row_cameras):
        stats = _camera_stats(cam.get("cameraId", ""))
        with col:
            st.markdown(_card_html(cam, stats), unsafe_allow_html=True)

    # pad empty column in an odd-count last row
    if len(row_cameras) < COLS_PER_ROW:
        with cols[len(row_cameras)]:
            st.empty()
