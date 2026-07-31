import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import io
import json
from datetime import datetime, timezone, timedelta
import streamlit as st
import qrcode
from dashboard import api_client


def _make_qr_png(camera_id: str, public_key: str, enrolled_at: str = "") -> bytes:
    """Return PNG bytes of a QR code encoding the camera's pairing payload."""
    payload = json.dumps({
        "cameraId": camera_id,
        "publicKeyEd25519": public_key,
        "enrolledAt": enrolled_at,
    }, separators=(",", ":"))
    img = qrcode.make(payload)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()

st.set_page_config(page_title="Cameras — VidProof", layout="wide")
st.title("Cameras")

# ---------------------------------------------------------------------------
# Enroll form
# ---------------------------------------------------------------------------
with st.expander("Enroll a new camera", expanded=False):
    # Pre-fetch the owner public key so the operator doesn't need to type it manually
    server_owner_key = api_client.get_owner_public_key()

    if server_owner_key:
        st.success("Owner X25519 public key loaded from server.", icon="🔑")
    else:
        st.warning(
            "No owner X25519 keypair found on this server. "
            "Generate one first with the command in the setup guide, then refresh.",
            icon="⚠️",
        )

    with st.form("enroll_form"):
        camera_id_in  = st.text_input("Camera ID", placeholder="cam-01")
        device_serial = st.text_input("Device Serial", placeholder="SN123456")
        operator_id   = st.text_input("Operator ID", placeholder="alice")

        st.markdown("---")
        st.markdown("**Device signing key**")
        st.caption(
            "The camera device should generate its own Ed25519 keypair and give you only the "
            "public key. Paste it here. If left blank the server generates a keypair instead "
            "(less secure — the private key will reside on the server)."
        )
        device_pub_key = st.text_area(
            "Device Ed25519 Public Key (base64, 32 bytes)",
            placeholder="Paste the Pi's Ed25519 public key here — leave blank to generate server-side",
            height=80,
        )

        st.markdown("**Owner decryption key**")
        st.caption("X25519 public key used to wrap the per-evidence AES key. Auto-filled from the server.")
        owner_public_key = st.text_area(
            "Owner Public Key (base64 X25519)",
            value=server_owner_key or "",
            height=80,
        )

        submitted = st.form_submit_button("Enroll", disabled=not server_owner_key)

    if submitted:
        if not all([camera_id_in, device_serial, operator_id, owner_public_key]):
            st.error("Camera ID, Device Serial, Operator ID, and Owner Public Key are required.")
        else:
            with st.spinner("Enrolling…"):
                try:
                    result = api_client.enroll_camera(
                        camera_id=camera_id_in.strip(),
                        device_serial=device_serial.strip(),
                        operator_id=operator_id.strip(),
                        owner_public_key=owner_public_key.strip(),
                        device_public_key=device_pub_key.strip() or None,
                    )
                    if result.get("ok"):
                        st.success(f"Enrolled **{result['cameraId']}**")

                        if result.get("privateKeyPath"):
                            st.warning(
                                f"Server-generated private key stored at `{result['privateKeyPath']}`. "
                                "Copy it to the device — it cannot be retrieved later.",
                                icon="⚠️",
                            )
                        else:
                            st.info("Device supplied its own public key — no private key on server.", icon="✅")

                        # Download the camera record to copy to the Pi
                        import json as _json
                        cam_record = api_client.get_camera(result["cameraId"])
                        cam_json_bytes = _json.dumps(cam_record, indent=2).encode()
                        st.markdown("**Copy this record to the Pi**")
                        st.caption(
                            f"Save to `/etc/vidproof/cameras/{result['cameraId']}.json` on the device "
                            "so it uses the correct `ownerPublicKey` for AES key wrapping."
                        )
                        st.download_button(
                            f"Download {result['cameraId']}.json",
                            data=cam_json_bytes,
                            file_name=f"{result['cameraId']}.json",
                            mime="application/json",
                        )

                        # Pairing QR code
                        qr_png = _make_qr_png(
                            camera_id=result["cameraId"],
                            public_key=result.get("publicKeyEd25519", ""),
                        )
                        st.markdown("**Scan to pair**")
                        st.caption(
                            "This QR code contains the camera's Ed25519 public key. "
                            "Scan it on the owner device to establish trust without any third party."
                        )
                        col_qr, col_dl = st.columns([1, 3])
                        with col_qr:
                            st.image(qr_png, width=220)
                        with col_dl:
                            st.download_button(
                                "Download pairing QR (PNG)",
                                data=qr_png,
                                file_name=f"{result['cameraId']}-pairing-qr.png",
                                mime="image/png",
                            )
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
    if age > timedelta(hours=24):
        return "Unreachable", "#b45309", "🟠"
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
    badge_bg = {
        "Recording":   "#14532d",
        "Off":         "#1e293b",
        "Unreachable": "#431407",
        "Error":       "#450a0a",
    }.get(label, "#1e293b")

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
            with st.expander("Show pairing QR"):
                pub_key = cam.get("publicKeyEd25519", "")
                if pub_key:
                    qr_png = _make_qr_png(
                        camera_id=cam["cameraId"],
                        public_key=pub_key,
                        enrolled_at=cam.get("enrollmentTimestamp", ""),
                    )
                    st.caption(
                        "Scan this QR code on the owner device to establish "
                        "trust — it encodes the camera ID and Ed25519 public key."
                    )
                    col_img, col_btn = st.columns([1, 2])
                    with col_img:
                        st.image(qr_png, width=180)
                    with col_btn:
                        st.download_button(
                            "Download PNG",
                            data=qr_png,
                            file_name=f"{cam['cameraId']}-pairing-qr.png",
                            mime="image/png",
                            key=f"dl_qr_{cam['cameraId']}",
                        )
                else:
                    st.warning("Public key not available in camera record.")

            with st.expander("PRNU fingerprint reference"):
                cam_id = cam["cameraId"]
                prnu_hash = cam.get("prnuReferenceHash", "")
                if prnu_hash:
                    st.success(
                        f"Reference set — SHA-256 `{prnu_hash[:16]}…`",
                        icon="🔬",
                    )
                    st.caption(
                        "Upload a new reference video below to replace the current fingerprint."
                    )
                else:
                    st.info(
                        "No PRNU reference stored yet. Upload 30–60 s of flat, "
                        "evenly-lit footage from this camera to enable sensor fingerprinting.",
                        icon="🔬",
                    )
                prnu_file = st.file_uploader(
                    "Reference video",
                    type=["mp4", "mkv", "avi", "h264"],
                    key=f"prnu_upload_{cam_id}",
                    label_visibility="collapsed",
                )
                if prnu_file is not None:
                    if st.button(
                        "Extract & save fingerprint",
                        key=f"prnu_btn_{cam_id}",
                        type="primary",
                    ):
                        with st.spinner("Extracting PRNU fingerprint — this may take a minute…"):
                            try:
                                result = api_client.upload_prnu_reference(
                                    cam_id, prnu_file.read(), prnu_file.name
                                )
                                st.success(
                                    f"Fingerprint saved — {result.get('framesUsed', '?')} frames used. "
                                    f"SHA-256 `{result.get('prnuReferenceHash','')[:16]}…`"
                                )
                                st.cache_data.clear()
                                st.rerun()
                            except Exception as exc:
                                st.error(f"Upload failed: {exc}")

            with st.expander("Remove camera"):
                cam_id = cam["cameraId"]
                confirmed = st.checkbox(
                    f"I understand this removes `{cam_id}` from VidProof permanently",
                    key=f"confirm_del_{cam_id}",
                )
                if st.button(
                    "Delete camera",
                    key=f"del_{cam_id}",
                    type="primary",
                    disabled=not confirmed,
                ):
                    try:
                        api_client.delete_camera(cam_id)
                        st.success(f"Camera `{cam_id}` removed.")
                        st.cache_data.clear()
                        st.rerun()
                    except Exception as exc:
                        st.error(f"Delete failed: {exc}")

    # pad empty column in an odd-count last row
    if len(row_cameras) < COLS_PER_ROW:
        with cols[len(row_cameras)]:
            st.empty()
