import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from datetime import datetime, timezone
import streamlit as st
from dashboard import api_client

st.set_page_config(page_title="Verify — VidProof", layout="wide")
st.title("Verify Evidence")
st.caption(
    "Select a block to inspect its metadata, then run verification. "
    "Hash check confirms the encrypted file is unaltered. "
    "Signature check proves the footage came from the enrolled camera."
)

# ---------------------------------------------------------------------------
# Load evidence blocks
# ---------------------------------------------------------------------------
@st.cache_data(ttl=20)
def _load_evidence():
    try:
        return api_client.list_evidence()
    except Exception:
        return []

evidence_list = _load_evidence()

if not evidence_list:
    st.info("No evidence blocks found. Capture some footage first.")
    st.stop()

# ---------------------------------------------------------------------------
# Block selector
# ---------------------------------------------------------------------------
def _fmt_option(e: dict) -> str:
    ts = e.get("captureTimestamp", "")
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        ts_fmt = dt.strftime("%Y-%m-%d %H:%M")
    except Exception:
        ts_fmt = ts[:16] if ts else "unknown"
    eid = e.get("evidenceId", "")
    short_id = eid[:18] + "…" if len(eid) > 18 else eid
    return f"{e.get('cameraId', '?')}  ·  {ts_fmt}  ·  {short_id}"

options = {_fmt_option(e): e for e in sorted(
    evidence_list, key=lambda x: x.get("captureTimestamp", ""), reverse=True
)}

selected_label = st.selectbox(
    "Evidence block",
    options=list(options.keys()),
    index=0,
)
block = options[selected_label]
evidence_id = block["evidenceId"]

# ---------------------------------------------------------------------------
# Metadata card
# ---------------------------------------------------------------------------
def _trunc(s: str, n: int = 24) -> str:
    return s[:n] + "…" if len(s) > n else s

st.markdown(f"""
<div style="
  border:1px solid #334155;border-radius:10px;padding:18px 24px;
  background:#0f172a;font-family:sans-serif;color:#e2e8f0;
  margin:12px 0 20px;
">
  <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:12px">
    <div>
      <div style="font-size:0.72em;color:#64748b;text-transform:uppercase;letter-spacing:.07em">Evidence ID</div>
      <div style="font-family:monospace;color:#38bdf8;font-size:0.92em;margin-top:2px">{block.get('evidenceId','—')}</div>
    </div>
    <div>
      <div style="font-size:0.72em;color:#64748b;text-transform:uppercase;letter-spacing:.07em">Camera</div>
      <div style="color:#f1f5f9;font-size:0.92em;font-weight:600;margin-top:2px">{block.get('cameraId','—')}</div>
    </div>
    <div>
      <div style="font-size:0.72em;color:#64748b;text-transform:uppercase;letter-spacing:.07em">Captured</div>
      <div style="color:#f1f5f9;font-size:0.92em;margin-top:2px">{block.get('captureTimestamp','—')}</div>
    </div>
  </div>
  <div style="border-top:1px solid #1e293b;margin-top:14px;padding-top:14px;display:grid;grid-template-columns:1fr 1fr;gap:10px">
    <div>
      <div style="font-size:0.7em;color:#64748b;text-transform:uppercase;letter-spacing:.07em">Encrypted File Hash</div>
      <div style="font-family:monospace;font-size:0.8em;color:#94a3b8;margin-top:2px">{_trunc(block.get('encryptedFileHash','—'), 40)}</div>
    </div>
    <div>
      <div style="font-size:0.7em;color:#64748b;text-transform:uppercase;letter-spacing:.07em">Plaintext Hash</div>
      <div style="font-family:monospace;font-size:0.8em;color:#94a3b8;margin-top:2px">{_trunc(block.get('plaintextHash','—'), 40)}</div>
    </div>
    <div>
      <div style="font-size:0.7em;color:#64748b;text-transform:uppercase;letter-spacing:.07em">Device Signature</div>
      <div style="font-family:monospace;font-size:0.8em;color:#94a3b8;margin-top:2px">{_trunc(block.get('deviceSignature','—'), 40)}</div>
    </div>
    <div>
      <div style="font-size:0.7em;color:#64748b;text-transform:uppercase;letter-spacing:.07em">Fabric Tx</div>
      <div style="font-family:monospace;font-size:0.8em;color:#94a3b8;margin-top:2px">{_trunc(block.get('fabricTxId','') or '—', 40)}</div>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Verify controls
# ---------------------------------------------------------------------------
col_vid, col_dec, col_btn = st.columns([2, 2, 1])
with col_vid:
    verifier_id = st.text_input("Verifier ID", value="operator", label_visibility="visible")
with col_dec:
    include_decryption = st.checkbox(
        "Include decryption check",
        help="Requires owner.x25519.priv.pem in storage/keys/ on the server",
    )
with col_btn:
    st.write("")
    run = st.button("Run Verification", type="primary", use_container_width=True)

if not run:
    st.stop()

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------
with st.spinner("Verifying…"):
    try:
        response = api_client.verify_evidence(
            evidence_id=evidence_id,
            verifier_id=verifier_id.strip() or "operator",
            include_decryption=include_decryption,
        )
    except Exception as exc:
        st.error(f"Request failed: {exc}")
        st.stop()

if not response.get("ok"):
    st.error(response.get("detail", "Verification request failed"))
    st.stop()

result = response["result"]
decision = result.get("primaryDecision", "UNKNOWN")

if decision == "PASS":
    st.success(f"PRIMARY DECISION: **{decision}**", icon="✅")
else:
    st.error(f"PRIMARY DECISION: **{decision}**", icon="❌")

# ---------------------------------------------------------------------------
# Results grid
# ---------------------------------------------------------------------------
st.subheader("Check Results")

def _cell(label: str, value, checked: bool = True) -> str:
    if not checked:
        icon, colour, bg = "⏭", "#94a3b8", "#1e293b"
        status = "skipped"
    elif value is True:
        icon, colour, bg = "✅", "#4ade80", "#052e16"
        status = "pass"
    elif value is False:
        icon, colour, bg = "❌", "#f87171", "#450a0a"
        status = "FAIL"
    else:
        icon, colour, bg = "—", "#64748b", "#1e293b"
        status = "—"
    return f"""
<div style="border:1px solid {colour}30;border-radius:8px;padding:14px 16px;background:{bg};">
  <div style="font-size:0.72em;color:#64748b;text-transform:uppercase;letter-spacing:.07em;margin-bottom:6px">{label}</div>
  <div style="font-size:1.3em">{icon} <span style="color:{colour};font-weight:600;font-size:0.75em">{status}</span></div>
</div>"""

checks = [
    ("Encrypted file hash",    result.get("encryptedFileHashValid"),       True),
    ("Device signature",       result.get("deviceSignatureValid"),          True),
    ("Decryption",             result.get("decryptionValid"),               result.get("decryptionAttempted", False)),
    ("Plaintext hash match",   result.get("plaintextHashMatchesEvidence"),  result.get("decryptionAttempted", False)),
    ("RFC 3161 timestamp",     result.get("tsaValid"),                      result.get("tsaChecked", False)),
    ("PRNU",                   result.get("prnuScore"),                     result.get("prnuChecked", False)),
]

cols_html = "".join(_cell(lbl, val, chk) for lbl, val, chk in checks)
st.markdown(
    f'<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:16px">{cols_html}</div>',
    unsafe_allow_html=True,
)

if result.get("tsaChecked") and result.get("tsaDetail"):
    with st.expander("Timestamp detail"):
        st.code(result["tsaDetail"])

if result.get("prnuScore") is not None:
    st.caption(f"PRNU score: {result['prnuScore']:.4f} (secondary signal only — never a pass/fail gate)")

if result.get("notes"):
    st.info(result["notes"])

st.caption(
    f"Verification ID: `{result.get('verificationId','—')}` · "
    f"Verified at: `{result.get('verifiedAt','—')}` · "
    f"Verifier: `{result.get('verifierId','—')}`"
)
