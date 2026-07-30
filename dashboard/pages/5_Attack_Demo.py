import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from datetime import datetime, timezone
import streamlit as st
from dashboard import api_client

st.set_page_config(page_title="Attack Demo — VidProof", layout="wide")

st.title("Forensic Integrity Demo")
st.caption(
    "Demonstrates what happens when an attacker tampers with evidence. "
    "Each attack is applied to a temporary copy — real evidence is never modified. "
    "All three attacks produce a FAIL, caught by different forensic checks."
)

# ---------------------------------------------------------------------------
# Attack definitions
# ---------------------------------------------------------------------------
ATTACKS = {
    "bit_flip": {
        "label": "Physical File Tamper",
        "icon": "💾",
        "summary": "Flip a byte in the encrypted video file",
        "detail": (
            "Simulates an attacker who gains access to the storage drive and modifies "
            "the raw bytes of the encrypted video file. Even a single bit change is caught "
            "immediately by the SHA-256 hash of the encrypted file."
        ),
        "caught_by": "Encrypted file hash",
        "colour": "#ef4444",
    },
    "forge_signature": {
        "label": "Signature Forgery",
        "icon": "🔏",
        "summary": "Corrupt the Ed25519 device signature",
        "detail": (
            "Simulates an attacker who tries to create or modify a device signature without "
            "access to the camera's Ed25519 private key. Ed25519 is a 256-bit elliptic-curve "
            "scheme — any modification to the 64-byte signature makes it mathematically invalid."
        ),
        "caught_by": "Device signature",
        "colour": "#f97316",
    },
    "metadata_injection": {
        "label": "Metadata Injection",
        "icon": "📝",
        "summary": "Replace the claimed plaintext hash in evidence metadata",
        "detail": (
            "Simulates an attacker who modifies evidence metadata to claim the video "
            "contains different content. The device signature was computed over the real "
            "plaintext hash at capture time — verifying it against an injected hash always fails, "
            "even if the attacker knows the public key."
        ),
        "caught_by": "Device signature",
        "colour": "#a855f7",
    },
}

# ---------------------------------------------------------------------------
# Evidence selector
# ---------------------------------------------------------------------------
@st.cache_data(ttl=20)
def _load_evidence():
    try:
        return api_client.list_evidence()
    except Exception:
        return []

evidence_list = _load_evidence()

if not evidence_list:
    st.warning("No evidence blocks available. Capture some footage first.")
    st.stop()

def _fmt(e: dict) -> str:
    ts = e.get("captureTimestamp", "")
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        ts_fmt = dt.strftime("%Y-%m-%d %H:%M")
    except Exception:
        ts_fmt = ts[:16]
    eid = e.get("evidenceId", "")
    return f"{e.get('cameraId','?')}  ·  {ts_fmt}  ·  {eid[:18]}…"

options = {_fmt(e): e for e in sorted(
    evidence_list, key=lambda x: x.get("captureTimestamp",""), reverse=True
)}

col_sel, col_spacer = st.columns([3, 2])
with col_sel:
    selected_label = st.selectbox("Target evidence block", list(options.keys()))

block = options[selected_label]
evidence_id = block["evidenceId"]

st.divider()

# ---------------------------------------------------------------------------
# Attack cards
# ---------------------------------------------------------------------------
st.subheader("Choose an attack")

if "selected_attack" not in st.session_state:
    st.session_state.selected_attack = "bit_flip"

attack_cols = st.columns(3, gap="medium")
attack_key = st.session_state.selected_attack

for col, (key, atk) in zip(attack_cols, ATTACKS.items()):
    selected = (key == attack_key)
    border_colour = atk["colour"] if selected else "#334155"
    bg_colour = f"{atk['colour']}18" if selected else "#0f172a"
    with col:
        st.markdown(f"""
<div style="
  border:2px solid {border_colour};border-radius:10px;
  padding:18px 20px;background:{bg_colour};
  font-family:sans-serif;color:#e2e8f0;min-height:200px;
">
  <div style="font-size:1.6em;margin-bottom:8px">{atk['icon']}</div>
  <div style="font-weight:700;font-size:1em;color:#f1f5f9;margin-bottom:6px">{atk['label']}</div>
  <div style="font-size:0.82em;color:#94a3b8;line-height:1.55">{atk['detail']}</div>
  <div style="margin-top:12px;font-size:0.75em;color:{atk['colour']};font-weight:600;
              text-transform:uppercase;letter-spacing:.06em">
    Caught by: {atk['caught_by']}
  </div>
</div>
""", unsafe_allow_html=True)
        if st.button(
            "▶ Selected" if selected else "Select",
            key=f"sel_{key}",
            use_container_width=True,
            type="primary" if selected else "secondary",
        ):
            st.session_state.selected_attack = key
            st.rerun()

st.divider()

# ---------------------------------------------------------------------------
# Launch
# ---------------------------------------------------------------------------
attack_key = st.session_state.selected_attack
atk = ATTACKS[attack_key]

col_info, col_btn = st.columns([4, 1])
with col_info:
    st.markdown(
        f"**{atk['icon']} {atk['label']}** — {atk['summary']}  \n"
        f"Target: `{evidence_id}`"
    )
with col_btn:
    launch = st.button("Launch Attack", type="primary", use_container_width=True)

if not launch:
    st.stop()

# ---------------------------------------------------------------------------
# Run baseline, then tampered
# ---------------------------------------------------------------------------
with st.spinner("Running baseline verification on real evidence…"):
    try:
        baseline_resp = api_client.verify_evidence(evidence_id, verifier_id="attack-demo")
        baseline = baseline_resp.get("result", {})
    except Exception as exc:
        st.error(f"Baseline verification failed: {exc}")
        st.stop()

with st.spinner(f"Applying {atk['label'].lower()} and verifying tampered copy…"):
    try:
        demo_resp = api_client.run_attack_demo(evidence_id, attack_key)
        tampered = demo_resp.get("result", {})
        description = demo_resp.get("attackDescription", "")
    except Exception as exc:
        st.error(f"Attack demo failed: {exc}")
        st.stop()

# ---------------------------------------------------------------------------
# Before / After comparison
# ---------------------------------------------------------------------------
st.markdown("---")

def _icon(v, chk) -> str:
    if not chk: return "⏭ skip"
    if v is True: return "✅ pass"
    if v is False: return "❌ FAIL"
    return "—"

def _check_row(label, before_val, after_val, chk_before=True, chk_after=True) -> str:
    caught = chk_after and (after_val is False)
    row_bg = "#3b0808" if caught else "transparent"
    left_border = "border-left:3px solid #ef4444;" if caught else "border-left:3px solid transparent;"
    after_colour = "#f87171" if caught else "#e2e8f0"
    after_weight = "700" if caught else "400"
    caught_label = "  ← caught" if caught else ""
    return (
        f"<tr style='background:{row_bg};{left_border}'>"
        f"<td style='padding:9px 14px;color:#94a3b8;font-size:0.85em'>{label}</td>"
        f"<td style='padding:9px 14px;font-family:monospace;font-size:0.85em;color:#4ade80'>{_icon(before_val, chk_before)}</td>"
        f"<td style='padding:9px 14px;font-family:monospace;font-size:0.85em;"
        f"color:{after_colour};font-weight:{after_weight}'>{_icon(after_val, chk_after)}{caught_label}</td>"
        f"</tr>"
    )

checks = [
    ("Encrypted file hash",
     baseline.get("encryptedFileHashValid"), tampered.get("encryptedFileHashValid"), True, True),
    ("Device signature",
     baseline.get("deviceSignatureValid"), tampered.get("deviceSignatureValid"), True, True),
    ("Decryption",
     baseline.get("decryptionValid"), tampered.get("decryptionValid"),
     baseline.get("decryptionAttempted", False), tampered.get("decryptionAttempted", False)),
    ("RFC 3161 timestamp",
     baseline.get("tsaValid"), tampered.get("tsaValid"),
     baseline.get("tsaChecked", False), tampered.get("tsaChecked", False)),
]

rows_html = "".join(_check_row(*c) for c in checks)

col_before, col_after = st.columns(2, gap="large")
with col_before:
    bd = baseline.get("primaryDecision", "?")
    st.markdown(
        f"<div style='text-align:center;padding:10px;border-radius:8px;background:#052e16;"
        f"color:#4ade80;font-weight:700;font-size:1em;margin-bottom:8px'>✅ BEFORE ATTACK — {bd}</div>",
        unsafe_allow_html=True,
    )
with col_after:
    td = tampered.get("primaryDecision", "?")
    st.markdown(
        f"<div style='text-align:center;padding:10px;border-radius:8px;background:#450a0a;"
        f"color:#f87171;font-weight:700;font-size:1em;margin-bottom:8px'>❌ AFTER ATTACK — {td}</div>",
        unsafe_allow_html=True,
    )

st.markdown(f"""
<table style="width:100%;border-collapse:collapse;border:1px solid #334155;
              border-radius:8px;overflow:hidden;font-family:sans-serif">
  <thead>
    <tr style="background:#1e293b">
      <th style="padding:10px 14px;text-align:left;font-size:0.78em;color:#64748b;
                 text-transform:uppercase;letter-spacing:.07em;width:35%">Check</th>
      <th style="padding:10px 14px;text-align:left;font-size:0.78em;color:#64748b;
                 text-transform:uppercase;letter-spacing:.07em">Real evidence</th>
      <th style="padding:10px 14px;text-align:left;font-size:0.78em;color:#64748b;
                 text-transform:uppercase;letter-spacing:.07em">Tampered copy</th>
    </tr>
  </thead>
  <tbody>{rows_html}</tbody>
</table>
""", unsafe_allow_html=True)

st.markdown(f"""
<div style="margin-top:16px;padding:14px 18px;border-radius:8px;background:#1e293b;
            border-left:3px solid {atk['colour']};font-family:sans-serif">
  <div style="font-size:0.75em;color:{atk['colour']};text-transform:uppercase;
              letter-spacing:.07em;font-weight:600;margin-bottom:6px">What happened</div>
  <div style="color:#cbd5e1;font-size:0.88em;line-height:1.6">{description}</div>
</div>
""", unsafe_allow_html=True)

st.caption(
    "The tampered copy was verified in a temporary directory and immediately discarded. "
    "Real evidence metadata and the encrypted file were not modified."
)
