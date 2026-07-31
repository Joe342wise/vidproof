import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from datetime import datetime, timezone
import pandas as pd
import streamlit as st
from dashboard import api_client

st.set_page_config(page_title="Verify — VidProof", layout="wide")
st.title("Verify Evidence")
st.caption(
    "Select one or more blocks below, then run verification. "
    "Hash check confirms the encrypted file is unaltered. "
    "Signature check proves the footage came from the enrolled camera."
)

# ---------------------------------------------------------------------------
# Load evidence
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

col_refresh, col_spacer = st.columns([1, 6])
with col_refresh:
    if st.button("Refresh", use_container_width=True):
        st.cache_data.clear()
        st.rerun()

# ---------------------------------------------------------------------------
# Checkbox table
# ---------------------------------------------------------------------------
def _fmt_ts(ts: str) -> str:
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return ts

sorted_blocks = sorted(evidence_list, key=lambda x: x.get("captureTimestamp", ""), reverse=True)

df = pd.DataFrame([{
    "Select": False,
    "Camera": e.get("cameraId", ""),
    "Evidence ID": e.get("evidenceId", ""),
    "Captured": _fmt_ts(e.get("captureTimestamp", "")),
    "Fabric Tx": "✓" if e.get("fabricTxId") else "—",
} for e in sorted_blocks])

col_selall, col_btn, col_dec, col_vid = st.columns([1, 2, 2, 2])
with col_selall:
    select_all = st.checkbox("Select all", key="sel_all")

if select_all:
    df["Select"] = True

edited = st.data_editor(
    df,
    column_config={
        "Select": st.column_config.CheckboxColumn("", width="small"),
        "Camera": st.column_config.TextColumn("Camera", width="small"),
        "Evidence ID": st.column_config.TextColumn("Evidence ID", width="medium"),
        "Captured": st.column_config.TextColumn("Captured", width="medium"),
        "Fabric Tx": st.column_config.TextColumn("Fabric", width="small"),
    },
    hide_index=True,
    use_container_width=True,
    key="verify_table",
)

selected_ids = [
    row["Evidence ID"]
    for _, row in edited.iterrows()
    if row["Select"]
]

n = len(selected_ids)

with col_dec:
    include_decryption = st.checkbox(
        "Include decryption",
        help="Requires owner.x25519.priv.pem in storage/keys/ on the server",
    )
with col_vid:
    verifier_id = st.text_input("Verifier ID", value="operator", label_visibility="visible")
with col_btn:
    st.write("")
    run = st.button(
        f"Verify {n} block{'s' if n != 1 else ''}" if n else "Verify",
        type="primary",
        disabled=(n == 0),
        use_container_width=True,
    )

with st.expander("Advanced — override camera public key"):
    st.caption(
        "By default, verification uses the Ed25519 public key stored in the enrolled camera record. "
        "Paste a different key here to verify against a known-good key instead — "
        "for example, one obtained directly from the device QR code or out-of-band. "
        "Applies to all selected blocks."
    )
    override_public_key = st.text_input(
        "Camera Ed25519 public key (base64, 32 bytes)",
        placeholder="Leave blank to use the enrolled key",
        label_visibility="visible",
    ).strip() or None

if n == 0 and not run:
    st.caption("Select at least one block to verify.")
    st.stop()

if not run:
    st.stop()

# ---------------------------------------------------------------------------
# Run verification for each selected block
# ---------------------------------------------------------------------------
st.divider()
st.subheader(f"Results — {n} block{'s' if n != 1 else ''}")

progress = st.progress(0, text="Starting…")
results: dict[str, dict] = {}

for i, eid in enumerate(selected_ids):
    progress.progress(i / n, text=f"Verifying {eid} ({i + 1}/{n})…")
    try:
        resp = api_client.verify_evidence(
            evidence_id=eid,
            verifier_id=verifier_id.strip() or "operator",
            include_decryption=include_decryption,
            override_public_key=override_public_key,
        )
        results[eid] = resp.get("result", {}) if resp.get("ok") else {"_error": resp.get("detail", "failed")}
    except Exception as exc:
        results[eid] = {"_error": str(exc)}

progress.progress(1.0, text="Done.")

# ---------------------------------------------------------------------------
# Summary bar
# ---------------------------------------------------------------------------
n_pass = sum(1 for r in results.values() if r.get("primaryDecision") == "PASS")
n_fail = sum(1 for r in results.values() if r.get("primaryDecision") == "FAIL")
n_err  = sum(1 for r in results.values() if "_error" in r)

c1, c2, c3 = st.columns(3)
c1.metric("Passed", n_pass)
c2.metric("Failed", n_fail)
c3.metric("Errors", n_err)

# ---------------------------------------------------------------------------
# Per-block expandable results
# ---------------------------------------------------------------------------
def _cell(label: str, value, checked: bool = True, skip_reason: str = "") -> str:
    if not checked:
        icon, colour, bg = "⏭", "#94a3b8", "#1e293b"
        status = skip_reason or "skipped"
    elif value is True:
        icon, colour, bg = "✅", "#4ade80", "#052e16"
        status = "pass"
    elif value is False:
        icon, colour, bg = "❌", "#f87171", "#450a0a"
        status = "FAIL"
    else:
        icon, colour, bg = "—", "#64748b", "#1e293b"
        status = "—"
    return (
        f"<div style='border:1px solid {colour}30;border-radius:8px;padding:12px 14px;background:{bg};'>"
        f"<div style='font-size:0.7em;color:#64748b;text-transform:uppercase;letter-spacing:.07em;margin-bottom:4px'>{label}</div>"
        f"<div style='font-size:1.2em'>{icon} <span style='color:{colour};font-weight:600;font-size:0.72em'>{status}</span></div>"
        f"</div>"
    )

for eid in selected_ids:
    r = results.get(eid, {})
    err = r.get("_error")
    decision = r.get("primaryDecision", "ERROR" if err else "?")
    icon = "✅" if decision == "PASS" else "❌"

    with st.expander(f"{icon}  {eid}  —  {decision}", expanded=(decision != "PASS")):
        if err:
            st.error(f"Verification error: {err}")
            continue

        tsa_skip = ""
        if not r.get("tsaChecked"):
            tsa_skip = "no token" if not r.get("tsaTokenRef") else "certs missing"

        checks = [
            ("Encrypted file hash",   r.get("encryptedFileHashValid"),       True,                                ""),
            ("Device signature",      r.get("deviceSignatureValid"),          True,                                ""),
            ("Decryption",            r.get("decryptionValid"),               r.get("decryptionAttempted", False), "not requested"),
            ("Plaintext hash match",  r.get("plaintextHashMatchesEvidence"),  r.get("decryptionAttempted", False), "not requested"),
            ("RFC 3161 timestamp",    r.get("tsaValid"),                      r.get("tsaChecked", False),          tsa_skip),
        ]
        cells_html = "".join(_cell(lbl, val, chk, reason) for lbl, val, chk, reason in checks)
        st.markdown(
            f'<div style="display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-bottom:10px">{cells_html}</div>',
            unsafe_allow_html=True,
        )

        if r.get("notes"):
            st.info(r["notes"])

        if r.get("tsaChecked") and r.get("tsaDetail"):
            with st.expander("Timestamp detail"):
                st.code(r["tsaDetail"])

        key_source = r.get("publicKeySource", "enrolled")
        key_label = "🔑 Key: **override** (user-supplied)" if key_source == "override" else "🔑 Key: enrolled camera record"
        st.caption(
            f"Verification ID: `{r.get('verificationId','—')}` · "
            f"Verified at: `{r.get('verifiedAt','—')}` · "
            f"Verifier: `{r.get('verifierId','—')}` · "
            + key_label
        )
