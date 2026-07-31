import json
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from datetime import datetime

import streamlit as st
from dashboard import api_client

st.set_page_config(page_title="Chain of Custody — VidProof", layout="wide")
st.title("Chain of Custody")
st.caption(
    "Every action taken on an evidence block — capture, export, access, verification — "
    "is anchored on the Hyperledger Fabric ledger. This page renders that ledger history "
    "as a plain-English custody narrative."
)


def _fmt_ts(ts: str) -> str:
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return ts or "—"


# ---------------------------------------------------------------------------
# Evidence selector
# ---------------------------------------------------------------------------
try:
    evidence_list = api_client.list_evidence()
except Exception:
    evidence_list = []

evidence_list = sorted(evidence_list, key=lambda e: e.get("captureTimestamp", ""), reverse=True)
evidence_map = {e["evidenceId"]: e for e in evidence_list}

if not evidence_list:
    st.info("No evidence blocks found. Capture some footage first.")
    st.stop()

search = st.text_input(
    "Filter blocks",
    placeholder="Type camera ID or evidence ID…",
    label_visibility="collapsed",
).strip().lower()

filtered = [
    e for e in evidence_list
    if not search
    or search in e.get("evidenceId", "").lower()
    or search in e.get("cameraId", "").lower()
]

if not filtered:
    st.info("No blocks match that search.")
    st.stop()


def _label(eid: str) -> str:
    e = evidence_map.get(eid, {})
    cam = e.get("cameraId", "?")
    ts  = _fmt_ts(e.get("captureTimestamp", ""))
    fab = " · ⛓" if e.get("fabricTxId") else ""
    short_id = eid[:26] + "…" if len(eid) > 26 else eid
    return f"{cam}  ·  {ts}  ·  {short_id}{fab}"


filtered_ids = [e["evidenceId"] for e in filtered]
evidence_id = st.selectbox(
    "Select evidence block",
    options=filtered_ids,
    format_func=_label,
    label_visibility="collapsed",
)

if evidence_id:
    sel = evidence_map[evidence_id]
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Camera", sel.get("cameraId", "—"))
    c2.metric("Captured", _fmt_ts(sel.get("captureTimestamp", "—")))
    c3.metric("Fabric Tx", "Registered" if sel.get("fabricTxId") else "Not registered")
    c4.metric("Evidence ID", evidence_id[:18] + "…")

st.divider()

# ---------------------------------------------------------------------------
# Auto-load Fabric history
# ---------------------------------------------------------------------------
@st.cache_data(ttl=30)
def _load_history(eid: str) -> dict:
    try:
        return api_client.get_fabric_history(eid)
    except Exception as exc:
        return {"ok": False, "detail": str(exc)}


col_head, col_refresh = st.columns([6, 1])
with col_head:
    st.subheader("Custody Timeline")
with col_refresh:
    if st.button("Refresh", use_container_width=True):
        st.cache_data.clear()
        st.rerun()

resp = _load_history(evidence_id)

if not resp.get("ok"):
    st.error(resp.get("detail", "Failed to fetch history"))
    st.stop()

if not resp.get("available"):
    st.warning(
        "Fabric adapter is not reachable. "
        "Chain-of-custody history requires a running Hyperledger Fabric network.",
        icon="⚠️",
    )
    st.stop()

history = resp.get("history", [])

if not history:
    st.info(f"No Fabric history found for this evidence block yet.")
    st.stop()


# ---------------------------------------------------------------------------
# Narrative builders — convert each event type to plain English
# ---------------------------------------------------------------------------

def _narrative_registration(v: dict, tx_id: str, ts: str) -> tuple[str, str, str, str]:
    """Returns (icon, title, summary, detail_md)."""
    cam   = v.get("cameraId", "—")
    cap_ts = _fmt_ts(v.get("captureTimestamp", ts))
    eid   = v.get("evidenceId", "—")
    algo  = v.get("encryptionAlgo", "AES-256-GCM")
    fhash = v.get("encryptedFileHash", "—")
    phash = v.get("plaintextHash", "—")
    sig   = v.get("deviceSignature", "—")
    prnu  = v.get("prnuCaptureScore")
    tsa   = v.get("tsaTokenRef", "")

    summary = (
        f"Camera **{cam}** captured video footage at **{cap_ts}**. "
        f"The video was hashed, signed with the camera's Ed25519 private key, "
        f"encrypted with AES-256-GCM, and anchored to the Fabric ledger — "
        f"establishing an immutable, authenticated record of the footage."
    )

    prnu_line = ""
    if prnu is not None:
        prnu_line = f"\n- **PRNU capture score:** `{prnu:.3f}`"

    tsa_line = ""
    if tsa:
        tsa_line = f"\n- **RFC 3161 timestamp token:** `{tsa}`"

    detail = f"""\
- **Evidence ID:** `{eid}`
- **Camera:** `{cam}`
- **Captured at:** {cap_ts}
- **Encryption:** {algo}
- **Encrypted file hash (SHA-256):** `{fhash}`
- **Plaintext hash (SHA-256):** `{phash}`
- **Ed25519 device signature:** `{sig[:32]}…`{prnu_line}{tsa_line}
- **Fabric tx:** `{tx_id}`"""
    return "📹", "Evidence Registered on Fabric", summary, detail


def _narrative_export(v: dict, tx_id: str, ts: str) -> tuple[str, str, str, str]:
    actor = v.get("actorId", "an operator")
    event_ts = _fmt_ts(v.get("timestamp", ts))
    notes = v.get("notes", "")
    notes_clause = f" ({notes})" if notes else ""

    summary = (
        f"**{actor}** exported a forensic package at **{event_ts}**{notes_clause}. "
        f"The package was logged to the Fabric ledger to create an auditable record "
        f"of who received a copy of this evidence and when."
    )
    detail = f"""\
- **Actor:** `{actor}`
- **Exported at:** {event_ts}
- **Notes:** {notes or "—"}
- **Fabric tx:** `{tx_id}`"""
    return "📦", "Forensic Package Exported", summary, detail


def _narrative_access(v: dict, tx_id: str, ts: str) -> tuple[str, str, str, str]:
    actor = v.get("actorId", "an operator")
    event_ts = _fmt_ts(v.get("timestamp", ts))
    notes = v.get("notes", "")

    summary = (
        f"**{actor}** accessed this evidence at **{event_ts}**. "
        + (f"Reason: {notes}." if notes else "No reason recorded.")
    )
    detail = f"""\
- **Actor:** `{actor}`
- **Accessed at:** {event_ts}
- **Notes:** {notes or "—"}
- **Fabric tx:** `{tx_id}`"""
    return "👁️", "Evidence Accessed", summary, detail


def _narrative_verification(v: dict, tx_id: str, ts: str) -> tuple[str, str, str, str]:
    decision = v.get("primaryDecision", "UNKNOWN")
    verifier = v.get("verifierId", "an operator")
    ver_ts   = _fmt_ts(v.get("verifiedAt", ts))
    ver_id   = v.get("verificationId", "—")
    failed   = v.get("failedChecks", [])

    icon = "✅" if decision == "PASS" else "❌"
    if decision == "PASS":
        outcome = "**PASS** — all primary checks (encrypted file hash and Ed25519 signature) were valid."
    else:
        outcome = f"**FAIL** — the following checks did not pass: {', '.join(f'`{c}`' for c in failed)}."

    summary = (
        f"**{verifier}** ran a cryptographic verification at **{ver_ts}**. "
        f"Primary decision: {outcome}"
    )
    detail = f"""\
- **Verifier:** `{verifier}`
- **Verified at:** {ver_ts}
- **Verification ID:** `{ver_id}`
- **Primary decision:** {decision}
- **Failed checks:** {', '.join(failed) if failed else 'none'}
- **Fabric tx:** `{tx_id}`"""
    return icon, f"Verification — {decision}", summary, detail


def _narrative_delete(tx_id: str, ts: str) -> tuple[str, str, str, str]:
    summary = (
        f"A ledger record was **deleted** at **{_fmt_ts(ts)}**. "
        "Deletions are unusual and may indicate administrative action or ledger tampering."
    )
    detail = f"- **Fabric tx:** `{tx_id}`\n- **Timestamp:** {_fmt_ts(ts)}"
    return "🗑️", "Ledger Record Deleted", summary, detail


def _narrative_unknown(event_type: str, v: dict, tx_id: str, ts: str) -> tuple[str, str, str, str]:
    summary = f"An event of type **`{event_type}`** was recorded at **{_fmt_ts(ts)}**."
    detail  = f"- **Fabric tx:** `{tx_id}`\n```json\n{json.dumps(v, indent=2)}\n```"
    return "🔖", f"Event: {event_type}", summary, detail


def _build_narrative(entry: dict) -> tuple[str, str, str, str]:
    tx_id      = entry.get("txId", "—")
    ts         = entry.get("timestamp", "—")
    is_delete  = entry.get("isDelete", False)
    event_type = entry.get("eventType", "")

    raw_value = entry.get("value", {})
    if isinstance(raw_value, str):
        try:
            v = json.loads(raw_value)
        except Exception:
            v = {}
    else:
        v = raw_value or {}

    # event_type on the history entry takes precedence; fall back to value field
    if not event_type and isinstance(v, dict):
        event_type = v.get("eventType", "")

    if is_delete:
        return _narrative_delete(tx_id, ts)
    if event_type == "evidence_registration":
        return _narrative_registration(v, tx_id, ts)
    if event_type == "export":
        return _narrative_export(v, tx_id, ts)
    if event_type == "access":
        return _narrative_access(v, tx_id, ts)
    if event_type == "verification":
        return _narrative_verification(v, tx_id, ts)
    return _narrative_unknown(event_type or "unknown", v, tx_id, ts)


# ---------------------------------------------------------------------------
# Timeline CSS + render
# ---------------------------------------------------------------------------

_TIMELINE_CSS = """
<style>
.custody-timeline { position: relative; padding-left: 36px; }
.custody-timeline::before {
  content: "";
  position: absolute;
  left: 14px;
  top: 8px;
  bottom: 8px;
  width: 2px;
  background: #334155;
}
.custody-event {
  position: relative;
  margin-bottom: 28px;
}
.custody-dot {
  position: absolute;
  left: -29px;
  top: 4px;
  width: 28px;
  height: 28px;
  border-radius: 50%;
  background: #0f172a;
  border: 2px solid #475569;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 14px;
  z-index: 1;
}
.custody-dot.first { border-color: #38bdf8; }
.custody-dot.last  { border-color: #4ade80; }
.custody-card {
  background: #0f172a;
  border: 1px solid #1e293b;
  border-radius: 10px;
  padding: 16px 20px;
}
.custody-ts {
  font-size: 0.75em;
  color: #64748b;
  font-family: monospace;
  margin-bottom: 4px;
}
.custody-title {
  font-size: 1.05em;
  font-weight: 700;
  color: #f1f5f9;
  margin-bottom: 8px;
}
.custody-summary {
  font-size: 0.88em;
  color: #cbd5e1;
  line-height: 1.6;
}
</style>
"""

st.markdown(_TIMELINE_CSS, unsafe_allow_html=True)

# Summary sentence
event_labels = {
    "evidence_registration": "registered",
    "export": "exported",
    "access": "accessed",
    "verification": "verified",
}

def _event_label(entry: dict) -> str:
    et = entry.get("eventType", "")
    if not et:
        v = entry.get("value", {})
        if isinstance(v, dict):
            et = v.get("eventType", "")
    return event_labels.get(et, et or "unknown event")

summary_parts = [_event_label(e) for e in history]
st.markdown(
    f"**{len(history)} ledger entr{'y' if len(history) == 1 else 'ies'}** — "
    + ", ".join(summary_parts)
)
st.markdown("")

# Build timeline HTML
timeline_items = []
for i, entry in enumerate(history):
    icon, title, summary_text, _ = _build_narrative(entry)
    ts = _fmt_ts(entry.get("timestamp", ""))
    dot_class = "first" if i == 0 else ("last" if i == len(history) - 1 else "")
    timeline_items.append(f"""
<div class="custody-event">
  <div class="custody-dot {dot_class}">{icon}</div>
  <div class="custody-card">
    <div class="custody-ts">{ts}</div>
    <div class="custody-title">{title}</div>
    <div class="custody-summary">{summary_text}</div>
  </div>
</div>""")

st.markdown(
    f'<div class="custody-timeline">{"".join(timeline_items)}</div>',
    unsafe_allow_html=True,
)

# Technical detail expanders (outside the HTML so Streamlit renders them natively)
st.markdown("---")
st.markdown("**Technical details**")
for i, entry in enumerate(history):
    _, title, _, detail_md = _build_narrative(entry)
    ts = entry.get("timestamp", "—")
    with st.expander(f"{title}  ·  {_fmt_ts(ts)}"):
        st.markdown(detail_md)
