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
    "Every action taken on an evidence block — capture, RFC 3161 timestamping, "
    "export, access, verification — is anchored on the Hyperledger Fabric ledger. "
    "This page renders that ledger history as a plain-English custody narrative."
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
    st.info("No Fabric history found for this evidence block yet.")
    st.stop()


# ---------------------------------------------------------------------------
# Helper: parse value field (may be a JSON string or dict)
# ---------------------------------------------------------------------------
def _val(entry: dict) -> dict:
    raw = entry.get("value", {})
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except Exception:
            return {}
    return raw or {}


def _event_type(entry: dict) -> str:
    et = entry.get("eventType", "")
    if not et:
        et = _val(entry).get("eventType", "")
    return et


# ---------------------------------------------------------------------------
# Expand history: inject a synthetic TSA node after every registration event
# that has a TSA token.
# ---------------------------------------------------------------------------
def _expand_history(raw: list[dict]) -> list[dict]:
    expanded = []
    for entry in raw:
        expanded.append(entry)
        if _event_type(entry) == "evidence_registration":
            v = _val(entry)
            tsa_ref  = v.get("tsaTokenRef", "")
            tsa_hash = v.get("tsaTokenHash", "")
            if tsa_ref or tsa_hash:
                expanded.append({
                    "_synthetic": True,
                    "eventType":  "tsa_timestamp",
                    "txId":       entry.get("txId", ""),
                    "timestamp":  v.get("captureTimestamp", entry.get("timestamp", "")),
                    "value": {
                        "tsaTokenRef":       tsa_ref,
                        "tsaTokenHash":      tsa_hash,
                        "captureTimestamp":  v.get("captureTimestamp", ""),
                        "encryptedFileHash": v.get("encryptedFileHash", ""),
                    },
                })
    return expanded


# ---------------------------------------------------------------------------
# Narrative builders — one per event type
# ---------------------------------------------------------------------------

def _narrative_registration(v: dict, tx_id: str, ts: str) -> tuple[str, str, str, str]:
    cam      = v.get("cameraId", "—")
    cap_ts   = _fmt_ts(v.get("captureTimestamp", ts))
    eid      = v.get("evidenceId", "—")
    algo     = v.get("encryptionAlgo", "AES-256-GCM")
    fhash    = v.get("encryptedFileHash", "—")
    phash    = v.get("plaintextHash", "—")
    sig      = v.get("deviceSignature", "—")
    prnu     = v.get("prnuCaptureScore")
    tsa_ref  = v.get("tsaTokenRef", "")
    tsa_hash = v.get("tsaTokenHash", "")

    tsa_line = ""
    if tsa_ref or tsa_hash:
        tsa_line = (
            " An **RFC 3161 timestamp** was also obtained from an independent "
            "trusted timestamp authority immediately at capture — see the next "
            "entry in the timeline for details."
        )

    summary = (
        f"Camera **{cam}** captured video footage at **{cap_ts}**. "
        f"The video was SHA-256 hashed, signed with the camera's **Ed25519 private key** "
        f"(which never leaves the device), encrypted with **{algo}**, and anchored to "
        f"the Hyperledger Fabric ledger — establishing an immutable, authenticated "
        f"record of the footage.{tsa_line}"
    )

    prnu_line = f"\n- **PRNU capture score:** `{prnu:.3f}`" if prnu is not None else ""
    tsa_detail = ""
    if tsa_ref or tsa_hash:
        tsa_detail = f"\n- **TSA token hash (SHA-256):** `{tsa_hash}`\n- **TSA token file:** `{tsa_ref}`"

    detail = f"""\
- **Evidence ID:** `{eid}`
- **Camera:** `{cam}`
- **Captured at:** {cap_ts}
- **Encryption:** {algo}
- **Encrypted file hash (SHA-256):** `{fhash}`
- **Plaintext hash (SHA-256):** `{phash}`
- **Ed25519 device signature:** `{sig[:48]}…`{prnu_line}{tsa_detail}
- **Fabric tx:** `{tx_id}`"""
    return "📹", "Evidence Registered on Fabric", summary, detail


def _narrative_tsa(v: dict, tx_id: str, ts: str) -> tuple[str, str, str, str]:
    cap_ts   = _fmt_ts(v.get("captureTimestamp", ts))
    tsa_hash = v.get("tsaTokenHash", "—")
    tsa_ref  = v.get("tsaTokenRef", "—")
    fhash    = v.get("encryptedFileHash", "")

    what_was_stamped = (
        f"the SHA-256 hash of the encrypted video file (`{fhash[:16]}…`)"
        if fhash else "the SHA-256 hash of the encrypted video file"
    )

    summary = (
        f"At **{cap_ts}**, an **RFC 3161 timestamp** was issued by an independent "
        f"trusted timestamp authority (TSA). The TSA cryptographically bound "
        f"{what_was_stamped} to this exact moment in time. "
        f"The TSA operates **entirely independently of VidProof** — it receives only "
        f"a hash (no video content), signs it with its own private key, and returns "
        f"a token. This token proves the footage existed before **{cap_ts}** "
        f"and cannot be backdated or altered. Anyone can verify it using standard "
        f"OpenSSL tools with no connection to this system."
    )

    detail = f"""\
- **Standard:** RFC 3161 — Internet X.509 PKI Time-Stamp Protocol
- **What was stamped:** SHA-256 hash of the encrypted video file
- **Certified at:** {cap_ts} *(time issued by the TSA, not this server)*
- **TSA token hash (SHA-256):** `{tsa_hash}`
  *(this hash is stored on the Fabric ledger — anyone can verify the token file produces this exact hash)*
- **Token file location:** `{tsa_ref}`
- **Independent verification command:**
  ```
  openssl ts -verify -in token.tsr -digest <encryptedFileHash> \\
      -md sha256 -CAfile ca.crt -untrusted tsa.crt
  ```
- **Fabric tx:** `{tx_id}` *(the same tx that registered the evidence)*"""
    return "🕐", "RFC 3161 Timestamp — Independently Certified", summary, detail


def _narrative_export(v: dict, tx_id: str, ts: str) -> tuple[str, str, str, str]:
    actor    = v.get("actorId", "an operator")
    event_ts = _fmt_ts(v.get("timestamp", ts))
    notes    = v.get("notes", "")
    notes_clause = f" ({notes})" if notes else ""

    summary = (
        f"**{actor}** exported a forensic package at **{event_ts}**{notes_clause}. "
        f"This event was logged to the Fabric ledger to create an auditable record "
        f"of who received a copy of this evidence and when."
    )
    detail = f"""\
- **Actor:** `{actor}`
- **Exported at:** {event_ts}
- **Notes:** {notes or "—"}
- **Fabric tx:** `{tx_id}`"""
    return "📦", "Forensic Package Exported", summary, detail


def _narrative_access(v: dict, tx_id: str, ts: str) -> tuple[str, str, str, str]:
    actor    = v.get("actorId", "an operator")
    event_ts = _fmt_ts(v.get("timestamp", ts))
    notes    = v.get("notes", "")

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

    # TSA check details
    tsa_checked = v.get("tsaChecked", False)
    tsa_valid   = v.get("tsaValid")
    tsa_detail  = v.get("tsaDetail", "")

    icon = "✅" if decision == "PASS" else "❌"

    if decision == "PASS":
        primary_outcome = "**PASS** — the encrypted file hash and Ed25519 device signature were both valid."
    else:
        primary_outcome = (
            f"**FAIL** — the following checks did not pass: "
            f"{', '.join(f'`{c}`' for c in failed)}."
        )

    # TSA sentence
    if tsa_checked:
        if tsa_valid:
            tsa_sentence = (
                " The **RFC 3161 timestamp** was also verified against the trusted timestamp "
                "authority — the token is valid, confirming the evidence existed before "
                "the timestamp was issued and has not been altered since."
            )
        else:
            tsa_sentence = (
                " The **RFC 3161 timestamp** verification **failed** — "
                "the timestamp token did not match the evidence. "
                f"Detail: {tsa_detail or 'see logs'}."
            )
    else:
        tsa_sentence = (
            " RFC 3161 timestamp verification was not performed "
            "(either no token is stored for this block, or TSA certificates were unavailable)."
        )

    summary = (
        f"**{verifier}** ran a cryptographic verification at **{ver_ts}**. "
        f"Primary decision: {primary_outcome}{tsa_sentence}"
    )

    tsa_block = ""
    if tsa_checked:
        tsa_block = (
            f"\n- **RFC 3161 timestamp check:** {'✅ valid' if tsa_valid else '❌ invalid'}"
            + (f"\n- **TSA detail:** {tsa_detail}" if tsa_detail else "")
        )

    detail = f"""\
- **Verifier:** `{verifier}`
- **Verified at:** {ver_ts}
- **Verification ID:** `{ver_id}`
- **Primary decision:** {decision}
- **Failed checks:** {', '.join(failed) if failed else 'none'}{tsa_block}
- **Decryption performed:** {'yes' if v.get('decryptionAttempted') else 'no'}
- **PRNU checked:** {'yes — score ' + str(round(v['prnuScore'], 3)) if v.get('prnuChecked') else 'no'}
- **Fabric tx:** `{tx_id}`"""
    return icon, f"Verification Run — {decision}", summary, detail


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
    tx_id     = entry.get("txId", "—")
    ts        = entry.get("timestamp", "—")
    is_delete = entry.get("isDelete", False)
    et        = _event_type(entry)
    v         = _val(entry)

    if is_delete:
        return _narrative_delete(tx_id, ts)
    if et == "evidence_registration":
        return _narrative_registration(v, tx_id, ts)
    if et == "tsa_timestamp":
        return _narrative_tsa(v, tx_id, ts)
    if et == "export":
        return _narrative_export(v, tx_id, ts)
    if et == "access":
        return _narrative_access(v, tx_id, ts)
    if et == "verification":
        return _narrative_verification(v, tx_id, ts)
    return _narrative_unknown(et or "unknown", v, tx_id, ts)


# ---------------------------------------------------------------------------
# Expand the history to inject TSA nodes
# ---------------------------------------------------------------------------
full_history = _expand_history(history)

# ---------------------------------------------------------------------------
# Timeline CSS
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
.custody-event { position: relative; margin-bottom: 28px; }
.custody-dot {
  position: absolute;
  left: -29px; top: 4px;
  width: 28px; height: 28px;
  border-radius: 50%;
  background: #0f172a;
  border: 2px solid #475569;
  display: flex; align-items: center; justify-content: center;
  font-size: 14px; z-index: 1;
}
.custody-dot.reg   { border-color: #38bdf8; }
.custody-dot.tsa   { border-color: #a78bfa; background: #1e1b4b; }
.custody-dot.last  { border-color: #4ade80; }
.custody-dot.fail  { border-color: #f87171; }
.custody-card {
  background: #0f172a;
  border: 1px solid #1e293b;
  border-radius: 10px;
  padding: 16px 20px;
}
.custody-card.tsa {
  border-color: #4c1d95;
  background: #1e1b4b22;
}
.custody-ts {
  font-size: 0.75em; color: #64748b;
  font-family: monospace; margin-bottom: 4px;
}
.custody-tsa-badge {
  display: inline-block;
  font-size: 0.68em; font-weight: 700;
  background: #4c1d95; color: #c4b5fd;
  border-radius: 4px; padding: 1px 7px;
  margin-left: 8px; vertical-align: middle;
  letter-spacing: .05em; text-transform: uppercase;
}
.custody-title {
  font-size: 1.05em; font-weight: 700;
  color: #f1f5f9; margin-bottom: 8px;
}
.custody-summary {
  font-size: 0.88em; color: #cbd5e1; line-height: 1.6;
}
</style>
"""

st.markdown(_TIMELINE_CSS, unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Summary line
# ---------------------------------------------------------------------------
_LABELS = {
    "evidence_registration": "registered",
    "tsa_timestamp":         "RFC 3161 timestamped",
    "export":                "exported",
    "access":                "accessed",
    "verification":          "verified",
}

summary_parts = [_LABELS.get(_event_type(e), _event_type(e) or "unknown") for e in full_history]
st.markdown(
    f"**{len(history)} ledger entr{'y' if len(history) == 1 else 'ies'}** — "
    + ", ".join(summary_parts)
)
st.markdown("")

# ---------------------------------------------------------------------------
# Build timeline HTML
# ---------------------------------------------------------------------------
timeline_items = []
n = len(full_history)
for i, entry in enumerate(full_history):
    icon, title, summary_text, _ = _build_narrative(entry)
    et  = _event_type(entry)
    ts  = _fmt_ts(entry.get("timestamp", ""))

    dot_class = ""
    card_class = ""
    badge = ""
    if et == "evidence_registration":
        dot_class = "reg"
    elif et == "tsa_timestamp":
        dot_class = "tsa"
        card_class = "tsa"
        badge = '<span class="custody-tsa-badge">RFC 3161</span>'
    elif i == n - 1:
        dot_class = "last"
    elif et == "verification" and "FAIL" in title:
        dot_class = "fail"

    timeline_items.append(f"""
<div class="custody-event">
  <div class="custody-dot {dot_class}">{icon}</div>
  <div class="custody-card {card_class}">
    <div class="custody-ts">{ts}</div>
    <div class="custody-title">{title}{badge}</div>
    <div class="custody-summary">{summary_text}</div>
  </div>
</div>""")

st.markdown(
    f'<div class="custody-timeline">{"".join(timeline_items)}</div>',
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# Technical detail expanders
# ---------------------------------------------------------------------------
st.markdown("---")
st.markdown("**Technical details**")
for entry in full_history:
    _, title, _, detail_md = _build_narrative(entry)
    ts = entry.get("timestamp", "—")
    with st.expander(f"{title}  ·  {_fmt_ts(ts)}"):
        st.markdown(detail_md)
