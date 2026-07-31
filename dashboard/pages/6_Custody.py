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
    "Fetches the full Hyperledger Fabric ledger history for a given evidence block, "
    "showing every transaction that touched the record."
)


def _fmt_ts(ts: str) -> str:
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return ts


# ---------------------------------------------------------------------------
# Evidence selection
# ---------------------------------------------------------------------------
try:
    evidence_list = api_client.list_evidence()
except Exception:
    evidence_list = []

# Sort newest first
evidence_list = sorted(evidence_list, key=lambda e: e.get("captureTimestamp", ""), reverse=True)
evidence_map = {e["evidenceId"]: e for e in evidence_list}

if evidence_list:
    # Search box to narrow the dropdown
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
        fab = " · ⛓ on Fabric" if e.get("fabricTxId") else ""
        short_id = eid[:26] + "…" if len(eid) > 26 else eid
        return f"{cam}  ·  {ts}  ·  {short_id}{fab}"

    filtered_ids = [e["evidenceId"] for e in filtered]
    evidence_id = st.selectbox(
        "Select evidence block",
        options=filtered_ids,
        format_func=_label,
        label_visibility="collapsed",
    )

    # Detail card for the selected block
    if evidence_id:
        sel = evidence_map[evidence_id]
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Camera", sel.get("cameraId", "—"))
        c2.metric("Captured", _fmt_ts(sel.get("captureTimestamp", "—")))
        c3.metric("Fabric Tx", "Registered" if sel.get("fabricTxId") else "Not registered")
        c4.metric("Evidence ID", evidence_id[:18] + "…")
else:
    evidence_id = st.text_input("Evidence ID", placeholder="ev-001")

load = st.button("Load Fabric History", type="primary", disabled=not evidence_id)

if load and evidence_id:
    with st.spinner("Querying Fabric ledger…"):
        try:
            resp = api_client.get_fabric_history(evidence_id.strip())
        except Exception as exc:
            st.error(f"Request failed: {exc}")
            st.stop()

    if not resp.get("ok"):
        st.error(resp.get("detail", "Failed to fetch history"))
        st.stop()

    available = resp.get("available", False)
    history = resp.get("history", [])

    if not available:
        st.warning(
            "Fabric adapter is not reachable. "
            "Chain-of-custody history requires a running Hyperledger Fabric network. "
            "Start the network and re-deploy chaincode, then retry.",
            icon="⚠️",
        )
    elif not history:
        st.info(f"No Fabric history found for evidence `{evidence_id}`.")
    else:
        st.success(f"{len(history)} ledger entr{'y' if len(history) == 1 else 'ies'} found.", icon="📋")
        st.divider()

        for i, entry in enumerate(history):
            tx_id = entry.get("txId", f"tx-{i}")
            ts = entry.get("timestamp", "—")
            is_delete = entry.get("isDelete", False)

            if is_delete:
                label = f"🗑️  DELETE  ·  `{tx_id[:20]}…`  ·  {ts}"
            else:
                label = f"📝  TX {i + 1}  ·  `{tx_id[:20]}…`  ·  {ts}"

            with st.expander(label):
                col1, col2 = st.columns([1, 3])
                with col1:
                    st.markdown(f"**Transaction ID**")
                    st.code(tx_id, language=None)
                    st.markdown(f"**Timestamp**")
                    st.code(ts, language=None)
                    if is_delete:
                        st.error("Deleted entry")

                with col2:
                    value = entry.get("value")
                    if value and not is_delete:
                        try:
                            parsed = json.loads(value)
                            st.json(parsed)
                        except Exception:
                            st.code(value)
                    elif is_delete:
                        st.caption("(entry was deleted from the ledger)")
                    else:
                        st.caption("(no value)")
