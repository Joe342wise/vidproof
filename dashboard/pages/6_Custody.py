import json
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import streamlit as st
from dashboard import api_client

st.set_page_config(page_title="Chain of Custody — VidProof", layout="wide")
st.title("Chain of Custody")
st.caption(
    "Fetches the full Hyperledger Fabric ledger history for a given evidence ID, "
    "showing every transaction that touched the record."
)

# Evidence selection
try:
    evidence_list = api_client.list_evidence()
    evidence_ids = [e["evidenceId"] for e in evidence_list] if evidence_list else []
except Exception:
    evidence_ids = []

if evidence_ids:
    evidence_id = st.selectbox("Evidence ID", evidence_ids)
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
