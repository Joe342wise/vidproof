import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import streamlit as st
import pandas as pd
from dashboard import api_client

st.set_page_config(page_title="Results — VidProof", layout="wide")
st.title("Verification Results")

evidence_id = st.text_input("Evidence ID", placeholder="ev-001")
load = st.button("Load Results", disabled=not evidence_id)

if load and evidence_id:
    with st.spinner("Loading…"):
        try:
            results = api_client.list_verification_results(evidence_id.strip())
        except Exception as exc:
            st.error(f"Request failed: {exc}")
            st.stop()

    if not results:
        st.info("No verification results found for this evidence item.")
    else:
        # Summary row
        pass_count = sum(1 for r in results if r.get("primaryDecision") == "PASS")
        fail_count = len(results) - pass_count
        c1, c2, c3 = st.columns(3)
        c1.metric("Total runs", len(results))
        c2.metric("PASS", pass_count)
        c3.metric("FAIL", fail_count)

        # Results table
        df = pd.DataFrame(results)
        display = ["verificationId", "verifiedAt", "verifierId", "primaryDecision",
                   "encryptedFileHashValid", "deviceSignatureValid"]
        available = [c for c in display if c in df.columns]
        df_display = df[available].copy()

        def _color_decision(val):
            color = "green" if val == "PASS" else "red"
            return f"color: {color}; font-weight: bold"

        if "primaryDecision" in df_display.columns:
            styled = df_display.style.map(_color_decision, subset=["primaryDecision"])
            st.dataframe(styled, use_container_width=True, hide_index=True)
        else:
            st.dataframe(df_display, use_container_width=True, hide_index=True)

        # Expandable detail per result
        with st.expander("Raw JSON"):
            for r in results:
                st.json(r)
