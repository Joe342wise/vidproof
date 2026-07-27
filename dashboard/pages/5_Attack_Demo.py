import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import streamlit as st
import pandas as pd

st.set_page_config(page_title="Attack Demo — VidProof", layout="wide")
st.title("Attack Resilience Demo")
st.caption(
    "Runs live attack scenarios in isolated temporary directories. "
    "Each attack attempts to tamper with evidence and verifies that VidProof detects it."
)

from tests.test_attacks import ATTACKS

DESCRIPTIONS = {
    "enc_file_tamper":  "Bit-flip the .enc file (hash mismatch)",
    "signature_tamper": "Corrupt Ed25519 device signature",
    "auth_tag_tamper":  "Corrupt AES-GCM auth tag (decrypt failure)",
    "nonce_tamper":     "Corrupt AES-GCM nonce (decrypt failure)",
    "foreign_key":      "Sign with foreign camera key (wrong identity)",
    "missing_enc":      "Delete encrypted evidence file",
}

col_a, col_b = st.columns([2, 1])
with col_a:
    run_all = st.button("Run All 6 Attacks", type="primary")
with col_b:
    run_one = st.selectbox("Or run a single attack:", ["—"] + [n for n, _ in ATTACKS])

attacks_to_run = []
if run_all:
    attacks_to_run = list(ATTACKS)
elif run_one != "—":
    attacks_to_run = [(n, fn) for n, fn in ATTACKS if n == run_one]

if attacks_to_run:
    results = []
    prog = st.progress(0.0, text="Starting…")

    for i, (name, fn) in enumerate(attacks_to_run):
        prog.progress((i) / len(attacks_to_run), text=f"Running `{name}`…")
        try:
            res = fn()
            res["attack"] = name
        except Exception as exc:
            res = {
                "attack": name,
                "description": DESCRIPTIONS.get(name, name),
                "error": str(exc),
                "detectedFailure": False,
            }
        results.append(res)

    prog.progress(1.0, text="Complete.")
    prog.empty()

    detected_count = sum(1 for r in results if r.get("detectedFailure"))
    total = len(results)

    if detected_count == total:
        st.success(f"All {total} attacks detected correctly.", icon="✅")
    elif detected_count == 0:
        st.error(f"No attacks detected ({detected_count}/{total}).", icon="❌")
    else:
        st.warning(f"{detected_count}/{total} attacks detected.", icon="⚠️")

    rows = []
    for res in results:
        detected = res.get("detectedFailure", False)
        rows.append({
            "Attack": res["attack"],
            "Description": res.get("description", DESCRIPTIONS.get(res["attack"], res["attack"])),
            "Result": "DETECTED" if detected else "MISSED",
        })

    df = pd.DataFrame(rows)

    def _color_result(val: str) -> str:
        if val == "DETECTED":
            return "background-color: #d4edda; color: #155724"
        return "background-color: #f8d7da; color: #721c24"

    st.dataframe(
        df.style.map(_color_result, subset=["Result"]),
        use_container_width=True,
        hide_index=True,
    )

    st.subheader("Detailed Results")
    for res in results:
        detected = res.get("detectedFailure", False)
        icon = "✅" if detected else "❌"
        with st.expander(f"{icon}  {res['attack']}"):
            st.json({k: v for k, v in res.items() if k != "attack"})
