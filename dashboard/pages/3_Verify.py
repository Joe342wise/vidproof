import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import streamlit as st
from dashboard import api_client

st.set_page_config(page_title="Verify — VidProof", layout="wide")
st.title("Verify Evidence")

# ---------------------------------------------------------------------------
# Input
# ---------------------------------------------------------------------------
col1, col2 = st.columns([2, 1])
with col1:
    evidence_id = st.text_input("Evidence ID", placeholder="ev-001")
    verifier_id = st.text_input("Verifier ID", value="system")
with col2:
    include_decryption = st.checkbox(
        "Include decryption check",
        help="Requires owner.x25519.priv.pem to be present in storage/keys/ on the server",
    )

run = st.button("Run Verification", type="primary", disabled=not evidence_id)

if run and evidence_id:
    with st.spinner("Verifying…"):
        try:
            response = api_client.verify_evidence(
                evidence_id=evidence_id.strip(),
                verifier_id=verifier_id.strip() or "system",
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

    # Primary decision banner
    if decision == "PASS":
        st.success(f"PRIMARY DECISION: {decision}", icon="✅")
    else:
        st.error(f"PRIMARY DECISION: {decision}", icon="❌")

    # Detail table
    st.subheader("Check Results")
    checks = {
        "Encrypted file hash valid": result.get("encryptedFileHashValid"),
        "Device signature valid": result.get("deviceSignatureValid"),
        "Decryption attempted": result.get("decryptionAttempted"),
        "Decryption valid": result.get("decryptionValid"),
        "Plaintext hash matches evidence": result.get("plaintextHashMatchesEvidence"),
        "PRNU checked": result.get("prnuChecked"),
    }
    for label, value in checks.items():
        if value is True:
            st.markdown(f"- **{label}:** ✅ Yes")
        elif value is False:
            st.markdown(f"- **{label}:** ❌ No")
        else:
            st.markdown(f"- **{label}:** —")

    if result.get("prnuScore") is not None:
        st.markdown(f"- **PRNU score:** {result['prnuScore']:.4f}")

    st.caption(
        f"Verification ID: `{result.get('verificationId', '—')}` · "
        f"Verified at: `{result.get('verifiedAt', '—')}` · "
        f"Verifier: `{result.get('verifierId', '—')}`"
    )

    if result.get("notes"):
        st.info(result["notes"])
