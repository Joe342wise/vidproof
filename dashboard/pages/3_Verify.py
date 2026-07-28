import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import streamlit as st
from dashboard import api_client

st.set_page_config(page_title="Verify — VidProof", layout="wide")
st.title("Verify Evidence")
st.caption(
    "Hash check confirms the encrypted file is unaltered. "
    "Signature check proves the footage came from the enrolled camera — "
    "the device signature is stored in evidence metadata, not inside the encrypted video. "
    "RFC 3161 timestamp proves when the event occurred."
)

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
        help="Requires owner.x25519.priv.pem in storage/keys/ on the server",
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

    if decision == "PASS":
        st.success(f"PRIMARY DECISION: {decision}", icon="✅")
    else:
        st.error(f"PRIMARY DECISION: {decision}", icon="❌")

    # ---------------------------------------------------------------------------
    # Check results
    # ---------------------------------------------------------------------------
    st.subheader("Check Results")

    def _row(label: str, value, checked: bool = True) -> None:
        if not checked:
            st.markdown(f"- **{label}:** ⏭ skipped")
        elif value is True:
            st.markdown(f"- **{label}:** ✅ pass")
        elif value is False:
            st.markdown(f"- **{label}:** ❌ FAIL")
        else:
            st.markdown(f"- **{label}:** —")

    _row("Encrypted file hash", result.get("encryptedFileHashValid"))
    _row("Device signature",    result.get("deviceSignatureValid"))
    _row("Decryption",          result.get("decryptionValid"),
         checked=result.get("decryptionAttempted", False))
    _row("Plaintext hash match", result.get("plaintextHashMatchesEvidence"),
         checked=result.get("decryptionAttempted", False))
    _row("RFC 3161 timestamp",  result.get("tsaValid"),
         checked=result.get("tsaChecked", False))
    _row("PRNU",                result.get("prnuScore"),
         checked=result.get("prnuChecked", False))

    if result.get("tsaChecked") and result.get("tsaDetail"):
        with st.expander("Timestamp detail"):
            st.code(result["tsaDetail"])

    if result.get("prnuScore") is not None:
        st.markdown(f"- **PRNU score:** {result['prnuScore']:.4f} (secondary signal only)")

    st.caption(
        f"Verification ID: `{result.get('verificationId', '—')}` · "
        f"Verified at: `{result.get('verifiedAt', '—')}` · "
        f"Verifier: `{result.get('verifierId', '—')}`"
    )

    if result.get("notes"):
        st.info(result["notes"])
