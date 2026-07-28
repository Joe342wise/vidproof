import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import streamlit as st
from dashboard import api_client

st.set_page_config(page_title="Forensic Export — VidProof", layout="wide")
st.title("Forensic Export")
st.caption(
    "Runs full verification before packaging — hash check, signature check, decryption, "
    "and RFC 3161 timestamp. Failed blocks are flagged; user decides whether to include them."
)

# ---------------------------------------------------------------------------
# Session state initialisation
# ---------------------------------------------------------------------------
if "export_stage" not in st.session_state:
    st.session_state.export_stage = "select"   # select | results | done
if "export_evidence_id" not in st.session_state:
    st.session_state.export_evidence_id = ""
if "export_verify_result" not in st.session_state:
    st.session_state.export_verify_result = {}
if "export_zip_bytes" not in st.session_state:
    st.session_state.export_zip_bytes = b""


def _reset():
    st.session_state.export_stage = "select"
    st.session_state.export_evidence_id = ""
    st.session_state.export_verify_result = {}
    st.session_state.export_zip_bytes = b""


def _check_icon(value: bool | None, checked: bool) -> str:
    if not checked:
        return "⏭ skipped"
    return "✅ pass" if value else "❌ FAIL"


# ---------------------------------------------------------------------------
# Stage: select
# ---------------------------------------------------------------------------
if st.session_state.export_stage == "select":
    try:
        evidence_list = api_client.list_evidence()
        evidence_ids = [e["evidenceId"] for e in evidence_list] if evidence_list else []
    except Exception:
        evidence_ids = []

    if evidence_ids:
        evidence_id = st.selectbox("Evidence block", evidence_ids)
    else:
        evidence_id = st.text_input("Evidence ID", placeholder="ev-001")

    st.info(
        "Clicking **Verify & Export** runs the full verification pipeline on this block "
        "before any package is generated.",
        icon="ℹ️",
    )

    if st.button("Verify & Export", type="primary", disabled=not evidence_id):
        with st.spinner("Running verification…"):
            try:
                resp = api_client.verify_evidence(
                    evidence_id.strip(),
                    verifier_id="export-operator",
                    include_decryption=True,
                )
            except Exception as exc:
                st.error(f"Verification request failed: {exc}")
                st.stop()

        if not resp.get("ok"):
            st.error(f"Verification error: {resp.get('detail', resp)}")
            st.stop()

        st.session_state.export_evidence_id = evidence_id.strip()
        st.session_state.export_verify_result = resp["result"]
        st.session_state.export_stage = "results"
        st.rerun()


# ---------------------------------------------------------------------------
# Stage: results — show per-check outcome, let user confirm
# ---------------------------------------------------------------------------
elif st.session_state.export_stage == "results":
    r = st.session_state.export_verify_result
    eid = st.session_state.export_evidence_id
    passed = r.get("primaryDecision") == "PASS"

    st.subheader(f"Verification results — {eid}")

    if passed:
        st.success("All primary checks passed.", icon="✅")
    else:
        st.error("One or more primary checks failed.", icon="❌")

    # Per-check table
    checks = [
        ("Encrypted file hash",   r.get("encryptedFileHashValid"), True),
        ("Device signature",      r.get("deviceSignatureValid"),   True),
        ("Decryption",            r.get("decryptionValid"),        r.get("decryptionAttempted", False)),
        ("Plaintext hash match",  r.get("plaintextHashMatchesEvidence"), r.get("decryptionAttempted", False)),
        ("RFC 3161 timestamp",    r.get("tsaValid"),               r.get("tsaChecked", False)),
    ]

    rows = "".join(
        f"<tr>"
        f"<td style='padding:6px 14px'>{name}</td>"
        f"<td style='padding:6px 14px;font-family:monospace'>{_check_icon(val, chk)}</td>"
        f"</tr>"
        for name, val, chk in checks
    )
    st.markdown(
        f"""<table style='border-collapse:collapse;font-size:0.9em;width:100%;max-width:560px'>
        <thead><tr style='border-bottom:1px solid #334155'>
          <th style='padding:6px 14px;text-align:left'>Check</th>
          <th style='padding:6px 14px;text-align:left'>Result</th>
        </tr></thead>
        <tbody>{rows}</tbody></table>""",
        unsafe_allow_html=True,
    )

    if r.get("tsaChecked") and r.get("tsaDetail"):
        with st.expander("Timestamp detail"):
            st.code(r["tsaDetail"])

    if r.get("notes"):
        st.caption(f"Notes: {r['notes']}")

    st.divider()

    include_failed = False
    if not passed:
        st.warning(
            "This block failed verification. A failed block can still be included in the "
            "export package — it is itself evidence of tampering and should not be silently "
            "discarded. The package will clearly mark it as failed.",
            icon="⚠️",
        )
        include_failed = st.checkbox("Include this failed block in the export package")

    col_pkg, col_back = st.columns([2, 6])
    with col_pkg:
        generate_disabled = not passed and not include_failed
        if st.button("Generate Package", type="primary", disabled=generate_disabled):
            with st.spinner("Building forensic package…"):
                try:
                    zip_bytes = api_client.export_evidence(eid)
                except Exception as exc:
                    st.error(f"Export failed: {exc}")
                    st.stop()
            st.session_state.export_zip_bytes = zip_bytes
            st.session_state.export_stage = "done"
            st.rerun()
    with col_back:
        if st.button("Start over"):
            _reset()
            st.rerun()


# ---------------------------------------------------------------------------
# Stage: done — download
# ---------------------------------------------------------------------------
elif st.session_state.export_stage == "done":
    eid = st.session_state.export_evidence_id
    zip_bytes = st.session_state.export_zip_bytes
    size_kb = len(zip_bytes) / 1024

    st.success(f"Package ready — {size_kb:.1f} KB", icon="📦")

    st.download_button(
        label="Download .zip",
        data=zip_bytes,
        file_name=f"{eid}.zip",
        mime="application/zip",
        type="primary",
    )

    st.divider()
    st.subheader("Package Contents")
    st.markdown(f"""
| Path | Contents |
|---|---|
| `evidence/{eid}.enc` | AES-256-GCM encrypted video (ciphertext only) |
| `metadata/evidence.json` | Immutable evidence record — hashes, signature, timestamps |
| `metadata/camera.json` | Enrolled camera record — Ed25519 public key |
| `metadata/verification-results/` | All verification runs for this evidence item |
| `tsa/token.tsr` | RFC 3161 timestamp token (if captured) |
| `fabric-history.json` | Hyperledger Fabric custody history (if Fabric is running) |
| `MANIFEST.json` | SHA-256 hashes of every file in this package |
| `VERIFY_INSTRUCTIONS.md` | Step-by-step independent verification guide |
""")

    st.info(
        "The export event (including verification outcome) has been logged to Fabric. "
        "The recipient can verify the package without VidProof installed — "
        "see VERIFY_INSTRUCTIONS.md inside the zip.",
        icon="ℹ️",
    )

    if st.button("Export another block"):
        _reset()
        st.rerun()
