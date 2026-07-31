import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import streamlit as st
from dashboard import api_client

st.set_page_config(page_title="Package Verify — VidProof", layout="wide")
st.title("Package Verify")
st.caption(
    "Upload an exported VidProof package (.zip) to verify its integrity. "
    "Any file that was tampered after export will be identified, and the "
    "verification checks will show exactly which cryptographic property failed."
)

uploaded = st.file_uploader("Upload export package (.zip)", type=["zip"])

if not uploaded:
    st.info("Download a package from the Export page, optionally tamper with any file inside it, then upload it here.", icon="ℹ️")
    st.stop()

with st.spinner("Verifying package…"):
    try:
        report = api_client.verify_package(uploaded.getvalue(), filename=uploaded.name)
    except Exception as exc:
        st.error(f"Verification request failed: {exc}")
        st.stop()

if not report.get("ok"):
    st.error(report.get("detail", "Unknown error from server"))
    st.stop()

pkg_type  = report.get("packageType", "unknown")
blocks    = report.get("blocks", [])
n_blocks  = report.get("blockCount", len(blocks))

n_pass  = sum(1 for b in blocks if b.get("verification", {}).get("primaryDecision") == "PASS" and not b.get("_error"))
n_fail  = sum(1 for b in blocks if b.get("verification", {}).get("primaryDecision") == "FAIL")
n_err   = sum(1 for b in blocks if b.get("_error"))
n_clean = sum(1 for b in blocks if b.get("manifestIntegrity", {}).get("ok"))
n_no_manifest = sum(1 for b in blocks if not b.get("manifestIntegrity", {}).get("available", True))
n_tamp  = n_blocks - n_clean - n_no_manifest

st.markdown(f"**Package type:** `{pkg_type}` · **{n_blocks} block(s)**")

c1, c2, c3, c4 = st.columns(4)
c1.metric("Verification PASS", n_pass)
c2.metric("Verification FAIL", n_fail)
c3.metric("Files clean",    n_clean if not n_no_manifest else f"{n_clean} (manifest skipped: {n_no_manifest})")
c4.metric("Files tampered", n_tamp, delta=f"-{n_tamp}" if n_tamp else None, delta_color="inverse")

st.divider()

# ---------------------------------------------------------------------------
# Per-block results
# ---------------------------------------------------------------------------

_CHECK_LABELS = [
    ("Encrypted file hash",  "encryptedFileHashValid",       None),
    ("Device signature",     "deviceSignatureValid",          None),
    ("Decryption",           "decryptionValid",               "decryptionAttempted"),
    ("Plaintext hash match", "plaintextHashMatchesEvidence",  "decryptionAttempted"),
    ("RFC 3161 timestamp",   "tsaValid",                      "tsaChecked"),
]

_FILE_ICON = {"OK": "✅", "TAMPERED": "❌", "MISSING": "⚠️"}
_FILE_COLOUR = {"OK": "#4ade80", "TAMPERED": "#f87171", "MISSING": "#fbbf24"}


def _check_cell(label: str, value, checked: bool) -> str:
    if not checked:
        icon, colour, bg, status = "⏭", "#94a3b8", "#1e293b", "skipped"
    elif value is True:
        icon, colour, bg, status = "✅", "#4ade80", "#052e16", "pass"
    elif value is False:
        icon, colour, bg, status = "❌", "#f87171", "#450a0a", "FAIL"
    else:
        icon, colour, bg, status = "—", "#64748b", "#1e293b", "—"
    return (
        f"<div style='border:1px solid {colour}30;border-radius:8px;padding:12px 14px;background:{bg};'>"
        f"<div style='font-size:0.7em;color:#64748b;text-transform:uppercase;letter-spacing:.07em;margin-bottom:4px'>{label}</div>"
        f"<div style='font-size:1.2em'>{icon} <span style='color:{colour};font-weight:600;font-size:0.72em'>{status}</span></div>"
        f"</div>"
    )


for block in blocks:
    eid   = block.get("evidenceId", "?")
    err   = block.get("_error")
    mi    = block.get("manifestIntegrity", {})
    vr    = block.get("verification", {})

    mi_ok    = mi.get("ok", True)
    decision = vr.get("primaryDecision", "ERROR" if (err or not vr) else "?")
    icon     = "✅" if decision == "PASS" else "❌"
    tampered = mi.get("tamperedFiles", [])

    with st.expander(f"{icon}  {eid}  —  {decision}", expanded=(decision != "PASS" or not mi_ok)):

        if err:
            st.error(f"Error: {err}")
            if mi.get("fileResults"):
                st.write("Manifest check ran before error:")
        elif not vr:
            st.warning("No verification result returned.")

        # Manifest integrity table
        file_results = mi.get("fileResults", {})
        st.markdown("**Manifest integrity**")
        if not mi.get("available", True):
            st.warning(
                "This package was exported without a MANIFEST.json (legacy format). "
                "File hash checks are skipped — cryptographic verification still runs below.",
                icon="⚠️",
            )
        elif file_results:
            def _file_row(path: str, status: str) -> str:
                colour = _FILE_COLOUR.get(status, "#94a3b8")
                icon   = _FILE_ICON.get(status, "?")
                return (
                    f"<tr>"
                    f"<td style='padding:4px 12px;font-family:monospace;font-size:0.82em'>{path}</td>"
                    f"<td style='padding:4px 12px'>"
                    f"<span style='color:{colour};font-weight:600'>{icon} {status}</span>"
                    f"</td></tr>"
                )
            rows = "".join(_file_row(p, s) for p, s in file_results.items())
            st.markdown(
                f"""<table style='border-collapse:collapse;font-size:0.88em;margin-bottom:12px;width:100%'>
                <thead><tr style='border-bottom:1px solid #334155'>
                  <th style='padding:4px 12px;text-align:left'>File</th>
                  <th style='padding:4px 12px;text-align:left'>Status</th>
                </tr></thead><tbody>{rows}</tbody></table>""",
                unsafe_allow_html=True,
            )
            if tampered:
                st.warning(
                    f"**{len(tampered)} file(s) tampered:** {', '.join(f'`{f}`' for f in tampered)}",
                    icon="⚠️",
                )
            else:
                st.success("All files match their manifest hashes — package is unmodified.", icon="✅")

        if vr and not vr.get("_error"):
            st.markdown("**Cryptographic verification**")
            cells = "".join(
                _check_cell(label, vr.get(val_key), vr.get(checked_key, True) if checked_key else True)
                for label, val_key, checked_key in _CHECK_LABELS
            )
            st.markdown(
                f'<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:10px">{cells}</div>',
                unsafe_allow_html=True,
            )
            if vr.get("notes"):
                st.info(vr["notes"])

            failed = vr.get("failedChecks", [])
            if failed:
                # Explain what each failure means in plain English
                _meanings = {
                    "encryptedFileHash": "The encrypted video file was modified after capture.",
                    "deviceSignature":   "The evidence metadata (plaintextHash) was altered, or the wrong camera key was used.",
                    "decryption":        "The AES key could not be unwrapped — the wrappedKey or owner key is wrong.",
                    "plaintextHashMatch":"Decryption succeeded but the plaintext content differs from what was signed.",
                    "tsaToken":          "The RFC 3161 timestamp token does not match the encrypted file hash.",
                }
                for check in failed:
                    meaning = _meanings.get(check, check)
                    st.error(f"**{check}** — {meaning}", icon="🔍")

        elif vr.get("_error"):
            st.error(f"Verification error: {vr['_error']}")

        st.caption(
            f"Evidence ID: `{eid}` · "
            f"Verified using camera key from **package** (not server record)"
        )
