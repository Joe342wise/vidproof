import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import streamlit as st
from dashboard import api_client

st.set_page_config(page_title="Forensic Export — VidProof", layout="wide")
st.title("Forensic Export")
st.caption(
    "Select one or more evidence blocks. Full verification runs on each before packaging — "
    "hash check, signature check, decryption, RFC 3161 timestamp. "
    "Failed blocks are flagged; you decide whether to include them."
)

# ---------------------------------------------------------------------------
# Session state
# ---------------------------------------------------------------------------
def _reset():
    st.session_state.export_stage = "select"
    st.session_state.export_selected_ids = []
    st.session_state.export_verify_results = {}   # id → result dict
    st.session_state.export_include = {}           # id → bool
    st.session_state.export_zip_bytes = b""

for key, default in [
    ("export_stage", "select"),
    ("export_selected_ids", []),
    ("export_verify_results", {}),
    ("export_include", {}),
    ("export_zip_bytes", b""),
    ("export_include_decryption", False),
]:
    if key not in st.session_state:
        st.session_state[key] = default


def _failure_reason(r: dict) -> str:
    """Return a specific human-readable failure reason for a failed block."""
    reasons = []
    if r.get("encryptedFileHashValid") is False:
        reasons.append("hash mismatch")
    if r.get("deviceSignatureValid") is False:
        reasons.append("invalid signature")
    if r.get("tsaChecked") and r.get("tsaValid") is False:
        reasons.append("invalid timestamp")
    if r.get("decryptionAttempted") and r.get("decryptionValid") is False:
        reasons.append("decryption failed")
    if r.get("decryptionAttempted") and r.get("plaintextHashMatchesEvidence") is False:
        reasons.append("plaintext hash mismatch")
    return ", ".join(reasons) if reasons else "unknown"


def _check_icon(value, checked: bool) -> str:
    if not checked:
        return "⏭ skipped"
    return "✅ pass" if value else "❌ FAIL"


def _overall_icon(passed: bool) -> str:
    return "✅ PASS" if passed else "❌ FAIL"


# ---------------------------------------------------------------------------
# Stage: select
# ---------------------------------------------------------------------------
if st.session_state.export_stage == "select":
    # Consume pre-selection from the Evidence page if present
    preselected = st.session_state.pop("export_preselected", [])

    try:
        evidence_list = api_client.list_evidence()
        evidence_ids = [e["evidenceId"] for e in evidence_list] if evidence_list else []
    except Exception:
        evidence_ids = []

    if evidence_ids:
        selected = st.multiselect(
            "Evidence blocks to export",
            options=evidence_ids,
            default=preselected if preselected else None,
            placeholder="Select one or more blocks…",
        )
    else:
        raw = st.text_input("Evidence IDs (comma-separated)", placeholder="ev-001, ev-002",
                            value=", ".join(preselected) if preselected else "")
        selected = [s.strip() for s in raw.split(",") if s.strip()] if raw else []

    n = len(selected)
    st.info(
        f"{n} block{'s' if n != 1 else ''} selected. "
        "Verification runs on each block before any package is generated.",
        icon="ℹ️",
    )

    include_decryption = st.checkbox(
        "Include decrypted video in package",
        value=False,
        help="Decrypts the footage using the owner key stored on the server and adds it to the zip as a viewable video file. Requires owner.x25519.priv.pem on the server.",
    )

    if st.button("Verify & Export", type="primary", disabled=n == 0):
        verify_results: dict[str, dict] = {}
        progress = st.progress(0, text="Starting verification…")
        for i, eid in enumerate(selected):
            progress.progress((i) / n, text=f"Verifying {eid} ({i + 1}/{n})…")
            try:
                resp = api_client.verify_evidence(
                    eid, verifier_id="export-operator", include_decryption=False
                )
                verify_results[eid] = resp.get("result", {}) if resp.get("ok") else {
                    "_error": resp.get("detail", "Verification failed")
                }
            except Exception as exc:
                verify_results[eid] = {"_error": str(exc)}
        progress.progress(1.0, text="Verification complete.")

        st.session_state.export_selected_ids = selected
        st.session_state.export_verify_results = verify_results
        st.session_state.export_include = {eid: True for eid in selected}
        st.session_state.export_include_decryption = include_decryption

        # If everything passed, skip results screen and package immediately
        all_passed = bool(selected) and all(
            not r.get("_error") and r.get("primaryDecision") == "PASS"
            for r in verify_results.values()
        )
        if all_passed:
            with st.spinner(f"All {n} block(s) verified — building package…"):
                try:
                    zip_bytes = api_client.export_evidence_bulk(selected, include_decryption=include_decryption)
                except Exception as exc:
                    st.error(f"Export failed: {exc}")
                    st.stop()
            st.session_state.export_zip_bytes = zip_bytes
            st.session_state.export_stage = "done"
        else:
            st.session_state.export_stage = "results"
        st.rerun()


# ---------------------------------------------------------------------------
# Stage: results — per-block outcome table + include/exclude
# ---------------------------------------------------------------------------
elif st.session_state.export_stage == "results":
    selected = st.session_state.export_selected_ids
    results = st.session_state.export_verify_results

    all_passed = all(
        r.get("primaryDecision") == "PASS"
        for r in results.values()
        if "_error" not in r
    ) and not any("_error" in r for r in results.values())

    st.subheader("Verification Results")
    if all_passed:
        st.success(f"All {len(selected)} block(s) passed verification.", icon="✅")
    else:
        st.warning("One or more blocks failed — review below and choose what to include.", icon="⚠️")

    # Per-block table
    include_state: dict[str, bool] = dict(st.session_state.export_include)

    for eid in selected:
        r = results.get(eid, {})
        error = r.get("_error")
        passed = not error and r.get("primaryDecision") == "PASS"

        with st.expander(
            f"{'✅' if passed else '❌'}  {eid}",
            expanded=not passed,
        ):
            if error:
                st.error(f"Verification request failed: {error}")
                include_state[eid] = st.checkbox(
                    "Include this block anyway (verification could not run)",
                    value=False,
                    key=f"inc_{eid}",
                )
                continue

            checks = [
                ("Encrypted file hash", r.get("encryptedFileHashValid"), True),
                ("Device signature",    r.get("deviceSignatureValid"),   True),
                ("Decryption",          r.get("decryptionValid"),        r.get("decryptionAttempted", False)),
                ("Plaintext hash match",r.get("plaintextHashMatchesEvidence"), r.get("decryptionAttempted", False)),
                ("RFC 3161 timestamp",  r.get("tsaValid"),               r.get("tsaChecked", False)),
            ]

            rows = "".join(
                f"<tr><td style='padding:4px 12px'>{name}</td>"
                f"<td style='padding:4px 12px;font-family:monospace'>{_check_icon(val, chk)}</td></tr>"
                for name, val, chk in checks
            )
            st.markdown(
                f"""<table style='border-collapse:collapse;font-size:0.88em;margin-bottom:8px'>
                <thead><tr style='border-bottom:1px solid #334155'>
                  <th style='padding:4px 12px;text-align:left'>Check</th>
                  <th style='padding:4px 12px;text-align:left'>Result</th>
                </tr></thead><tbody>{rows}</tbody></table>""",
                unsafe_allow_html=True,
            )

            if r.get("notes"):
                st.caption(r["notes"])

            if not passed:
                st.error(
                    f"Failure reason: **{_failure_reason(r)}**",
                    icon="🔍",
                )
                st.warning(
                    "A failed block is itself evidence of tampering — it should not be "
                    "silently excluded. Include it clearly marked as failed, or exclude it.",
                    icon="⚠️",
                )
                include_state[eid] = st.checkbox(
                    "Include this failed block (marked as failed in the package)",
                    value=False,
                    key=f"inc_{eid}",
                )
            else:
                include_state[eid] = True

    st.session_state.export_include = include_state

    st.divider()
    included = [eid for eid, inc in include_state.items() if inc]
    excluded = [eid for eid in selected if not include_state.get(eid)]

    col_info, col_btn, col_back = st.columns([4, 2, 2])
    with col_info:
        if included:
            st.markdown(f"**{len(included)} block(s) will be packaged:** {', '.join(f'`{e}`' for e in included)}")
        if excluded:
            st.markdown(f"**{len(excluded)} excluded:** {', '.join(f'`{e}`' for e in excluded)}")

    with col_btn:
        if st.button("Generate Package", type="primary", disabled=len(included) == 0):
            with st.spinner(f"Building package for {len(included)} block(s)…"):
                try:
                    zip_bytes = api_client.export_evidence_bulk(
                        included,
                        include_decryption=st.session_state.get("export_include_decryption", False),
                    )
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
    selected = st.session_state.export_selected_ids
    include_state = st.session_state.export_include
    zip_bytes = st.session_state.export_zip_bytes
    included = [eid for eid in selected if include_state.get(eid)]

    size_kb = len(zip_bytes) / 1024
    st.success(f"Package ready — {len(included)} block(s), {size_kb:.1f} KB", icon="📦")

    from datetime import datetime, timezone
    filename = f"vidproof-export-{datetime.now(timezone.utc).strftime('%Y-%m-%d')}.zip"

    st.download_button(
        label="Download .zip",
        data=zip_bytes,
        file_name=filename,
        mime="application/zip",
        type="primary",
    )

    st.divider()
    st.subheader("Package Structure")

    dec = st.session_state.get("export_include_decryption", False)
    rows = "\n".join(
        f"| `blocks/{eid}/` | Evidence block, metadata, verification results, TSA token, Fabric history"
        + (", **decrypted video**" if dec else "") + " |"
        for eid in included
    )
    st.markdown(f"""
| Path | Contents |
|---|---|
{rows}
| `MANIFEST.json` | Block list, export timestamp, per-block summary |
| `VERIFY_INSTRUCTIONS.md` | How to verify each block independently |

Each `blocks/<id>/` directory contains its own `VERIFY_INSTRUCTIONS.md`
with the exact OpenSSL and Python commands needed to verify that block
without VidProof installed.
""")

    st.info(
        "Export events have been logged to Fabric for each included block.",
        icon="ℹ️",
    )

    if st.button("Export another batch"):
        _reset()
        st.rerun()
