import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from datetime import datetime, timezone

import streamlit as st
from dashboard import api_client

st.set_page_config(page_title="Forensic Export — VidProof", layout="wide")
st.title("Forensic Export")
st.caption(
    "Select one or more evidence blocks. Verification runs on each before packaging — "
    "hash check, signature check, RFC 3161 timestamp. "
    "Failed blocks are flagged; you decide whether to include them."
)

# ---------------------------------------------------------------------------
# Session state
# ---------------------------------------------------------------------------
def _reset():
    for key in [
        "export_stage", "export_selected_ids", "export_verify_results",
        "export_include", "export_zip_bytes", "export_include_decryption",
        "export_evidence_map",
    ]:
        st.session_state.pop(key, None)


for key, default in [
    ("export_stage", "select"),
    ("export_selected_ids", []),
    ("export_verify_results", {}),
    ("export_include", {}),
    ("export_zip_bytes", b""),
    ("export_include_decryption", False),
    ("export_evidence_map", {}),
]:
    if key not in st.session_state:
        st.session_state[key] = default


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _fmt_ts(ts: str) -> str:
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return ts or "—"


def _size_str(nbytes: int) -> str:
    if nbytes >= 1_048_576:
        return f"{nbytes / 1_048_576:.1f} MB"
    return f"{nbytes / 1024:.1f} KB"


def _block_label(eid: str, emap: dict) -> str:
    e = emap.get(eid, {})
    cam = e.get("cameraId", "?")
    ts  = _fmt_ts(e.get("captureTimestamp", ""))
    fab = " · ⛓" if e.get("fabricTxId") else ""
    short = eid[:24] + "…" if len(eid) > 24 else eid
    return f"{cam}  ·  {ts}  ·  {short}{fab}"


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
        f"<div style='border:1px solid {colour}30;border-radius:8px;"
        f"padding:10px 12px;background:{bg};'>"
        f"<div style='font-size:0.68em;color:#64748b;text-transform:uppercase;"
        f"letter-spacing:.07em;margin-bottom:3px'>{label}</div>"
        f"<div style='font-size:1.1em'>{icon} "
        f"<span style='color:{colour};font-weight:600;font-size:0.7em'>{status}</span></div>"
        f"</div>"
    )


def _failure_reason(r: dict) -> str:
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


# ---------------------------------------------------------------------------
# Stage: select
# ---------------------------------------------------------------------------
if st.session_state.export_stage == "select":
    preselected = st.session_state.pop("export_preselected", [])

    try:
        evidence_list = api_client.list_evidence()
    except Exception:
        evidence_list = []

    evidence_list = sorted(
        evidence_list, key=lambda e: e.get("captureTimestamp", ""), reverse=True
    )
    emap = {e["evidenceId"]: e for e in evidence_list}
    evidence_ids = list(emap)

    if evidence_ids:
        selected = st.multiselect(
            "Evidence blocks to export",
            options=evidence_ids,
            default=[p for p in preselected if p in emap] or None,
            format_func=lambda eid: _block_label(eid, emap),
            placeholder="Select one or more blocks…",
        )
    else:
        raw = st.text_input(
            "Evidence IDs (comma-separated)", placeholder="ev-001, ev-002",
            value=", ".join(preselected) if preselected else "",
        )
        selected = [s.strip() for s in raw.split(",") if s.strip()] if raw else []
        emap = {}

    n = len(selected)

    # Preview table of selected blocks
    if selected:
        rows_html = ""
        for eid in selected:
            e = emap.get(eid, {})
            cam = e.get("cameraId", "—")
            ts  = _fmt_ts(e.get("captureTimestamp", ""))
            fab = "⛓ yes" if e.get("fabricTxId") else "—"
            short = f'<span style="font-family:monospace;font-size:0.82em">{eid}</span>'
            rows_html += (
                f"<tr style='border-bottom:1px solid #1e293b'>"
                f"<td style='padding:5px 10px'>{short}</td>"
                f"<td style='padding:5px 10px;font-size:0.88em'>{cam}</td>"
                f"<td style='padding:5px 10px;font-size:0.88em;white-space:nowrap'>{ts}</td>"
                f"<td style='padding:5px 10px;font-size:0.88em;color:#4ade80'>{fab}</td>"
                f"</tr>"
            )
        hdr = "".join(
            f"<th style='padding:5px 10px;text-align:left;border-bottom:1px solid #334155;"
            f"font-size:0.75em;text-transform:uppercase;letter-spacing:.06em;color:#94a3b8'>{h}</th>"
            for h in ["Evidence ID", "Camera", "Captured", "On Fabric"]
        )
        st.markdown(
            f"<div style='overflow-x:auto;margin:8px 0 16px'>"
            f"<table style='border-collapse:collapse;font-size:0.9em;width:100%'>"
            f"<thead><tr style='background:#0f172a'>{hdr}</tr></thead>"
            f"<tbody>{rows_html}</tbody></table></div>",
            unsafe_allow_html=True,
        )
    else:
        st.caption("No blocks selected yet.")

    include_decryption = st.checkbox(
        "Include decrypted video in package",
        value=False,
        help="Decrypts footage using the owner key on the server and adds the video file to the zip. Requires owner.x25519.priv.pem.",
    )

    if st.button("Verify & Export", type="primary", disabled=n == 0):
        verify_results: dict[str, dict] = {}
        progress = st.progress(0, text="Starting verification…")
        for i, eid in enumerate(selected):
            progress.progress(i / n, text=f"Verifying {_block_label(eid, emap)} ({i+1}/{n})…")
            try:
                resp = api_client.verify_evidence(eid, verifier_id="export-operator", include_decryption=False)
                verify_results[eid] = resp.get("result", {}) if resp.get("ok") else {
                    "_error": resp.get("detail", "Verification failed")
                }
            except Exception as exc:
                verify_results[eid] = {"_error": str(exc)}
        progress.progress(1.0, text="Verification complete.")

        st.session_state.export_selected_ids  = selected
        st.session_state.export_verify_results = verify_results
        st.session_state.export_include        = {eid: True for eid in selected}
        st.session_state.export_include_decryption = include_decryption
        st.session_state.export_evidence_map   = emap

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
# Stage: results — per-block outcome + include/exclude
# ---------------------------------------------------------------------------
elif st.session_state.export_stage == "results":
    selected = st.session_state.export_selected_ids
    results  = st.session_state.export_verify_results
    emap     = st.session_state.get("export_evidence_map", {})

    n_pass = sum(1 for r in results.values() if r.get("primaryDecision") == "PASS")
    n_fail = sum(1 for r in results.values() if r.get("primaryDecision") == "FAIL")
    n_err  = sum(1 for r in results.values() if "_error" in r)

    st.subheader("Verification Results")
    c1, c2, c3 = st.columns(3)
    c1.metric("Passed", n_pass)
    c2.metric("Failed", n_fail)
    c3.metric("Errors", n_err)

    if n_fail or n_err:
        st.warning("One or more blocks failed — review below and decide what to include.", icon="⚠️")
    else:
        st.success(f"All {len(selected)} block(s) passed verification.", icon="✅")

    include_state: dict[str, bool] = dict(st.session_state.export_include)

    for eid in selected:
        r     = results.get(eid, {})
        error = r.get("_error")
        passed = not error and r.get("primaryDecision") == "PASS"
        e = emap.get(eid, {})
        cam = e.get("cameraId", "")
        ts  = _fmt_ts(e.get("captureTimestamp", ""))
        icon = "✅" if passed else ("⚠️" if error else "❌")
        title = f"{icon}  {cam}  ·  {ts}  ·  {eid}"

        with st.expander(title, expanded=not passed):
            if error:
                st.error(f"Verification request failed: {error}")
                include_state[eid] = st.checkbox(
                    "Include anyway (verification could not run)",
                    value=False, key=f"inc_{eid}",
                )
                continue

            checks = [
                ("Enc file hash",    r.get("encryptedFileHashValid"),        None),
                ("Device signature", r.get("deviceSignatureValid"),          None),
                ("Decryption",       r.get("decryptionValid"),               "decryptionAttempted"),
                ("Plaintext hash",   r.get("plaintextHashMatchesEvidence"),  "decryptionAttempted"),
                ("RFC 3161 TSA",     r.get("tsaValid"),                      "tsaChecked"),
            ]
            cells = "".join(
                _check_cell(lbl, val, r.get(chk_key, True) if chk_key else True)
                for lbl, val, chk_key in checks
            )
            st.markdown(
                f'<div style="display:grid;grid-template-columns:repeat(5,1fr);gap:8px;margin-bottom:10px">{cells}</div>',
                unsafe_allow_html=True,
            )

            if r.get("notes"):
                st.caption(r["notes"])

            if not passed:
                st.error(f"Failure reason: **{_failure_reason(r)}**", icon="🔍")
                st.warning(
                    "A failed block is itself evidence of tampering — include it marked as failed, or exclude it.",
                    icon="⚠️",
                )
                include_state[eid] = st.checkbox(
                    "Include this failed block in the package",
                    value=False, key=f"inc_{eid}",
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
            st.markdown(f"**{len(included)} block(s) will be packaged**")
            for eid in included:
                st.caption(f"↳ {_block_label(eid, emap)}")
        if excluded:
            st.markdown(f"**{len(excluded)} excluded**")
            for eid in excluded:
                st.caption(f"✗ {_block_label(eid, emap)}")

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
    selected      = st.session_state.export_selected_ids
    include_state = st.session_state.export_include
    zip_bytes     = st.session_state.export_zip_bytes
    emap          = st.session_state.get("export_evidence_map", {})
    dec           = st.session_state.get("export_include_decryption", False)
    included      = [eid for eid in selected if include_state.get(eid)]

    size_label = _size_str(len(zip_bytes))
    st.success(
        f"Package ready — **{len(included)} block{'s' if len(included) != 1 else ''}**, {size_label}",
        icon="📦",
    )

    date_str  = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    filename  = f"vidproof-{len(included)}block{'s' if len(included) != 1 else ''}-{date_str}.zip"

    st.download_button(
        label=f"Download {filename}",
        data=zip_bytes,
        file_name=filename,
        mime="application/zip",
        type="primary",
        use_container_width=True,
    )

    st.divider()
    st.subheader("Package Contents")

    # Per-block summary
    for eid in included:
        e   = emap.get(eid, {})
        cam = e.get("cameraId", "—")
        ts  = _fmt_ts(e.get("captureTimestamp", ""))
        fab = "⛓ on Fabric" if e.get("fabricTxId") else "not on Fabric"
        with st.expander(f"📁  blocks/{eid}/  ·  {cam}  ·  {ts}"):
            items_list = [
                f"`evidence/{eid}.enc` — AES-256-GCM encrypted video",
                "`metadata/evidence.json` — immutable evidence record",
                "`metadata/camera.json` — enrolled camera record",
                "`metadata/verification-results/` — all verification runs",
            ]
            if e.get("fabricTxId"):
                items_list.append("`fabric-history.json` — Hyperledger Fabric custody trail")
            if dec:
                items_list.append(f"`video/{eid}.mp4` — **decrypted video** (owner-decrypted)")
            items_list.append("`MANIFEST.json` — SHA-256 hashes of every file")
            items_list.append("`VERIFY_INSTRUCTIONS.md` — standalone verification steps")
            for item in items_list:
                st.markdown(f"- {item}")
            st.caption(f"Fabric status: {fab}")

    st.markdown(f"""
| Root file | Contents |
|---|---|
| `MANIFEST.json` | Block list, export timestamp, per-block summary |
| `VERIFY_INSTRUCTIONS.md` | How to verify each block independently |
""")

    st.info("Export events have been logged to Fabric for each included block.", icon="ℹ️")

    if dec:
        st.warning(
            "This package contains **decrypted video footage**. "
            "Handle it according to your evidence handling policy.",
            icon="🔐",
        )

    if st.button("Export another batch"):
        _reset()
        st.rerun()
