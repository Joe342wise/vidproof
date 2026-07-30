#!/usr/bin/env python3
"""Apply the VidProof widened verification decision — v2, line-based.

Robust to local edits around the decision block. Idempotent. Validates the end
state before writing anything, and writes nothing at all if any step fails.

Run from the repo root:  python apply_fixes2.py
"""
import ast
import sys
from pathlib import Path

NEW_BLOCK = '''    # Overall decision.
    #
    # Mandatory gates are always evaluated. Conditional gates bind only when the
    # corresponding check actually ran — a check that was skipped is reported as
    # unchecked, never as a failure. This stops records ingested before a
    # capability existed (e.g. no TSA running) from becoming retroactive
    # failures, while ensuring a check that ran and failed can never be
    # reported as an overall pass.
    failed_checks: list[str] = []

    if not encrypted_file_hash_valid:
        failed_checks.append("encryptedFileHash")
    if not device_signature_valid:
        failed_checks.append("deviceSignature")

    if decryption_attempted:
        if not decryption_valid:
            failed_checks.append("decryption")
        elif not plaintext_hash_matches_evidence:
            # Only a distinct failure when decryption itself succeeded.
            failed_checks.append("plaintextHashMatch")

    if tsa_checked and not tsa_valid:
        failed_checks.append("tsaToken")

    primary_decision = "FAIL" if failed_checks else "PASS"
'''


def die(msg: str):
    print(f"\n  ABORTED: {msg}\n  Nothing was written.")
    sys.exit(1)


vp = Path("forensics/verify.py")
if not vp.exists():
    die("forensics/verify.py not found — run this from the repo root.")

lines = vp.read_text().splitlines(keepends=True)

if any("failed_checks: list[str] = []" in ln for ln in lines):
    print("\n  already applied  forensics/verify.py")
else:
    # Locate every line that assigns primary_decision, ignoring comments.
    hits = [
        i for i, ln in enumerate(lines)
        if ln.lstrip().startswith("primary_decision") and "=" in ln
        and not ln.lstrip().startswith("#")
    ]
    if len(hits) != 1:
        die(f"expected exactly 1 active 'primary_decision =' line, found {len(hits)}")

    idx = hits[0]
    out = lines[:idx] + [NEW_BLOCK] + lines[idx + 1:]

    # Drop any commented-out duplicate immediately following.
    while idx + 1 < len(out) and out[idx + 1].lstrip().startswith("# primary_decision"):
        del out[idx + 1]

    text = "".join(out)

    # Add failedChecks to the result dict if absent.
    if '"failedChecks"' not in text:
        anchor = '        "primaryDecision": primary_decision,\n'
        if text.count(anchor) != 1:
            die(f"result-dict anchor matched {text.count(anchor)} times, expected 1")
        text = text.replace(anchor, anchor + '        "failedChecks": failed_checks,\n')

    # Validate before writing: must parse, and failed_checks must be defined
    # before the result dict uses it.
    try:
        ast.parse(text)
    except SyntaxError as exc:
        die(f"result would not parse: {exc}")

    def_at = text.index("failed_checks: list[str] = []")
    use_at = text.index('"failedChecks": failed_checks,')
    if def_at > use_at:
        die("failed_checks would be used before it is defined")

    vp.write_text(text)
    print("\n  applied          forensics/verify.py")

# --- models.py -------------------------------------------------------------
mp = Path("backend/app/models.py")
if mp.exists():
    mt = mp.read_text()
    if "failedChecks" in mt:
        print("  already applied  backend/app/models.py")
    else:
        anchor = "    primaryDecision: str\n"
        if mt.count(anchor) == 1:
            mp.write_text(mt.replace(anchor, anchor + "    failedChecks: list[str] = []\n"))
            print("  applied          backend/app/models.py")
        else:
            print("  SKIPPED          backend/app/models.py (anchor ambiguous — add manually)")

# --- tamper test -----------------------------------------------------------
tp = Path("tests/test_tamper.sh")
if tp.exists():
    tt = tp.read_text()
    if "owner.x25519.pub.b64" in tt:
        print("  already applied  tests/test_tamper.sh")
    else:
        old = 'OWNER_PUB="$STORAGE_DIR/keys/owner.x25519.pub"'
        if tt.count(old) == 1:
            tp.write_text(tt.replace(old, 'OWNER_PUB="$STORAGE_DIR/keys/owner.x25519.pub.b64"'))
            print("  applied          tests/test_tamper.sh")
        else:
            print("  SKIPPED          tests/test_tamper.sh (add .b64 to OWNER_PUB manually)")

print("\n  Verified: file parses and failed_checks is defined before use.")
print("  Restart the backend, then re-verify a record.\n")