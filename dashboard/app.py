import streamlit as st
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dashboard import api_client

st.set_page_config(page_title="VidProof", page_icon="VP", layout="wide")

st.title("VidProof")
st.caption("Privacy-preserving IoT surveillance verification")

try:
    status = api_client.health()
    st.success(f"Backend online — {status.get('service', 'unknown')}")
except Exception:
    st.error("Backend offline — start with: `uvicorn backend.app.main:app --reload`")

st.markdown("""
### How it works

1. **Cameras** — enroll a camera device and generate its Ed25519 signing key pair
2. **Evidence** — the camera hashes the plaintext, signs the hash, then encrypts with AES-256-GCM; the device signature is stored in immutable evidence metadata — not embedded inside the encrypted video bytes
3. **Verify** — hash check confirms the encrypted file is unaltered; signature check proves the footage came from the enrolled camera; RFC 3161 timestamp proves when
4. **Export** — run full verification on each block, review per-block results, then download a self-contained forensic package any investigator can verify independently
5. **Chain of custody** — every enrollment, verification, and export event is logged to Hyperledger Fabric

Navigate using the pages in the sidebar.
""")
