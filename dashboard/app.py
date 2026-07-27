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
2. **Evidence** — upload a video clip to trigger AES-256-GCM encryption + device signing
3. **Verify** — run hash + signature checks to confirm chain-of-custody integrity
4. **Results** — browse all verification results per evidence item

Navigate using the pages in the sidebar.
""")
