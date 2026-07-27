import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import streamlit as st
import pandas as pd
from dashboard import api_client

st.set_page_config(page_title="Cameras — VidProof", layout="wide")
st.title("Cameras")

# ---------------------------------------------------------------------------
# Enroll form
# ---------------------------------------------------------------------------
with st.expander("Enroll a new camera", expanded=False):
    with st.form("enroll_form"):
        camera_id = st.text_input("Camera ID", placeholder="cam-001")
        device_serial = st.text_input("Device Serial", placeholder="SN123456")
        operator_id = st.text_input("Operator ID", placeholder="alice")
        owner_public_key = st.text_area(
            "Owner Public Key (base64 X25519)",
            placeholder="Paste base64-encoded X25519 public key here",
            height=80,
        )
        submitted = st.form_submit_button("Enroll")

    if submitted:
        if not all([camera_id, device_serial, operator_id, owner_public_key]):
            st.error("All fields are required.")
        else:
            with st.spinner("Enrolling…"):
                try:
                    result = api_client.enroll_camera(
                        camera_id=camera_id.strip(),
                        device_serial=device_serial.strip(),
                        operator_id=operator_id.strip(),
                        owner_public_key=owner_public_key.strip(),
                    )
                    if result.get("ok"):
                        st.success(f"Enrolled **{result['cameraId']}**")
                        st.info(f"Private key saved to: `{result['privateKeyPath']}`")
                        st.info(f"Camera record: `{result['cameraJsonPath']}`")
                    else:
                        st.error(result.get("detail", "Enrollment failed"))
                except Exception as exc:
                    st.error(f"Error: {exc}")

# ---------------------------------------------------------------------------
# Enrolled cameras list
# ---------------------------------------------------------------------------
st.subheader("Enrolled Cameras")

if st.button("Refresh"):
    st.rerun()

try:
    cameras = api_client.list_cameras()
    if not cameras:
        st.info("No cameras enrolled yet.")
    else:
        df = pd.DataFrame(cameras)[
            ["cameraId", "deviceSerial", "operatorId", "enrollmentTimestamp"]
        ]
        df.columns = ["Camera ID", "Serial", "Operator", "Enrolled At"]
        st.dataframe(df, use_container_width=True, hide_index=True)
except Exception as exc:
    st.error(f"Could not load cameras: {exc}")
