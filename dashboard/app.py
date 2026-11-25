"""Streamlit dashboard for the DDoS detection and mitigation project.

Pipeline (same idea as Codes/controller/controller.py):
  flow statistics -> machine learning -> verdict per 10 s window -> mitigation rules
Mitigation is simulated: real blocking needs Mininet + Ryu on Linux.

Run from the project folder:  streamlit run dashboard/app.py
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))   # so that the `ddos` package can be imported

import streamlit as st

import state
import ui
from views import about, dataset, detection, mitigation, models, overview

st.set_page_config(page_title="DDoS Detection and Mitigation", page_icon=":material/shield:",
                   layout="wide")
ui.inject_css()
state.init_state()

navigation = st.navigation([
    st.Page(overview.render, title="Overview Dashboard", icon=":material/dashboard:",
            url_path="overview", default=True),
    st.Page(detection.render, title="Live DDoS Detection", icon=":material/radar:",
            url_path="detection"),
    st.Page(models.render, title="Machine Learning Models", icon=":material/model_training:",
            url_path="models"),
    st.Page(dataset.render, title="Network Traffic Dataset", icon=":material/table_chart:",
            url_path="dataset"),
    st.Page(mitigation.render, title="Attack Mitigation", icon=":material/security:",
            url_path="mitigation"),
    st.Page(about.render, title="About Project", icon=":material/info:", url_path="about"),
])

with st.sidebar:
    st.html('<div class="brand">DDoS Shield<span>ML + SDN monitoring prototype</span></div>')
    st.divider()
    uploaded = st.session_state.train_upload or st.session_state.monitor_upload
    st.markdown("**Data source**")
    if uploaded:
        if st.session_state.train_upload:
            st.text(f"Training: {st.session_state.train_upload.name}")
        else:
            st.text("Training: synthetic sample")
        if st.session_state.monitor_upload:
            st.text(f"Monitoring: {st.session_state.monitor_upload.name}")
        else:
            st.text("Monitoring: training file")
    else:
        st.badge("Synthetic sample data", icon=":material/science:", color="orange")
    st.markdown("**Network mode**")
    st.badge("Simulation (no live SDN)", icon=":material/cloud_off:", color="blue")
    st.caption("No switch or controller is connected. No packets are captured or blocked.")

navigation.run()
