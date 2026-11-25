"""Overview Dashboard: the whole monitored period at a glance."""
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

import state
import ui
from ddos import detection
from ddos.schema import DDOS, LEGIT_THRESHOLD, PROTOCOL_NAMES, WINDOW_SECONDS


def render():
    ui.header("Overview Dashboard",
              "Summary of all monitored network flows and what the detector concluded.")
    ctx = state.get_context()
    ui.data_notice(ctx)

    scored, summary = ctx.scored, ctx.summary
    total = len(scored)
    attack_flows = int((scored["predicted"] == DDOS).sum())
    attack_windows = int(summary["attack"].sum())

    if attack_windows:
        ui.banner("alert", f"DDoS Attack Detected in {attack_windows} of {len(summary)} "
                  "time windows",
                  "See Live DDoS Detection for each window and Attack Mitigation for the "
                  "response.")
    else:
        ui.banner("ok", "Normal Traffic - no DDoS attack detected",
                  f"Every one of the {len(summary)} time windows stayed above "
                  f"{LEGIT_THRESHOLD:.0f}% legitimate flows.")

    a, b, c, d = st.columns(4)
    a.metric("Total network flows", f"{total:,}", border=True)
    b.metric("Normal Traffic (flows)", f"{total - attack_flows:,}", border=True)
    c.metric("Suspicious Traffic (flows)", f"{attack_flows:,}", border=True)
    d.metric("Windows under attack", f"{attack_windows} / {len(summary)}", border=True)
    st.caption("A flow is one network conversation. *Suspicious* flows are those the model "
               "classified as DDoS. A window is 10 seconds of traffic.")

    left, right = st.columns([1, 2])
    with left:
        st.subheader("Traffic distribution")
        fig = go.Figure(go.Pie(
            labels=["Normal", "DDoS"], values=[total - attack_flows, attack_flows], hole=0.62,
            sort=False, direction="clockwise", textinfo="percent",
            marker=dict(colors=[ui.BLUE, ui.ORANGE], line=dict(color=ui.SURFACE, width=2)),
            hovertemplate="%{label}: %{value:,} flows<extra></extra>"))
        fig.add_annotation(text=f"<b>{total:,}</b><br>flows", showarrow=False,
                           font=dict(color=ui.INK, size=15))
        ui.chart(fig, "overview_distribution", height=330)
        st.caption("Share of all flows in each class.")
    with right:
        st.subheader("Attack detection timeline")
        ui.chart(ui.flows_timeline(summary), "overview_flows", height=330)
        st.caption("Flows in each time window. More orange means more suspicious traffic.")

    ui.chart(ui.share_timeline(summary), "overview_share", height=250, legend=False)
    st.caption("When the line reaches the dotted limit, the window is reported as an attack.")

    episodes = detection.attack_episodes(summary)
    if len(episodes):
        st.markdown("**Detected attack periods**")
        table = pd.DataFrame({
            "From window": episodes["first_window"],
            "To window": episodes["last_window"],
            "Duration (s)": (episodes["last_window"] - episodes["first_window"] + 1)
            * WINDOW_SECONDS,
            "Suspicious flows": episodes["ddos_flows"],
            "Suspicious packets": episodes["ddos_packets"].astype("int64"),
        })
        st.dataframe(table, hide_index=True, width="stretch", column_config={
            name: st.column_config.NumberColumn(format="localized")
            for name in ("Suspicious flows", "Suspicious packets")})

    st.subheader("Network traffic summary")
    a, b, c, d = st.columns(4)
    a.metric("Packets", f"{int(scored['packet_count'].sum()):,}", border=True,
             help="Sum of the packet counters of all recorded flow entries.")
    b.metric("Data volume", f"{scored['byte_count'].sum() / 1e6:,.1f} MB", border=True)
    c.metric("Source addresses", f"{scored['ip_src'].nunique():,}", border=True)
    d.metric("Switches reporting", f"{scored['datapath_id'].nunique():,}", border=True)

    flagged = scored["predicted"] == DDOS
    protocols = (scored.assign(flagged=flagged.astype(int),
                               Protocol=scored["ip_proto"].map(PROTOCOL_NAMES).fillna("Other"))
                 .groupby("Protocol")
                 .agg(Flows=("flagged", "size"), Flagged=("flagged", "sum"),
                      Packets=("packet_count", "sum"), Bytes=("byte_count", "sum"))
                 .reset_index().rename(columns={"Flagged": "DDoS flows"}))
    protocols[["Packets", "Bytes"]] = protocols[["Packets", "Bytes"]].astype("int64")
    st.dataframe(protocols, hide_index=True, width="stretch", column_config={
        name: st.column_config.NumberColumn(format="localized")
        for name in ("Flows", "DDoS flows", "Packets", "Bytes")})

    st.subheader("What does this mean?")
    st.markdown(f"""
- A **flow** is one conversation between two addresses (with protocol and ports) as counted
  by a network switch.
- The **{ctx.evaluation.metrics.iloc[0]['Model']}** model labels every flow as *Normal* or *DDoS*.
- Time is cut into **{WINDOW_SECONDS}-second windows**. If **{LEGIT_THRESHOLD:.0f}% or less** of
  the flows in a window are normal, the window is reported as **under attack**.
- Here the model flagged **{attack_flows:,}** of **{total:,}** flows
  ({attack_flows / total:.1%}), and **{attack_windows}** window(s) crossed the limit.
- Data being monitored: *{ctx.monitor_name}*.
""")
