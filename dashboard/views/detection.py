"""Live DDoS Detection: replay the traffic one 10 second window at a time."""
import pandas as pd
import streamlit as st

import state
import ui
from ddos import sample_data
from ddos.detection import host_name
from ddos.schema import CLASS_NAMES, DDOS, LEGIT_THRESHOLD, PROTOCOL_NAMES, WINDOW_SECONDS

MAX_ROWS = 500


def _top(flows, column, label):
    table = (flows.groupby(column)
             .agg(Flows=("predicted", "size"), Packets=("packet_count", "sum"))
             .reset_index().sort_values(["Packets", "Flows"], ascending=False).head(8))
    table["Packets"] = table["Packets"].astype("int64")
    return table.rename(columns={column: label})


def render():
    ui.header("Live DDoS Detection",
              "Recorded flow statistics are replayed window by window, as the controller "
              "would receive them.")
    ctx = state.get_context()
    ui.data_notice(ctx)

    if ctx.monitor_synthetic:
        truth = ctx.summary.loc[ctx.summary["true_attack"], "window"]
        first, last = sample_data.ATTACK_WINDOWS
        if len(truth):
            st.caption(f"Synthetic attack burst: planned for windows {first}-{last - 1}. Random "
                       f"arrival times blur its edges, so in this sample the labels mark windows "
                       f"{truth.min()}-{truth.max()} as attack windows.")
    window = ui.window_picker(ctx, "detect")
    row = ctx.summary.set_index("window").loc[window]
    flows = ctx.scored[ctx.scored["window"] == window]
    flagged = flows[flows["predicted"] == DDOS]
    attack = bool(row["attack"])
    victim = row["victim_ip"] if attack and pd.notna(row["victim_ip"]) else None

    if attack:
        ui.banner("alert", "DDoS Attack Detected",
                  f"Only {row['legit_pct']:.0f}% of the flows look legitimate"
                  + (f"; most suspicious flows target {host_name(victim)} ({victim})."
                     if victim else "."))
    else:
        ui.banner("ok", "Normal Traffic",
                  f"{row['legit_pct']:.0f}% of the flows look legitimate. No action is needed.")

    has_score = flagged["ddos_score"].notna().any()
    columns = st.columns(5)
    columns[0].metric("Flows in window", f"{len(flows):,}", border=True)
    columns[1].metric("Legitimate flows", f"{row['legit_pct']:.0f} %", border=True)
    columns[2].metric("Suspicious flows", f"{len(flagged):,}", border=True)
    columns[3].metric(
        "Model confidence", f"{flagged['ddos_score'].mean():.0%}" if has_score else "-",
        border=True,
        help="Average Random Forest tree vote for 'DDoS' over suspicious flows. It shows how "
             "strongly the trees agree. It is not a calibrated probability, and not the "
             "chance that the verdict is correct.")
    columns[4].metric("Victim host", host_name(victim) if victim else "-", border=True,
                      help="Destination receiving the most suspicious flows (attack windows only).")

    st.caption("*Model confidence* is how strongly the Random Forest's decision trees agree "
               "that the suspicious flows are DDoS. It is not the chance that the result is "
               "correct.")

    with st.container(border=True):
        st.markdown("**How this verdict was reached**")
        st.markdown(
            f"1. The switches reported **{len(flows):,} flows** in this {WINDOW_SECONDS}-second "
            f"window.\n"
            f"2. The model classified **{len(flows) - len(flagged):,}** as normal and "
            f"**{len(flagged):,}** as DDoS.\n"
            f"3. Legitimate share = {len(flows) - len(flagged):,} / {len(flows):,} = "
            f"**{row['legit_pct']:.1f}%**.\n"
            f"4. The rule from `controller.py`: more than {LEGIT_THRESHOLD:.0f}% legitimate is "
            f"normal, otherwise attack. So this window is **"
            f"{'an attack' if attack else 'normal'}**.")
        if ctx.monitor_has_labels and not ctx.monitor_is_training:
            truth = "attack" if row["true_attack"] else "normal"
            agree = "agrees" if bool(row["true_attack"]) == attack else "does NOT agree"
            st.caption(f"The labels in this file say the window is **{truth}**: the detector "
                       f"{agree}.")

    st.subheader("Network traffic monitoring")
    left, right = st.columns(2)
    with left:
        ui.chart(ui.share_timeline(ctx.summary, window), "detect_share", height=290,
                 legend=False)
        st.caption("Percentage of suspicious flows. Above the dotted line means attack.")
    with right:
        ui.chart(ui.flows_timeline(ctx.summary, window), "detect_flows", height=290)
        st.caption("Number of flows. The dashed line marks the selected window.")
    if ctx.monitor_has_labels and not ctx.monitor_is_training:
        correct = int((ctx.summary["attack"] == ctx.summary["true_attack"]).sum())
        st.caption(f"Compared with the file's labels, {correct} of {len(ctx.summary)} window "
                   "verdicts are correct on this data"
                   + (" (synthetic)." if ctx.monitor_synthetic else "."))

    if len(flagged):
        st.subheader("Attack information" if attack else "Suspicious Traffic (below alarm level)")
        a, b, c = st.columns(3)
        with a:
            st.markdown("**Top sources**")
            st.dataframe(_top(flagged, "ip_src", "Source IP"), hide_index=True, width="stretch")
        with b:
            st.markdown("**Targets**")
            st.dataframe(_top(flagged, "ip_dst", "Destination IP"), hide_index=True,
                         width="stretch")
        with c:
            st.markdown("**Protocols**")
            named = flagged.assign(
                protocol=flagged["ip_proto"].map(PROTOCOL_NAMES).fillna("Other"))
            st.dataframe(_top(named, "protocol", "Protocol"), hide_index=True, width="stretch")

    st.subheader("Flows in this window")
    shown = pd.DataFrame({
        "Prediction": flows["predicted"].map(CLASS_NAMES),
        "DDoS score": flows["ddos_score"],
        "Switch": "s" + flows["datapath_id"].astype(str),
        "Source IP": flows["ip_src"],
        "Destination IP": flows["ip_dst"],
        "Protocol": flows["ip_proto"].map(PROTOCOL_NAMES).fillna("Other"),
        "Packets": flows["packet_count"],
        "Bytes": flows["byte_count"],
        "Duration (s)": flows["flow_duration_sec"],
    }).sort_values(["DDoS score", "Packets"], ascending=False)
    st.dataframe(shown.head(MAX_ROWS), hide_index=True, width="stretch", column_config={
        "DDoS score": st.column_config.ProgressColumn(min_value=0.0, max_value=1.0,
                                                      format="%.2f")})
    if len(shown) > MAX_ROWS:
        st.caption(f"Showing {MAX_ROWS:,} of {len(shown):,} flows. The download has all rows.")
    st.download_button("Download this window (CSV)", lambda: shown.to_csv(index=False),
                       f"window_{window}_predictions.csv", "text/csv",
                       icon=":material/download:", on_click="ignore")
