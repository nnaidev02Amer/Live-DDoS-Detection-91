"""Attack Mitigation: a safe simulation of how drop rules would stop an attack."""
import json

import pandas as pd
import streamlit as st

import state
import ui
from ddos import mitigation, sdn
from ddos.detection import host_name
from ddos.schema import DDOS, PROTOCOL_NAMES, WINDOW_SECONDS

BLOCK_WINDOWS = sdn.BLOCK_SECONDS // WINDOW_SECONDS


def _protocol(number):
    return PROTOCOL_NAMES.get(number, str(number))


def _install(flows, window):
    engine = st.session_state.engine
    added = engine.apply_window(flows, window)
    st.toast(f"{len(added)} new simulated rule(s) installed." if added
             else "These rules are already active.", icon=":material/security:")


def _respond_tab(ctx):
    window = ui.window_picker(ctx, "mitigate")
    row = ctx.summary.set_index("window").loc[window]
    flows = ctx.scored[ctx.scored["window"] == window]
    if not row["attack"]:
        ui.banner("ok", "Normal Traffic",
                  f"{row['legit_pct']:.0f}% of the flows are legitimate, so no rule is "
                  "proposed. Use 'Next attack window'.")
        return
    victim = row["victim_ip"]
    ui.banner("alert", "DDoS Attack Detected",
              f"{int(row['ddos_flows']):,} suspicious flows, mainly towards "
              f"{host_name(victim)} ({victim}).")

    candidates = mitigation.propose_rules(flows)
    st.markdown("**Suspicious Traffic and proposed blocking rules**")
    table = pd.DataFrame({
        "Switch": "s" + candidates["datapath_id"].astype(str),
        "Attack source": candidates["ip_src"],
        "Destination": candidates["ip_dst"],
        "Protocol": candidates["ip_proto"].map(_protocol),
        "Flows": candidates["flows"],
        "Packets": candidates["packets"].astype("int64"),
        "Action (simulated)": "DROP",
    })
    st.dataframe(table, hide_index=True, width="stretch", height=300)

    engine = st.session_state.engine
    installed = {key for key, (start, last) in engine.lifetime.items() if start <= window <= last}
    keys = set(zip(*(candidates[c].tolist() for c in mitigation.RULE_FIELDS)))
    done = keys <= installed
    st.button("All rules installed" if done
              else f"Install {len(keys - installed)} simulated drop rule(s)", type="primary",
              icon=":material/block:", disabled=done, on_click=_install, args=(flows, window))
    if done:
        st.success(f"**Mitigation Simulated.** Blocking rules for all {len(keys)} suspicious "
                   "flow groups are active in the simulator. No real traffic is blocked.",
                   icon=":material/check_circle:")
    else:
        st.caption("Mitigation status: waiting. Press the button to simulate blocking.")


def _blocked_summary(ctx):
    """Simulated effect of the rules that are currently installed."""
    engine = st.session_state.engine
    matched = engine.matched_flows(ctx.scored)
    a, b, c, d = st.columns(4)
    a.metric("Installed rules", f"{len(engine.controller.list_rules()):,}", border=True)
    b.metric("Flows blocked (simulated)", f"{len(matched):,}", border=True,
             help="Recorded flows in the 120 s after installation that match a rule.")
    c.metric("Packets blocked (simulated)", f"{int(matched['packet_count'].sum()):,}",
             border=True)
    d.metric("Data blocked (simulated)", f"{matched['byte_count'].sum() / 1e6:,.1f} MB",
             border=True)
    if ctx.monitor_has_labels and len(matched):
        wrong = int((matched["label"] != DDOS).sum())
        st.caption(f"Blocked flows according to the file's labels: {len(matched) - wrong:,} "
                   f"attack, {wrong:,} normal (collateral damage).")


def _rules_tab(ctx):
    engine = st.session_state.engine
    _blocked_summary(ctx)
    rules = engine.controller.list_rules()
    if not rules:
        st.info("No rules installed. Open an attack window under *Respond to a window*.")
        return
    table = pd.DataFrame([{
        "Switch": f"s{r.datapath_id}", "Source": r.ip_src, "Destination": r.ip_dst,
        "Protocol": _protocol(r.ip_proto), "Priority": r.priority,
        "Installed after window": engine.lifetime[r.key][0],
        "Active until window": engine.lifetime[r.key][1], "State": "Simulated",
    } for r in rules])
    st.dataframe(table, hide_index=True, width="stretch", height=280)

    by_text = {f"{mitigation.describe_rule(r)}": r for r in rules}
    choice = st.selectbox("Inspect or remove a rule", list(by_text))
    rule = by_text[choice]
    left, right = st.columns(2)
    with left:
        st.markdown("Open vSwitch command (**not executed**)")
        st.code(sdn.to_ovs_command(rule), language="bash", wrap_lines=True)
    with right:
        st.markdown("Ryu `ofctl_rest` message (**not sent**)")
        st.code(json.dumps(sdn.to_ryu_flow_entry(rule), indent=2), language="json")
    with st.container(horizontal=True):
        st.button("Remove selected rule", icon=":material/delete:", on_click=engine.remove,
                  args=(rule, st.session_state.window))
        st.button("Remove all rules", icon=":material/delete_sweep:", on_click=engine.clear,
                  args=(st.session_state.window,))


def _run_replay(ctx):
    result = mitigation.replay(ctx.scored, ctx.summary)
    st.session_state.replay = result
    engine = st.session_state.engine
    engine.events.extend(result.events)
    del engine.events[:-mitigation.MAX_EVENTS]
    engine.log(None, "Replay finished",
               f"{result.totals['rules_installed']} rule installations, "
               f"{result.totals['blocked_packets']:,} packets blocked (simulated)")


def _replay_tab(ctx):
    st.markdown(f"Plays the whole timeline with **automatic** response: after each attack "
                f"window, drop rules are added for its malicious flows and stay for "
                f"{sdn.BLOCK_SECONDS} seconds ({BLOCK_WINDOWS} windows).")
    st.button("Run automatic mitigation replay", type="primary", icon=":material/play_arrow:",
              on_click=_run_replay, args=(ctx,))
    result = st.session_state.replay
    if result is None:
        return
    totals = result.totals
    share = totals["blocked_packets"] / totals["total_packets"] if totals["total_packets"] else 0
    a, b, c, d = st.columns(4)
    a.metric("Rule installations", f"{totals['rules_installed']:,}", border=True)
    b.metric("Packets blocked (simulated)", f"{totals['blocked_packets']:,}", border=True)
    c.metric("Share of all packets", f"{share:.1%}", border=True)
    if result.has_labels:
        d.metric("Normal flows blocked", f"{totals['normal_flows_blocked']:,}", border=True,
                 help="Collateral damage: normal flows that matched a drop rule.")
        total_attack = totals["attack_flows_total"]
        caught = totals["attack_flows_blocked"] / total_attack if total_attack else 0
        st.markdown(f"Of **{total_attack:,}** labelled attack flows, "
                    f"**{totals['attack_flows_blocked']:,}** ({caught:.0%}) would have been "
                    f"blocked. The rest arrived before a matching rule existed. "
                    f"**{totals['normal_flows_blocked']:,}** of "
                    f"{totals['normal_flows_total']:,} normal flows would also be blocked.")

    table = result.per_window
    size = max(1, -(-len(table) // ui.MAX_POINTS))
    if size > 1:
        table = table.groupby(table.reset_index(drop=True).index // size).agg(
            window=("window", "first"), forwarded_packets=("forwarded_packets", "sum"),
            blocked_packets=("blocked_packets", "sum"))
    fig = ui.stacked_bars(table, [("Forwarded", "forwarded_packets", ui.BLUE),
                                  ("Blocked (simulated)", "blocked_packets", ui.AQUA)],
                          "packets")
    fig.update_xaxes(title_text=f"Window ({WINDOW_SECONDS} s each)")
    fig.update_yaxes(title_text="Packets")
    ui.chart(fig, "replay_packets", height=320)
    st.caption("Green shows packets the rules would have stopped; blue would still pass.")
    with st.expander("Table view"):
        st.dataframe(result.per_window, hide_index=True, width="stretch")
    st.caption("The recorded traffic does not change when a rule is added, so this shows what "
               "the rules would match, not how a live attacker would react.")


def _log_tab():
    engine = st.session_state.engine
    if not engine.events:
        st.info("The event log is empty. Install rules or run a replay.")
        return
    log = pd.DataFrame(engine.events[::-1])
    log["window"] = log["window"].astype("Int64")
    st.dataframe(log, hide_index=True, width="stretch", column_config={
        "logged_at": "Logged at", "window": "Window", "event": "Event",
        "detail": st.column_config.TextColumn("Detail", width="large"), "mode": "Mode"})
    with st.container(horizontal=True):
        st.download_button("Download event log (CSV)", lambda: log.to_csv(index=False),
                           "mitigation_log.csv", "text/csv", icon=":material/download:",
                           on_click="ignore")
        st.button("Clear log", icon=":material/delete:", on_click=engine.events.clear)
    st.caption(f"The log keeps the last {mitigation.MAX_EVENTS:,} events of this browser "
               "session. It resets when the data changes or the page is reloaded.")


def _sdn_tab():
    st.markdown("""
### How an SDN controller applies mitigation
In Software-Defined Networking the **controller** decides and the **switches** obey. The
controller changes switch behaviour by sending OpenFlow *flow rules*.
""")
    st.graphviz_chart("""
digraph {
  rankdir=LR; bgcolor="transparent";
  node [shape=box style="rounded,filled" fillcolor="#17223a" color="#338ced"
        fontcolor="#e6edf7" fontname="Helvetica" fontsize=11];
  edge [color="#9aa8c0" fontcolor="#9aa8c0" fontname="Helvetica" fontsize=10];
  s [label="Switches\\ncount flows"];
  c [label="Controller\\ncollects statistics\\nevery 10 s"];
  m [label="ML model\\nnormal or DDoS"];
  r [label="Mitigation\\nchoose drop rules"];
  s -> c [label="flow stats reply"]; c -> m; m -> r [label="attack window"];
  r -> s [label="FlowMod: drop, 120 s" color="#e76624"];
}
""", width="stretch")
    st.markdown(f"""
1. A rule has a **match** (which packets), **actions** (what to do), a **priority** and a
   **timeout**.
2. A rule with **no actions** drops matching packets. Priority {sdn.RULE_PRIORITY} beats the
   learning switch's forwarding rules (priority 1).
3. After {sdn.BLOCK_SECONDS} seconds the switch removes the rule automatically.

**How the original project code does it** (`Codes/controller/mitigation_module.py` with
`switchm.py`, Linux only): after an attack verdict it watches new packets and, if a source IP
was never announced by ARP on that port (a sign of spoofing), it blocks the **whole ingress
port** for 120 s. The recorded CSV has no port-of-entry or ARP information, so this dashboard
cannot simulate that method. It proposes **source-destination-protocol** rules instead.

**Limits to remember:** blocking source addresses does not stop an attacker who uses a new
random source for every packet, and a wrong prediction blocks a real user.
""")


def render():
    ui.header("Attack Mitigation", "Identify malicious traffic and simulate the SDN response.")
    ctx = state.get_context()
    ui.data_notice(ctx)
    controller = st.session_state.engine.controller
    ui.banner("info", f"SIMULATION MODE - {controller.name}",
              "No switch is connected. No real packets are blocked. 'Blocked' means recorded "
              "flows that an installed rule would have matched.")
    tabs = st.tabs(["Respond to a window", "Active rules", "Timeline replay", "Event log",
                    "How SDN does it"])
    with tabs[0]:
        _respond_tab(ctx)
    with tabs[1]:
        _rules_tab(ctx)
    with tabs[2]:
        _replay_tab(ctx)
    with tabs[3]:
        _log_tab()
    with tabs[4]:
        _sdn_tab()
