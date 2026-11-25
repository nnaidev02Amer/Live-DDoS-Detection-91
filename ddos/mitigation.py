"""Mitigation engine: turn detected attack flows into drop rules (simulation).

A rule installed after window w is active in the following windows until its hard
timeout ends (120 s = 12 windows). "Blocked" always means "recorded flows that match
an active rule and would have been dropped". No real traffic is touched.
"""
from dataclasses import dataclass
from datetime import datetime

import pandas as pd

from .schema import DDOS, LABEL, PROTOCOL_NAMES, WINDOW_SECONDS
from .sdn import BLOCK_SECONDS, FlowRule, SimulatedController

RULE_FIELDS = ["datapath_id", "ip_src", "ip_dst", "ip_proto"]
MAX_EVENTS = 2000


def propose_rules(window_flows):
    """One candidate rule per (switch, source, destination, protocol) of flagged flows."""
    flagged = window_flows[window_flows["predicted"] == DDOS]
    return (flagged.groupby(RULE_FIELDS)
            .agg(flows=("predicted", "size"), packets=("packet_count", "sum"),
                 bytes=("byte_count", "sum"))
            .reset_index()
            .sort_values(["packets", "flows"], ascending=False, ignore_index=True))


def describe_rule(rule):
    protocol = PROTOCOL_NAMES.get(rule.ip_proto, f"protocol {rule.ip_proto}")
    return f"s{rule.datapath_id}: DROP {protocol} {rule.ip_src} -> {rule.ip_dst}"


def _event(window, kind, detail):
    return {"logged_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "window": window,
            "event": kind, "detail": detail, "mode": "SIMULATED"}


class MitigationEngine:
    """Keeps the installed rules, their expiry and an event log."""

    def __init__(self, controller=None):
        self.controller = controller or SimulatedController()
        # rule key -> (window it was installed after, last window in which it is active)
        self.lifetime = {}
        self.events = []

    def log(self, window, kind, detail):
        self.events.append(_event(window, kind, detail))
        del self.events[:-MAX_EVENTS]

    def expire(self, window):
        """Remove rules whose hard timeout ended before `window`."""
        for rule in self.controller.list_rules():
            if self.lifetime.get(rule.key, (window, window))[1] < window:
                self.controller.remove_rule(rule)
                self.lifetime.pop(rule.key, None)
                self.log(window, "Rule expired", describe_rule(rule))

    def apply_window(self, window_flows, window):
        """Install rules for the flagged flows of one attack window.

        Returns the rules that were new. The caller decides whether the window is
        under attack.
        """
        self.expire(window)
        active = {key for key, (start, last) in self.lifetime.items() if start <= window <= last}
        added = []
        for row in propose_rules(window_flows).itertuples():
            rule = FlowRule(int(row.datapath_id), str(row.ip_src), str(row.ip_dst),
                            int(row.ip_proto))
            if rule.key in active:
                continue
            self.controller.install_rule(rule)
            self.lifetime[rule.key] = (window, window + rule.hard_timeout // WINDOW_SECONDS)
            self.log(window, "Rule installed",
                     f"{describe_rule(rule)} ({row.flows} flows, {int(row.packets):,} packets)")
            added.append(rule)
        return added

    def remove(self, rule, window=None):
        self.controller.remove_rule(rule)
        self.lifetime.pop(rule.key, None)
        self.log(window, "Rule removed", describe_rule(rule))

    def matched_flows(self, scored):
        """Recorded flows that the installed rules would have dropped.

        A flow matches when its key equals a rule and its window lies after the
        installation window and not after the expiry window.
        """
        if not self.lifetime:
            return scored.iloc[0:0]
        lifetimes = pd.DataFrame([(*key, start, last)
                                  for key, (start, last) in self.lifetime.items()],
                                 columns=RULE_FIELDS + ["_start", "_last"])
        joined = scored.merge(lifetimes, on=RULE_FIELDS, how="inner")
        inside = (joined["window"] > joined["_start"]) & (joined["window"] <= joined["_last"])
        return joined[inside].drop(columns=["_start", "_last"])

    def clear(self, window=None):
        rules = self.controller.list_rules()
        for rule in rules:
            self.controller.remove_rule(rule)
        self.lifetime.clear()
        self.log(window, "All rules removed", f"{len(rules)} rule(s)")


@dataclass
class ReplayResult:
    per_window: pd.DataFrame
    events: list
    totals: dict
    has_labels: bool


def replay(scored, summary, block_seconds=BLOCK_SECONDS):
    """Play the whole timeline with automatic mitigation.

    The recorded traffic is not changed by the rules, so detection results stay the
    same; the replay only counts what the rules would have matched.
    """
    block_windows = block_seconds // WINDOW_SECONDS
    keys = pd.Series(list(zip(*(scored[c].tolist() for c in RULE_FIELDS))), index=scored.index)
    attack_windows = set(summary.loc[summary["attack"], "window"])
    has_labels = LABEL in scored.columns

    active = {}     # rule key -> last window in which it is active
    rows, events = [], []
    installed = 0
    for window, flows in scored.groupby("window", sort=True):
        for key in [k for k, last in active.items() if last < window]:
            del active[key]
        window_keys = keys.loc[flows.index]
        blocked = window_keys.isin(list(active)) if active else pd.Series(False, index=flows.index)
        row = {
            "window": window,
            "total_packets": flows["packet_count"].sum(),
            "blocked_flows": int(blocked.sum()),
            "blocked_packets": flows.loc[blocked, "packet_count"].sum(),
            "blocked_bytes": flows.loc[blocked, "byte_count"].sum(),
        }
        if has_labels:
            row["attack_flows_blocked"] = int((blocked & (flows[LABEL] == DDOS)).sum())
            row["normal_flows_blocked"] = int((blocked & (flows[LABEL] != DDOS)).sum())
        if window in attack_windows:
            new = [k for k in window_keys[flows["predicted"] == DDOS].unique() if k not in active]
            for key in new:
                active[key] = window + block_windows
            if new:
                installed += len(new)
                events.append(_event(int(window), "Rules installed (replay)",
                                     f"{len(new)} drop rule(s); {len(active)} now active"))
        row["active_rules"] = len(active)
        rows.append(row)

    per_window = pd.DataFrame(rows)
    per_window["forwarded_packets"] = per_window["total_packets"] - per_window["blocked_packets"]
    totals = {
        "rules_installed": installed,
        "total_packets": int(per_window["total_packets"].sum()),
        "blocked_packets": int(per_window["blocked_packets"].sum()),
        "blocked_flows": int(per_window["blocked_flows"].sum()),
        "blocked_bytes": int(per_window["blocked_bytes"].sum()),
    }
    if has_labels:
        totals["attack_flows_total"] = int((scored[LABEL] == DDOS).sum())
        totals["normal_flows_total"] = int((scored[LABEL] != DDOS).sum())
        totals["attack_flows_blocked"] = int(per_window["attack_flows_blocked"].sum())
        totals["normal_flows_blocked"] = int(per_window["normal_flows_blocked"].sum())
    return ReplayResult(per_window, events[-MAX_EVENTS:], totals, has_labels)
