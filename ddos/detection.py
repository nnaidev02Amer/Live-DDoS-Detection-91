"""Detection engine: classify flows and give one verdict per 10 second window.

The verdict rule is the one used by Codes/controller/controller.py:
    more than 80 % of the flows legitimate  ->  normal
    otherwise                               ->  DDoS attack
"""
import ipaddress

import pandas as pd

from .models import feature_matrix
from .schema import DDOS, LABEL, LEGIT_THRESHOLD, WINDOW_SECONDS

MININET_NETWORK = ipaddress.ip_network("10.0.0.0/24")
MININET_HOSTS = 18


def assign_windows(timestamps, seconds=WINDOW_SECONDS):
    """Window number of each timestamp, counted from the earliest one."""
    return ((timestamps - timestamps.min()) // seconds).astype("int64")


def is_attack(legit_percent):
    return legit_percent <= LEGIT_THRESHOLD


def host_name(ip):
    """'h5' for a host of the project's Mininet topology, otherwise the address itself."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return str(ip)
    if address in MININET_NETWORK:
        number = int(str(address).rsplit(".", 1)[1])
        if 1 <= number <= MININET_HOSTS:
            return f"h{number}"
    return str(ip)


def score_flows(model, df):
    """Copy of `df` (sorted by time) with window, predicted and ddos_score columns.

    ddos_score is the model's predict_proba for the DDoS class. For the Random Forest
    it is the average vote of the trees. It is not a calibrated probability.
    """
    out = df.sort_values("timestamp", kind="stable").reset_index(drop=True)
    X = feature_matrix(out)
    out["window"] = assign_windows(out["timestamp"])
    out["predicted"] = model.predict(X).astype(int)
    if hasattr(model, "predict_proba"):
        column = list(model.classes_).index(DDOS)
        out["ddos_score"] = model.predict_proba(X)[:, column]
    else:
        out["ddos_score"] = float("nan")
    return out


def summarize_windows(scored):
    """One row per window that contains flows."""
    flagged = scored["predicted"] == DDOS
    work = scored.assign(
        _ddos=flagged.astype(int),
        _ddos_packets=scored["packet_count"].where(flagged, 0),
        _score=scored["ddos_score"].where(flagged),
    )
    aggregations = dict(
        flows=("_ddos", "size"), ddos_flows=("_ddos", "sum"),
        packets=("packet_count", "sum"), ddos_packets=("_ddos_packets", "sum"),
        bytes=("byte_count", "sum"), mean_ddos_score=("_score", "mean"),
    )
    if LABEL in scored.columns:
        aggregations["true_ddos_flows"] = (LABEL, "sum")
    summary = work.groupby("window").agg(**aggregations).reset_index()
    summary["normal_flows"] = summary["flows"] - summary["ddos_flows"]
    summary["legit_pct"] = summary["normal_flows"] / summary["flows"] * 100
    summary["ddos_pct"] = 100 - summary["legit_pct"]
    summary["attack"] = is_attack(summary["legit_pct"])
    if LABEL in scored.columns:
        true_legit = (summary["flows"] - summary["true_ddos_flows"]) / summary["flows"] * 100
        summary["true_attack"] = is_attack(true_legit)

    # victim = destination that receives most flagged flows (only in attack windows)
    targets = (scored[flagged].groupby(["window", "ip_dst"]).size().reset_index(name="n")
               .sort_values(["window", "n", "ip_dst"], ascending=[True, False, True])
               .drop_duplicates("window").set_index("window")["ip_dst"])
    summary["victim_ip"] = summary["window"].map(targets).where(summary["attack"])
    return summary


def attack_episodes(summary):
    """Group consecutive attack windows into episodes."""
    episodes = []
    current = None
    for row in summary.itertuples():
        if row.attack and current is not None and row.window == current["last_window"] + 1:
            current["last_window"] = row.window
            current["ddos_flows"] += row.ddos_flows
            current["ddos_packets"] += row.ddos_packets
        elif row.attack:
            current = {"first_window": row.window, "last_window": row.window,
                       "ddos_flows": row.ddos_flows, "ddos_packets": row.ddos_packets}
            episodes.append(current)
        else:
            current = None
    return pd.DataFrame(episodes, columns=["first_window", "last_window", "ddos_flows",
                                           "ddos_packets"])
