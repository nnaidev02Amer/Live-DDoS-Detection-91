"""Synthetic flow statistics in the format the Ryu collectors write.

THIS IS NOT REAL NETWORK DATA. The real FlowStatsfile.csv is not in the repository.
The two classes are generated from clearly different ranges (for example attack
flows carry 500-20000 packets and normal flows 5-60), so any reasonable model
scores close to 100 % on it. Such scores say nothing about real networks.
"""
import numpy as np
import pandas as pd

from .schema import COLUMNS

TRAIN_FLOWS = 4000
TIMELINE_FLOWS = 6000
TIMELINE_WINDOWS = 60           # 60 windows x 10 s = 10 minutes
ATTACK_WINDOWS = (20, 35)       # attack burst planned for windows 20 to 34
# Flows get their class by position while arrival times are random, so the edges of the
# burst are not exact (with seed 0 about half of window 35 is still attack traffic).


def make_flows(n, seed, attack_share=0.5, windows=None):
    """Return `n` synthetic flows.

    attack_share  probability that a flow is an attack flow
    windows       optional array of per-flow attack probabilities (timeline mode)
    """
    rng = np.random.default_rng(seed)
    label = (rng.random(n) < attack_share).astype(int)
    if windows is not None:  # timeline mode: attack share depends on the window
        label = (rng.random(n) < windows).astype(int)
    atk = label == 1
    proto = rng.choice([1, 6, 17], n)
    dur = np.where(atk, rng.integers(1, 6, n), rng.integers(1, 31, n))
    ns = rng.integers(1, 10**9, n)
    pc = np.where(atk, rng.integers(500, 20000, n), rng.integers(5, 61, n))
    bsize = np.where(atk, rng.integers(120, 161, n), rng.integers(60, 121, n))
    bc = pc * bsize
    src = rng.integers(2, 19, n)
    sp = np.where(proto == 1, 0, rng.integers(1024, 65000, n))
    dp = np.where(proto == 1, 0, 80)
    victim = np.where(atk, 1, rng.integers(1, 19, n))  # attacks target h1
    df = pd.DataFrame({
        "timestamp": 1.7e9 + np.sort(rng.random(n)) * 600,
        "datapath_id": rng.integers(1, 7, n),
        "ip_src": [f"10.0.0.{s}" for s in src], "tp_src": sp,
        "ip_dst": [f"10.0.0.{v}" for v in victim], "tp_dst": dp, "ip_proto": proto,
        "icmp_code": np.where(proto == 1, 0, -1), "icmp_type": np.where(proto == 1, 8, -1),
        "flow_duration_sec": dur, "flow_duration_nsec": ns,
        "idle_timeout": rng.choice([0, 10], n), "hard_timeout": 0, "flags": 0,
        "packet_count": pc, "byte_count": bc,
        "packet_count_per_second": pc / dur, "packet_count_per_nsecond": pc / ns,
        "byte_count_per_second": bc / dur, "byte_count_per_nsecond": bc / ns,
        "label": label,
    })
    df.insert(2, "flow_id", df.ip_src + df.tp_src.astype(str) + df.ip_dst + df.tp_dst.astype(str)
              + df.ip_proto.astype(str))
    return df[COLUMNS]


def training_sample(seed=0):
    """Balanced synthetic training data."""
    return make_flows(TRAIN_FLOWS, seed)


def timeline_sample(seed=0):
    """Synthetic 10 minute timeline with an attack burst in the middle."""
    n = TIMELINE_FLOWS
    position = np.arange(n) / n * TIMELINE_WINDOWS
    start, stop = ATTACK_WINDOWS
    share = np.where((position >= start) & (position < stop), 0.9, 0.05)
    return make_flows(n, seed + 1, windows=share)
