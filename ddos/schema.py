"""Column layout of FlowStatsfile.csv and project-wide constants.

The layout is the one written by the Ryu collectors in Codes/controller.
"""

LABEL = "label"

# The 21 columns the detector reads (PredictFlowStatsfile.csv has exactly these).
INPUT_COLUMNS = [
    "timestamp", "datapath_id", "flow_id", "ip_src", "tp_src", "ip_dst", "tp_dst",
    "ip_proto", "icmp_code", "icmp_type", "flow_duration_sec", "flow_duration_nsec",
    "idle_timeout", "hard_timeout", "flags", "packet_count", "byte_count",
    "packet_count_per_second", "packet_count_per_nsecond", "byte_count_per_second",
    "byte_count_per_nsecond",
]

# FlowStatsfile.csv (training data) adds the label as the 22nd column.
COLUMNS = INPUT_COLUMNS + [LABEL]

# Features given to the models. Identifiers and noise columns are left out on purpose.
FEATURE_COLUMNS = [
    "ip_proto", "icmp_code", "icmp_type", "flow_duration_sec", "idle_timeout",
    "hard_timeout", "flags", "packet_count", "byte_count",
    "packet_count_per_second", "byte_count_per_second",
]

EXCLUDED_FEATURES = {
    "timestamp": "Benign and attack data are collected at different times, so the clock "
                 "alone would reveal the label (data leakage).",
    "datapath_id": "Switch identifier. The model would learn where the lab attack ran.",
    "flow_id": "Identifier built from IPs and ports. Used only to keep one flow on one "
               "side of the train/test split.",
    "ip_src": "Identifier. Attackers change or spoof source addresses.",
    "tp_src": "Source port is chosen at random by the sender.",
    "ip_dst": "Identifier. The model would memorise which host was the victim.",
    "tp_dst": "Destination port identifies the lab's target service, not attack behaviour.",
    "flow_duration_nsec": "Sub-second remainder of the duration; close to random noise.",
    "packet_count_per_nsecond": "Packets divided by that remainder; not a real rate.",
    "byte_count_per_nsecond": "Bytes divided by that remainder; not a real rate.",
}

IP_COLUMNS = ["ip_src", "ip_dst"]
TEXT_COLUMNS = ["flow_id"] + IP_COLUMNS
NUMERIC_COLUMNS = [c for c in INPUT_COLUMNS if c not in TEXT_COLUMNS]

# Without these a row cannot be placed in a window, shown or turned into a rule,
# and they cannot be estimated, so such rows are always dropped.
ESSENTIAL_COLUMNS = ["timestamp", "datapath_id", "flow_id", "ip_src", "ip_dst", "ip_proto"]

# icmp_code and icmp_type use -1 for "not ICMP"; every other numeric column is >= 0.
SIGNED_COLUMNS = ["icmp_code", "icmp_type"]

NORMAL, DDOS = 0, 1  # label values used by the collectors: 0 = benign, 1 = attack
CLASS_NAMES = {NORMAL: "Normal", DDOS: "DDoS"}
PROTOCOL_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}

WINDOW_SECONDS = 10      # the controller polls the switches every 10 s
LEGIT_THRESHOLD = 80.0   # controller.py: more than 80 % legitimate flows = normal
