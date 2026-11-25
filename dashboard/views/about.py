"""About Project: the report in short form, for visitors and examiners."""
import streamlit as st

import ui
from ddos.schema import FEATURE_COLUMNS, LEGIT_THRESHOLD, WINDOW_SECONDS

ARCHITECTURE = """
digraph {
  rankdir=TB; bgcolor="transparent"; compound=true; nodesep=0.35;
  node [shape=box style="rounded,filled" fillcolor="#17223a" color="#338ced"
        fontcolor="#e6edf7" fontname="Helvetica" fontsize=11];
  edge [color="#9aa8c0" fontcolor="#9aa8c0" fontname="Helvetica" fontsize=10];
  graph [fontname="Helvetica" fontsize=11 fontcolor="#9aa8c0" color="#33425f" style=rounded];
  subgraph cluster_app { label="Application layer";
    detect [label="Detection engine\\n(Random Forest)"];
    mitigate [label="Mitigation engine"]; ui [label="Streamlit dashboard"]; }
  subgraph cluster_ctl { label="Control layer";
    ryu [label="Ryu controller (Linux)\\nor Simulated controller (Windows)"]; }
  subgraph cluster_infra { label="Infrastructure layer (Mininet)";
    sw [label="Open vSwitch s1 - s6"]; hosts [label="Hosts h1 - h18"]; }
  hosts -> sw [dir=both label="packets"];
  sw -> ryu [label="flow statistics"];
  ryu -> detect [label="CSV records"];
  detect -> mitigate [label="attack flows"];
  mitigate -> ryu [label="drop rules"];
  ryu -> sw [label="OpenFlow 1.3"];
  detect -> ui [style=dashed]; mitigate -> ui [style=dashed];
}
"""

WORKFLOW = f"""
digraph {{
  rankdir=TB; bgcolor="transparent"; nodesep=0.3; ranksep=0.3;
  node [shape=box style="rounded,filled" fillcolor="#17223a" color="#338ced"
        fontcolor="#e6edf7" fontname="Helvetica" fontsize=11];
  edge [color="#9aa8c0" fontcolor="#9aa8c0" fontname="Helvetica" fontsize=10];
  a [label="Read flow statistics (CSV)"];
  b [label="Validate columns and clean values"];
  c [label="Split train / test by flow id"];
  d [label="Train and compare 5 models"];
  e [label="Classify flows in each {WINDOW_SECONDS} s window"];
  f [label="Legitimate share > {LEGIT_THRESHOLD:.0f}% ?" shape=diamond];
  g [label="Normal: keep monitoring"];
  h [label="Attack: find victim and sources" color="#e76624"];
  i [label="Create drop rules (120 s)" color="#e76624"];
  j [label="Write event log"];
  a -> b -> c -> d -> e -> f;
  f -> g [label="yes"]; f -> h [label="no"]; h -> i -> j; g -> e [style=dashed];
}}
"""


def render():
    ui.header("About Project",
              "DDoS Attack Detection and Mitigation using Machine Learning and "
              "Software-Defined Networking")
    intro, design, method, outlook = st.tabs(
        ["Introduction", "Architecture", "Methodology", "Advantages and conclusion"])

    with intro:
        st.markdown("""
### Abstract
A DDoS attack floods a target with traffic so that real users cannot use it. This project reads
network flow statistics, uses machine learning to separate normal traffic from attack traffic,
raises an alarm for each 10-second window and shows how a Software-Defined Networking
controller could block the attack. The prototype uses synthetic sample data and simulated
mitigation.

### Introduction
A **Distributed Denial of Service (DDoS)** attack floods a server or network with traffic from
many sources until real users cannot get service. **Software-Defined Networking (SDN)**
separates the control of a network from the switches that forward packets, so one program can
watch all switches and change their rules. This project uses that central view together with
**machine learning** to find attacks and respond to them.

### Problem statement
DDoS traffic can look like normal traffic. Fixed thresholds are hard to tune, and manual
response is slow. We need a method that learns the difference from data, decides quickly and
tells the network what to block.

### Objectives
1. Build an SDN test network with Mininet and a Ryu controller.
2. Collect flow statistics for normal and attack traffic.
3. Train and compare machine learning models; use Random Forest as the main detector.
4. Detect attacks in 10-second windows and identify the victim.
5. Respond with mitigation rules.
6. Present everything in a simple dashboard.

### Existing system
Traditional defences rely on firewalls, rate limits and signature rules configured on each
device. They need manual updates, see only part of the network and struggle with new attack
patterns.

### Proposed system
The SDN controller polls every switch for flow statistics. A trained model classifies each
flow. When too many flows in a window are malicious, the system identifies the victim and
creates drop rules. This dashboard demonstrates the pipeline with recorded or synthetic data
and a **simulated** controller.
""")

    with design:
        st.markdown("### SDN architecture")
        st.graphviz_chart(ARCHITECTURE, width="stretch")
        st.markdown("""
| Layer | Role | In this project |
|---|---|---|
| Application | Network programs that make decisions | Detection, mitigation, dashboard |
| Control | The central brain; talks OpenFlow to switches | Ryu (Linux) or simulator |
| Infrastructure | Switches and hosts that move packets | Mininet with Open vSwitch |
""")
        st.markdown("### Workflow")
        st.graphviz_chart(WORKFLOW)

    with method:
        st.markdown(f"""
### Machine learning methodology
1. **Data:** one row per flow with counters such as packets, bytes and duration.
2. **Cleaning:** check columns, reject invalid values, handle missing values.
3. **Features ({len(FEATURE_COLUMNS)}):** {', '.join(f'`{c}`' for c in FEATURE_COLUMNS)}.
   Addresses, ports, time and flow id are excluded to avoid memorising the lab setup.
4. **Split:** 75% training, 25% testing; all rows of one flow stay on one side.
5. **Models:** Random Forest, Decision Tree, Logistic Regression, K-Nearest Neighbors,
   Support Vector Machine.
6. **Evaluation:** accuracy, precision, recall, F1-score, confusion matrix and 3-fold
   cross-validation.
7. **Detection rule:** a window is an attack when {LEGIT_THRESHOLD:.0f}% or less of its flows
   are classified as normal.

### Technologies used
| Technology | Purpose |
|---|---|
| Python | Programming language |
| pandas, NumPy | Data handling |
| scikit-learn, joblib | Machine learning and model saving |
| Streamlit, Plotly | Dashboard and charts |
| Matplotlib | Charts of the original command-line ML scripts |
| Ryu, Mininet, Open vSwitch, hping3 | SDN lab (Linux only; not running in this dashboard) |
""")

    with outlook:
        st.markdown("""
### Advantages
- Central, network-wide view through SDN.
- Learns patterns from data instead of hand-written thresholds.
- Fast decision for every 10-second window.
- Runs on a normal Windows laptop in simulation mode.
- Clear, separate detection, mitigation and controller modules.

### Limitations
- The real dataset is not available; the sample data is **synthetic**.
- Mitigation is **simulated**; no packets are blocked.
- No live capture: the dashboard replays recorded files.
- Mininet and Ryu integration has not been run or verified in this prototype.
- Source-based rules cannot stop attacks that spoof random source addresses.
- Only two classes (normal / DDoS); attack types are not named.

### Future scope
- Collect a real dataset in the Mininet lab and report results on it.
- Implement a live Ryu controller behind the existing controller interface.
- Detect attack types (SYN, UDP, ICMP floods) and slow attacks.
- Rate limiting and port blocking in addition to dropping flows.
- Alerts by e-mail or chat, and storage of events in a database.
- Test with public datasets after mapping their features carefully.

### Conclusion
The project brings data checking, model comparison, window-based detection and a safe
mitigation simulation into one dashboard that a student can run on Windows. The pipeline works
as designed on synthetic data. Accuracy on a real network and real blocking still have to be
proven with a collected dataset and a live controller.

### Credits
Based on the open-source project by Chirag Biradar and contributors (Akash Kumar, Apoorv
Bagal, Abhishek Ray), distributed under the licence in the `LICENSE` file.
""")
