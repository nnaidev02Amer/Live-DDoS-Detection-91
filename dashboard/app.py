"""Streamlit dashboard for the DDoS detection project.

Re-implements the project's pipeline in a browser view (original code is untouched):
  flow stats -> Random Forest (same settings as Codes/controller/controller.py)
  -> normal vs DDoS per 10 s window -> simulated mitigation action.

Run:  streamlit run dashboard/app.py
"""
import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn.tree import DecisionTreeClassifier

COLS = ("timestamp,datapath_id,flow_id,ip_src,tp_src,ip_dst,tp_dst,ip_proto,icmp_code,"
        "icmp_type,flow_duration_sec,flow_duration_nsec,idle_timeout,hard_timeout,flags,"
        "packet_count,byte_count,packet_count_per_second,packet_count_per_nsecond,"
        "byte_count_per_second,byte_count_per_nsecond,label").split(",")
NORMAL, DDOS = "#2a78c8", "#d9622b"  # blue / orange: distinguishable for colour-blind viewers
NAMES = {0: "Normal", 1: "DDoS"}
COLOR_MAP = {"Normal": NORMAL, "DDoS": DDOS}

st.set_page_config(page_title="DDoS Detection Dashboard", layout="wide")


# ---------------------------------------------------------------- data
def make_flows(n, seed, attack_share=0.5, windows=None):
    """Synthetic flow stats in the exact column format the Ryu collectors write."""
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
    return df[COLS]


def features(df):
    """Same preprocessing as the project: strip dots from flow_id / ip_src / ip_dst."""
    d = df.copy()
    for c in (2, 3, 5):
        d.iloc[:, c] = d.iloc[:, c].astype(str).str.replace(".", "", regex=False)
    return d.drop(columns="label").astype("float64").values


@st.cache_data(show_spinner=False)
def train_and_compare(train_df):
    X, y = features(train_df), train_df["label"].values
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.25, random_state=0)
    models = {
        "Logistic Regression": LogisticRegression(solver="liblinear", random_state=0),
        "KNN": KNeighborsClassifier(n_neighbors=5),
        "Naive Bayes": GaussianNB(),
        "Decision Tree": DecisionTreeClassifier(criterion="entropy", random_state=0),
        "Random Forest": RandomForestClassifier(n_estimators=10, criterion="entropy", random_state=0),
    }
    rows, rf, cm = [], None, None
    for name, m in models.items():
        m.fit(Xtr, ytr)
        pred = m.predict(Xte)
        rows.append({"Model": name, "Accuracy %": round(accuracy_score(yte, pred) * 100, 2)})
        if name == "Random Forest":
            rf, cm = m, confusion_matrix(yte, pred, labels=[0, 1])
    return rf, pd.DataFrame(rows), cm


# ---------------------------------------------------------------- sidebar
st.sidebar.header("Data source")
src_choice = st.sidebar.radio("Flow data", ["Synthetic sample traffic", "Upload FlowStatsfile.csv"])
seed = st.sidebar.number_input("Random seed (sample data)", 0, 9999, 0)
uploaded = None
if src_choice.startswith("Upload"):
    uploaded = st.sidebar.file_uploader("FlowStatsfile.csv", type="csv")
    if uploaded is None:
        st.info("Upload your FlowStatsfile.csv (with the 22 columns the Ryu collectors write), "
                "or switch to the synthetic sample.")
        st.stop()

if uploaded is not None:
    train_df = pd.read_csv(uploaded)
    timeline_df = train_df.sort_values("timestamp").reset_index(drop=True)
    st.sidebar.caption("Uploaded data: the timeline is predicted on the same rows the model "
                       "trained on, so it is optimistic.")
else:
    train_df = make_flows(4000, seed)
    # attack burst in the middle of the 10-minute timeline (windows 20-35 of 60)
    n = 6000
    pos = np.arange(n) / n * 60
    share = np.where((pos >= 20) & (pos < 35), 0.9, 0.05)
    timeline_df = make_flows(n, seed + 1, windows=share)
    st.sidebar.caption("Sample data is synthetic (the real dataset is not in the repo): "
                       "accuracy shown is NOT a real result.")

rf, comp, cm = train_and_compare(train_df)

# ---------------------------------------------------------------- header
st.title("DDoS Attack Detection & Mitigation")
st.caption("SDN flow statistics -> Random Forest -> normal vs DDoS -> mitigation action. "
           "Mitigation here is simulated: the real one needs Mininet + Ryu on Linux.")

tab1, tab2, tab3 = st.tabs(["Live detection", "Model accuracy", "Data"])

# ---------------------------------------------------------------- tab 1
with tab1:
    t = timeline_df.copy()
    t["window"] = ((t["timestamp"] - t["timestamp"].min()) // 10).astype(int)
    t["Predicted"] = [NAMES[p] for p in rf.predict(features(timeline_df))]
    nwin = int(t["window"].max())
    w = st.slider("Monitoring window (each = 10 s, the controller's polling interval)", 0, nwin,
                  min(25, nwin))
    cur = t[t["window"] == w]
    legit_pct = (cur["Predicted"] == "Normal").mean() * 100 if len(cur) else 100.0
    attack = legit_pct <= 80  # same rule as controller.py: >80 % legitimate = OK

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Flows in window", len(cur))
    c2.metric("Legitimate flows", f"{legit_pct:.0f} %")
    c3.metric("Verdict", "DDoS ATTACK" if attack else "Normal")
    flagged = cur[cur["Predicted"] == "DDoS"]
    victim = flagged["ip_dst"].mode().iat[0] if len(flagged) else "-"
    c4.metric("Victim host", "h" + victim.split(".")[-1] if attack and victim != "-" else "-")

    if attack:
        st.error("Attack detected - more than 20 % of flows classified as DDoS.")
        mit = (flagged.groupby(["datapath_id", "ip_src"]).size().reset_index(name="malicious flows")
               .sort_values("malicious flows", ascending=False).head(8))
        mit["datapath_id"] = "s" + mit["datapath_id"].astype(int).astype(str)
        mit["Mitigation action (simulated)"] = "install DROP rule on ingress port"
        st.subheader("Mitigation action taken")
        st.dataframe(mit.rename(columns={"datapath_id": "switch", "ip_src": "attacker source"}),
                     hide_index=True, width="stretch")
    else:
        st.success("Traffic is legitimate - no action taken.")

    st.subheader("Incoming traffic over time (packets per window, by predicted class)")
    agg = t.groupby(["window", "Predicted"])["packet_count"].sum().reset_index()
    fig = px.area(agg, x="window", y="packet_count", color="Predicted", color_discrete_map=COLOR_MAP,
                  labels={"window": "10 s window", "packet_count": "packets"})
    fig.add_vline(x=w, line_dash="dash", line_color="gray")
    fig.update_layout(height=330, margin=dict(t=10, b=10), legend_title_text="")
    st.plotly_chart(fig, width="stretch")

    share_df = t.groupby("window")["Predicted"].apply(lambda s: (s == "DDoS").mean() * 100).reset_index(
        name="DDoS flows %")
    fig2 = px.line(share_df, x="window", y="DDoS flows %", labels={"window": "10 s window"})
    fig2.update_traces(line_color=DDOS)
    fig2.add_hline(y=20, line_dash="dot", line_color="gray", annotation_text="alarm threshold (20 %)")
    fig2.update_layout(height=260, margin=dict(t=10, b=10))
    st.plotly_chart(fig2, width="stretch")

# ---------------------------------------------------------------- tab 2
with tab2:
    rf_acc = float(comp.loc[comp.Model == "Random Forest", "Accuracy %"].iat[0])
    a, b = st.columns([1, 1])
    with a:
        st.metric("Random Forest accuracy (25 % hold-out)", f"{rf_acc:.2f} %")
        fig = px.bar(comp, x="Model", y="Accuracy %", text="Accuracy %")
        fig.update_traces(marker_color=NORMAL, textposition="outside")
        fig.update_layout(height=360, yaxis_range=[0, 105], margin=dict(t=10))
        st.plotly_chart(fig, width="stretch")
    with b:
        st.markdown("**Confusion matrix (Random Forest)**")
        fig = go.Figure(go.Heatmap(z=cm, x=["Pred Normal", "Pred DDoS"], y=["True Normal", "True DDoS"],
                                   text=cm, texttemplate="%{text}", colorscale=[[0, "#eef4fb"], [1, NORMAL]],
                                   showscale=False))
        fig.update_layout(height=360, margin=dict(t=10), yaxis_autorange="reversed")
        st.plotly_chart(fig, width="stretch")
    st.dataframe(comp, hide_index=True)

# ---------------------------------------------------------------- tab 3
with tab3:
    st.write(f"Training data: {len(train_df):,} flows, {int(train_df.label.sum()):,} labelled DDoS.")
    st.dataframe(train_df.head(200), width="stretch")
    st.download_button("Download sample FlowStatsfile.csv", train_df.to_csv(index=False),
                       "FlowStatsfile.csv", "text/csv")
