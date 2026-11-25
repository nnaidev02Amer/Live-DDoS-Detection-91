"""Network Traffic Dataset: inspect the current data and upload CSV files."""
import hashlib
import io

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

import state
import ui
from ddos import models, preprocessing, sample_data
from ddos.schema import (CLASS_NAMES, COLUMNS, EXCLUDED_FEATURES, FEATURE_COLUMNS,
                         INPUT_COLUMNS, LABEL, NUMERIC_COLUMNS, PROTOCOL_NAMES)

PREVIEW_ROWS = 200
TRAIN, MONITOR = "Training data (label required)", "Monitoring data (label optional)"
MISSING_OPTIONS = {
    "Remove incomplete rows (recommended)": preprocessing.MISSING_DROP,
    "Keep them; the model fills gaps with the training median": preprocessing.MISSING_KEEP,
}


@st.cache_data(max_entries=3, show_spinner="Reading and checking the file...")
def _parse(content, missing, require_label):
    return preprocessing.load_flows(io.BytesIO(content), missing=missing,
                                    require_label=require_label)


def _show_data(data, key, title):
    """Preview, summary, distributions and download of one table."""
    a, b, c, d = st.columns(4)
    a.metric("Rows", f"{len(data):,}", border=True)
    b.metric("Columns", f"{data.shape[1]}", border=True)
    c.metric("Missing cells", f"{int(data.isna().sum().sum()):,}", border=True)
    if LABEL in data.columns:
        d.metric("Labelled DDoS", f"{int((data[LABEL] == 1).sum()):,}", border=True)
    else:
        d.metric("Labels", "None", border=True)

    st.markdown(f"**Preview** (first {min(PREVIEW_ROWS, len(data))} rows)")
    st.dataframe(data.head(PREVIEW_ROWS), hide_index=True, width="stretch", height=300)

    left, right = st.columns(2)
    with left:
        st.markdown("**Traffic by class**" if LABEL in data.columns else "**Class labels**")
        if LABEL in data.columns:
            counts = data[LABEL].map(CLASS_NAMES).value_counts().reindex(
                ["Normal", "DDoS"], fill_value=0)
            fig = go.Figure(go.Bar(x=counts.index, y=counts.values,
                                   marker_color=[ui.BLUE, ui.ORANGE], width=0.5,
                                   text=[f"{v:,}" for v in counts.values],
                                   textposition="outside", textfont_color=ui.INK,
                                   hovertemplate="%{x}: %{y:,} flows<extra></extra>"))
            fig.update_yaxes(title_text="Flows", range=[0, max(counts.max(), 1) * 1.15])
            ui.chart(fig, f"{key}_classes", height=280, legend=False)
            st.caption("How many rows are labelled normal and DDoS.")
        else:
            st.info("This file has no label column, so true classes are unknown.")
    with right:
        st.markdown("**Traffic by protocol**")
        counts = data["ip_proto"].map(PROTOCOL_NAMES).fillna("Other").value_counts()
        fig = go.Figure(go.Bar(x=counts.index, y=counts.values, marker_color=ui.BLUE, width=0.5,
                               text=[f"{v:,}" for v in counts.values], textposition="outside",
                               textfont_color=ui.INK,
                               hovertemplate="%{x}: %{y:,} flows<extra></extra>"))
        fig.update_yaxes(title_text="Flows", range=[0, max(counts.max(), 1) * 1.15])
        ui.chart(fig, f"{key}_protocols", height=280, legend=False)
        st.caption("The kind of network traffic: ping (ICMP), TCP or UDP.")

    st.markdown("**Numeric summary**")
    numeric = data[[c for c in NUMERIC_COLUMNS if c != "timestamp"]]
    st.dataframe(numeric.describe().T, width="stretch")
    st.download_button(f"Download processed {title} (CSV)", lambda: data.to_csv(index=False),
                       f"processed_{title}.csv", "text/csv", icon=":material/download:",
                       key=f"{key}_download", on_click="ignore")


def _report(result):
    """What validation and cleaning did to the file."""
    st.markdown("**Validation report**")
    a, b, c = st.columns(3)
    a.metric("Rows in file", f"{result.rows_in:,}", border=True)
    b.metric("Rows usable", f"{result.rows_out:,}", border=True)
    c.metric("Rows removed", f"{result.rows_in - result.rows_out:,}", border=True)
    st.markdown(f"- All {len(INPUT_COLUMNS)} required columns are present.\n"
                f"- Label column: **{'present' if result.has_labels else 'absent'}**.")
    if result.extra_columns:
        st.info(f"Extra column(s) ignored: {', '.join(map(str, result.extra_columns))}")
    for reason, count in result.dropped.items():
        st.warning(f"Removed {count:,} row(s): {reason}.")
    if result.duplicate_rows:
        st.info(f"{result.duplicate_rows:,} duplicate row(s) found. They were kept.")
    if result.missing:
        st.markdown("Missing or invalid cells found, by column:")
        st.dataframe(pd.DataFrame(result.missing.items(), columns=["Column", "Cells"]),
                     hide_index=True)
    else:
        st.success("No missing or invalid values.")


def _use(purpose, upload):
    slot = "train_upload" if purpose == TRAIN else "monitor_upload"
    st.session_state[slot] = upload


def _upload_tab():
    st.markdown("Upload a `FlowStatsfile.csv` written by the Ryu collectors (training), or a "
                "`PredictFlowStatsfile.csv` / any file with the same columns (monitoring). "
                "In the label column **0 = normal** and **1 = DDoS**.")
    purpose = st.radio("What is this file for?", [TRAIN, MONITOR], horizontal=True)
    choice = st.radio("Rows with missing values", list(MISSING_OPTIONS))
    file = st.file_uploader("Choose a CSV file", type="csv", key="csv_upload")
    if file is None:
        return
    content = file.getvalue()
    missing = MISSING_OPTIONS[choice]
    try:
        result = _parse(content, missing, purpose == TRAIN)
    except preprocessing.DatasetError as exc:
        st.error(f"**This file cannot be used.** {exc}", icon=":material/error:")
        st.caption("Nothing was changed. The previous data is still active.")
        return
    except MemoryError:
        st.error("The file is too large for the available memory.")
        return

    _report(result)
    problem = None
    if purpose == TRAIN:
        try:
            models.check_labels(result.data)
        except models.ModelError as exc:
            problem = str(exc)
    if problem:
        st.error(f"**Cannot train on this file.** {problem}", icon=":material/error:")
    else:
        digest = hashlib.sha256(content).hexdigest()[:16]
        upload = state.Upload(file.name, result.data, f"upload:{digest}:{missing}", digest)
        active = st.session_state["train_upload" if purpose == TRAIN else "monitor_upload"]
        if active is not None and active.key == upload.key:
            st.success("This file is now in use. Open the other pages to see the results.",
                       icon=":material/check_circle:")
        else:
            st.button("Use this file for " + ("training" if purpose == TRAIN else "monitoring"),
                      type="primary", icon=":material/play_arrow:", on_click=_use,
                      args=(purpose, upload))
    _show_data(result.data, "preview", "upload")


def _current_tab():
    ctx = state.get_context()
    if st.session_state.train_upload or st.session_state.monitor_upload:
        st.button("Return to the synthetic sample", icon=":material/restart_alt:",
                  on_click=state.reset_to_synthetic)
    else:
        st.number_input("Random seed for the synthetic sample (0 = default demo)", 0, 9999,
                        value=int(st.session_state.seed), key="seed_input",
                        on_change=state.set_seed)
    ui.data_notice(ctx)
    options = {f"Training: {ctx.train_name}": (ctx.train_df, "training_data")}
    if not ctx.monitor_is_training:
        options[f"Monitoring: {ctx.monitor_name}"] = (ctx.monitor_df, "monitoring_data")
    selected = st.radio("Table to view", list(options), horizontal=True)
    data, title = options[selected]
    _show_data(data, "current", title)


def _schema_tab():
    rows = [{"Column": c,
             "Required": "training only" if c == LABEL else "yes",
             "Used by the model": "target" if c == LABEL
             else "yes" if c in FEATURE_COLUMNS else "no",
             "Note": EXCLUDED_FEATURES.get(c, "0 = normal, 1 = DDoS" if c == LABEL else "")}
            for c in COLUMNS]
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch", height=810)
    a, b, c = st.columns(3)
    a.download_button("Empty template (header only)", ",".join(COLUMNS) + "\n",
                      "FlowStatsfile_template.csv", "text/csv", icon=":material/description:",
                      on_click="ignore")
    b.download_button("Synthetic training sample",
                      lambda: sample_data.training_sample(0).to_csv(index=False),
                      "synthetic_FlowStatsfile.csv", "text/csv", icon=":material/science:",
                      on_click="ignore")
    c.download_button("Synthetic monitoring sample",
                      lambda: sample_data.timeline_sample(0).to_csv(index=False),
                      "synthetic_monitor.csv", "text/csv", icon=":material/science:",
                      on_click="ignore")


def render():
    ui.header("Network Traffic Dataset",
              "Check the data behind the results, or upload your own flow statistics.")
    current, upload, schema = st.tabs(["Current data", "Upload CSV", "Columns and samples"])
    with current:
        _current_tab()
    with upload:
        _upload_tab()
    with schema:
        _schema_tab()
