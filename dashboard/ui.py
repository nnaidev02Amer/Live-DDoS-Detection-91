"""Shared look and feel: page styles, banners, charts and the window selector."""
import html

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from ddos.schema import LEGIT_THRESHOLD, WINDOW_SECONDS

# Chart colours (checked for colour-blind safety and contrast on the dark background).
BLUE, ORANGE, AQUA, YELLOW = "#338ced", "#e76624", "#00a888", "#d28e05"
SURFACE, GRID, AXIS = "#0b1220", "#1e2a41", "#33425f"
INK, MUTED = "#e6edf7", "#9aa8c0"
STATUS = {"ok": ("#0aac23", "✔"), "alert": ("#dc3c3d", "⚠"), "info": ("#338ced", "ℹ"),
          "warn": ("#fbb315", "⚠")}
MAX_POINTS = 600    # longer timelines are grouped before plotting
DENSE_BARS = 120    # above this, bars are too thin for a gap between them

CSS = """
<style>
.block-container {padding-top: 2.6rem; padding-bottom: 3rem; max-width: 1400px;}
h1 {font-size: 1.9rem !important; margin-bottom: 0 !important;}
h2 {font-size: 1.35rem !important;}
h3 {font-size: 1.1rem !important;}
[data-testid="stMetric"] {background: #111a2b;}
[data-testid="stMetricValue"] {font-size: 1.7rem;}
.page-sub {color: #9aa8c0; margin: .1rem 0 1rem 0;}
.banner {border: 1px solid #24324d; border-left: 5px solid var(--c); border-radius: .5rem;
         background: #111a2b; padding: .8rem 1rem; margin: .4rem 0 1rem 0;}
.banner b {font-size: 1.1rem;}
.banner .icon {color: var(--c); margin-right: .5rem;}
.banner div {color: #b9c5da; margin-top: .2rem;}
.brand {font-weight: 700; font-size: 1.1rem; letter-spacing: .02em;}
.brand span {color: #9aa8c0; font-weight: 400; font-size: .8rem; display: block;}
</style>
"""


def inject_css():
    st.html(CSS)


def header(title, subtitle):
    st.title(title)
    st.html(f'<div class="page-sub">{html.escape(subtitle)}</div>')


def banner(kind, title, text=""):
    """Coloured status box. Icon and words carry the meaning, not only the colour."""
    color, icon = STATUS[kind]
    st.html(f'<div class="banner" style="--c:{color}"><b><span class="icon">{icon}</span>'
            f'{html.escape(title)}</b><div>{html.escape(text)}</div></div>')


def data_notice(ctx):
    """Tell the user how far the numbers on the page can be trusted."""
    if ctx.train_synthetic and ctx.monitor_synthetic:
        st.warning("**Synthetic sample data.** The real FlowStatsfile.csv is not in the project. "
                   "All counts and scores are demonstrations, not real-world performance.",
                   icon=":material/science:")
    elif ctx.train_synthetic:
        st.warning("**The model was trained on synthetic data** and is now applied to your "
                   "uploaded file. Its predictions for real traffic must not be trusted. Upload "
                   "labelled training data on the *Network Traffic Dataset* page.",
                   icon=":material/warning:")
    elif ctx.monitor_is_training:
        st.warning("**Monitoring uses the same file as training**, so most of these flows were "
                   "seen during training and detection looks better than it would on new "
                   "traffic. Use the *Machine Learning Models* page for held-out test scores.",
                   icon=":material/warning:")


def chart(fig, key, height=320, legend=True):
    """Apply the shared chart style and draw the figure.

    `key` must be unique on the page: two identical charts would otherwise clash.
    """
    fig.update_layout(
        height=height, margin=dict(l=8, r=8, t=36 if legend else 12, b=8),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color=MUTED, size=12), showlegend=legend,
        legend=dict(orientation="h", yanchor="bottom", y=1.02, x=0, title_text="",
                    traceorder="normal", font=dict(color=INK)),
        hoverlabel=dict(bgcolor="#17223a", font_color=INK, bordercolor=AXIS),
    )
    fig.update_xaxes(gridcolor=GRID, linecolor=AXIS, zeroline=False, automargin=True)
    fig.update_yaxes(gridcolor=GRID, linecolor=AXIS, zeroline=False, automargin=True)
    st.plotly_chart(fig, key=key, width="stretch", theme=None,
                    config={"displaylogo": False, "displayModeBar": False})


def binned(summary):
    """Group neighbouring windows when there are too many to draw one bar each.

    Returns (table, number of windows per point).
    """
    size = max(1, -(-len(summary) // MAX_POINTS))
    if size == 1:
        return summary, 1
    grouped = summary.groupby(summary.reset_index(drop=True).index // size).agg(
        window=("window", "first"), normal_flows=("normal_flows", "sum"),
        ddos_flows=("ddos_flows", "sum"), ddos_pct=("ddos_pct", "max"),
        packets=("packets", "sum"), ddos_packets=("ddos_packets", "sum"))
    return grouped, size


def stacked_bars(table, series, unit):
    """Stacked bar figure over windows. `series` is a list of (name, column, colour)."""
    dense = len(table) > DENSE_BARS
    fig = go.Figure()
    for name, column, color in series:
        # an outline would hide very thin bars completely, so it is dropped when dense
        fig.add_bar(x=table["window"], y=table[column], name=name,
                    marker=dict(color=color, line=dict(color=SURFACE, width=0 if dense else 1)),
                    hovertemplate="window %{x}<br>%{y:,} " + unit + "<extra>" + name
                    + "</extra>")
    fig.update_layout(barmode="stack", bargap=0 if dense else 0.1)
    return fig


def flows_timeline(summary, selected=None):
    """Stacked bars: flows per window split by predicted class."""
    table, size = binned(summary)
    fig = stacked_bars(table, [("Normal", "normal_flows", BLUE),
                               ("DDoS", "ddos_flows", ORANGE)], "flows")
    fig.update_xaxes(title_text=_axis_title(size))
    fig.update_yaxes(title_text="Flows")
    _mark(fig, selected)
    return fig


def share_timeline(summary, selected=None):
    """Line: percentage of flows flagged as DDoS, with the alarm threshold."""
    table, size = binned(summary)
    points = _with_breaks(table[["window", "ddos_pct"]], size)
    fig = go.Figure()
    fig.add_scatter(x=points["window"], y=points["ddos_pct"], mode="lines", name="DDoS flows %",
                    line=dict(color=ORANGE, width=2),
                    hovertemplate="window %{x}<br>%{y:.1f}% flagged<extra></extra>")
    limit = 100 - LEGIT_THRESHOLD
    fig.add_hline(y=limit, line_dash="dot", line_color=MUTED,
                  annotation_text=f"alarm at {limit:.0f}%", annotation_font_color=MUTED)
    fig.update_xaxes(title_text=_axis_title(size))
    fig.update_yaxes(title_text="DDoS flows (%)" + (", maximum" if size > 1 else ""),
                     range=[0, 105])
    _mark(fig, selected)
    return fig


def _with_breaks(points, size):
    """Add an empty point inside every long gap, so no line is drawn where no traffic was."""
    previous = points["window"].shift()
    gaps = previous[points["window"] - previous > 2 * size]
    if gaps.empty:
        return points
    breaks = pd.DataFrame({"window": gaps + size, "ddos_pct": float("nan")})
    return pd.concat([points, breaks]).sort_values("window")


def _axis_title(size):
    title = f"Window ({WINDOW_SECONDS} s each)"
    return title if size == 1 else f"{title}, {size} windows per point"


def _mark(fig, selected):
    if selected is not None:
        fig.add_vline(x=selected, line_dash="dash", line_color=INK, line_width=1)


# ---------------------------------------------------------------- window selector
def _go_to(window):
    st.session_state.window = int(window)


def _slider_moved(key, windows):
    st.session_state.window = int(windows[st.session_state[key]])


def window_picker(ctx, name):
    """Slider and buttons to choose the monitoring window. Shared between pages."""
    windows = ctx.summary["window"].tolist()
    if st.session_state.window not in windows:
        st.session_state.window = windows[0]
    position = windows.index(st.session_state.window)
    contiguous = windows == list(range(len(windows)))
    if len(windows) > 1:
        key = f"{name}_slider"
        if st.session_state.get(key) != position:    # moved by a button or another page
            st.session_state[key] = position
        label = ("Monitoring window" if contiguous else "Monitoring window (position among "
                 "windows that contain traffic)")
        st.slider(f"{label} - each is {WINDOW_SECONDS} seconds", 0, len(windows) - 1, key=key,
                  on_change=_slider_moved, args=(key, windows))
    attacks = ctx.summary.loc[ctx.summary["attack"], "window"].tolist()
    later = [w for w in attacks if w > st.session_state.window]
    with st.container(horizontal=True):
        st.button("Previous", icon=":material/chevron_left:", key=f"{name}_prev",
                  disabled=position == 0, on_click=_go_to,
                  args=(windows[max(position - 1, 0)],))
        st.button("Next", icon=":material/chevron_right:", key=f"{name}_next",
                  disabled=position == len(windows) - 1, on_click=_go_to,
                  args=(windows[min(position + 1, len(windows) - 1)],))
        st.button("Next attack window", icon=":material/crisis_alert:", key=f"{name}_attack",
                  disabled=not attacks, on_click=_go_to,
                  args=((later or attacks or [windows[0]])[0],))
    window = st.session_state.window
    start = window * WINDOW_SECONDS
    st.caption(f"Window **{window}**: seconds {start:,} to {start + WINDOW_SECONDS:,} after the "
               "first recorded flow.")
    return window
