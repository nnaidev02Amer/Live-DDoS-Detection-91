"""Session state and cached heavy work shared by all pages."""
from dataclasses import dataclass

import pandas as pd
import streamlit as st

from ddos import detection, models, sample_data
from ddos.mitigation import MitigationEngine
from ddos.schema import LABEL
from ddos.sdn import SimulatedController

SYNTHETIC_DEFAULT_WINDOW = 25   # inside the synthetic attack burst (windows 20-34)


@dataclass
class Upload:
    """A cleaned CSV file the user chose to use."""
    name: str
    data: pd.DataFrame
    key: str            # changes when the file or the cleaning option changes
    digest: str         # identifies the file content


@dataclass
class Context:
    key: str
    train_df: pd.DataFrame
    train_name: str
    train_synthetic: bool
    monitor_df: pd.DataFrame
    monitor_name: str
    monitor_synthetic: bool
    monitor_is_training: bool
    evaluation: models.Evaluation
    scored: pd.DataFrame
    summary: pd.DataFrame

    @property
    def monitor_has_labels(self):
        return LABEL in self.monitor_df.columns


def init_state():
    defaults = {"seed": 0, "train_upload": None, "monitor_upload": None, "window": None,
                "engine": None, "engine_key": None, "replay": None}
    for name, value in defaults.items():
        st.session_state.setdefault(name, value)


@st.cache_data(max_entries=4, show_spinner=False)
def synthetic_data(seed):
    return sample_data.training_sample(seed), sample_data.timeline_sample(seed)


@st.cache_resource(max_entries=4, show_spinner="Training and testing the five models...")
def _evaluate(key, _train_df, seed):
    return models.train_and_evaluate(_train_df, seed=seed)


@st.cache_resource(max_entries=4, show_spinner="Classifying network flows...")
def _detect(key, _model, _monitor_df):
    scored = detection.score_flows(_model, _monitor_df)
    return scored, detection.summarize_windows(scored)


def get_context():
    """Data, trained models and detection results for the current choice of files.

    The returned tables are shared between reruns: pages must not modify them.
    """
    seed = int(st.session_state.seed)
    train_up = st.session_state.train_upload
    monitor_up = st.session_state.monitor_upload

    if train_up is None:
        train_df, timeline = synthetic_data(seed)
        train_name, train_key = "Synthetic training sample", f"synthetic:{seed}"
    else:
        train_df, train_name, train_key = train_up.data, train_up.name, train_up.key

    if monitor_up is not None:
        monitor_df, monitor_name, monitor_key = monitor_up.data, monitor_up.name, monitor_up.key
        monitor_synthetic = False
        same = train_up is not None and monitor_up.digest == train_up.digest
    elif train_up is not None:
        monitor_df, monitor_name, monitor_key = train_df, train_name, train_key
        monitor_synthetic, same = False, True
    else:
        monitor_df, monitor_name = timeline, "Synthetic 10-minute timeline"
        monitor_key, monitor_synthetic, same = f"timeline:{seed}", True, False

    try:
        evaluation = _evaluate(train_key, train_df, seed)
        key = f"{train_key}|{monitor_key}|{seed}"
        scored, summary = _detect(key, evaluation.primary, monitor_df)
    except (models.ModelError, ValueError, MemoryError) as exc:
        st.error(f"The selected data could not be processed: {exc}")
        st.button("Return to the synthetic sample", on_click=reset_to_synthetic, type="primary")
        st.stop()

    if st.session_state.engine_key != key:      # new data: old rules and results are void
        st.session_state.engine = MitigationEngine(SimulatedController())
        st.session_state.engine_key = key
        st.session_state.replay = None
        st.session_state.window = _default_window(summary, monitor_synthetic)

    return Context(key=key, train_df=train_df, train_name=train_name,
                   train_synthetic=train_up is None, monitor_df=monitor_df,
                   monitor_name=monitor_name, monitor_synthetic=monitor_synthetic,
                   monitor_is_training=same, evaluation=evaluation, scored=scored,
                   summary=summary)


def _default_window(summary, synthetic):
    windows = summary["window"].tolist()
    if synthetic and SYNTHETIC_DEFAULT_WINDOW in windows:
        return SYNTHETIC_DEFAULT_WINDOW
    attacks = summary.loc[summary["attack"], "window"].tolist()
    return int(attacks[0] if attacks else windows[0])


def reset_to_synthetic():
    st.session_state.train_upload = None
    st.session_state.monitor_upload = None


def set_seed():
    st.session_state.seed = int(st.session_state.seed_input)
