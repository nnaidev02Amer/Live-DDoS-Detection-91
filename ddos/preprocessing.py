"""Reading, validating and cleaning flow statistic CSV files.

Rule followed everywhere: missing columns or labels are reported, never invented.
"""
import ipaddress
from dataclasses import dataclass, field

import numpy as np
import pandas as pd

from .schema import (ESSENTIAL_COLUMNS, FEATURE_COLUMNS, INPUT_COLUMNS, IP_COLUMNS, LABEL,
                     NUMERIC_COLUMNS, SIGNED_COLUMNS)

MISSING_DROP = "drop"   # remove rows with a missing feature value
MISSING_KEEP = "keep"   # keep them; the model pipeline fills them with the training median


class DatasetError(ValueError):
    """The file cannot be used. The message is meant to be shown to the user."""


@dataclass
class CleanResult:
    data: pd.DataFrame
    has_labels: bool
    rows_in: int
    dropped: dict = field(default_factory=dict)        # reason -> number of rows
    missing: dict = field(default_factory=dict)        # column -> missing/invalid cells
    extra_columns: list = field(default_factory=list)  # ignored columns
    duplicate_rows: int = 0

    @property
    def rows_out(self):
        return len(self.data)


def read_csv(source):
    """Read a path or file-like object and turn parser errors into DatasetError."""
    try:
        return pd.read_csv(source, low_memory=False)
    except pd.errors.EmptyDataError as exc:
        raise DatasetError("The file is empty.") from exc
    except UnicodeDecodeError as exc:
        raise DatasetError("The file is not a text CSV (could not decode it as UTF-8).") from exc
    except pd.errors.ParserError as exc:
        raise DatasetError(f"The file is not a well formed CSV: {exc}") from exc
    except FileNotFoundError as exc:
        raise DatasetError(f"File not found: {source}") from exc


def check_columns(df):
    """Return (missing required columns, extra columns, label present)."""
    names = [str(c).strip() for c in df.columns]
    missing = [c for c in INPUT_COLUMNS if c not in names]
    extra = [c for c in names if c not in INPUT_COLUMNS and c != LABEL]
    return missing, extra, LABEL in names


def _valid_ipv4(series):
    """Keep valid IPv4 text, replace everything else with a missing value."""
    text = series.astype("string").str.strip()
    good = []
    for value in text.dropna().unique():
        try:
            ipaddress.IPv4Address(value)
            good.append(value)
        except ValueError:
            pass
    return text.where(text.isin(good))


def clean_flows(raw, missing=MISSING_DROP, require_label=False):
    """Validate a raw flow table and return a CleanResult.

    Raises DatasetError when the table cannot be used at all.
    """
    if missing not in (MISSING_DROP, MISSING_KEEP):
        raise ValueError(f"unknown missing-value option: {missing}")
    df = raw.rename(columns=lambda c: str(c).strip())
    absent, extra, has_label = check_columns(df)
    if absent:
        hint = ""
        if len(absent) == len(INPUT_COLUMNS):
            hint = " No expected column was found - is the header row missing?"
        raise DatasetError(f"Missing required column(s): {', '.join(absent)}.{hint}")
    if require_label and not has_label:
        raise DatasetError("Training data needs a 'label' column (0 = normal, 1 = DDoS).")
    if df.empty:
        raise DatasetError("The file has a header but no data rows.")

    rows_in = len(df)
    df = df[INPUT_COLUMNS + ([LABEL] if has_label else [])].copy()

    for col in NUMERIC_COLUMNS:
        values = pd.to_numeric(df[col], errors="coerce").astype("float64")
        values = values.where(np.isfinite(values))
        if col not in SIGNED_COLUMNS:
            values = values.where(values >= 0)
        df[col] = values
    for col in IP_COLUMNS:
        df[col] = _valid_ipv4(df[col])
    flow_id = df["flow_id"].astype("string").str.strip()
    df["flow_id"] = flow_id.where(flow_id != "")

    if has_label:
        label = pd.to_numeric(df[LABEL], errors="coerce")
        df[LABEL] = label.where(label.isin([0, 1]))
        if df[LABEL].isna().all():
            raise DatasetError("The 'label' column has no usable value. Use 0 = normal and "
                               "1 = DDoS.")

    missing_cells = {c: int(n) for c, n in df.isna().sum().items() if n}

    dropped = {}

    def drop_rows(mask, reason):
        nonlocal df
        count = int(mask.sum())
        if count:
            dropped[reason] = count
            df = df[~mask]

    drop_rows(df[ESSENTIAL_COLUMNS].isna().any(axis=1),
              "missing or invalid identifier (time, switch, flow, IP or protocol)")
    if has_label:
        drop_rows(df[LABEL].isna(), "missing or invalid label")
    if missing == MISSING_DROP:
        drop_rows(df[FEATURE_COLUMNS].isna().any(axis=1), "missing or invalid feature value")

    if df.empty:
        raise DatasetError("No usable rows remain after cleaning: " +
                           "; ".join(f"{n} rows with {r}" for r, n in dropped.items()))

    for col in ["datapath_id", "ip_proto"] + ([LABEL] if has_label else []):
        df[col] = df[col].astype("int64")
    for col in ["flow_id"] + IP_COLUMNS:
        df[col] = df[col].astype(str)
    df = df.reset_index(drop=True)

    return CleanResult(data=df, has_labels=has_label, rows_in=rows_in, dropped=dropped,
                       missing=missing_cells, extra_columns=extra,
                       duplicate_rows=int(df.duplicated().sum()))


def load_flows(source, missing=MISSING_DROP, require_label=False):
    """Read and clean in one step."""
    return clean_flows(read_csv(source), missing=missing, require_label=require_label)
