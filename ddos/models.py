"""Training, evaluating and saving the machine learning models.

How data leakage is avoided
* identifiers (time, IPs, ports, flow id) are not features;
* all rows of one flow id go to the same side of the train/test split;
* missing-value filling and scaling are inside each Pipeline, so they are learnt
  from training rows only;
* the best model is chosen by cross-validation on the training rows, not by looking
  at the test rows.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score, precision_score,
                             recall_score)
from sklearn.model_selection import StratifiedGroupKFold, StratifiedKFold, train_test_split
from sklearn.neighbors import KNeighborsClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier

from .schema import DDOS, FEATURE_COLUMNS, LABEL, NORMAL

PRIMARY_MODEL = "Random Forest"
MODEL_NAMES = [PRIMARY_MODEL, "Decision Tree", "Logistic Regression",
               "K-Nearest Neighbors", "Support Vector Machine"]
MIN_ROWS_PER_CLASS = 10
MAX_TRAIN_ROWS = 100_000
MAX_TEST_ROWS = 100_000
# KNN and SVM become very slow on large data, so they learn from a smaller sample.
TRAIN_CAPS = {"K-Nearest Neighbors": 50_000, "Support Vector Machine": 10_000}
CV_FOLDS = 3
# StratifiedGroupKFold takes minutes with millions of flows, so a faster split is used.
MANY_FLOWS = 50_000


class ModelError(ValueError):
    """Training or loading failed for a reason the user can understand."""


@dataclass
class Evaluation:
    models: dict                 # name -> fitted Pipeline
    metrics: pd.DataFrame        # one row per model
    confusion: dict              # name -> 2x2 array [[TN, FP], [FN, TP]]
    best_name: str
    tied: list                   # models sharing the top cross-validation score
    split_method: str
    split_warning: str
    n_train: int
    n_test: int
    train_index: np.ndarray
    test_index: np.ndarray
    importances: pd.DataFrame = field(default_factory=pd.DataFrame)

    @property
    def primary(self):
        return self.models[PRIMARY_MODEL]


def feature_matrix(df):
    """The model input. Training and prediction both go through this function."""
    absent = [c for c in FEATURE_COLUMNS if c not in df.columns]
    if absent:
        raise ModelError(f"Data is missing feature column(s): {', '.join(absent)}")
    return df[FEATURE_COLUMNS].astype("float64")


def build_model(name, seed=0):
    """Return an unfitted Pipeline for one of MODEL_NAMES."""
    estimators = {
        # same settings as Codes/controller/controller.py
        "Random Forest": lambda: RandomForestClassifier(
            n_estimators=10, criterion="entropy", random_state=seed),
        "Decision Tree": lambda: DecisionTreeClassifier(criterion="entropy", random_state=seed),
        "Logistic Regression": lambda: LogisticRegression(solver="liblinear", random_state=seed),
        "K-Nearest Neighbors": lambda: KNeighborsClassifier(n_neighbors=5),
        "Support Vector Machine": lambda: SVC(kernel="rbf", random_state=seed),
    }
    if name not in estimators:
        raise ModelError(f"Unknown model: {name}")
    steps = [("fill_missing", SimpleImputer(strategy="median", keep_empty_features=True))]
    if name in ("Logistic Regression", "K-Nearest Neighbors", "Support Vector Machine"):
        steps.append(("scale", StandardScaler()))
    steps.append(("model", estimators[name]()))
    return Pipeline(steps)


def check_labels(df):
    """Raise ModelError unless both classes have enough rows to train on."""
    if LABEL not in df.columns:
        raise ModelError("Training needs a 'label' column.")
    counts = df[LABEL].value_counts()
    for value, name in ((NORMAL, "normal (0)"), (DDOS, "DDoS (1)")):
        if counts.get(value, 0) < MIN_ROWS_PER_CLASS:
            raise ModelError(f"Training needs at least {MIN_ROWS_PER_CLASS} {name} rows; "
                             f"found {int(counts.get(value, 0))}.")


def _split_many_groups(y, groups, seed):
    """Hold out 25 % of the flow ids, stratified by whether a flow has any attack row."""
    codes, unique = pd.factorize(groups)
    group_label = np.zeros(len(unique), dtype=int)
    np.maximum.at(group_label, codes, y)
    _, test_groups = train_test_split(np.arange(len(unique)), test_size=0.25,
                                      random_state=seed, stratify=group_label)
    in_test = np.zeros(len(unique), dtype=bool)
    in_test[test_groups] = True
    return np.flatnonzero(~in_test[codes]), np.flatnonzero(in_test[codes])


def split_data(df, seed=0):
    """Return (train positions, test positions, method description, warning).

    Preferred: about 25 % of rows held out, with every flow id on one side only.
    """
    y = df[LABEL].to_numpy()
    positions = np.arange(len(df))
    groups = df["flow_id"].astype(str).to_numpy()
    flows = pd.Series(groups).nunique()
    if flows >= 4:
        try:
            if flows > MANY_FLOWS:
                train, test = _split_many_groups(y, groups, seed)
            else:
                splitter = StratifiedGroupKFold(n_splits=4, shuffle=True, random_state=seed)
                train, test = next(splitter.split(positions, y, groups))
        except ValueError:      # for example only one flow of one class
            train = test = positions[:0]
        usable = all(len(np.unique(y[part])) == 2 for part in (train, test))
        if usable and 0.15 <= len(test) / len(df) <= 0.35:
            return train, test, "75 / 25 split grouped by flow id and stratified by label", ""
    train, test = train_test_split(positions, test_size=0.25, random_state=seed, stratify=y)
    return (train, test, "75 / 25 split stratified by label (rows)",
            "A flow-grouped split was not possible for this data (too few distinct flows), so "
            "rows of one flow may be in both parts. Scores may be optimistic.")


def _sample(positions, y, limit, seed):
    """Stratified sub-sample of `positions` when there are more than `limit`."""
    if len(positions) <= limit:
        return positions
    chosen, _ = train_test_split(positions, train_size=limit, random_state=seed,
                                 stratify=y[positions])
    return chosen


def _cross_validate(name, X, y, groups, seed):
    """Mean F1 over folds of the training data (NaN when folds cannot be built)."""
    if pd.Series(groups).nunique() >= CV_FOLDS * 2:
        folds = StratifiedGroupKFold(CV_FOLDS, shuffle=True, random_state=seed).split(X, y, groups)
    else:
        folds = StratifiedKFold(CV_FOLDS, shuffle=True, random_state=seed).split(X, y)
    scores = []
    for fit_part, score_part in folds:
        if len(np.unique(y[fit_part])) < 2:
            continue
        model = build_model(name, seed).fit(X.iloc[fit_part], y[fit_part])
        scores.append(f1_score(y[score_part], model.predict(X.iloc[score_part]),
                               zero_division=0))
    return float(np.mean(scores)) if scores else float("nan")


def train_and_evaluate(df, seed=0, names=MODEL_NAMES):
    """Train every model on the same split and measure it on the held-out rows."""
    check_labels(df)
    X = feature_matrix(df)
    y = df[LABEL].to_numpy().astype(int)
    groups = df["flow_id"].astype(str).to_numpy()
    train, test, method, warning = split_data(df, seed)
    train = _sample(train, y, MAX_TRAIN_ROWS, seed)
    test = _sample(test, y, MAX_TEST_ROWS, seed)

    models, rows, confusion = {}, [], {}
    for name in names:
        use = _sample(train, y, TRAIN_CAPS.get(name, MAX_TRAIN_ROWS), seed)
        cv_f1 = _cross_validate(name, X.iloc[use], y[use], groups[use], seed)
        model = build_model(name, seed).fit(X.iloc[use], y[use])
        pred = model.predict(X.iloc[test])
        models[name] = model
        confusion[name] = confusion_matrix(y[test], pred, labels=[NORMAL, DDOS])
        tn, fp = confusion[name][0]
        rows.append({
            "Model": name,
            "Accuracy": accuracy_score(y[test], pred),
            "Precision": precision_score(y[test], pred, zero_division=0),
            "Recall": recall_score(y[test], pred, zero_division=0),
            "F1-score": f1_score(y[test], pred, zero_division=0),
            "False alarm rate": fp / (tn + fp) if tn + fp else 0.0,
            "CV F1 (training data)": cv_f1,
            "Training rows": len(use),
        })
    metrics = pd.DataFrame(rows)

    ranking = metrics["CV F1 (training data)"]
    if ranking.isna().all():
        ranking = metrics["F1-score"]
    top = ranking.max()
    tied = metrics.loc[(ranking - top).abs() < 5e-4, "Model"].tolist()
    best = PRIMARY_MODEL if PRIMARY_MODEL in tied else tied[0]

    importances = pd.DataFrame()
    if PRIMARY_MODEL in models:
        forest = models[PRIMARY_MODEL].named_steps["model"]
        importances = (pd.DataFrame({"Feature": FEATURE_COLUMNS,
                                     "Importance": forest.feature_importances_})
                       .sort_values("Importance", ascending=False, ignore_index=True))

    return Evaluation(models=models, metrics=metrics, confusion=confusion, best_name=best,
                      tied=tied, split_method=method, split_warning=warning,
                      n_train=len(train), n_test=len(test), train_index=train,
                      test_index=test, importances=importances)


def model_bundle(model, name, data_source, synthetic):
    """Everything needed to use a saved model safely later."""
    return {
        "model": model,
        "name": name,
        "features": list(FEATURE_COLUMNS),
        "data_source": data_source,
        "synthetic": bool(synthetic),
        "sklearn_version": sklearn.__version__,
        "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def save_model(bundle, target):
    """Write a model bundle to a path or file object."""
    joblib.dump(bundle, target)


def load_model(path):
    """Load a bundle written by save_model.

    Only open model files you created yourself: loading a pickle file can run code.
    """
    try:
        bundle = joblib.load(path)
    except FileNotFoundError as exc:
        raise ModelError(f"Model file not found: {path}") from exc
    except Exception as exc:  # unpickling can fail in many ways
        raise ModelError(f"Could not load the model file: {exc}") from exc
    if not isinstance(bundle, dict) or "model" not in bundle:
        raise ModelError("This file is not a model saved by this project.")
    if bundle.get("features") != FEATURE_COLUMNS:
        raise ModelError("The saved model uses a different feature list. Train it again.")
    if bundle.get("sklearn_version") != sklearn.__version__:
        raise ModelError(f"Model was saved with scikit-learn {bundle.get('sklearn_version')}, "
                         f"installed is {sklearn.__version__}. Train it again.")
    return bundle
