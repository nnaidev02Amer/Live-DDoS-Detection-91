"""Machine Learning Models: compare five classifiers on the same held-out data."""
import io

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

import state
import ui
from ddos import models
from ddos.schema import CLASS_NAMES, EXCLUDED_FEATURES, FEATURE_COLUMNS, LABEL

SCORES = ["Accuracy", "Precision", "Recall", "F1-score"]


def render():
    ui.header("Machine Learning Models",
              "Five classifiers trained and tested on exactly the same split.")
    ctx = state.get_context()
    result = ctx.evaluation

    if ctx.train_synthetic:
        st.warning("**These are SYNTHETIC test results.** Normal and attack flows were "
                   "generated from clearly different number ranges, so near-perfect scores are "
                   "expected. They are **not** real-world accuracy.", icon=":material/science:")
    else:
        st.info(f"Results on the uploaded file **{ctx.train_name}**. They describe this "
                "dataset only; traffic from another network can give different results.",
                icon=":material/database:")
    if result.split_warning:
        st.warning(result.split_warning, icon=":material/warning:")

    best = result.metrics.set_index("Model").loc[result.best_name]
    a, b, c, d = st.columns(4)
    a.metric("Selected best model", result.best_name, border=True)
    b.metric("Its test F1-score", f"{best['F1-score']:.2%}", border=True)
    c.metric("Training rows", f"{result.n_train:,}", border=True)
    d.metric("Held-out test rows", f"{result.n_test:,}", border=True)
    if len(result.tied) > 1:
        st.caption(f"**Tie:** {', '.join(result.tied)} have the same cross-validation F1-score "
                   "(within 0.05 points). When Random Forest is among them it is chosen, as it "
                   "is the project's primary model.")
    else:
        st.caption("Chosen by the highest cross-validation F1-score on the training data.")
    if result.best_name != models.PRIMARY_MODEL:
        st.info(f"{result.best_name} scored higher than Random Forest on this data. Detection "
                f"in this dashboard still uses the primary model, {models.PRIMARY_MODEL}.")

    st.subheader("Model comparison (held-out test data)")
    fig = go.Figure()
    for score, color in zip(SCORES, [ui.BLUE, ui.ORANGE, ui.AQUA, ui.YELLOW]):
        fig.add_bar(x=result.metrics["Model"], y=result.metrics[score] * 100, name=score,
                    marker=dict(color=color, line=dict(color=ui.SURFACE, width=1)),
                    hovertemplate="%{x}<br>%{y:.2f}%<extra>" + score + "</extra>")
    fig.update_layout(barmode="group", bargap=0.25)
    fig.update_yaxes(title_text="Score (%)", range=[0, 102])
    ui.chart(fig, "model_comparison", height=360)
    st.caption("Each group is one model. Taller bars are better.")

    table = result.metrics.copy()
    percent = SCORES + ["False alarm rate", "CV F1 (training data)"]
    table[percent] = table[percent] * 100
    st.dataframe(table, hide_index=True, width="stretch", column_config={
        name: st.column_config.NumberColumn(format="%.2f %%") for name in percent})
    st.download_button("Download results (CSV)", lambda: table.to_csv(index=False),
                       "model_comparison.csv", "text/csv", icon=":material/download:",
                       on_click="ignore")
    with st.expander("What do these measures mean?"):
        st.markdown("""
| Measure | Question it answers |
|---|---|
| **Accuracy** | What share of all flows was classified correctly? |
| **Precision** | When the model says *DDoS*, how often is it right? |
| **Recall** | Of all real attack flows, how many were found? |
| **F1-score** | One number balancing precision and recall. |
| **False alarm rate** | What share of normal flows was wrongly called DDoS? |
| **CV F1** | Average F1 over 3 folds of the training data, used to pick the best model. |
""")

    left, right = st.columns(2)
    with left:
        st.subheader("Confusion matrix")
        names = result.metrics["Model"].tolist()
        name = st.selectbox("Model", names, index=names.index(result.best_name))
        matrix = result.confusion[name]
        labels = [CLASS_NAMES[0], CLASS_NAMES[1]]
        fig = go.Figure(go.Heatmap(
            z=matrix, x=[f"Predicted {n}" for n in labels], y=[f"Actual {n}" for n in labels],
            text=matrix, texttemplate="%{text:,}", textfont=dict(size=18, color="#ffffff"),
            colorscale=[[0, "#132038"], [1, "#1b64be"]], showscale=False, xgap=2, ygap=2,
            hovertemplate="%{y}, %{x}: %{z:,}<extra></extra>"))
        fig.update_yaxes(autorange="reversed")
        ui.chart(fig, "model_confusion", height=320, legend=False)
        tn, fp, fn, tp = matrix.ravel()
        st.caption(f"Correct: {tn:,} normal and {tp:,} attack flows. Wrong: {fp:,} false "
                   f"alarms and {fn:,} missed attacks.")
    with right:
        st.subheader("What Random Forest looks at")
        importances = result.importances.iloc[::-1]
        fig = go.Figure(go.Bar(
            x=importances["Importance"], y=importances["Feature"], orientation="h",
            marker_color=ui.BLUE, hovertemplate="%{y}: %{x:.3f}<extra></extra>"))
        fig.update_xaxes(title_text="Importance (all features add up to 1)")
        ui.chart(fig, "model_importance", height=400, legend=False)
        st.caption("A longer bar means that measurement helps the model more in deciding.")

    if ctx.train_synthetic:
        st.subheader("Why are the synthetic scores so high?")
        columns = ["packet_count", "byte_count", "flow_duration_sec", "packet_count_per_second"]
        grouped = ctx.train_df.groupby(LABEL)[columns].agg(["min", "max"])
        ranges = pd.DataFrame({
            "Feature": columns,
            **{f"{CLASS_NAMES[k]} (min - max)": [
                f"{grouped.loc[k, (c, 'min')]:,.0f} - {grouped.loc[k, (c, 'max')]:,.0f}"
                for c in columns] for k in (0, 1)},
        })
        st.dataframe(ranges, hide_index=True, width="stretch")
        st.markdown("The packet counts of the two classes **do not overlap at all**, so one "
                    "simple threshold separates them. Real traffic is much harder: heavy "
                    "downloads look like floods and slow attacks look normal.")

    st.subheader("Method")
    st.markdown(f"""
- **Split:** {result.split_method}. Random seed {st.session_state.seed}, so results repeat.
- **Preprocessing:** missing values are filled with the training median; Logistic Regression,
  KNN and SVM also use standard scaling. Both steps learn from training rows only.
- **Features used ({len(FEATURE_COLUMNS)}):** {', '.join(f'`{c}`' for c in FEATURE_COLUMNS)}.
- **Large files:** at most {models.MAX_TRAIN_ROWS:,} training and {models.MAX_TEST_ROWS:,} test
  rows are sampled; KNN uses at most {models.TRAIN_CAPS['K-Nearest Neighbors']:,} and SVM
  {models.TRAIN_CAPS['Support Vector Machine']:,} training rows.
""")
    with st.expander("Features deliberately left out, and why"):
        st.dataframe(pd.DataFrame(EXCLUDED_FEATURES.items(), columns=["Column", "Reason"]),
                     hide_index=True, width="stretch")

    def saved_model():
        buffer = io.BytesIO()
        models.save_model(models.model_bundle(result.primary, models.PRIMARY_MODEL,
                                              ctx.train_name, ctx.train_synthetic), buffer)
        return buffer.getvalue()

    st.download_button("Download the trained Random Forest (.joblib)", saved_model,
                       "random_forest.joblib", "application/octet-stream",
                       icon=":material/save:", on_click="ignore")
    st.caption("The file stores the pipeline, feature list, data source and library version. "
               "Only load model files that you created yourself.")
