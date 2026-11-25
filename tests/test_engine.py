"""Tests of the engine (no Streamlit needed).

Run from the project folder:  python -m unittest discover -s tests -v
"""
import contextlib
import io
import tempfile
import unittest
from pathlib import Path

import numpy as np
import pandas as pd

from ddos import detection, mitigation, models, preprocessing, sample_data, schema, sdn
from ddos.__main__ import main as cli


def as_csv(df):
    return io.StringIO(df.to_csv(index=False))


class Shared(unittest.TestCase):
    """Train once and reuse in every test class."""

    @classmethod
    def setUpClass(cls):
        if not hasattr(Shared, "evaluation"):
            Shared.train = sample_data.training_sample(0)
            Shared.timeline = sample_data.timeline_sample(0)
            Shared.evaluation = models.train_and_evaluate(Shared.train)
            Shared.scored = detection.score_flows(Shared.evaluation.primary, Shared.timeline)
            Shared.summary = detection.summarize_windows(Shared.scored)


class SampleDataTests(unittest.TestCase):
    def test_columns_and_reproducibility(self):
        first, second = sample_data.training_sample(3), sample_data.training_sample(3)
        self.assertEqual(list(first.columns), schema.COLUMNS)
        pd.testing.assert_frame_equal(first, second)


class PreprocessingTests(unittest.TestCase):
    def setUp(self):
        self.df = sample_data.make_flows(300, 5)

    def test_valid_file(self):
        result = preprocessing.load_flows(as_csv(self.df), require_label=True)
        self.assertEqual(result.rows_out, 300)
        self.assertTrue(result.has_labels)
        self.assertEqual(result.dropped, {})

    def test_unlabelled_file_is_allowed_for_monitoring_only(self):
        unlabelled = self.df.drop(columns="label")
        self.assertFalse(preprocessing.load_flows(as_csv(unlabelled)).has_labels)
        with self.assertRaisesRegex(preprocessing.DatasetError, "label"):
            preprocessing.load_flows(as_csv(unlabelled), require_label=True)

    def test_missing_column_is_reported_not_invented(self):
        with self.assertRaisesRegex(preprocessing.DatasetError, "packet_count"):
            preprocessing.load_flows(as_csv(self.df.drop(columns="packet_count")))

    def test_bad_files(self):
        cases = {
            "empty": io.StringIO(""),
            "header only": io.StringIO(",".join(schema.COLUMNS) + "\n"),
            "other csv": io.StringIO("a,b\n1,2\n"),
            "binary": io.BytesIO(b"\x89PNG\r\n\x1a\n\x00\xff\xfe\x00" * 20),
        }
        for name, source in cases.items():
            with self.subTest(name), self.assertRaises(preprocessing.DatasetError):
                preprocessing.load_flows(source)

    def test_wrong_label_values(self):
        bad = self.df.assign(label="attack")
        with self.assertRaisesRegex(preprocessing.DatasetError, "label"):
            preprocessing.load_flows(as_csv(bad))

    def test_missing_and_invalid_values(self):
        dirty = self.df.astype({"packet_count": object, "ip_src": object,
                                "label": object}).copy()
        dirty.loc[0, "packet_count"] = "many"     # invalid feature
        dirty.loc[1, "byte_count"] = np.nan       # missing feature
        dirty.loc[2, "ip_src"] = "<script>"       # invalid identifier
        dirty.loc[3, "label"] = 7                 # invalid label
        dirty.loc[4, "byte_count"] = -5           # impossible value
        dropped = preprocessing.load_flows(as_csv(dirty), missing="drop")
        self.assertEqual(dropped.rows_out, 295)
        kept = preprocessing.load_flows(as_csv(dirty), missing="keep")
        self.assertEqual(kept.rows_out, 298)      # identifier and label rows still removed
        self.assertEqual(int(kept.data["packet_count"].isna().sum()), 1)
        self.assertEqual(int(kept.data["byte_count"].isna().sum()), 2)

    def test_extra_columns_and_spaces_in_header(self):
        renamed = self.df.rename(columns={"ip_src": " ip_src "}).assign(note="x")
        result = preprocessing.load_flows(as_csv(renamed))
        self.assertEqual(result.extra_columns, ["note"])
        self.assertNotIn("note", result.data.columns)


class ModelTests(Shared):
    def test_five_models_with_all_metrics(self):
        metrics = self.evaluation.metrics
        self.assertEqual(metrics["Model"].tolist(), models.MODEL_NAMES)
        for column in ["Accuracy", "Precision", "Recall", "F1-score"]:
            self.assertTrue(metrics[column].between(0, 1).all(), column)
        for name in models.MODEL_NAMES:
            self.assertEqual(self.evaluation.confusion[name].sum(), self.evaluation.n_test)

    def test_no_flow_is_in_both_train_and_test(self):
        flows = self.train["flow_id"].to_numpy()
        self.assertFalse(set(flows[self.evaluation.train_index]) &
                         set(flows[self.evaluation.test_index]))

    def test_large_data_split_keeps_flows_together(self):
        data = self.train.copy()
        data["flow_id"] = (np.arange(len(data)) // 3).astype(str)     # 3 rows per flow
        original = models.MANY_FLOWS
        models.MANY_FLOWS = 10
        try:
            train, test, _, warning = models.split_data(data)
        finally:
            models.MANY_FLOWS = original
        self.assertEqual(warning, "")
        self.assertEqual(len(train) + len(test), len(data))
        flows = data["flow_id"].to_numpy()
        self.assertFalse(set(flows[train]) & set(flows[test]))
        self.assertAlmostEqual(len(test) / len(data), 0.25, delta=0.02)

    def test_too_few_flows_falls_back_with_a_warning(self):
        data = self.train.assign(flow_id="same")
        self.assertTrue(models.split_data(data)[3])

    def test_identifiers_are_not_features(self):
        for column in ["timestamp", "flow_id", "ip_src", "ip_dst", "datapath_id", "label"]:
            self.assertNotIn(column, schema.FEATURE_COLUMNS)

    def test_changing_identifiers_does_not_change_predictions(self):
        changed = self.timeline.assign(ip_src="192.0.2.1", ip_dst="192.0.2.2", timestamp=1.0,
                                       flow_id="x", datapath_id=99)
        model = self.evaluation.primary
        np.testing.assert_array_equal(model.predict(models.feature_matrix(self.timeline)),
                                      model.predict(models.feature_matrix(changed)))

    def test_reproducible(self):
        again = models.train_and_evaluate(self.train)
        pd.testing.assert_frame_equal(again.metrics, self.evaluation.metrics)

    def test_too_few_rows_or_one_class(self):
        for data in (self.train[self.train["label"] == 0], self.train.head(5)):
            with self.assertRaises(models.ModelError):
                models.train_and_evaluate(data)

    def test_save_and_load(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "model.joblib"
            models.save_model(models.model_bundle(self.evaluation.primary, "Random Forest",
                                                  "test", True), path)
            loaded = models.load_model(path)
            X = models.feature_matrix(self.timeline)
            np.testing.assert_array_equal(loaded["model"].predict(X),
                                          self.evaluation.primary.predict(X))
            path.write_bytes(b"not a model")
            with self.assertRaises(models.ModelError):
                models.load_model(path)


class DetectionTests(Shared):
    def window(self, number):
        return self.summary.set_index("window").loc[number]

    def test_attack_window_matches_previous_dashboard(self):
        row = self.window(25)
        self.assertEqual(int(row["flows"]), 109)
        self.assertEqual(round(row["legit_pct"]), 17)
        self.assertTrue(row["attack"])
        self.assertEqual(detection.host_name(row["victim_ip"]), "h1")

    def test_normal_window_matches_previous_dashboard(self):
        row = self.window(5)
        self.assertEqual(int(row["flows"]), 107)
        self.assertEqual(round(row["legit_pct"]), 96)
        self.assertFalse(row["attack"])
        self.assertTrue(pd.isna(row["victim_ip"]))

    def test_attack_burst(self):
        # The burst is planned for windows 20-34. Flows are assigned by position while
        # arrival times are random, so its tail also makes window 35 a real attack window.
        attacks = self.summary.loc[self.summary["attack"], "window"].tolist()
        self.assertEqual(attacks, list(range(20, 36)))
        episodes = detection.attack_episodes(self.summary)
        self.assertEqual(episodes[["first_window", "last_window"]].values.tolist(), [[20, 35]])

    def test_window_verdicts_match_synthetic_labels(self):
        self.assertTrue((self.summary["attack"] == self.summary["true_attack"]).all())

    def test_threshold(self):
        self.assertTrue(detection.is_attack(80.0))
        self.assertFalse(detection.is_attack(80.1))

    def test_host_name(self):
        self.assertEqual(detection.host_name("10.0.0.18"), "h18")
        self.assertEqual(detection.host_name("10.0.0.200"), "10.0.0.200")
        self.assertEqual(detection.host_name("192.168.1.1"), "192.168.1.1")


class MitigationTests(Shared):
    def window_flows(self, number):
        return self.scored[self.scored["window"] == number]

    def test_rules_only_for_flagged_flows(self):
        flows = self.window_flows(25)
        proposed = mitigation.propose_rules(flows)
        self.assertEqual(proposed["flows"].sum(), (flows["predicted"] == 1).sum())

    def test_install_expire_and_log(self):
        engine = mitigation.MitigationEngine()
        added = engine.apply_window(self.window_flows(25), 25)
        self.assertTrue(added)
        self.assertEqual(engine.apply_window(self.window_flows(25), 25), [])
        matched = engine.matched_flows(self.scored)
        self.assertTrue(matched["window"].between(26, 37).all())
        engine.expire(37)
        self.assertEqual(len(engine.controller.list_rules()), len(added))
        engine.expire(38)
        self.assertEqual(engine.controller.list_rules(), [])
        self.assertIn("Rule expired", {e["event"] for e in engine.events})
        self.assertTrue(all(e["mode"] == "SIMULATED" for e in engine.events))

    def test_remove_and_clear(self):
        engine = mitigation.MitigationEngine()
        added = engine.apply_window(self.window_flows(25), 25)
        engine.remove(added[0])
        self.assertEqual(len(engine.controller.list_rules()), len(added) - 1)
        engine.clear()
        self.assertEqual(engine.controller.list_rules(), [])
        self.assertTrue(engine.matched_flows(self.scored).empty)

    def test_replay_matches_a_direct_calculation(self):
        result = mitigation.replay(self.scored, self.summary)
        active, blocked = {}, 0
        attack = set(self.summary.loc[self.summary["attack"], "window"])
        for window, flows in self.scored.groupby("window"):
            keys = list(flows[mitigation.RULE_FIELDS].itertuples(index=False, name=None))
            live = {k for k, last in active.items() if last >= window}
            blocked += sum(k in live for k in keys)
            if window in attack:
                for key, predicted in zip(keys, flows["predicted"]):
                    if predicted == 1 and key not in live:
                        active[key] = window + 12
        self.assertEqual(result.totals["blocked_flows"], blocked)
        self.assertGreater(blocked, 0)
        before = result.per_window[result.per_window["window"] <= 20]
        self.assertEqual(before["blocked_flows"].sum(), 0)
        self.assertEqual(result.totals["attack_flows_blocked"] +
                         result.totals["normal_flows_blocked"], blocked)

    def test_controller_is_simulated_and_message_format(self):
        controller = sdn.SimulatedController()
        self.assertFalse(controller.is_live)
        rule = sdn.FlowRule(1, "10.0.0.5", "10.0.0.1", 6)
        entry = sdn.to_ryu_flow_entry(rule)
        self.assertEqual(entry["actions"], [])
        self.assertEqual(entry["match"]["ipv4_src"], "10.0.0.5")
        self.assertIn("add-flow s1", sdn.to_ovs_command(rule))


class CommandLineTests(unittest.TestCase):
    def test_sample_train_predict(self):
        with tempfile.TemporaryDirectory() as folder, contextlib.redirect_stdout(io.StringIO()):
            root = Path(folder)
            self.assertEqual(cli(["sample", "--out", folder]), 0)
            model = str(root / "rf.joblib")
            self.assertEqual(cli(["train", "--data", str(root / "synthetic_FlowStatsfile.csv"),
                                  "--out", model]), 0)
            output = root / "predictions.csv"
            self.assertEqual(cli(["predict", "--model", model, "--data",
                                  str(root / "synthetic_monitor.csv"), "--out", str(output)]), 0)
            self.assertEqual(len(pd.read_csv(output)), sample_data.TIMELINE_FLOWS)
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(cli(["train", "--data", str(root / "none.csv")]), 1)


if __name__ == "__main__":
    unittest.main()
