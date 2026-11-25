"""Tests of the dashboard pages using Streamlit's built-in test runner."""
import sys
import unittest
from pathlib import Path

import pandas as pd
from streamlit.testing.v1 import AppTest

ROOT = Path(__file__).resolve().parents[1]
PAGES = ["overview", "detection", "models", "dataset", "mitigation", "about"]


def page_script(name):
    """Small script that renders one page the way app.py does."""
    return f"""
import sys
for folder in (r"{ROOT}", r"{ROOT / 'dashboard'}"):
    if folder not in sys.path:
        sys.path.insert(0, folder)
import state
from views import {name}
state.init_state()
{name}.render()
"""


def open_page(name):
    return AppTest.from_string(page_script(name), default_timeout=120).run()


def metrics(app):
    return {m.label: m.value for m in app.metric}


def button(app, label):
    return next(b for b in app.button if b.label.startswith(label))


class DashboardTests(unittest.TestCase):
    def assert_clean(self, app):
        self.assertEqual([e.value for e in app.exception], [])
        self.assertEqual([e.value for e in app.error], [])

    def test_full_app_starts(self):
        app = AppTest.from_file(str(ROOT / "dashboard" / "app.py"), default_timeout=120).run()
        self.assert_clean(app)
        self.assertEqual(app.title[0].value, "Overview Dashboard")

    def test_every_page_renders(self):
        for name in PAGES:
            with self.subTest(page=name):
                self.assert_clean(open_page(name))

    def test_overview_numbers(self):
        shown = metrics(open_page("overview"))
        self.assertEqual(shown["Total network flows"], "6,000")
        self.assertEqual(shown["Windows under attack"], "16 / 60")

    def test_attack_and_normal_windows(self):
        app = open_page("detection")
        shown = metrics(app)
        self.assertEqual((shown["Flows in window"], shown["Legitimate flows"],
                          shown["Victim host"]), ("109", "17 %", "h1"))
        app.slider[0].set_value(5).run()
        shown = metrics(app)
        self.assertEqual((shown["Flows in window"], shown["Legitimate flows"],
                          shown["Victim host"]), ("107", "96 %", "-"))
        button(app, "Next attack window").click().run()
        self.assertEqual(app.session_state["window"], 20)
        button(app, "Previous").click().run()
        self.assertEqual(app.session_state["window"], 19)
        self.assert_clean(app)

    def test_model_page_has_five_models_and_synthetic_warning(self):
        app = open_page("models")
        self.assertEqual(len(app.selectbox[0].options), 5)
        self.assertTrue(any("SYNTHETIC" in w.value for w in app.warning))
        app.selectbox[0].set_value("Support Vector Machine").run()
        self.assert_clean(app)

    def test_mitigation_install_remove_replay_and_log(self):
        app = open_page("mitigation")
        self.assertEqual(metrics(app)["Installed rules"], "0")
        button(app, "Install").click().run()
        installed = int(metrics(app)["Installed rules"].replace(",", ""))
        self.assertGreater(installed, 0)
        self.assertNotEqual(metrics(app)["Packets blocked (simulated)"], "0")
        button(app, "Remove selected rule").click().run()
        self.assertEqual(int(metrics(app)["Installed rules"].replace(",", "")), installed - 1)
        button(app, "Remove all rules").click().run()
        self.assertEqual(metrics(app)["Installed rules"], "0")
        button(app, "Run automatic mitigation replay").click().run()
        self.assertIn("Normal flows blocked", metrics(app))
        button(app, "Clear log").click().run()
        self.assert_clean(app)

    def test_same_table_shown_twice_does_not_clash(self):
        script = page_script("dataset").replace("dataset.render()", """
from ddos import sample_data
data = sample_data.training_sample(0)
dataset._show_data(data, "first", "a")
dataset._show_data(data, "second", "b")
""")
        self.assert_clean(AppTest.from_string(script, default_timeout=120).run())

    def test_same_file_for_training_and_monitoring_is_flagged(self):
        script = page_script("overview").replace("overview.render()", """
from ddos import sample_data
data = sample_data.training_sample(0)
st_ = state.st
st_.session_state.train_upload = state.Upload("a.csv", data, "upload:abc:drop", "abc")
st_.session_state.monitor_upload = state.Upload("a.csv", data, "upload:abc:keep", "abc")
overview.render()
""")
        app = AppTest.from_string(script, default_timeout=120).run()
        self.assert_clean(app)
        self.assertTrue(any("same file as training" in w.value for w in app.warning))

    def test_timeline_line_breaks_where_there_is_no_traffic(self):
        for folder in (str(ROOT), str(ROOT / "dashboard")):
            if folder not in sys.path:
                sys.path.insert(0, folder)
        import ui
        summary = pd.DataFrame({"window": [0, 1, 2, 900, 901], "ddos_pct": [1, 2, 3, 99, 98]})
        line = ui.share_timeline(summary).data[0]
        self.assertEqual(list(line.x), [0, 1, 2, 3, 900, 901])
        self.assertTrue(pd.isna(line.y[3]))

    def test_seed_change_resets_rules(self):
        app = open_page("dataset")
        app.number_input[0].set_value(7).run()
        self.assertEqual(app.session_state["seed"], 7)
        self.assert_clean(app)


if __name__ == "__main__":
    unittest.main()
