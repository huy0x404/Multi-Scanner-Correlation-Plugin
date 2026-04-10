import unittest
from argparse import Namespace

from mscp.cli import _has_any_diff, _has_input_sources, _is_at_least, _should_alert


class TestCliAlertThreshold(unittest.TestCase):
    def test_risk_compare(self) -> None:
        self.assertTrue(_is_at_least("CRITICAL", "HIGH"))
        self.assertFalse(_is_at_least("MEDIUM", "HIGH"))

    def test_should_alert_without_diff(self) -> None:
        report = {
            "assets": [
                {"host": "10.0.0.1", "port": 80, "risk": "HIGH"},
            ]
        }
        self.assertTrue(_should_alert(report, None, "HIGH"))
        self.assertFalse(_should_alert(report, None, "CRITICAL"))

    def test_should_alert_with_diff(self) -> None:
        report = {"assets": []}
        diff = {
            "added": [],
            "removed": [],
            "risk_changed": [
                {"host": "10.0.0.1", "port": 80, "old_risk": "LOW", "new_risk": "CRITICAL"}
            ],
        }
        self.assertTrue(_should_alert(report, diff, "HIGH"))

    def test_has_input_sources(self) -> None:
        no_inputs = Namespace(nmap=None, nikto=None, openvas=None, wireshark=None)
        with_input = Namespace(nmap="sample_data/nmap.xml", nikto=None, openvas=None, wireshark=None)

        self.assertFalse(_has_input_sources(no_inputs))
        self.assertTrue(_has_input_sources(with_input))

    def test_has_any_diff(self) -> None:
        self.assertFalse(_has_any_diff({"added": [], "removed": [], "risk_changed": []}))
        self.assertTrue(_has_any_diff({"added": [{"host": "1.1.1.1"}], "removed": [], "risk_changed": []}))


if __name__ == "__main__":
    unittest.main()
