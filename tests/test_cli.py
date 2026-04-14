import unittest
from argparse import Namespace
from unittest.mock import patch

from mscp.cli import (
    _has_any_diff,
    _has_input_sources,
    _is_at_least,
    _prompt_value,
    _select_sources,
    _should_alert,
)


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

    @patch("builtins.input", return_value='"D:\\CODE_WORD\\a.xml"')
    def test_prompt_value_strips_double_quotes(self, _mock_input) -> None:
        value = _prompt_value("Path")
        self.assertEqual(value, "D:\\CODE_WORD\\a.xml")

    @patch("builtins.input", return_value="'D:\\CODE_WORD\\b.xml'")
    def test_prompt_value_strips_single_quotes(self, _mock_input) -> None:
        value = _prompt_value("Path")
        self.assertEqual(value, "D:\\CODE_WORD\\b.xml")

    def test_select_sources_auto(self) -> None:
        args = Namespace(
            nmap="a.xml",
            nikto=None,
            openvas="o.xml",
            wireshark="w.json",
            analysis_mode="auto",
        )
        selected = _select_sources(args)
        self.assertEqual(set(selected.keys()), {"nmap", "openvas", "wireshark"})

    def test_select_sources_mode_2(self) -> None:
        args = Namespace(
            nmap="a.xml",
            nikto="n.txt",
            openvas="o.xml",
            wireshark=None,
            analysis_mode="2",
        )
        selected = _select_sources(args)
        self.assertEqual(list(selected.keys()), ["nmap", "nikto"])

    def test_select_sources_mode_2_count_based(self) -> None:
        args = Namespace(
            nmap="a.xml",
            nikto="n.txt",
            openvas="o.xml",
            wireshark="w.json",
            analysis_mode="2",
        )
        selected = _select_sources(
            args,
            source_scores={"nmap": 1, "nikto": 6, "openvas": 2, "wireshark": 4},
        )
        self.assertEqual(list(selected.keys()), ["nikto", "wireshark"])


if __name__ == "__main__":
    unittest.main()
