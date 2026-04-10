import unittest

from mscp.engine.diff import diff_reports


class TestDiff(unittest.TestCase):
    def test_detects_risk_change(self) -> None:
        old_report = {
            "assets": [
                {"host": "10.0.0.1", "port": 80, "risk": "MEDIUM"},
            ]
        }
        new_report = {
            "assets": [
                {"host": "10.0.0.1", "port": 80, "risk": "HIGH"},
            ]
        }

        diff = diff_reports(old_report, new_report)
        self.assertEqual(len(diff["risk_changed"]), 1)
        self.assertEqual(diff["risk_changed"][0]["old_risk"], "MEDIUM")
        self.assertEqual(diff["risk_changed"][0]["new_risk"], "HIGH")


if __name__ == "__main__":
    unittest.main()
