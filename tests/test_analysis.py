import unittest

from mscp.analysis import build_analysis_insights


class TestAnalysis(unittest.TestCase):
    def test_build_insights(self) -> None:
        report = {
            "assets": [
                {
                    "host": "1.1.1.1",
                    "port": 443,
                    "risk": "HIGH",
                    "score": 12,
                    "evidence": ["open_port", "traffic_signal"],
                    "findings": ["Traffic: suspicious_traffic x5"],
                },
                {
                    "host": "192.168.1.5",
                    "port": 22,
                    "risk": "LOW",
                    "score": 1,
                    "evidence": ["open_port"],
                    "findings": [],
                },
            ]
        }

        insights = build_analysis_insights(report)
        self.assertEqual(insights["risk_counts"]["HIGH"], 1)
        self.assertEqual(len(insights["top_traffic"]), 1)
        self.assertEqual(insights["top_traffic"][0]["traffic_events"], 5)


if __name__ == "__main__":
    unittest.main()
