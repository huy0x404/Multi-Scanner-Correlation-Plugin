import unittest

from mscp.advisor import suggest_actions
from mscp.models import CorrelatedAsset


class TestAdvisor(unittest.TestCase):
    def test_sql_injection_hint(self) -> None:
        asset = CorrelatedAsset(
            host="10.0.0.2",
            port=443,
            service="https",
            findings=["Nikto: Possible SQL Injection at /login"],
            evidence={"web_vuln"},
            risk="HIGH",
        )
        hints = suggest_actions(asset)
        self.assertTrue(any("SQL Injection" in h for h in hints))


if __name__ == "__main__":
    unittest.main()
