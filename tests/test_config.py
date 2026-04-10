import unittest

from mscp.config import load_weights


class TestConfig(unittest.TestCase):
    def test_load_json_weights(self) -> None:
        weights = load_weights("config/risk_weights.json")
        self.assertEqual(weights["open_port"], 1)
        self.assertEqual(weights["exploit"], 10)


if __name__ == "__main__":
    unittest.main()
