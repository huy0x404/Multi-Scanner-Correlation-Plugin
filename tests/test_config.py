import unittest
import os
from tempfile import NamedTemporaryFile

from mscp.config import load_weights


class TestConfig(unittest.TestCase):
    def test_load_json_weights(self) -> None:
        weights = load_weights("config/risk_weights.json")
        self.assertEqual(weights["open_port"], 1)
        self.assertEqual(weights["exploit"], 10)
        self.assertEqual(weights["dos_indicator"], 7)

    def test_load_weights_with_mode_profile(self) -> None:
        weights = load_weights(None, mode="dos")
        self.assertEqual(weights["dos_indicator"], 14)
        self.assertEqual(weights["traffic_anomaly"], 8)

    def test_load_weights_mode_overridden_by_file_mode(self) -> None:
        payload = '{"mode": "balanced", "weights": {"web_vuln": 9}}'
        with NamedTemporaryFile("w", suffix=".json", encoding="utf-8", delete=False) as tmp:
            tmp.write(payload)
            tmp_path = tmp.name
        try:
            weights = load_weights(tmp_path, mode="dos")
            self.assertEqual(weights["dos_indicator"], 10)
            self.assertEqual(weights["web_vuln"], 9)
        finally:
            os.unlink(tmp_path)


if __name__ == "__main__":
    unittest.main()
