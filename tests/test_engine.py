import unittest

from mscp.engine.correlation import correlate
from mscp.engine.risk import score_assets
from mscp.models import NiktoVuln, NmapService, OpenVASCve, WiresharkSignal


class TestEngine(unittest.TestCase):
    def test_correlation_and_risk(self) -> None:
        assets = correlate(
            nmap=[NmapService(host="10.0.0.1", port=80, service="http")],
            nikto=[NiktoVuln(host="10.0.0.1", port=80, item="XSS /admin")],
            openvas=[OpenVASCve(host="10.0.0.1", port=80, cve="CVE-2021-41773", has_exploit_hint=True)],
            wireshark=[WiresharkSignal(host="10.0.0.1", port=80, signal="many_500")],
        )
        scored = score_assets(assets)

        self.assertEqual(len(scored), 1)
        self.assertEqual(scored[0].score, 29)
        self.assertEqual(scored[0].score_details["interaction_bonus"], 7)
        self.assertEqual(scored[0].risk, "CRITICAL")

    def test_traffic_findings_are_aggregated(self) -> None:
        assets = correlate(
            nmap=[],
            nikto=[],
            openvas=[],
            wireshark=[
                WiresharkSignal(host="10.0.0.2", port=443, signal="suspicious_traffic"),
                WiresharkSignal(host="10.0.0.2", port=443, signal="suspicious_traffic"),
                WiresharkSignal(host="10.0.0.2", port=443, signal="udp_traffic"),
            ],
        )

        self.assertEqual(len(assets), 1)
        self.assertIn("Traffic: suspicious_traffic x2", assets[0].findings)
        self.assertIn("Traffic: udp_traffic", assets[0].findings)

    def test_loopback_low_value_noise_is_suppressed(self) -> None:
        assets = correlate(
            nmap=[],
            nikto=[],
            openvas=[],
            wireshark=[
                WiresharkSignal(host="127.0.0.1", port=5000, signal="suspicious_traffic"),
                WiresharkSignal(host="127.0.0.1", port=5000, signal="udp_traffic"),
            ],
        )
        self.assertEqual(len(assets), 0)

    def test_high_volume_traffic_becomes_high_risk(self) -> None:
        assets = correlate(
            nmap=[],
            nikto=[],
            openvas=[],
            wireshark=[WiresharkSignal(host="10.10.10.10", port=3306, signal="suspicious_traffic") for _ in range(400)],
        )
        scored = score_assets(assets)

        self.assertEqual(len(scored), 1)
        self.assertIn("traffic_anomaly", scored[0].evidence)
        self.assertEqual(scored[0].risk, "MEDIUM")

    def test_extreme_volume_traffic_becomes_critical(self) -> None:
        assets = correlate(
            nmap=[],
            nikto=[],
            openvas=[],
            wireshark=[WiresharkSignal(host="10.10.10.11", port=3306, signal="suspicious_traffic") for _ in range(3500)],
        )
        scored = score_assets(assets)

        self.assertEqual(len(scored), 1)
        self.assertIn("dos_indicator", scored[0].evidence)
        self.assertEqual(scored[0].risk, "HIGH")

    def test_web_heavy_traffic_is_alertable(self) -> None:
        assets = correlate(
            nmap=[],
            nikto=[],
            openvas=[],
            wireshark=[WiresharkSignal(host="127.0.0.1", port=80, signal="suspicious_traffic") for _ in range(1200)],
        )
        scored = score_assets(assets)

        self.assertEqual(len(scored), 1)
        self.assertIn("dos_indicator", scored[0].evidence)
        self.assertEqual(scored[0].risk, "HIGH")


if __name__ == "__main__":
    unittest.main()
