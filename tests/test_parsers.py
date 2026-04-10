from pathlib import Path
import unittest

from mscp.parsers.nikto_parser import parse_nikto
from mscp.parsers.nmap_parser import parse_nmap_xml
from mscp.parsers.openvas_parser import parse_openvas


class TestNmapParser(unittest.TestCase):
    def test_parse_open_ports(self) -> None:
        path = Path("sample_data/nmap.xml")
        services = parse_nmap_xml(path)

        ports = sorted((s.host, s.port, s.service) for s in services)
        self.assertEqual(
            ports,
            [
                ("192.168.1.10", 22, "ssh"),
                ("192.168.1.10", 80, "http"),
            ],
        )

    def test_parse_nikto_txt(self) -> None:
        findings = parse_nikto(Path("sample_data/nikto.txt"))
        self.assertGreaterEqual(len(findings), 2)
        self.assertEqual(findings[0].host, "192.168.1.10")
        self.assertEqual(findings[0].port, 80)

    def test_parse_openvas_xml(self) -> None:
        findings = parse_openvas(Path("sample_data/openvas.xml"))
        cves = sorted(x.cve for x in findings)
        self.assertEqual(cves, ["CVE-2021-41773", "CVE-2021-42013"])


if __name__ == "__main__":
    unittest.main()
