import tempfile
import unittest
from unittest.mock import patch

from threat_intelligence.cache import ThreatIntelCache
from threat_intelligence.vt_client import VirusTotalClient


class TestVirusTotalClient(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_directory = tempfile.TemporaryDirectory()
        self.cache = ThreatIntelCache(
            cache_directory=self.temp_directory.name
        )

        self.client = VirusTotalClient(
            api_key="test-key",
            cache=self.cache,
        )

    def tearDown(self) -> None:
        self.client.close()
        self.temp_directory.cleanup()

    def test_detect_ipv4(self) -> None:
        self.assertEqual(
            VirusTotalClient.detect_ioc_type("8.8.8.8"),
            "ipv4",
        )

    def test_detect_ipv6(self) -> None:
        self.assertEqual(
            VirusTotalClient.detect_ioc_type("2001:4860:4860::8888"),
            "ipv6",
        )

    def test_detect_domain(self) -> None:
        self.assertEqual(
            VirusTotalClient.detect_ioc_type("example.com"),
            "domain",
        )

    def test_detect_url(self) -> None:
        self.assertEqual(
            VirusTotalClient.detect_ioc_type(
                "https://example.com/path"
            ),
            "url",
        )

    def test_detect_sha256(self) -> None:
        sample_hash = "a" * 64

        self.assertEqual(
            VirusTotalClient.detect_ioc_type(sample_hash),
            "sha256",
        )

    def test_invalid_ioc_raises_error(self) -> None:
        with self.assertRaises(ValueError):
            VirusTotalClient.detect_ioc_type("not a valid ioc")

    def test_build_ip_endpoint(self) -> None:
        endpoint = VirusTotalClient._build_endpoint(
            "8.8.8.8",
            "ipv4",
        )

        self.assertEqual(endpoint, "/ip_addresses/8.8.8.8")

    def test_normalize_response(self) -> None:
        raw_response = {
            "data": {
                "id": "8.8.8.8",
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 1,
                        "suspicious": 0,
                        "harmless": 54,
                        "undetected": 36,
                        "timeout": 0,
                    },
                    "reputation": 550,
                    "tags": ["suspicious-udp"],
                },
            }
        }

        result = self.client._normalize_response(
            ioc="8.8.8.8",
            ioc_type="ipv4",
            response=raw_response,
        )

        self.assertEqual(result["total_engines"], 91)
        self.assertEqual(
            result["detection_ratio_percent"],
            1.1,
        )
        self.assertEqual(result["verdict"], "suspicious")

    @patch.object(VirusTotalClient, "_request")
    def test_lookup_uses_cache(
        self,
        mocked_request,
    ) -> None:
        mocked_request.return_value = {
            "data": {
                "id": "8.8.8.8",
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 80,
                        "undetected": 10,
                        "timeout": 0,
                    },
                    "reputation": 500,
                },
            }
        }

        first_result = self.client.lookup("8.8.8.8")
        second_result = self.client.lookup("8.8.8.8")

        self.assertFalse(first_result["cache_hit"])
        self.assertTrue(second_result["cache_hit"])
        mocked_request.assert_called_once()


if __name__ == "__main__":
    unittest.main()