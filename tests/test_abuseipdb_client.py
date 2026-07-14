import tempfile
import unittest
from unittest.mock import patch

from threat_intelligence.abuseipdb_client import (
    AbuseIPDBClient,
)
from threat_intelligence.cache import ThreatIntelCache


class TestAbuseIPDBClient(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_directory = tempfile.TemporaryDirectory()
        self.cache = ThreatIntelCache(
            cache_directory=self.temp_directory.name
        )

        self.client = AbuseIPDBClient(
            api_key="test-key",
            cache=self.cache,
        )

    def tearDown(self) -> None:
        self.client.close()
        self.temp_directory.cleanup()

    def test_validate_public_ipv4(self) -> None:
        result = AbuseIPDBClient.validate_ip("8.8.8.8")

        self.assertEqual(result, "8.8.8.8")

    def test_private_ipv4_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            AbuseIPDBClient.validate_ip("192.168.1.10")

    def test_loopback_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            AbuseIPDBClient.validate_ip("127.0.0.1")

    def test_invalid_ip_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            AbuseIPDBClient.validate_ip("not-an-ip")

    def test_normalize_trusted_response(self) -> None:
        raw_response = {
            "data": {
                "ipAddress": "8.8.8.8",
                "isPublic": True,
                "ipVersion": 4,
                "isWhitelisted": True,
                "abuseConfidenceScore": 0,
                "countryCode": "US",
                "usageType": "Content Delivery Network",
                "isp": "Google LLC",
                "domain": "google.com",
                "hostnames": ["dns.google"],
                "totalReports": 123,
                "numDistinctUsers": 65,
                "lastReportedAt": "2026-07-14T12:31:53+00:00",
            }
        }

        result = self.client._normalize_response(
            ip_address="8.8.8.8",
            response=raw_response,
        )

        self.assertEqual(result["verdict"], "trusted")
        self.assertEqual(
            result["abuse_confidence_score"],
            0,
        )
        self.assertTrue(result["is_whitelisted"])

    def test_confirmed_abusive_verdict(self) -> None:
        verdict = AbuseIPDBClient._derive_verdict(
            abuse_score=100,
            total_reports=500,
            is_whitelisted=False,
        )

        self.assertEqual(verdict, "confirmed_abusive")

    @patch.object(AbuseIPDBClient, "_request")
    def test_lookup_uses_cache(
        self,
        mocked_request,
    ) -> None:
        mocked_request.return_value = {
            "data": {
                "ipAddress": "8.8.8.8",
                "isPublic": True,
                "ipVersion": 4,
                "isWhitelisted": True,
                "abuseConfidenceScore": 0,
                "countryCode": "US",
                "usageType": "Content Delivery Network",
                "isp": "Google LLC",
                "domain": "google.com",
                "hostnames": ["dns.google"],
                "totalReports": 123,
                "numDistinctUsers": 65,
                "lastReportedAt": None,
            }
        }

        first_result = self.client.lookup("8.8.8.8")
        second_result = self.client.lookup("8.8.8.8")

        self.assertFalse(first_result["cache_hit"])
        self.assertTrue(second_result["cache_hit"])
        mocked_request.assert_called_once()


if __name__ == "__main__":
    unittest.main()