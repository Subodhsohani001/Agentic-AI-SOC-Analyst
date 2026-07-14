import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from threat_intelligence.cache import ThreatIntelCache


class TestThreatIntelCache(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_directory = tempfile.TemporaryDirectory()
        self.cache = ThreatIntelCache(
            cache_directory=self.temp_directory.name,
            default_ttl_hours=24,
        )

    def tearDown(self) -> None:
        self.temp_directory.cleanup()

    def test_set_and_get_entry(self) -> None:
        self.cache.set(
            source="virustotal",
            ioc="8.8.8.8",
            data={"verdict": "trusted"},
        )

        result = self.cache.get("virustotal", "8.8.8.8")

        self.assertEqual(result, {"verdict": "trusted"})

    def test_ioc_normalization(self) -> None:
        self.cache.set(
            source="virustotal",
            ioc=" EXAMPLE.COM ",
            data={"verdict": "suspicious"},
        )

        result = self.cache.get("virustotal", "example.com")

        self.assertIsNotNone(result)

        assert result is not None
        
        self.assertEqual(result["verdict"], "suspicious")

    def test_missing_entry_returns_none(self) -> None:
        result = self.cache.get("virustotal", "1.1.1.1")

        self.assertIsNone(result)

    def test_delete_entry(self) -> None:
        self.cache.set(
            source="abuseipdb",
            ioc="8.8.8.8",
            data={"score": 0},
        )

        deleted = self.cache.delete("abuseipdb", "8.8.8.8")

        self.assertTrue(deleted)
        self.assertIsNone(
            self.cache.get("abuseipdb", "8.8.8.8")
        )

    def test_clear_cache(self) -> None:
        self.cache.set(
            "virustotal",
            "8.8.8.8",
            {"verdict": "trusted"},
        )
        self.cache.set(
            "virustotal",
            "1.1.1.1",
            {"verdict": "trusted"},
        )

        self.cache.clear("virustotal")

        stats = self.cache.get_stats()

        self.assertEqual(
            stats["sources"]["virustotal"]["entry_count"],
            0,
        )

    def test_expired_entry_returns_none(self) -> None:
        cache_file = (
            Path(self.temp_directory.name)
            / "vt_cache.json"
        )

        expired_time = (
            datetime.now(timezone.utc)
            - timedelta(hours=1)
        ).isoformat()

        cache_file.write_text(
            json.dumps(
                {
                    "8.8.8.8": {
                        "cached_at": expired_time,
                        "expires_at": expired_time,
                        "ttl_hours": 24,
                        "data": {"verdict": "trusted"},
                    }
                }
            ),
            encoding="utf-8",
        )

        result = self.cache.get("virustotal", "8.8.8.8")

        self.assertIsNone(result)

    def test_invalid_source_raises_error(self) -> None:
        with self.assertRaises(ValueError):
            self.cache.get("unknown_provider", "8.8.8.8")

    def test_corrupted_json_is_recovered(self) -> None:
        cache_file = (
            Path(self.temp_directory.name)
            / "vt_cache.json"
        )
        cache_file.write_text(
            "{ invalid json",
            encoding="utf-8",
        )

        result = self.cache.get("virustotal", "8.8.8.8")

        self.assertIsNone(result)

        recovered_data = json.loads(
            cache_file.read_text(encoding="utf-8")
        )
        self.assertEqual(recovered_data, {})


if __name__ == "__main__":
    unittest.main()