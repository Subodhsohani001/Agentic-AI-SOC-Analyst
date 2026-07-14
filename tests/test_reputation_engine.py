import unittest

from threat_intelligence.reputation_engine import (
    ReputationEngine,
)


class TestReputationEngine(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = ReputationEngine()

    def test_trusted_public_service(self) -> None:
        result = self.engine.evaluate(
            ioc="8.8.8.8",
            virustotal={
                "analysis_stats": {
                    "malicious": 1,
                    "suspicious": 0,
                    "harmless": 54,
                    "undetected": 36,
                    "timeout": 0,
                },
                "total_engines": 91,
                "reputation": 550,
                "verdict": "suspicious",
            },
            abuseipdb={
                "abuse_confidence_score": 0,
                "total_reports": 123,
                "num_distinct_users": 65,
                "is_whitelisted": True,
                "verdict": "trusted",
            },
            history={
                "occurrence_count": 0,
                "is_repeat_offender": False,
                "highest_historical_risk_score": 0,
            },
            local_evidence={
                "severity": "Low",
                "confidence": "Medium",
                "detection_count": 1,
            },
        )

        self.assertEqual(result["risk_score"], 2)
        self.assertEqual(result["verdict"], "trusted")
        self.assertEqual(
            result["recommended_action"],
            "allow_with_logging",
        )
        self.assertEqual(result["evidence_source_count"], 3)

    def test_malicious_multi_source_agreement(self) -> None:
        result = self.engine.evaluate(
            ioc="185.220.101.45",
            virustotal={
                "analysis_stats": {
                    "malicious": 40,
                    "suspicious": 5,
                    "harmless": 5,
                    "undetected": 40,
                    "timeout": 0,
                },
                "total_engines": 90,
                "reputation": -100,
            },
            abuseipdb={
                "abuse_confidence_score": 100,
                "total_reports": 500,
                "num_distinct_users": 100,
                "is_whitelisted": False,
            },
            history={
                "occurrence_count": 3,
                "is_repeat_offender": True,
                "highest_historical_risk_score": 90,
            },
            local_evidence={
                "severity": "Critical",
                "confidence": "High",
                "detection_count": 5,
            },
        )

        self.assertGreaterEqual(result["risk_score"], 85)
        self.assertEqual(
            result["verdict"],
            "confirmed_malicious",
        )
        self.assertEqual(result["severity"], "CRITICAL")

    def test_provider_contradiction(self) -> None:
        result = self.engine.evaluate(
            ioc="203.0.113.10",
            virustotal={
                "analysis_stats": {
                    "malicious": 10,
                    "suspicious": 0,
                },
                "total_engines": 90,
                "reputation": 0,
            },
            abuseipdb={
                "abuse_confidence_score": 0,
                "total_reports": 0,
                "num_distinct_users": 0,
                "is_whitelisted": True,
            },
        )

        self.assertGreater(
            len(result["contradictions"]),
            0,
        )

    def test_no_evidence_returns_trusted(self) -> None:
        result = self.engine.evaluate(ioc="example.com")

        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["verdict"], "trusted")
        self.assertEqual(result["confidence"], "Low")


if __name__ == "__main__":
    unittest.main()