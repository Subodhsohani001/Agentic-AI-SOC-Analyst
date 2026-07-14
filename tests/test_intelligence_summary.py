import unittest

from threat_intelligence.intelligence_summary import (
    IntelligenceSummaryBuilder,
)


class TestIntelligenceSummaryBuilder(unittest.TestCase):
    def setUp(self) -> None:
        self.builder = IntelligenceSummaryBuilder()

    def test_build_complete_summary(self) -> None:
        result = self.builder.build(
            ioc="185.220.101.45",
            reputation={
                "risk_score": 91,
                "verdict": "confirmed_malicious",
                "severity": "CRITICAL",
                "confidence": "High",
                "recommended_action": "block_and_escalate",
                "evidence": [
                    "VirusTotal reports malicious detections."
                ],
                "contradictions": [],
            },
            correlation={
                "correlation_score": 92,
                "match_level": "CRITICAL",
                "investigation_priority": "P1",
                "recommended_action": "escalate_and_contain",
                "occurrence_count": 2,
                "is_repeat_offender": True,
                "risk_trend": "stable",
                "provider_agreement": "malicious_agreement",
                "shared_mitre_techniques": [
                    "T1059",
                    "T1105",
                ],
                "historical_incident_ids": [
                    "INC-2026-0001",
                    "INC-2026-0002",
                ],
                "evidence": [
                    "IOC is classified as a repeat offender."
                ],
            },
            virustotal={
                "analysis_stats": {
                    "malicious": 34,
                    "suspicious": 5,
                    "harmless": 10,
                    "undetected": 42,
                },
                "total_engines": 91,
                "detection_ratio_percent": 42.86,
                "reputation": -80,
                "verdict": "malicious",
            },
            abuseipdb={
                "abuse_confidence_score": 100,
                "is_whitelisted": False,
                "total_reports": 540,
                "num_distinct_users": 120,
                "verdict": "confirmed_abusive",
            },
        )

        self.assertEqual(result["risk_score"], 91)
        self.assertEqual(
            result["recommended_action"],
            "escalate_and_contain",
        )
        self.assertTrue(
            result["provider_findings"]
            ["virustotal"]["available"]
        )
        self.assertTrue(
            result["provider_findings"]
            ["abuseipdb"]["available"]
        )
        self.assertTrue(
            result["correlation"]["is_repeat_offender"]
        )

    def test_missing_provider_data(self) -> None:
        result = self.builder.build(
            ioc="example.com",
            reputation={
                "risk_score": 0,
                "verdict": "trusted",
                "severity": "INFORMATIONAL",
                "confidence": "Low",
                "evidence": [],
                "contradictions": [],
            },
        )

        self.assertFalse(
            result["provider_findings"]
            ["virustotal"]["available"]
        )
        self.assertFalse(
            result["provider_findings"]
            ["abuseipdb"]["available"]
        )
        self.assertFalse(
            result["correlation"]["available"]
        )

    def test_evidence_is_deduplicated(self) -> None:
        result = self.builder.build(
            ioc="example.com",
            reputation={
                "risk_score": 40,
                "verdict": "suspicious",
                "severity": "MEDIUM",
                "confidence": "Medium",
                "evidence": ["Shared evidence"],
                "contradictions": [],
            },
            correlation={
                "evidence": ["Shared evidence"],
            },
        )

        self.assertEqual(
            result["evidence"].count("Shared evidence"),
            1,
        )


if __name__ == "__main__":
    unittest.main()