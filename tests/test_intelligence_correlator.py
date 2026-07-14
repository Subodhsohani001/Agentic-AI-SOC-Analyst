import unittest

from threat_intelligence.intelligence_correlator import (
    IntelligenceCorrelator,
)


class TestIntelligenceCorrelator(unittest.TestCase):
    def setUp(self) -> None:
        self.correlator = IntelligenceCorrelator()

    def test_critical_repeat_offender(self) -> None:
        result = self.correlator.correlate(
            ioc="185.220.101.45",
            reputation={
                "risk_score": 91,
                "verdict": "confirmed_malicious",
            },
            history={
                "occurrence_count": 2,
                "is_repeat_offender": True,
                "first_seen": "2026-07-12T17:52:39+00:00",
                "last_seen": "2026-07-12T18:27:51+00:00",
                "highest_historical_risk_score": 91,
                "incidents": [
                    {
                        "incident_id": "INC-2026-0001",
                        "risk_score": 82,
                        "mitre_ids": ["T1059", "T1071.001"],
                        "detections": [
                            "Suspicious PowerShell execution"
                        ],
                    },
                    {
                        "incident_id": "INC-2026-0002",
                        "risk_score": 91,
                        "mitre_ids": ["T1059", "T1105"],
                        "detections": [
                            "Remote payload transfer"
                        ],
                    },
                ],
            },
            current_incident={
                "risk_score": 91,
                "mitre_ids": ["T1059", "T1105"],
                "detections": [
                    "Suspicious PowerShell execution",
                    "Remote payload transfer",
                ],
            },
            virustotal={
                "analysis_stats": {
                    "malicious": 34,
                    "suspicious": 5,
                }
            },
            abuseipdb={
                "abuse_confidence_score": 100,
                "is_whitelisted": False,
            },
        )

        self.assertTrue(result["is_repeat_offender"])
        self.assertEqual(
            result["provider_agreement"],
            "malicious_agreement",
        )
        self.assertEqual(
            result["investigation_priority"],
            "P1",
        )
        self.assertEqual(
            result["recommended_action"],
            "escalate_and_contain",
        )
        self.assertIn(
            "T1059",
            result["shared_mitre_techniques"],
        )
        self.assertIn(
            "T1105",
            result["shared_mitre_techniques"],
        )

    def test_new_ioc_has_new_risk_trend(self) -> None:
        result = self.correlator.correlate(
            ioc="1.1.1.1",
            reputation={"risk_score": 5},
        )

        self.assertEqual(result["risk_trend"], "new")
        self.assertEqual(result["match_level"], "NONE")
        self.assertFalse(result["is_repeat_offender"])

    def test_increasing_risk_trend(self) -> None:
        result = self.correlator.correlate(
            ioc="203.0.113.10",
            reputation={"risk_score": 90},
            history={
                "incidents": [
                    {
                        "incident_id": "INC-1",
                        "risk_score": 50,
                    }
                ]
            },
        )

        self.assertEqual(result["risk_trend"], "increasing")


if __name__ == "__main__":
    unittest.main()