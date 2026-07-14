import unittest

from threat_intelligence import (
    IntelligenceCorrelator,
    IntelligenceSummaryBuilder,
    ReputationEngine,
)


class TestThreatIntelligenceIntegration(unittest.TestCase):
    def test_complete_deterministic_pipeline(self) -> None:
        ioc = "185.220.101.45"

        virustotal = {
            "analysis_stats": {
                "malicious": 34,
                "suspicious": 5,
                "harmless": 10,
                "undetected": 42,
                "timeout": 0,
            },
            "total_engines": 91,
            "detection_ratio_percent": 42.86,
            "reputation": -80,
            "verdict": "malicious",
            "tags": ["tor", "malware"],
        }

        abuseipdb = {
            "abuse_confidence_score": 100,
            "is_whitelisted": False,
            "total_reports": 540,
            "num_distinct_users": 120,
            "country_code": "DE",
            "isp": "Example Hosting",
            "usage_type": "Data Center/Web Hosting/Transit",
            "verdict": "confirmed_abusive",
        }

        history = {
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
        }

        current_incident = {
            "severity": "Critical",
            "confidence": "High",
            "detection_count": 2,
            "risk_score": 91,
            "mitre_ids": ["T1059", "T1105"],
            "detections": [
                "Suspicious PowerShell execution",
                "Remote payload transfer",
            ],
        }

        reputation_engine = ReputationEngine()
        correlator = IntelligenceCorrelator()
        summary_builder = IntelligenceSummaryBuilder()

        reputation = reputation_engine.evaluate(
            ioc=ioc,
            virustotal=virustotal,
            abuseipdb=abuseipdb,
            history=history,
            local_evidence=current_incident,
        )

        correlation = correlator.correlate(
            ioc=ioc,
            reputation=reputation,
            history=history,
            current_incident=current_incident,
            virustotal=virustotal,
            abuseipdb=abuseipdb,
        )

        summary = summary_builder.build(
            ioc=ioc,
            reputation=reputation,
            correlation=correlation,
            virustotal=virustotal,
            abuseipdb=abuseipdb,
        )

        self.assertGreaterEqual(
            reputation["risk_score"],
            85,
        )
        self.assertEqual(
            reputation["verdict"],
            "confirmed_malicious",
        )
        self.assertTrue(
            correlation["is_repeat_offender"]
        )
        self.assertEqual(
            correlation["investigation_priority"],
            "P1",
        )
        self.assertEqual(
            summary["recommended_action"],
            "escalate_and_contain",
        )
        self.assertTrue(
            summary["provider_findings"]
            ["virustotal"]["available"]
        )
        self.assertTrue(
            summary["provider_findings"]
            ["abuseipdb"]["available"]
        )


if __name__ == "__main__":
    unittest.main()