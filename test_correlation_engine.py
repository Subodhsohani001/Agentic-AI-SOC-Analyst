from pprint import pprint

from memory.correlation_engine import CorrelationEngine


engine = CorrelationEngine()

current_incident = {
    "source": "correlation-test",
    "iocs": {
        "ips": [
            "185.220.101.45",
            "10.10.10.50",
        ],
        "domains": [
            "different-example.test",
        ],
        "hashes": [],
    },
    "mitre": [
        "T1059",
        "T1078",
    ],
    "risk_score": 88,
    "severity": "HIGH",
    "detections": [
        "Suspicious PowerShell execution",
        "Credential misuse detected",
    ],
}

print("Correlation result:")
correlation_result = engine.correlate_incident(
    current_incident,
    minimum_score=1,
)
pprint(correlation_result)

print("\nIOC history:")
ioc_history = engine.find_ioc_occurrences(
    "185.220.101.45",
    ioc_type="ips",
)
pprint(ioc_history)