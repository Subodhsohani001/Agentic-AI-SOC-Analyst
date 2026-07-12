from memory.incident_store import IncidentStore


store = IncidentStore()

test_incident = {
    "source": "unit-test",
    "iocs": {
        "ips": ["185.220.101.45"],
        "domains": ["malicious-example.test"],
        "hashes": [],
    },
    "mitre": [
        "T1059",
        "T1071.001",
    ],
    "risk_score": 82,
    "severity": "HIGH",
    "detections": [
        "Suspicious PowerShell execution",
        "Outbound connection to suspicious IP",
    ],
}

second_incident = {
    "source": "repeat-test",
    "iocs": {
        "ips": [
            "185.220.101.45",
            "192.168.1.25",
        ],
        "domains": [
            "another-malicious-example.test",
        ],
        "hashes": [],
    },
    "mitre": [
        "T1059",
        "T1105",
    ],
    "risk_score": 91,
    "severity": "CRITICAL",
    "detections": [
        "Suspicious PowerShell execution",
        "Remote payload transfer",
    ],
}


print(
    store.save_incident(
        second_incident
    )
)

saved_incident = store.save_incident(test_incident)

print("Saved incident:")
print(saved_incident)

print("\nTotal incidents:")
print(store.count_incidents())

print("\nRetrieved incident:")
print(store.get_incident(saved_incident["incident_id"]))