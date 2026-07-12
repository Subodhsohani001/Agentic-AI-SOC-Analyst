from pprint import pprint

from memory.timeline import IncidentTimeline


timeline = IncidentTimeline()

print("Incident chronology:")
pprint(
    timeline.get_incident_chronology()
)

print("\nIOC timeline:")
pprint(
    timeline.build_ioc_timeline(
        "185.220.101.45",
        ioc_type="ips",
    )
)

print("\nMITRE timeline:")
pprint(
    timeline.build_mitre_timeline(
        "T1059"
    )
)

print("\nRepeat offenders:")
pprint(
    timeline.get_repeat_offenders()
)

print("\nHistorical summary:")
pprint(
    timeline.build_summary()
)