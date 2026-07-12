# Changelog

## [0.4.0] - 2026-07-13

### Added
- Persistent incident memory with deterministic incident IDs.
- Historical IOC correlation across stored incidents.
- MITRE ATT&CK technique correlation and historical tracking.
- Repeat-offender detection for recurring indicators.
- First-seen, last-seen, and occurrence-count timeline analysis.
- Evidence-based similarity scoring for related incidents.
- Historical correlation and timeline sections in analyst PDF reports.
- Incident IDs and repeat-offender context in generated reports.

### Changed
- Main SOC pipeline now correlates incidents before persistence.
- PDF reports now include incident memory, historical matches, IOC timelines, and MITRE history.

## v0.3.0 — Threat Intelligence
> Enrich. Validate. Correlate. Respond.

### Added
- VirusTotal enrichment
- AbuseIPDB enrichment
- Centralized policy engine
- Unified threat risk scoring
- Threat Intelligence PDF section

### Improved
- IOC normalization
- Analyst-ready reporting
- Private IP safety checks

---

## v0.2.0 — Deterministic Core
> Building trust through deterministic IOC extraction, MITRE validation, and analyst-ready reporting.

### Added
- Generic log analysis
- IOC defanging
- Validation engine
- PDF incident reporting

---

## v0.1.0 — Foundation
> From raw security logs to structured SOC analysis.

### Added
- Initial SOC analysis pipeline
- MITRE ATT&CK mapping
- IOC extraction