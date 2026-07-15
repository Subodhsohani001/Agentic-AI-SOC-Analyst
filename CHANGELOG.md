# Changelog

## [v0.5.0] - 2026-07-15

### Added

- Added a dedicated `threat_intelligence/` package for deterministic IOC enrichment.
- Added VirusTotal enrichment for IP addresses, domains, URLs, and file hashes.
- Added AbuseIPDB enrichment for public IPv4 and IPv6 addresses.
- Added persistent JSON-based threat-intelligence caching with configurable TTL.
- Added cache metadata tracking, cache statistics, corruption recovery, and API quota protection.
- Added deterministic multi-source reputation scoring using:
  - VirusTotal evidence
  - AbuseIPDB evidence
  - Local detection context
  - Historical incident memory
- Added provider disagreement and contradiction detection.
- Added deterministic risk score, verdict, severity, confidence, and recommended response actions.
- Added historical intelligence correlation for:
  - Repeat-offender detection
  - IOC occurrence tracking
  - First-seen and last-seen timestamps
  - Historical risk trends
  - Shared MITRE ATT&CK techniques
  - Shared detection patterns
  - Provider agreement
- Added analyst-ready intelligence summaries with:
  - Executive summaries
  - Provider findings
  - Historical correlation findings
  - Analyst guidance
  - Contradiction notes
- Added package-level exports through `threat_intelligence/__init__.py`.
- Added `.env.example` for required API environment variables.
- Added unit and integration tests for the complete threat-intelligence subsystem.
- Added dedicated PDF report sections for:
  - Deterministic intelligence investigation
  - External provider findings
  - Reputation analysis
  - Historical correlation
  - Analyst guidance

### Changed

- Integrated the new threat-intelligence subsystem into `json_llama.py`.
- Integrated VirusTotal, AbuseIPDB, reputation scoring, intelligence correlation, and summary generation into the main SOC workflow.
- Updated incident risk calculation to use the new multi-source reputation score.
- Preserved the legacy local threat-intelligence module for backward compatibility.
- Updated the PDF report generator to display both legacy and v0.5.0 intelligence results.
- Improved analyst-facing IOC safety by defanging observables in reports.
- Improved PDF safety by escaping user-controlled text before ReportLab rendering.
- Updated incident memory initialization to use a versioned empty schema:
  - `schema_version`
  - `incidents`
- Updated `.gitignore` to exclude:
  - Generated reports
  - Threat-intelligence cache files
  - Local environment files
  - Python cache files
  - Virtual environments
  - VS Code settings
  - Backup files

### Fixed

- Fixed false-positive handling where a single VirusTotal detection could incorrectly classify highly trusted infrastructure as suspicious.
- Fixed confidence calculation so empty evidence sources no longer increase confidence.
- Fixed private-IP handling so AbuseIPDB lookups are skipped safely without stopping the investigation.
- Fixed incident-memory schema validation by using the required `incidents` list.
- Fixed PDF report integration issues caused by missing or misaligned report helper methods.
- Fixed inconsistent risk-score handling between legacy and v0.5.0 threat-intelligence formats.

### Testing

- Added 35 passing automated tests covering:
  - Threat-intelligence cache
  - VirusTotal client
  - AbuseIPDB client
  - Reputation engine
  - Intelligence correlator
  - Intelligence summary builder
  - Existing incident-memory subsystem
  - End-to-end deterministic threat-intelligence integration
- Verified:
  - Python syntax compilation
  - Package imports
  - Orchestrator initialization
  - Full SOC workflow execution
  - Incident-memory updates
  - Historical correlation
  - PDF report generation

### Result

v0.5.0 evolves the project from a memory-enabled SOC agent into a deterministic threat-intelligence investigation platform capable of enriching observables, combining external and internal evidence, scoring risk, correlating repeat activity, and generating analyst-ready reports.

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