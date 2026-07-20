from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from ioc_formatter import IOCFormatter
from report_generator import PDFReportGenerator
from policy_engine import PolicyEngine
from threat_intel import ThreatIntelClient as LocalThreatClient

from threat_intelligence import (
    AbuseIPDBClient,
    AbuseIPDBError,
    IntelligenceCorrelator,
    IntelligenceSummaryBuilder,
    ReputationEngine,
    VirusTotalClient,
    VirusTotalError,
)

from response_engine import (
    ActionExecutor,
    ActionStatus,
    ActionType,
    ApprovalManager,
    AuditLogger,
    ResponsePlanner,
    ResponsePolicyEngine,
    TicketManager,
)

from memory.incident_store import IncidentStore
from memory.correlation_engine import CorrelationEngine
from memory.timeline import IncidentTimeline

from multi_agent import (
    CorrelationAgent as MultiAgentCorrelationAgent,
    Investigation,
    InvestigationCoordinator,
    InvestigationReporter,
    IOCAgent as MultiAgentIOCAgent,
    MITREAgent as MultiAgentMITREAgent,
    ResponseAdvisorAgent,
    RootCauseAgent,
    TaskPriority,
    ThreatIntelAgent,
    TriageAgent,
)

ALLOWED_SEVERITIES = {"Low", "Medium", "High", "Critical"}
ALLOWED_CONFIDENCE = {"Low", "Medium", "High"}
ALLOWED_TOOLS = {
    "block_ip",
    "create_ticket",
    "check_ip_reputation",
    "generate_report",
    "none",
}

DEFAULT_MITRE = {
    "attack_type": "Unknown",
    "technique_id": "Unknown",
    "technique_name": "Unknown",
    "tactic": "Unknown",
}


# =========================================================
# CORE UTILITIES
# =========================================================

def read_text_log(file_path: str | Path) -> str:
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Log file not found: {path}")
    return path.read_text(encoding="utf-8", errors="ignore")


def trim_log(log_data: str, max_lines: int = 100) -> str:
    if max_lines <= 0:
        raise ValueError("max_lines must be greater than zero")
    return "\n".join(log_data.splitlines()[:max_lines])


def load_json(file_path: str | Path) -> Any:
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"JSON file not found: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in {path}: {exc}") from exc


def valid_ipv4(value: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv4Address)
    except ValueError:
        return False


# =========================================================
# GENERIC LOG PROFILER — DETERMINISTIC, NO ATTACK GUESSING
# =========================================================

@dataclass(frozen=True)
class LogProfile:
    probable_source: str
    format: str
    contains_timestamp: bool
    contains_ip: bool
    contains_event_id: bool
    contains_process: bool
    contains_url: bool
    contains_hash: bool
    line_count: int
    agents: tuple[str, ...]


class LogProfilerAgent:
    """Profiles observable log characteristics without classifying attacks."""

    TIMESTAMP_PATTERNS = (
        r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}",
        r"\b[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}",
        r"\b\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}",
    )

    def profile(self, log_data: str) -> LogProfile:
        text = log_data.lower()
        stripped = log_data.lstrip()

        if stripped.startswith("{") or stripped.startswith("["):
            log_format = "JSON or JSON-like"
        elif "," in log_data and "\n" in log_data:
            log_format = "Delimited text"
        else:
            log_format = "Plain text"

        if any(marker in text for marker in ("event id", "eventid", "sysmon", "powershell", "windows security")):
            source = "Windows event or endpoint log"
        elif any(marker in text for marker in ("sshd", "failed password", "pam_unix", "/var/log/auth")):
            source = "Linux authentication or SSH log"
        elif any(marker in text for marker in ("suricata", "eve.json", "flow_id", "alert.signature")):
            source = "Network IDS log"
        elif any(marker in text for marker in ("src_ip", "dst_ip", "firewall", "action=deny", "action=allow")):
            source = "Firewall or network security log"
        elif any(marker in text for marker in ("http/1.1", "user-agent", "request_method", "status_code")):
            source = "Web or proxy log"
        else:
            source = "Unknown or generic security log"

        return LogProfile(
            probable_source=source,
            format=log_format,
            contains_timestamp=any(re.search(p, log_data) for p in self.TIMESTAMP_PATTERNS),
            contains_ip=bool(re.search(IOCAgent.IP_PATTERN, log_data)),
            contains_event_id=bool(re.search(IOCAgent.EVENT_ID_PATTERN, log_data)),
            contains_process=bool(re.search(IOCAgent.FILE_PATTERN, log_data, re.IGNORECASE)),
            contains_url=bool(re.search(IOCAgent.URL_PATTERN, log_data)),
            contains_hash=bool(re.search(r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b", log_data)),
            line_count=len(log_data.splitlines()),
            agents=("IOC Agent", "MITRE Agent", "Threat Analyst Agent", "Response Agent"),
        )


# =========================================================
# IOC AGENT — DETERMINISTIC FACT EXTRACTION
# =========================================================

class IOCAgent:
    IP_PATTERN = (
        r"\b(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)"
        r"(?:\.(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)){3}\b"
    )
    URL_PATTERN = r"https?://[^\s'\"<>]+"
    DOMAIN_PATTERN = (
        r"\b(?:[a-zA-Z0-9-]+\.)+"
        r"(?:com|org|net|io|local|in|co|edu|gov|biz|info)\b"
    )
    FILE_PATTERN = (
        r"\b[\w.-]+\."
        r"(?:exe|dll|ps1|bat|cmd|vbs|js|jar|py|sh|msi|scr)\b"
    )
    EVENT_ID_PATTERN = r"(?i)\bEvent\s*ID\s*:?\s*(\d+)\b"
    EMAIL_PATTERN = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"

    def extract(self, log_data: str) -> dict[str, list[str]]:
        urls = sorted(set(re.findall(self.URL_PATTERN, log_data)))
        emails = sorted(set(re.findall(self.EMAIL_PATTERN, log_data)))
        file_names = sorted(set(re.findall(self.FILE_PATTERN, log_data, re.IGNORECASE)))

        # Remove domains already embedded in URLs or email addresses to reduce false context.
        raw_domains = set(re.findall(self.DOMAIN_PATTERN, log_data))
        excluded_domains = {
            domain.lower()
            for item in urls + emails
            for domain in re.findall(self.DOMAIN_PATTERN, item)
        }
        domains = sorted(d for d in raw_domains if d.lower() not in excluded_domains)

        hashes = sorted(
            set(
                re.findall(r"\b[a-fA-F0-9]{32}\b", log_data)
                + re.findall(r"\b[a-fA-F0-9]{40}\b", log_data)
                + re.findall(r"\b[a-fA-F0-9]{64}\b", log_data)
            )
        )
        ip_addresses = sorted(
            ip for ip in set(re.findall(self.IP_PATTERN, log_data)) if valid_ipv4(ip)
        )
        process_names = sorted(
            name for name in file_names if name.lower().endswith(".exe")
        )

        return {
            "ip_addresses": ip_addresses,
            "domains": domains,
            "urls": urls,
            "hashes": hashes,
            "file_names": file_names,
            "process_names": process_names,
            "event_ids": sorted(set(re.findall(self.EVENT_ID_PATTERN, log_data))),
            "email_addresses": emails,
        }


# =========================================================
# MITRE AGENT — TRUSTED LOCAL KNOWLEDGE
# =========================================================

class MitreAgent:
    def __init__(self, knowledge_path: str | Path):
        knowledge = load_json(knowledge_path)
        if not isinstance(knowledge, list):
            raise ValueError("MITRE knowledge must be a JSON list")
        self.knowledge = knowledge

    def retrieve_candidates(self, log_data: str, limit: int = 5) -> list[dict[str, Any]]:
        text = log_data.lower()
        candidates: list[dict[str, Any]] = []

        for technique in self.knowledge:
            required = {"attack_type", "technique_id", "technique_name", "tactic", "keywords"}
            if not isinstance(technique, dict) or not required.issubset(technique):
                continue

            matched_keywords = [
                str(keyword)
                for keyword in technique.get("keywords", [])
                if str(keyword).lower() in text
            ]
            if matched_keywords:
                candidate = {**technique}
                candidate["score"] = len(matched_keywords)
                candidate["matched_keywords"] = matched_keywords
                candidates.append(candidate)

        return sorted(
            candidates,
            key=lambda item: (-item["score"], item["technique_id"]),
        )[:limit]

    @staticmethod
    def select_trusted(candidates: list[dict[str, Any]]) -> dict[str, str]:
        if not candidates:
            return dict(DEFAULT_MITRE)
        best = candidates[0]
        return {
            "attack_type": str(best["attack_type"]),
            "technique_id": str(best["technique_id"]),
            "technique_name": str(best["technique_name"]),
            "tactic": str(best["tactic"]),
        }


# =========================================================
# OLLAMA CLIENT + THREAT ANALYST AGENT
# =========================================================

class OllamaClient:
    def __init__(self, model: str = "llama3.2"):
        self.model = model

    def json_chat(self, prompt: str) -> dict[str, Any]:
        try:
            import ollama
        except ImportError as exc:
            raise RuntimeError(
                "The ollama Python package is not installed. Run: pip install ollama"
            ) from exc

        response = ollama.chat(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            format="json",
            options={"temperature": 0},
        )
        content = response.get("message", {}).get("content", "")
        try:
            result = json.loads(content)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Ollama returned invalid JSON: {exc}") from exc
        if not isinstance(result, dict):
            raise ValueError("Ollama response must be a JSON object")
        return result


class ThreatAnalystAgent:
    def __init__(self, client: OllamaClient):
        self.client = client

    def analyze(
        self,
        log_data: str,
        profile: LogProfile,
        facts: dict[str, list[str]],
        trusted_mitre: dict[str, str],
    ) -> dict[str, Any]:
        prompt = f"""
You are the Threat Analyst Agent in a SOC workflow.

Python has already extracted all observable facts and selected the trusted MITRE mapping.
You must not generate or modify MITRE fields, IPs, domains, files, processes, hashes, URLs,
event IDs, or email addresses.

Log profile:
{json.dumps(profile.__dict__, indent=2)}

Trusted MITRE mapping:
{json.dumps(trusted_mitre, indent=2)}

Deterministically extracted facts:
{json.dumps(facts, indent=2)}

Rules:
- severity: exactly Low, Medium, High, or Critical.
- confidence: exactly Low, Medium, or High.
- summary and recommendation must not be empty.
- Relevant facts must be exact members of the extracted fact lists.
- recommended_tool: exactly block_ip, create_ticket, check_ip_reputation,
  generate_report, or none.
- block_ip and check_ip_reputation require at least one extracted IP.
- Prefer create_ticket for investigation and generate_report for documentation.
- Do not claim an action was executed.

Return only this JSON schema:
{{
  "summary": "",
  "severity": "",
  "confidence": "",
  "recommended_tool": "",
  "verified_fact_assessment": {{
    "relevant_ip_addresses": [],
    "relevant_domains": [],
    "relevant_files": [],
    "relevant_processes": [],
    "notes": ""
  }},
  "recommendation": ""
}}

Security log:
{log_data}
"""
        return self.client.json_chat(prompt)


# =========================================================
# VALIDATION ENGINE — TRUST BOUNDARY
# =========================================================

class ValidationEngine:
    FACT_FIELD_MAP = {
        "relevant_ip_addresses": "ip_addresses",
        "relevant_domains": "domains",
        "relevant_files": "file_names",
        "relevant_processes": "process_names",
    }

    def validate(
        self,
        ai_data: dict[str, Any],
        facts: dict[str, list[str]],
        trusted_mitre: dict[str, str],
        log_data: str,
    ) -> dict[str, Any]:
        severity = str(ai_data.get("severity", "")).title()
        confidence = str(ai_data.get("confidence", "")).title()
        tool = str(ai_data.get("recommended_tool", "none")).strip().lower()

        if severity not in ALLOWED_SEVERITIES:
            severity = "Medium"
        if confidence not in ALLOWED_CONFIDENCE:
            confidence = "Low"
        if tool not in ALLOWED_TOOLS:
            tool = "none"

        assessment = ai_data.get("verified_fact_assessment", {})
        if not isinstance(assessment, dict):
            assessment = {}

        clean_assessment: dict[str, Any] = {}
        for output_field, source_field in self.FACT_FIELD_MAP.items():
            proposed = assessment.get(output_field, [])
            if not isinstance(proposed, list):
                proposed = []
            trusted_values = set(facts.get(source_field, []))
            clean_assessment[output_field] = sorted(
                {str(value) for value in proposed if str(value) in trusted_values}
            )
        clean_assessment["notes"] = str(assessment.get("notes", "")).strip()

        source_ip = facts.get("ip_addresses", [""])[0] if facts.get("ip_addresses") else ""
        if tool in {"block_ip", "check_ip_reputation"} and not source_ip:
            tool = "create_ticket"

        summary = str(ai_data.get("summary", "")).strip()
        if not summary:
            summary = f"{trusted_mitre['attack_type']} activity detected in the security log."

        recommendation = str(ai_data.get("recommendation", "")).strip()
        if not recommendation:
            recommendation = (
                "Review the affected host, validate the observed activity, "
                "and investigate related events before containment."
            )

        # =====================================================
        # DETERMINISTIC RESPONSE POLICY
        # =====================================================

        technique_id = trusted_mitre.get("technique_id", "")
        log_lower = log_data.lower()

        if (
            technique_id == "T1059.001"
            and any(
                keyword in log_lower
                for keyword in ["-enc", "encodedcommand", "invoke-expression"]
            )
        ):
            severity = "High"
            confidence = "High"

            if tool == "none":
                tool = "create_ticket"

        return {
            "summary": summary,
            "severity": severity,
            "confidence": confidence,
            "recommended_tool": tool,
            "verified_fact_assessment": clean_assessment,
            "recommendation": recommendation,
            "attack_type": trusted_mitre["attack_type"],
            "mitre_attack": {
                "technique_id": trusted_mitre["technique_id"],
                "technique_name": trusted_mitre["technique_name"],
                "tactic": trusted_mitre["tactic"],
            },
            "source_ip": source_ip,
            "extracted_facts": facts,
        }


# =========================================================
# RESPONSE AGENT + TOOL EXECUTOR
# =========================================================

def block_ip(ip: str) -> str:
    return f"[SIMULATION] Firewall rule created to block IP: {ip}"


def create_ticket(summary: str, severity: str) -> str:
    return f"[TICKET MUST BE CREATED]\nSeverity : {severity}\nSummary  : {summary}"


def check_ip_reputation(ip: str) -> str:
    malicious_ips = {"192.168.1.45", "10.10.10.10"}
    if ip in malicious_ips:
        return f"[THREAT INTEL] {ip} is flagged as suspicious."
    return f"[THREAT INTEL] {ip} is not present in the local threat database."


def generate_incident_report(data: dict[str, Any]) -> str:
    mitre = data["mitre_attack"]
    return f"""
================ INCIDENT REPORT ================

Summary:
{data['summary']}

Severity:
{data['severity']}

Attack Type:
{data['attack_type']}

Source IP:
{data['source_ip'] or 'Not observed'}

Confidence:
{data['confidence']}

MITRE ATT&CK
----------------------------
Technique ID   : {mitre['technique_id']}
Technique Name : {mitre['technique_name']}
Tactic         : {mitre['tactic']}

Recommendation:
{data['recommendation']}

===============================================
""".strip()


class ResponseAgent:
    """Executes only allow-listed, simulated SOC actions."""

    def execute(self, data: dict[str, Any]) -> str:
        tool = data["recommended_tool"]
        source_ip = data["source_ip"]

        if tool == "block_ip":
            return block_ip(source_ip)
        if tool == "create_ticket":
            return create_ticket(data["summary"], data["severity"])
        if tool == "check_ip_reputation":
            return check_ip_reputation(source_ip)
        if tool == "generate_report":
            return generate_incident_report(data)
        return "No tool was required."


# =========================================================
# ORCHESTRATOR — CONTROLS THE AGENT WORKFLOW
# =========================================================

class SOCOrchestrator:
    def __init__(self, mitre_path: str | Path, model: str = "llama3.2"):
        self.profiler = LogProfilerAgent()
        self.ioc_agent = IOCAgent()
        self.ioc_formatter = IOCFormatter()
        self.mitre_agent = MitreAgent(mitre_path)
        self.threat_agent = ThreatAnalystAgent(OllamaClient(model))
        self.validator = ValidationEngine()
        self.policy_engine = PolicyEngine()
        self.local_threat_intel = LocalThreatClient()

        # v0.5.0 external threat-intelligence subsystem.
        self.virustotal_client = VirusTotalClient()
        self.abuseipdb_client = AbuseIPDBClient()
        self.reputation_engine = ReputationEngine()
        self.intelligence_correlator = IntelligenceCorrelator()
        self.intelligence_summary_builder = IntelligenceSummaryBuilder()
        
        self.response_agent = ResponseAgent()

        # v0.6.0 policy-driven response orchestration.
        self.response_policy_engine = ResponsePolicyEngine()

        self.response_planner = ResponsePlanner(
            simulation_mode=True,
        )

        self.ticket_manager = TicketManager()
        self.approval_manager = ApprovalManager()

        self.action_executor = ActionExecutor(
            simulation_mode=True,
        )

        self.audit_logger = AuditLogger()

        self.incident_store = IncidentStore()
        self.correlation_engine = CorrelationEngine(
            incident_store=self.incident_store
        )
        self.incident_timeline = IncidentTimeline(
            incident_store=self.incident_store
        )

        self.report_generator = PDFReportGenerator("reports")
    
    
    def _adapt_intelligence_for_multi_agent(
        self,
        intelligence_results: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """
        Convert existing v0.5.0 intelligence output into the shared
        format expected by the v0.7.0 multi-agent framework.
        """

        observables: list[dict[str, Any]] = []

        severity_order = {
            "INFORMATIONAL": 0,
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4,
        }

        highest_severity = "INFORMATIONAL"
        highest_risk_score = 0

        malicious_count = 0
        suspicious_count = 0
        trusted_count = 0
        unknown_count = 0

        type_mapping = {
            "ip_addresses": "ip",
            "domains": "domain",
            "urls": "url",
            "hashes": "hash",
        }

        for item in intelligence_results:
            if not isinstance(item, dict):
                continue

            summary = item.get("summary", {})

            if not isinstance(summary, dict):
                summary = {}

            reputation = item.get(
                "reputation",
                {},
            )

            if not isinstance(reputation, dict):
                reputation = {}

            correlation = item.get(
                "correlation",
                {},
            )

            if not isinstance(correlation, dict):
                correlation = {}

            observable = str(
                item.get(
                    "ioc",
                    item.get("observable", ""),
                )
            ).strip()

            raw_type = str(
                item.get(
                    "ioc_type",
                    item.get(
                        "observable_type",
                        "unknown",
                    ),
                )
            ).strip().lower()

            observable_type = type_mapping.get(
                raw_type,
                raw_type,
            )

            risk_score = self._safe_int(
                summary.get(
                    "risk_score",
                    reputation.get(
                        "risk_score",
                        0,
                    ),
                )
            )

            verdict = str(
                summary.get(
                    "verdict",
                    reputation.get(
                        "verdict",
                        "unknown",
                    ),
                )
            ).strip().lower()

            severity = str(
                summary.get(
                    "severity",
                    reputation.get(
                        "severity",
                        "UNKNOWN",
                    ),
                )
            ).strip().upper()

            confidence_value = summary.get(
                "confidence",
                reputation.get(
                    "confidence",
                    0.70,
                ),
            )

            if isinstance(
                confidence_value,
                str,
            ):
                confidence_mapping = {
                    "LOW": 0.45,
                    "MEDIUM": 0.70,
                    "HIGH": 0.90,
                }

                confidence = confidence_mapping.get(
                    confidence_value.upper(),
                    0.70,
                )
            else:
                try:
                    confidence = float(
                        confidence_value
                    )
                except (TypeError, ValueError):
                    confidence = 0.70

                if confidence > 1:
                    confidence /= 100

                confidence = min(
                    max(confidence, 0.0),
                    1.0,
                )

            if verdict in {
                "malicious",
                "confirmed_malicious",
            }:
                malicious_count += 1
            elif verdict == "suspicious":
                suspicious_count += 1
            elif verdict == "trusted":
                trusted_count += 1
            else:
                unknown_count += 1

            if (
                severity_order.get(
                    severity,
                    0,
                )
                > severity_order.get(
                    highest_severity,
                    0,
                )
            ):
                highest_severity = severity

            highest_risk_score = max(
                highest_risk_score,
                risk_score,
            )

            observables.append(
                {
                    "observable": observable,
                    "observable_type": (
                        observable_type
                    ),
                    "risk_score": risk_score,
                    "verdict": verdict,
                    "severity": severity,
                    "confidence": confidence,
                    "provider_results": {
                        "virustotal": item.get(
                            "virustotal"
                        ),
                        "abuseipdb": item.get(
                            "abuseipdb"
                        ),
                    },
                    "correlation": correlation,
                    "intelligence_summary": (
                        summary
                    ),
                    "provider_errors": item.get(
                        "provider_errors",
                        [],
                    ),
                }
            )

        return {
            "observables": observables,
            "summary": {
                "observable_count": len(
                    observables
                ),
                "malicious_count": malicious_count,
                "suspicious_count": (
                    suspicious_count
                ),
                "trusted_count": trusted_count,
                "unknown_count": unknown_count,
                "highest_risk_score": (
                    highest_risk_score
                ),
                "highest_severity": (
                    highest_severity
                ),
            },
        }


    @staticmethod
    def _calculate_incident_risk(
        threat_intel_results: list[dict[str, Any]],
    ) -> int:
        scores: list[int] = []

        for item in threat_intel_results:
            if not isinstance(item, dict):
                continue

            summary = item.get("summary")

            if isinstance(summary, dict):
                score = summary.get("risk_score", 0)
            else:
                score = item.get(
                    "risk_score",
                    item.get("combined_risk_score", 0),
                )

            if isinstance(score, bool):
                continue

            if isinstance(score, (int, float)):
                scores.append(
                    int(min(max(score, 0), 100))
                )

        return max(scores, default=0)
    
    @staticmethod
    def _ioc_memory_type(fact_type: str) -> str | None:
        """Map extracted-fact IOC names to incident-memory IOC names."""
        mapping = {
            "ip_addresses": "ips",
            "domains": "domains",
            "urls": "urls",
            "hashes": "hashes",
        }

        return mapping.get(fact_type)

    def _build_ioc_history(
        self,
        ioc: str,
        ioc_type: str,
    ) -> dict[str, Any]:
        """Build reputation-compatible history from incident memory."""
        timeline = self.incident_timeline.build_ioc_timeline(
            ioc,
            ioc_type=ioc_type,
        )

        if not isinstance(timeline, dict):
            return {
                "occurrence_count": 0,
                "is_repeat_offender": False,
                "incidents": [],
            }

        raw_occurrences = timeline.get(
            "timeline",
            timeline.get("occurrences", []),
        )

        occurrences = (
            [
                occurrence
                for occurrence in raw_occurrences
                if isinstance(occurrence, dict)
            ]
            if isinstance(raw_occurrences, list)
            else []
        )

        historical_risks = [
            int(occurrence.get("risk_score", 0))
            for occurrence in occurrences
            if isinstance(occurrence.get("risk_score"), (int, float))
            and not isinstance(occurrence.get("risk_score"), bool)
        ]

        return {
            "occurrence_count": int(
                timeline.get("occurrence_count", len(occurrences))
            ),
            "is_repeat_offender": bool(
                timeline.get("is_repeat_offender", False)
            ),
            "first_seen": timeline.get("first_seen"),
            "last_seen": timeline.get("last_seen"),
            "highest_historical_risk_score": (
                max(historical_risks)
                if historical_risks
                else 0
            ),
            "incidents": occurrences,
        }


    def _enrich_observable(
        self,
        ioc: str,
        fact_type: str,
        history: dict[str, Any],
        validated: dict[str, Any],
        trusted_mitre: dict[str, str],
    ) -> dict[str, Any]:
        """Run the complete deterministic v0.5.0 pipeline for one IOC."""
        virustotal_result: dict[str, Any] | None = None
        abuseipdb_result: dict[str, Any] | None = None
        provider_errors: list[str] = []

        try:
            virustotal_result = self.virustotal_client.lookup(ioc)
        except (VirusTotalError, ValueError, TypeError) as exc:
            provider_errors.append(
                f"VirusTotal enrichment failed: {exc}"
            )

        if fact_type == "ip_addresses":
            try:
                abuseipdb_result = self.abuseipdb_client.lookup(ioc)
            except (AbuseIPDBError, ValueError, TypeError) as exc:
                provider_errors.append(
                    f"AbuseIPDB enrichment skipped or failed: {exc}"
                )

        technique_id = trusted_mitre.get(
            "technique_id",
            "Unknown",
        )

        detections = sorted(
            {
                value
                for value in (
                    trusted_mitre.get("attack_type"),
                    trusted_mitre.get("technique_name"),
                )
                if value and value != "Unknown"
            }
        )

        local_evidence = {
            "severity": validated.get("severity", "Medium"),
            "confidence": validated.get("confidence", "Low"),
            "detection_count": len(detections),
        }

        reputation = self.reputation_engine.evaluate(
            ioc=ioc,
            virustotal=virustotal_result,
            abuseipdb=abuseipdb_result,
            history=history,
            local_evidence=local_evidence,
        )

        current_incident = {
            "risk_score": reputation["risk_score"],
            "severity": validated.get("severity"),
            "confidence": validated.get("confidence"),
            "mitre_ids": (
                [technique_id]
                if technique_id != "Unknown"
                else []
            ),
            "detections": detections,
        }

        correlation = self.intelligence_correlator.correlate(
            ioc=ioc,
            reputation=reputation,
            history=history,
            current_incident=current_incident,
            virustotal=virustotal_result,
            abuseipdb=abuseipdb_result,
        )

        summary = self.intelligence_summary_builder.build(
            ioc=ioc,
            reputation=reputation,
            correlation=correlation,
            virustotal=virustotal_result,
            abuseipdb=abuseipdb_result,
        )

        return {
            "ioc": ioc,
            "ioc_type": fact_type,
            "virustotal": virustotal_result,
            "abuseipdb": abuseipdb_result,
            "reputation": reputation,
            "correlation": correlation,
            "summary": summary,
            "provider_errors": provider_errors,
        }

    def _run_threat_intelligence_pipeline(
        self,
        facts: dict[str, list[str]],
        validated: dict[str, Any],
        trusted_mitre: dict[str, str],
    ) -> list[dict[str, Any]]:
        """Enrich supported IOCs without allowing one failure to stop analysis."""
        results: list[dict[str, Any]] = []

        supported_fact_types = (
            "ip_addresses",
            "domains",
            "urls",
            "hashes",
        )

        for fact_type in supported_fact_types:
            memory_type = self._ioc_memory_type(fact_type)

            if memory_type is None:
                continue

            values = facts.get(fact_type, [])

            if not isinstance(values, list):
                continue

            for value in values:
                if not isinstance(value, str) or not value.strip():
                    continue

                normalized_value = value.strip()

                history = self._build_ioc_history(
                    ioc=normalized_value,
                    ioc_type=memory_type,
                )

                result = self._enrich_observable(
                    ioc=normalized_value,
                    fact_type=fact_type,
                    history=history,
                    validated=validated,
                    trusted_mitre=trusted_mitre,
                )

                results.append(result)

        return results

    @staticmethod
    def _build_memory_incident(
        validated: dict[str, Any],
        facts: dict[str, list[str]],
        trusted_mitre: dict[str, str],
        threat_intel_results: list[dict[str, Any]],
        source_log: str | Path | None,
    ) -> dict[str, Any]:
        technique_id = trusted_mitre.get(
            "technique_id",
            "Unknown",
        )

        mitre_techniques = (
            [technique_id]
            if technique_id != "Unknown"
            else []
        )

        detections = sorted(
            {
                value
                for value in (
                    trusted_mitre.get("attack_type"),
                    trusted_mitre.get("technique_name"),
                )
                if value and value != "Unknown"
            }
        )

        return {
            "source": (
                str(source_log)
                if source_log is not None
                else "Unknown source"
            ),
            "iocs": {
                "ips": facts.get("ip_addresses", []),
                "domains": facts.get("domains", []),
                "urls": facts.get("urls", []),
                "hashes": facts.get("hashes", []),
                "emails": facts.get("email_addresses", []),
                "files": facts.get("file_names", []),
            },
            "mitre": mitre_techniques,
            "risk_score": SOCOrchestrator._calculate_incident_risk(
                threat_intel_results
            ),
            "severity": validated.get(
                "severity",
                "Unknown",
            ).upper(),
            "detections": detections,
        }
    
    @staticmethod
    def _safe_int(
        value: Any,
        default: int = 0,
    ) -> int:
        try:
            if value is None or isinstance(value, bool):
                return default

            return int(float(value))

        except (TypeError, ValueError):
            return default

    @staticmethod
    def _build_response_context(
        validated: dict[str, Any],
        facts: dict[str, list[str]],
        trusted_mitre: dict[str, str],
        intelligence_results: list[dict[str, Any]],
        memory_context: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Normalize trusted v0.1-v0.5 evidence for the v0.6 response engine.
        """

        summaries = [
            item["summary"]
            for item in intelligence_results
            if isinstance(item, dict)
            and isinstance(item.get("summary"), dict)
        ]

        highest_summary = max(
            summaries,
            key=lambda item: SOCOrchestrator._safe_int(
                item.get("risk_score")
            ),
            default={},
        )

        correlations = [
            item["correlation"]
            for item in intelligence_results
            if isinstance(item, dict)
            and isinstance(item.get("correlation"), dict)
        ]

        highest_correlation = max(
            correlations,
            key=lambda item: SOCOrchestrator._safe_int(
                item.get(
                    "correlation_score",
                    item.get("current_risk_score", 0),
                )
            ),
            default={},
        )

        repeat_offenders = memory_context.get(
            "repeat_offenders",
            [],
        )

        is_repeat_offender = bool(
            repeat_offenders
        ) or bool(
            highest_correlation.get(
                "is_repeat_offender",
                False,
            )
        )

        risk_candidates = [
            SOCOrchestrator._safe_int(
                memory_context.get("risk_score")
            ),
            SOCOrchestrator._safe_int(
                highest_summary.get("risk_score")
            ),
            SOCOrchestrator._safe_int(
                highest_correlation.get(
                    "current_risk_score"
                )
            ),
            SOCOrchestrator._safe_int(
                highest_correlation.get(
                    "correlation_score"
                )
            ),
        ]

        combined_risk_score = max(
            0,
            min(max(risk_candidates, default=0), 100),
        )

        technique_id = trusted_mitre.get(
            "technique_id",
            "Unknown",
        )

        mitre_ids = (
            [technique_id]
            if technique_id != "Unknown"
            else []
        )

        ip_addresses = facts.get(
            "ip_addresses",
            [],
        )

        source_ip = (
            ip_addresses[0]
            if isinstance(ip_addresses, list)
            and ip_addresses
            else ""
        )

        verdict = str(
            highest_summary.get(
                "verdict",
                "unknown",
            )
        ).strip().lower()

        correlation_level = str(
            highest_correlation.get(
                "match_level",
                "NONE",
            )
        ).strip().upper()

        return {
            "incident_id": memory_context.get(
                "incident_id",
                "INC-UNKNOWN",
            ),
            "summary": validated.get(
                "summary",
                "Security incident detected.",
            ),
            "attack_type": validated.get(
                "attack_type",
                trusted_mitre.get(
                    "attack_type",
                    "Unknown",
                ),
            ),
            "severity": validated.get(
                "severity",
                "Unknown",
            ),
            "confidence": validated.get(
                "confidence",
                "Unknown",
            ),
            "combined_risk_score": combined_risk_score,
            "risk_score": combined_risk_score,
            "verdict": verdict,
            "intelligence_verdict": verdict,
            "source_ip": source_ip,
            "ip_addresses": (
                ip_addresses
                if isinstance(ip_addresses, list)
                else []
            ),
            "mitre_ids": mitre_ids,
            "mitre_attack": validated.get(
                "mitre_attack",
                {},
            ),
            "indicators_of_compromise": {
                "ips": facts.get(
                    "ip_addresses",
                    [],
                ),
                "domains": facts.get(
                    "domains",
                    [],
                ),
                "hashes": facts.get(
                    "hashes",
                    [],
                ),
            },
            "extracted_facts": facts,
            "is_repeat_offender": is_repeat_offender,
            "repeat_offender": is_repeat_offender,
            "correlation_level": correlation_level,
            "historical_correlation": {
                **memory_context.get(
                    "correlation",
                    {},
                ),
                "match_level": correlation_level,
                "is_repeat_offender": is_repeat_offender,
            },
            "intelligence_summary": highest_summary,
            "threat_intelligence": {
                "risk_score": combined_risk_score,
                "verdict": verdict,
            },
        }
    
    @staticmethod
    def _multi_agent_priority(
        severity: str,
    ) -> TaskPriority:
        """Convert SOC severity into multi-agent task priority."""

        normalized = str(
            severity or "Medium"
        ).strip().upper()

        if normalized == "CRITICAL":
            return TaskPriority.P1

        if normalized == "HIGH":
            return TaskPriority.P2

        if normalized == "MEDIUM":
            return TaskPriority.P3

        return TaskPriority.P4


    def _run_multi_agent_investigation(
        self,
        log_data: str,
        validated: dict[str, Any],
        facts: dict[str, list[str]],
        trusted_mitre: dict[str, str],
        intelligence_results: list[dict[str, Any]],
        memory_context: dict[str, Any],
        source_log: str | Path | None,
    ) -> dict[str, Any]:
        """
        Run the v0.7.0 multi-agent investigation using trusted
        evidence already produced by v0.1-v0.6.

        External threat-intelligence queries are not repeated here.
        """

        severity = str(
            validated.get(
                "severity",
                "Medium",
            )
        ).strip().upper()

        priority = self._multi_agent_priority(
            severity
        )

        incident_id = str(
            memory_context.get(
                "incident_id",
                validated.get(
                    "incident_id",
                    "INC-UNKNOWN",
                ),
            )
        )

        investigation = Investigation(
            incident_id=incident_id,
            title=str(
                validated.get(
                    "summary",
                    "Multi-agent SOC investigation",
                )
            ),
            description=(
                "Investigate validated security activity from "
                f"{source_log or 'an unknown source'}."
            ),
            severity=severity,
            priority=priority,
            metadata={
                "source_log": (
                    str(source_log)
                    if source_log is not None
                    else None
                ),
                "framework_version": "0.7.0",
                "log_line_count": len(
                    log_data.splitlines()
                ),
            },
        )

        coordinator = InvestigationCoordinator(
            investigation
        )

        coordinator.register_agents(
            [
                TriageAgent(
                    coordinator.context
                ),
                MultiAgentIOCAgent(
                    coordinator.context
                ),
                MultiAgentMITREAgent(
                    coordinator.context
                ),
                ThreatIntelAgent(
                    coordinator.context
                ),
                MultiAgentCorrelationAgent(
                    coordinator.context
                ),
                RootCauseAgent(
                    coordinator.context
                ),
                ResponseAdvisorAgent(
                    coordinator.context
                ),
            ]
        )

        technique_id = trusted_mitre.get(
            "technique_id",
            "Unknown",
        )

        mitre_mappings: list[dict[str, Any]] = []

        if technique_id != "Unknown":
            mitre_mappings.append(
                {
                    "id": technique_id,
                    "name": trusted_mitre.get(
                        "technique_name",
                        "Unknown",
                    ),
                    "tactic": trusted_mitre.get(
                        "tactic",
                        "Unknown",
                    ),
                    "confidence": 0.95,
                    "source": "trusted_legacy_mapping",
                }
            )

        normalized_iocs = {
            "ips": facts.get(
                "ip_addresses",
                [],
            ),
            "domains": facts.get(
                "domains",
                [],
            ),
            "urls": facts.get(
                "urls",
                [],
            ),
            "hashes": facts.get(
                "hashes",
                [],
            ),
        }

        adapted_intelligence = (
            self._adapt_intelligence_for_multi_agent(
                intelligence_results
            )
        )

        correlation_result = memory_context.get(
            "correlation",
            {},
        )

        if not isinstance(
            correlation_result,
            dict,
        ):
            correlation_result = {}

        repeat_offenders = memory_context.get(
            "repeat_offenders",
            [],
        )

        is_repeat_offender = bool(
            repeat_offenders
        ) or bool(
            correlation_result.get(
                "is_repeat_offender",
                False,
            )
        )

        correlation_score = self._safe_int(
            correlation_result.get(
                "correlation_score",
                correlation_result.get(
                    "highest_similarity_score",
                    0,
                ),
            )
        )

        if correlation_score >= 85:
            match_level = "CRITICAL"
        elif correlation_score >= 65:
            match_level = "HIGH"
        elif correlation_score >= 40:
            match_level = "MEDIUM"
        elif correlation_score >= 20:
            match_level = "LOW"
        else:
            match_level = "NONE"

        historical_correlation = {
            **correlation_result,
            "correlation_score": (
                correlation_score
            ),
            "match_level": match_level,
            "is_repeat_offender": (
                is_repeat_offender
            ),
            "repeat_offenders": repeat_offenders,
        }

        coordinator.context.set_shared_value(
            key="triage_assessment",
            value={
                "reported_severity": severity,
                "assessed_severity": severity,
                "assessed_priority": (
                    priority.value
                ),
                "source_ips": facts.get(
                    "ip_addresses",
                    [],
                ),
                "domains": facts.get(
                    "domains",
                    [],
                ),
                "hashes": facts.get(
                    "hashes",
                    [],
                ),
                "hostnames": facts.get(
                    "hostnames",
                    [],
                ),
                "usernames": facts.get(
                    "usernames",
                    [],
                ),
                "is_repeat_offender": (
                    is_repeat_offender
                ),
                "behavior_signals": [
                    {
                        "name": trusted_mitre.get(
                            "attack_type",
                            "Unknown activity",
                        ),
                        "matched_keywords": [],
                    }
                ],
            },
            actor="legacy_pipeline_adapter",
        )

        coordinator.context.set_shared_value(
            key="normalized_iocs",
            value={
                "normalized": normalized_iocs,
                "defanged": (
                    self.ioc_formatter.format_facts(
                        facts
                    )
                ),
                "valid_indicator_count": sum(
                    len(values)
                    for values
                    in normalized_iocs.values()
                    if isinstance(
                        values,
                        list,
                    )
                ),
            },
            actor="legacy_pipeline_adapter",
        )

        coordinator.context.set_shared_value(
            key="mitre_attack_mapping",
            value={
                "technique_ids": (
                    [technique_id]
                    if technique_id != "Unknown"
                    else []
                ),
                "tactics": (
                    [
                        trusted_mitre.get(
                            "tactic",
                            "Unknown",
                        )
                    ]
                    if technique_id != "Unknown"
                    else []
                ),
                "mappings": mitre_mappings,
                "confidence": (
                    0.95
                    if mitre_mappings
                    else 0.35
                ),
            },
            actor="legacy_pipeline_adapter",
        )

        coordinator.context.set_shared_value(
            key="threat_intelligence_results",
            value=adapted_intelligence,
            actor="legacy_pipeline_adapter",
        )

        coordinator.context.set_shared_value(
            key="historical_correlation",
            value=historical_correlation,
            actor="legacy_pipeline_adapter",
        )

        root_task, _ = coordinator.create_task(
            task_type="root_cause_analysis",
            description=(
                "Reconstruct the attack chain and determine the "
                "most probable root cause using validated evidence."
            ),
            priority=priority,
            input_data={
                "raw_logs": log_data,
                "mitre_mappings": mitre_mappings,
                "threat_intelligence_results": (
                    adapted_intelligence.get(
                        "observables",
                        [],
                    )
                ),
                "historical_correlation": (
                    historical_correlation
                ),
            },
            assigned_agent="root_cause_agent",
            route_immediately=True,
            raise_errors=False,
        )

        coordinator.start_investigation()

        root_result = coordinator.router.execute_task(
            root_task,
            auto_route=True,
            raise_errors=False,
        )

        response_tasks = [
            task
            for task
            in coordinator.context.investigation.tasks
            if task.task_type == "response_recommendation"
            and task.status.value == "pending"
        ]

        response_results = []

        for response_task in response_tasks:
            response_result = (
                coordinator.router.execute_task(
                    response_task,
                    auto_route=True,
                    raise_errors=False,
                )
            )

            if response_result is not None:
                response_results.append(
                    response_result
                )

        incomplete_tasks = (
            coordinator.get_incomplete_tasks()
        )

        if not incomplete_tasks:
            coordinator.complete_investigation()
        else:
            coordinator.pause_for_evidence(
                "One or more multi-agent tasks remain incomplete."
            )

        reporter = InvestigationReporter(
            coordinator.context
        )

        report = reporter.build_report(
            include_event_log=True,
            include_messages=True,
            include_execution_results=True,
        )

        return {
            "status": coordinator.get_status(),
            "root_cause_execution": (
                root_result.to_dict()
                if root_result is not None
                else None
            ),
            "response_executions": [
                result.to_dict()
                for result in response_results
            ],
            "report": report,
            "shared_context": (
                coordinator.context.to_dict()
            ),
        }


    def process(
        self,
        log_data: str,
        source_log: str | Path | None = None,
    ) -> dict[str, Any]:
        profile = self.profiler.profile(log_data)
        facts = self.ioc_agent.extract(log_data)
        legacy_threat_intel_results = (
            self.local_threat_intel.enrich_facts(facts)
        )
        display_facts = self.ioc_formatter.format_facts(facts)
        candidates = self.mitre_agent.retrieve_candidates(log_data)
        trusted_mitre = self.mitre_agent.select_trusted(candidates)
        ai_data = self.threat_agent.analyze(log_data, profile, facts, trusted_mitre)
        validated = self.validator.validate(ai_data, facts, trusted_mitre, log_data)
        policy_decision = self.policy_engine.apply(
            technique_id=trusted_mitre["technique_id"],
            log_data=log_data,
            current_severity=validated["severity"],
            current_confidence=validated["confidence"],
            current_tool=validated["recommended_tool"],
        )

        validated["severity"] = policy_decision.severity
        validated["confidence"] = policy_decision.confidence
        validated["recommended_tool"] = policy_decision.recommended_tool
        validated["policy_reason"] = policy_decision.reason

        # v0.5.0 deterministic external threat-intelligence investigation.
        intelligence_results = (
            self._run_threat_intelligence_pipeline(
                facts=facts,
                validated=validated,
                trusted_mitre=trusted_mitre,
            )
        )

        validated["threat_intelligence"] = intelligence_results

        # Build the current incident before saving.
        memory_incident = self._build_memory_incident(
            validated=validated,
            facts=facts,
            trusted_mitre=trusted_mitre,
            threat_intel_results=intelligence_results,
            source_log=source_log,
        )

        # Correlate only against historical incidents.
        correlation_result = self.correlation_engine.correlate_incident(
            memory_incident,
            minimum_score=1,
            maximum_results=5,
        )

        memory_incident["correlation"] = correlation_result

        # Save current incident after correlation.
        saved_incident = self.incident_store.save_incident(
            memory_incident
        )

        # Build IOC timelines including the current incident.
        ioc_timelines: list[dict[str, Any]] = []

        for ioc_type, values in saved_incident.get("iocs", {}).items():
            if not isinstance(values, list):
                continue

            for ioc_value in values:
                ioc_timelines.append(
                    self.incident_timeline.build_ioc_timeline(
                        str(ioc_value),
                        ioc_type=ioc_type,
                    )
                )

        # Build MITRE timelines.
        mitre_timelines: list[dict[str, Any]] = []

        for technique_id in saved_incident.get("mitre", []):
            mitre_timelines.append(
                self.incident_timeline.build_mitre_timeline(
                    str(technique_id)
                )
            )

        memory_context = {
            "incident_id": saved_incident["incident_id"],
            "timestamp": saved_incident["timestamp"],
            "risk_score": saved_incident.get("risk_score", 0),
            "correlation": correlation_result,
            "ioc_timelines": ioc_timelines,
            "mitre_timelines": mitre_timelines,
            "repeat_offenders": [
                timeline
                for timeline in ioc_timelines
                if timeline.get("is_repeat_offender")
            ],
        }

        validated["incident_id"] = saved_incident["incident_id"]
        validated["historical_correlation"] = correlation_result

        # =====================================================
        # v0.7.0 MULTI-AGENT INVESTIGATION
        # =====================================================

        multi_agent_output = (
            self._run_multi_agent_investigation(
                log_data=log_data,
                validated=validated,
                facts=facts,
                trusted_mitre=trusted_mitre,
                intelligence_results=intelligence_results,
                memory_context=memory_context,
                source_log=source_log,
            )
        )

        multi_agent_report_path = Path(
            "reports"
        ) / (
            f"multi_agent_{saved_incident['incident_id']}.json"
        )

        multi_agent_report_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        multi_agent_report_path.write_text(
            json.dumps(
                multi_agent_output["report"],
                indent=4,
                sort_keys=True,
                default=str,
            ),
            encoding="utf-8",
        )

        validated["multi_agent_investigation"] = (
            multi_agent_output["report"]
        )

        # =====================================================
        # v0.6.0 POLICY-DRIVEN RESPONSE ORCHESTRATION
        # =====================================================

        response_context = self._build_response_context(
            validated=validated,
            facts=facts,
            trusted_mitre=trusted_mitre,
            intelligence_results=intelligence_results,
            memory_context=memory_context,
        )

        multi_agent_report = multi_agent_output.get(
            "report",
            {},
        )

        response_context[
            "multi_agent_investigation"
        ] = multi_agent_report

        response_context[
            "root_cause_assessment"
        ] = multi_agent_report.get(
            "root_cause_assessment",
            {},
        )

        response_context[
            "attack_chain"
        ] = multi_agent_report.get(
            "attack_chain",
            [],
        )

        response_context[
            "response_advisory"
        ] = multi_agent_report.get(
            "response_advisory",
            {},
        )

        response_context[
            "hypothesis_summary"
        ] = multi_agent_report.get(
            "hypothesis_summary",
            {},
        )

        response_decision = (
            self.response_policy_engine.evaluate(
                response_context
            )
        )

        response_plan = self.response_planner.build_plan(
            incident_id=saved_incident["incident_id"],
            decision=response_decision,
            incident=response_context,
        )

        self.audit_logger.log_plan_created(
            response_plan
        )

        approval_requests = (
            self.approval_manager.create_requests_for_plan(
                response_plan
            )
        )

        for approval_request in approval_requests:
            self.audit_logger.log_approval_requested(
                approval_request
            )

        created_ticket = None

        has_ticket_action = any(
            action.action_type == ActionType.CREATE_TICKET
            and action.status == ActionStatus.PENDING
            for action in response_plan.actions
        )

        if has_ticket_action:
            created_ticket = self.ticket_manager.create_ticket(
                incident=response_context,
                plan=response_plan,
            )

        execution_results = (
            self.action_executor.execute_plan(
                response_plan,
                actor="agentic_soc_analyst",
            )
        )

        for action in response_plan.actions:
            self.audit_logger.log_action_execution(
                action=action,
                incident_id=response_plan.incident_id,
                actor="agentic_soc_analyst",
            )

        self.audit_logger.log_plan_completed(
            response_plan,
            actor="agentic_soc_analyst",
        )

        response_output = {
            "mode": "simulation",
            "context": response_context,
            "decision": response_decision.to_dict(),
            "plan": response_plan.to_dict(),
            "approval_requests": [
                request.to_dict()
                for request in approval_requests
            ],
            "ticket": (
                created_ticket.to_dict()
                if created_ticket is not None
                else None
            ),
            "execution_results": execution_results,
            "audit_log_path": str(
                self.audit_logger.log_path
            ),
        }

        tool_output = (
            "v0.6.0 response orchestration completed in "
            "simulation mode. "
            f"Plan status: {response_plan.status}. "
            f"Pending approvals: "
            f"{len(approval_requests)}."
        )

        report_path = self.report_generator.generate(
            analysis=validated,
            profile=profile.__dict__,
            display_facts=display_facts,
            mitre_candidates=candidates,
            threat_intel=legacy_threat_intel_results,
            intelligence_results=intelligence_results,
            source_log=source_log,
            memory_context=memory_context,
            multi_agent_report=multi_agent_output["report"],
            response_output=response_output,
        )

        return {
            "profile": profile.__dict__,
            "mitre_candidates": candidates,
            "analysis": validated,
            "display_facts": display_facts,
            "threat_intel": legacy_threat_intel_results,
            "intelligence_results": intelligence_results,
            "memory": memory_context,
            "multi_agent": multi_agent_output,
            "response": response_output,
            "tool_output": tool_output,
            "report_path": str(report_path),
            "multi_agent_report_path": str(
                 multi_agent_report_path
            ),
        }
        


# =========================================================
# CLI — ACCEPTS ANY TEXT LOG FILE
# =========================================================

def resolve_log_path() -> Path:
    import sys

    if len(sys.argv) > 1:
        raw_path = " ".join(sys.argv[1:]).strip().strip('"')
    else:
        raw_path = input("\nEnter the path of any log file: ").strip().strip('"')

    if not raw_path:
        raise ValueError("No log file path was provided.")

    path = Path(raw_path).expanduser()
    if not path.is_file():
        raise FileNotFoundError(f"Log file not found: {path}")
    return path


def main() -> None:
    try:
        file_path = resolve_log_path()
        log = trim_log(read_text_log(file_path), max_lines=500)

        if not log.strip():
            raise ValueError("The selected log file is empty.")

        print(f"\nAnalyzing: {file_path}")
        print("\n🐍 Profiling the log and extracting trusted evidence...")

        orchestrator = SOCOrchestrator("mitre_knowledge.json", model="llama3.2")
        result = orchestrator.process(
            log, 
            source_log=file_path,
        )

        print("\n========== LOG PROFILE ==========\n")
        print(json.dumps(result["profile"], indent=4))

        print("\n========== PYTHON EXTRACTED FACTS ==========\n")
        print(json.dumps(result["analysis"]["extracted_facts"], indent=4, sort_keys=True))

        print("\n========== DEFANGED IOC DISPLAY ==========\n")
        print(json.dumps(result["display_facts"], indent=4, sort_keys=True))

        print("\n========== MITRE CANDIDATES ==========\n")
        print(json.dumps(result["mitre_candidates"], indent=4))

        print("\n========== VALIDATED SOC ANALYSIS ==========\n")
        print(json.dumps(result["analysis"], indent=4, sort_keys=True))

        print("\n========== LOCAL THREAT INTELLIGENCE ==========\n")
        print(json.dumps(result["threat_intel"], indent=4, sort_keys=True))

        print("\n========== v0.5.0 INTELLIGENCE INVESTIGATION ==========\n")
        print(
            json.dumps(
                result["intelligence_results"],
                indent=4,
                sort_keys=True,
            )
        )

        print("\n========== INCIDENT MEMORY ==========\n")
        print(
            json.dumps(
                result["memory"],
                indent=4,
                sort_keys=True,
            )
        )

        print("\n========== HISTORICAL CORRELATION ==========\n")
        print(
            json.dumps(
                result["memory"]["correlation"],
                indent=4,
                sort_keys=True,
            )
        )

        print(
            "\n========== v0.7.0 MULTI-AGENT INVESTIGATION ==========\n"
        )
        multi_agent_report = result["multi_agent"]["report"]

        print(
            json.dumps(
                {
                    "report_metadata": (
                        multi_agent_report.get(
                            "report_metadata",
                            {},
                        )
                    ),
                    "investigation": (
                        multi_agent_report.get(
                            "investigation",
                            {},
                        )
                    ),
                    "executive_summary": (
                        multi_agent_report.get(
                            "executive_summary",
                            {},
                        )
                    ),
                    "completion_assessment": (
                        multi_agent_report.get(
                            "completion_assessment",
                            {},
                        )
                    ),
                    "root_cause_assessment": (
                        multi_agent_report.get(
                            "root_cause_assessment",
                            {},
                        )
                    ),
                    "hypothesis_summary": (
                        multi_agent_report.get(
                            "hypothesis_summary",
                            {},
                        )
                    ),
                    "response_advisory": (
                        multi_agent_report.get(
                            "response_advisory",
                            {},
                        )
                    ),
                },
                indent=4,
                sort_keys=True,
                default=str,
            )
        )

        print(
            "\n========== RESPONSE ORCHESTRATION — v0.6.0 ENGINE ==========\n"
        )
        print(
            json.dumps(
                result["response"]["decision"],
                indent=4,
                sort_keys=True,
                default=str,
            )
        )

        print(
            "\n========== RESPONSE PLAN — v0.6.0 ENGINE ==========\n"
        )
        print(
            json.dumps(
                result["response"]["plan"],
                indent=4,
                sort_keys=True,
                default=str,
            )
        )

        print(
            "\n========== APPROVAL REQUESTS ==========\n"
        )
        print(
            json.dumps(
                result["response"]["approval_requests"],
                indent=4,
                sort_keys=True,
                default=str,
            )
        )

        print(
            "\n========== RESPONSE EXECUTION ==========\n"
        )
        print(
            json.dumps(
                result["response"]["execution_results"],
                indent=4,
                sort_keys=True,
                default=str,
            )
        )

        print(
            "\n========== SOC TICKET ==========\n"
        )
        print(
            json.dumps(
                result["response"]["ticket"],
                indent=4,
                sort_keys=True,
                default=str,
            )
        )

        print(
            "\n========== RESPONSE AUDIT TRAIL ==========\n"
        )
        print(
            "Audit log: "
            f"{result['response']['audit_log_path']}"
        )

        print("\n========== TOOL OUTPUT ==========\n")
        print(result["tool_output"])

        print("\n========== PDF REPORT ==========\n")
        print(f"Report created: {result['report_path']}")

        print(
            "\nFull v0.7.0 report saved to: "
            f"{result['multi_agent_report_path']}"
        )

    except (FileNotFoundError, ValueError, OSError) as exc:
        print(f"\n[ERROR] {exc}")
        raise SystemExit(1) from exc
    except Exception as exc:
        print(f"\n[UNEXPECTED ERROR] {type(exc).__name__}: {exc}")
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()