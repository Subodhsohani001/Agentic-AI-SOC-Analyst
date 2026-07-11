from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from ioc_formatter import IOCFormatter
from report_generator import PDFReportGenerator


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
        self.response_agent = ResponseAgent()
        self.report_generator = PDFReportGenerator("reports")

    def process(
    self,
    log_data: str,
    source_log: str | Path | None = None,
    ) -> dict[str, Any]:
        profile = self.profiler.profile(log_data)
        facts = self.ioc_agent.extract(log_data)
        display_facts = self.ioc_formatter.format_facts(facts)
        candidates = self.mitre_agent.retrieve_candidates(log_data)
        trusted_mitre = self.mitre_agent.select_trusted(candidates)
        ai_data = self.threat_agent.analyze(log_data, profile, facts, trusted_mitre)
        validated = self.validator.validate(ai_data, facts, trusted_mitre, log_data)
        tool_output = self.response_agent.execute(validated)
        report_path = self.report_generator.generate(
            analysis=validated,
            profile=profile.__dict__,
            display_facts=display_facts,
            mitre_candidates=candidates,
            source_log=source_log,
        )
        

        return {
            "profile": profile.__dict__,
            "mitre_candidates": candidates,
            "analysis": validated,
            "display_facts": display_facts,
            "tool_output": tool_output,
            "report_path": str(report_path),
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
        result = orchestrator.process(log, source_log=file_path,)

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

        print("\n========== TOOL OUTPUT ==========\n")
        print(result["tool_output"])

        print("\n========== PDF REPORT ==========\n")
        print(f"Report created: {result['report_path']}")

    except (FileNotFoundError, ValueError, OSError) as exc:
        print(f"\n[ERROR] {exc}")
        raise SystemExit(1) from exc
    except Exception as exc:
        print(f"\n[UNEXPECTED ERROR] {type(exc).__name__}: {exc}")
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()