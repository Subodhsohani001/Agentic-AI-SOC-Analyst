from __future__ import annotations

from typing import Any, Dict, List, Set

from ..agent_base import (
    AgentExecutionError,
    BaseInvestigationAgent,
)
from ..investigation_models import (
    AgentExecutionResult,
    AgentFinding,
    Evidence,
    EvidenceType,
    InvestigationHypothesis,
    InvestigationTask,
    TaskPriority,
)


class TriageAgent(BaseInvestigationAgent):
    """
    Performs initial incident triage.

    Responsibilities:
    - Assess incident severity
    - Determine urgency and investigation priority
    - Identify affected entities
    - Detect obvious indicators and suspicious behaviors
    - Establish investigation scope
    - Recommend follow-up specialist tasks
    """

    agent_name = "triage_agent"
    description = (
        "Performs initial incident severity, urgency, scope, "
        "and priority assessment."
    )
    version = "0.7.0"

    @property
    def supported_task_types(self) -> Set[str]:
        return {
            "triage",
            "initial_triage",
            "severity_assessment",
            "scope_assessment",
        }

    @staticmethod
    def _normalize_text(value: Any) -> str:
        """Convert input safely into lowercase searchable text."""

        if value is None:
            return ""

        if isinstance(value, str):
            return value.strip().lower()

        if isinstance(value, list):
            return " ".join(
                str(item).strip().lower()
                for item in value
            )

        if isinstance(value, dict):
            return " ".join(
                f"{key} {value}"
                for key, value in value.items()
            ).lower()

        return str(value).strip().lower()

    @staticmethod
    def _normalize_severity(value: Any) -> str:
        """Normalize severity into a supported SOC severity value."""

        severity = str(value or "UNKNOWN").strip().upper()

        aliases = {
            "INFO": "INFORMATIONAL",
            "INFORMATION": "INFORMATIONAL",
            "WARN": "MEDIUM",
            "WARNING": "MEDIUM",
            "SEVERE": "HIGH",
            "URGENT": "CRITICAL",
        }

        severity = aliases.get(severity, severity)

        allowed = {
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW",
            "INFORMATIONAL",
            "UNKNOWN",
        }

        if severity not in allowed:
            return "UNKNOWN"

        return severity

    @staticmethod
    def _severity_score(severity: str) -> int:
        """Return a deterministic numeric score for severity."""

        severity_scores = {
            "CRITICAL": 95,
            "HIGH": 80,
            "MEDIUM": 55,
            "LOW": 30,
            "INFORMATIONAL": 10,
            "UNKNOWN": 20,
        }

        return severity_scores.get(severity, 20)

    @staticmethod
    def _priority_from_score(score: int) -> TaskPriority:
        """Convert triage score into investigation priority."""

        if score >= 85:
            return TaskPriority.P1

        if score >= 65:
            return TaskPriority.P2

        if score >= 40:
            return TaskPriority.P3

        return TaskPriority.P4

    @staticmethod
    def _extract_list(
        input_data: Dict[str, Any],
        *keys: str,
    ) -> List[str]:
        """Extract and normalize list-like values from input data."""

        results: List[str] = []

        for key in keys:
            value = input_data.get(key)

            if value is None:
                continue

            if isinstance(value, list):
                candidates = value
            else:
                candidates = [value]

            for candidate in candidates:
                normalized = str(candidate).strip()

                if normalized and normalized not in results:
                    results.append(normalized)

        return results

    def _detect_behavior_signals(
        self,
        searchable_text: str,
    ) -> List[Dict[str, Any]]:
        """Detect suspicious behaviors from incident text."""

        behavior_rules = [
            {
                "name": "PowerShell execution",
                "keywords": [
                    "powershell",
                    "powershell.exe",
                    "encodedcommand",
                    "-enc",
                    "invoke-expression",
                    "iex",
                ],
                "score": 18,
                "severity": "HIGH",
            },
            {
                "name": "Credential access",
                "keywords": [
                    "mimikatz",
                    "lsass",
                    "credential dump",
                    "credential dumping",
                    "sekurlsa",
                    "procdump",
                ],
                "score": 25,
                "severity": "CRITICAL",
            },
            {
                "name": "Command-and-control activity",
                "keywords": [
                    "command and control",
                    "command-and-control",
                    "c2",
                    "beacon",
                    "callback",
                    "outbound connection",
                ],
                "score": 24,
                "severity": "CRITICAL",
            },
            {
                "name": "Malware execution",
                "keywords": [
                    "malware",
                    "ransomware",
                    "trojan",
                    "payload",
                    "backdoor",
                    "shellcode",
                ],
                "score": 25,
                "severity": "CRITICAL",
            },
            {
                "name": "Privilege escalation",
                "keywords": [
                    "privilege escalation",
                    "elevated privileges",
                    "administrator access",
                    "system privileges",
                    "sudo",
                ],
                "score": 20,
                "severity": "HIGH",
            },
            {
                "name": "Lateral movement",
                "keywords": [
                    "lateral movement",
                    "psexec",
                    "wmic",
                    "remote service",
                    "remote desktop",
                    "rdp",
                    "smb",
                ],
                "score": 20,
                "severity": "HIGH",
            },
            {
                "name": "Persistence activity",
                "keywords": [
                    "persistence",
                    "scheduled task",
                    "registry run key",
                    "startup folder",
                    "service creation",
                ],
                "score": 16,
                "severity": "HIGH",
            },
            {
                "name": "Data exfiltration",
                "keywords": [
                    "exfiltration",
                    "data theft",
                    "upload archive",
                    "stolen data",
                    "large outbound transfer",
                ],
                "score": 25,
                "severity": "CRITICAL",
            },
            {
                "name": "Brute-force activity",
                "keywords": [
                    "brute force",
                    "failed login",
                    "authentication failure",
                    "multiple login attempts",
                    "password spraying",
                ],
                "score": 14,
                "severity": "MEDIUM",
            },
            {
                "name": "Defense evasion",
                "keywords": [
                    "disable antivirus",
                    "disable defender",
                    "clear logs",
                    "log deletion",
                    "obfuscated command",
                    "tamper protection",
                ],
                "score": 20,
                "severity": "HIGH",
            },
        ]

        matches: List[Dict[str, Any]] = []

        for rule in behavior_rules:
            matched_keywords = [
                keyword
                for keyword in rule["keywords"]
                if keyword in searchable_text
            ]

            if matched_keywords:
                matches.append(
                    {
                        "name": rule["name"],
                        "matched_keywords": matched_keywords,
                        "score": rule["score"],
                        "severity": rule["severity"],
                    }
                )

        return matches

    def _calculate_triage_score(
        self,
        reported_severity: str,
        behavior_signals: List[Dict[str, Any]],
        source_ips: List[str],
        domains: List[str],
        hashes: List[str],
        hostnames: List[str],
        usernames: List[str],
        is_repeat_offender: bool,
        threat_intel_verdict: str,
        risk_score: int,
    ) -> int:
        """Calculate a deterministic triage risk score."""

        score = self._severity_score(reported_severity)

        behavior_score = sum(
            int(signal["score"])
            for signal in behavior_signals
        )

        score += min(behavior_score, 35)

        if source_ips:
            score += 4

        if domains:
            score += 4

        if hashes:
            score += 8

        if hostnames:
            score += 3

        if usernames:
            score += 3

        if is_repeat_offender:
            score += 12

        malicious_verdicts = {
            "malicious",
            "confirmed_malicious",
            "suspicious",
            "high_risk",
        }

        if threat_intel_verdict in malicious_verdicts:
            score += 12

        if risk_score >= 90:
            score += 10
        elif risk_score >= 70:
            score += 7
        elif risk_score >= 50:
            score += 4

        return min(score, 100)

    @staticmethod
    def _severity_from_score(score: int) -> str:
        """Convert triage score into normalized severity."""

        if score >= 85:
            return "CRITICAL"

        if score >= 65:
            return "HIGH"

        if score >= 40:
            return "MEDIUM"

        if score >= 20:
            return "LOW"

        return "INFORMATIONAL"

    def _build_follow_up_tasks(
        self,
        task: InvestigationTask,
        priority: TaskPriority,
        source_ips: List[str],
        domains: List[str],
        hashes: List[str],
        behavior_signals: List[Dict[str, Any]],
        hostnames: List[str],
        usernames: List[str],
    ) -> List[InvestigationTask]:
        """Build specialist tasks based on triage findings."""

        proposed_tasks: List[InvestigationTask] = []

        indicators_present = bool(
            source_ips or domains or hashes
        )

        if indicators_present:
            proposed_tasks.append(
                InvestigationTask(
                    task_type="ioc_analysis",
                    assigned_agent="ioc_agent",
                    description=(
                        "Extract, normalize, validate, and classify "
                        "incident indicators."
                    ),
                    priority=priority,
                    input_data={
                        "source_ips": source_ips,
                        "domains": domains,
                        "hashes": hashes,
                    },
                    dependencies=[task.task_id],
                )
            )

            proposed_tasks.append(
                InvestigationTask(
                    task_type="threat_intelligence",
                    assigned_agent="threat_intel_agent",
                    description=(
                        "Enrich incident indicators using configured "
                        "threat-intelligence providers."
                    ),
                    priority=priority,
                    input_data={
                        "source_ips": source_ips,
                        "domains": domains,
                        "hashes": hashes,
                    },
                    dependencies=[task.task_id],
                )
            )

        if behavior_signals:
            proposed_tasks.append(
                InvestigationTask(
                    task_type="mitre_mapping",
                    assigned_agent="mitre_agent",
                    description=(
                        "Map observed behaviors to trusted MITRE "
                        "ATT&CK techniques."
                    ),
                    priority=priority,
                    input_data={
                        "behavior_signals": behavior_signals,
                    },
                    dependencies=[task.task_id],
                )
            )

        proposed_tasks.append(
            InvestigationTask(
                task_type="historical_correlation",
                assigned_agent="correlation_agent",
                description=(
                    "Correlate this incident with historical incidents, "
                    "repeat offenders, and prior attack patterns."
                ),
                priority=priority,
                input_data={
                    "source_ips": source_ips,
                    "domains": domains,
                    "hashes": hashes,
                    "hostnames": hostnames,
                    "usernames": usernames,
                },
                dependencies=[task.task_id],
            )
        )

        proposed_tasks.append(
            InvestigationTask(
                task_type="root_cause_analysis",
                assigned_agent="root_cause_agent",
                description=(
                    "Determine the most likely attack origin, attack "
                    "chain, and root cause."
                ),
                priority=priority,
                input_data={
                    "behavior_signals": behavior_signals,
                    "hostnames": hostnames,
                    "usernames": usernames,
                },
                dependencies=[task.task_id],
            )
        )

        proposed_tasks.append(
            InvestigationTask(
                task_type="response_recommendation",
                assigned_agent="response_advisor_agent",
                description=(
                    "Recommend proportionate investigation and "
                    "containment actions."
                ),
                priority=priority,
                input_data={
                    "source_ips": source_ips,
                    "hostnames": hostnames,
                    "usernames": usernames,
                },
                dependencies=[task.task_id],
            )
        )

        return proposed_tasks

    def execute_task(
        self,
        task: InvestigationTask,
    ) -> AgentExecutionResult:
        """Perform deterministic initial incident triage."""

        input_data = dict(task.input_data or {})
        investigation = self.context.investigation

        description = input_data.get(
            "description",
            investigation.description,
        )

        summary = input_data.get(
            "summary",
            investigation.title,
        )

        raw_logs = input_data.get(
            "raw_logs",
            input_data.get("logs", ""),
        )

        searchable_text = " ".join(
            [
                self._normalize_text(description),
                self._normalize_text(summary),
                self._normalize_text(raw_logs),
                self._normalize_text(input_data),
            ]
        )

        reported_severity = self._normalize_severity(
            input_data.get(
                "severity",
                investigation.severity,
            )
        )

        source_ips = self._extract_list(
            input_data,
            "source_ip",
            "source_ips",
            "ips",
            "ip_addresses",
        )

        domains = self._extract_list(
            input_data,
            "domain",
            "domains",
        )

        hashes = self._extract_list(
            input_data,
            "hash",
            "hashes",
            "file_hashes",
        )

        hostnames = self._extract_list(
            input_data,
            "hostname",
            "hostnames",
            "affected_hosts",
        )

        usernames = self._extract_list(
            input_data,
            "username",
            "usernames",
            "affected_users",
        )

        behavior_signals = self._detect_behavior_signals(
            searchable_text
        )

        is_repeat_offender = bool(
            input_data.get(
                "is_repeat_offender",
                False,
            )
        )

        threat_intel_verdict = str(
            input_data.get(
                "threat_intel_verdict",
                input_data.get("verdict", ""),
            )
        ).strip().lower()

        try:
            risk_score = int(
                input_data.get(
                    "risk_score",
                    input_data.get(
                        "combined_risk_score",
                        0,
                    ),
                )
                or 0
            )
        except (TypeError, ValueError):
            risk_score = 0

        triage_score = self._calculate_triage_score(
            reported_severity=reported_severity,
            behavior_signals=behavior_signals,
            source_ips=source_ips,
            domains=domains,
            hashes=hashes,
            hostnames=hostnames,
            usernames=usernames,
            is_repeat_offender=is_repeat_offender,
            threat_intel_verdict=threat_intel_verdict,
            risk_score=risk_score,
        )

        assessed_severity = self._severity_from_score(
            triage_score
        )

        assessed_priority = self._priority_from_score(
            triage_score
        )

        affected_entity_count = (
            len(source_ips)
            + len(domains)
            + len(hashes)
            + len(hostnames)
            + len(usernames)
        )

        investigation.severity = assessed_severity
        investigation.priority = assessed_priority

        triage_summary = (
            f"Initial triage assessed the incident as "
            f"{assessed_severity} with priority "
            f"{assessed_priority.value}. "
            f"Triage score: {triage_score}/100. "
            f"Detected {len(behavior_signals)} suspicious behavior "
            f"signal(s) and {affected_entity_count} affected "
            f"entity or indicator value(s)."
        )

        evidence: List[Evidence] = []

        evidence.append(
            Evidence(
                evidence_type=EvidenceType.AGENT_FINDING,
                source=self.agent_name,
                value={
                    "reported_severity": reported_severity,
                    "assessed_severity": assessed_severity,
                    "assessed_priority": assessed_priority.value,
                    "triage_score": triage_score,
                },
                description=(
                    "Deterministic initial incident triage assessment."
                ),
                confidence=0.90,
                tags=[
                    "triage",
                    "severity",
                    "priority",
                ],
            )
        )

        for signal in behavior_signals:
            evidence.append(
                Evidence(
                    evidence_type=EvidenceType.AGENT_FINDING,
                    source=self.agent_name,
                    value=signal,
                    description=(
                        f"Suspicious behavior detected: "
                        f"{signal['name']}."
                    ),
                    confidence=0.85,
                    tags=[
                        "triage",
                        "behavior",
                        signal["severity"].lower(),
                    ],
                )
            )

        for ip_address in source_ips:
            evidence.append(
                Evidence(
                    evidence_type=EvidenceType.IOC,
                    source=self.agent_name,
                    value=ip_address,
                    description=(
                        "IP address identified during initial triage."
                    ),
                    confidence=0.75,
                    tags=["ioc", "ip"],
                )
            )

        for domain in domains:
            evidence.append(
                Evidence(
                    evidence_type=EvidenceType.IOC,
                    source=self.agent_name,
                    value=domain,
                    description=(
                        "Domain identified during initial triage."
                    ),
                    confidence=0.75,
                    tags=["ioc", "domain"],
                )
            )

        for file_hash in hashes:
            evidence.append(
                Evidence(
                    evidence_type=EvidenceType.IOC,
                    source=self.agent_name,
                    value=file_hash,
                    description=(
                        "File hash identified during initial triage."
                    ),
                    confidence=0.80,
                    tags=["ioc", "hash"],
                )
            )

        finding = AgentFinding(
            agent_name=self.agent_name,
            title="Initial Incident Triage",
            summary=triage_summary,
            severity=assessed_severity,
            confidence=0.90,
            evidence_ids=[
                item.evidence_id
                for item in evidence
            ],
            recommendations=[
                "Preserve relevant logs and endpoint telemetry.",
                "Validate and enrich all identified indicators.",
                "Map suspicious behaviors to MITRE ATT&CK.",
                "Correlate the incident with historical activity.",
                "Investigate root cause before destructive response actions.",
            ],
            metadata={
                "triage_score": triage_score,
                "reported_severity": reported_severity,
                "assessed_priority": assessed_priority.value,
                "behavior_signals": behavior_signals,
                "source_ips": source_ips,
                "domains": domains,
                "hashes": hashes,
                "hostnames": hostnames,
                "usernames": usernames,
                "is_repeat_offender": is_repeat_offender,
                "threat_intel_verdict": threat_intel_verdict,
                "input_risk_score": risk_score,
            },
        )

        hypothesis = InvestigationHypothesis(
            title="Potential malicious security incident",
            description=(
                "The observed behaviors and indicators may represent "
                "coordinated malicious activity requiring deeper "
                "specialist investigation."
            ),
            proposed_by=self.agent_name,
            confidence=min(
                max(triage_score / 100, 0.35),
                0.95,
            ),
            supporting_evidence_ids=[
                item.evidence_id
                for item in evidence
            ],
            required_evidence=[
                "Threat-intelligence enrichment results",
                "Trusted MITRE ATT&CK mappings",
                "Historical incident correlation",
                "Root-cause analysis",
            ],
            metadata={
                "triage_score": triage_score,
                "assessed_severity": assessed_severity,
            },
        )

        proposed_tasks = self._build_follow_up_tasks(
            task=task,
            priority=assessed_priority,
            source_ips=source_ips,
            domains=domains,
            hashes=hashes,
            behavior_signals=behavior_signals,
            hostnames=hostnames,
            usernames=usernames,
        )

        self.set_shared_value(
            key="triage_assessment",
            value={
                "triage_score": triage_score,
                "reported_severity": reported_severity,
                "assessed_severity": assessed_severity,
                "assessed_priority": assessed_priority.value,
                "behavior_signals": behavior_signals,
                "source_ips": source_ips,
                "domains": domains,
                "hashes": hashes,
                "hostnames": hostnames,
                "usernames": usernames,
                "is_repeat_offender": is_repeat_offender,
                "threat_intel_verdict": threat_intel_verdict,
            },
        )

        self.send_message(
            recipient_agent="broadcast",
            subject="Initial triage completed",
            content=triage_summary,
            message_type="triage_result",
            related_task_id=task.task_id,
            related_evidence_ids=[
                item.evidence_id
                for item in evidence
            ],
            metadata={
                "severity": assessed_severity,
                "priority": assessed_priority.value,
                "triage_score": triage_score,
            },
        )

        if not triage_summary:
            raise AgentExecutionError(
                "Triage agent failed to generate a summary."
            )

        return self.create_success_result(
            summary=triage_summary,
            findings=[finding],
            evidence=evidence,
            proposed_tasks=proposed_tasks,
            proposed_hypotheses=[hypothesis],
            metadata={
                "triage_score": triage_score,
                "assessed_severity": assessed_severity,
                "assessed_priority": assessed_priority.value,
                "behavior_signal_count": len(
                    behavior_signals
                ),
                "affected_entity_count": (
                    affected_entity_count
                ),
                "proposed_task_count": len(
                    proposed_tasks
                ),
            },
        )