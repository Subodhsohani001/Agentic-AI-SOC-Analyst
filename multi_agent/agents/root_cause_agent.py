from __future__ import annotations

from typing import Any, Dict, List, Set

from ..agent_base import BaseInvestigationAgent
from ..investigation_models import (
    AgentExecutionResult,
    AgentFinding,
    Evidence,
    EvidenceType,
    HypothesisStatus,
    InvestigationHypothesis,
    InvestigationTask,
    TaskPriority,
)


class RootCauseAgent(BaseInvestigationAgent):
    """
    Reconstructs the probable attack chain and determines root cause.

    Responsibilities:
    - Combine outputs from all specialist agents
    - Reconstruct ordered attack stages
    - Identify probable initial access and execution mechanisms
    - Evaluate supporting and contradicting evidence
    - Rank competing root-cause hypotheses
    - Produce a confidence-backed final assessment
    """

    agent_name = "root_cause_agent"
    description = (
        "Reconstructs the likely attack chain and identifies the "
        "probable root cause using evidence from all specialist agents."
    )
    version = "0.7.0"

    STAGE_ORDER = {
        "Initial Access": 1,
        "Execution": 2,
        "Persistence": 3,
        "Privilege Escalation": 4,
        "Defense Evasion": 5,
        "Credential Access": 6,
        "Discovery": 7,
        "Lateral Movement": 8,
        "Collection": 9,
        "Command and Control": 10,
        "Exfiltration": 11,
        "Impact": 12,
        "Unknown": 99,
    }

    @property
    def supported_task_types(self) -> Set[str]:
        return {
            "root_cause_analysis",
            "attack_chain_analysis",
            "causal_analysis",
            "incident_reconstruction",
        }

    @staticmethod
    def _flatten_values(value: Any) -> List[str]:
        """Flatten nested input into searchable strings."""

        values: List[str] = []

        if value is None:
            return values

        if isinstance(value, str):
            normalized = value.strip()

            if normalized:
                values.append(normalized)

            return values

        if isinstance(value, dict):
            for key, nested_value in value.items():
                values.extend(
                    RootCauseAgent._flatten_values(key)
                )
                values.extend(
                    RootCauseAgent._flatten_values(
                        nested_value
                    )
                )

            return values

        if isinstance(value, (list, tuple, set)):
            for item in value:
                values.extend(
                    RootCauseAgent._flatten_values(item)
                )

            return values

        values.append(str(value).strip())

        return values

    @staticmethod
    def _deduplicate(values: List[str]) -> List[str]:
        """Deduplicate strings while preserving order."""

        seen: Set[str] = set()
        results: List[str] = []

        for value in values:
            normalized = value.strip()

            if normalized and normalized not in seen:
                seen.add(normalized)
                results.append(normalized)

        return results

    @staticmethod
    def _safe_dict(value: Any) -> Dict[str, Any]:
        """Return a dictionary or an empty dictionary."""

        return value if isinstance(value, dict) else {}

    def _collect_sources(
        self,
        task: InvestigationTask,
    ) -> Dict[str, Any]:
        """Collect upstream specialist results."""

        return {
            "task_input": dict(task.input_data or {}),
            "triage": self._safe_dict(
                self.get_shared_value(
                    "triage_assessment",
                    {},
                )
            ),
            "iocs": self._safe_dict(
                self.get_shared_value(
                    "normalized_iocs",
                    {},
                )
            ),
            "mitre": self._safe_dict(
                self.get_shared_value(
                    "mitre_attack_mapping",
                    {},
                )
            ),
            "threat_intelligence": self._safe_dict(
                self.get_shared_value(
                    "threat_intelligence_results",
                    {},
                )
            ),
            "correlation": self._safe_dict(
                self.get_shared_value(
                    "historical_correlation",
                    {},
                )
            ),
        }

    def _build_searchable_text(
        self,
        sources: Dict[str, Any],
    ) -> str:
        """Build normalized text used for deterministic matching."""

        investigation = self.context.investigation

        values = [
            investigation.title,
            investigation.description,
            sources,
        ]

        return " ".join(
            self._flatten_values(values)
        ).lower()

    def _collect_mitre_mappings(
        self,
        sources: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Collect trusted MITRE mappings from all available inputs."""

        mappings: List[Dict[str, Any]] = []

        shared_mappings = sources["mitre"].get(
            "mappings",
            [],
        )

        task_mappings = sources["task_input"].get(
            "mitre_mappings",
            [],
        )

        for source_mappings in (
            shared_mappings,
            task_mappings,
        ):
            if isinstance(source_mappings, dict):
                source_mappings = [
                    source_mappings
                ]

            if not isinstance(source_mappings, list):
                continue

            for mapping in source_mappings:
                if not isinstance(mapping, dict):
                    continue

                technique_id = str(
                    mapping.get("id", "")
                ).strip().upper()

                if not technique_id:
                    continue

                mappings.append(
                    {
                        "id": technique_id,
                        "name": str(
                            mapping.get(
                                "name",
                                "Unknown Technique",
                            )
                        ),
                        "tactic": str(
                            mapping.get(
                                "tactic",
                                "Unknown",
                            )
                        ),
                        "confidence": float(
                            mapping.get(
                                "confidence",
                                0.70,
                            )
                            or 0.70
                        ),
                        "matched_keywords": (
                            mapping.get(
                                "matched_keywords",
                                [],
                            )
                        ),
                    }
                )

        technique_ids = self._deduplicate(
            self._flatten_values(
                sources["mitre"].get(
                    "technique_ids",
                    [],
                )
            )
            + self._flatten_values(
                sources["task_input"].get(
                    "mitre_ids",
                    [],
                )
            )
        )

        existing_ids = {
            mapping["id"]
            for mapping in mappings
        }

        for technique_id in technique_ids:
            normalized_id = technique_id.upper()

            if normalized_id not in existing_ids:
                mappings.append(
                    {
                        "id": normalized_id,
                        "name": "Trusted upstream mapping",
                        "tactic": "Unknown",
                        "confidence": 0.65,
                        "matched_keywords": [],
                    }
                )

        deduplicated: Dict[str, Dict[str, Any]] = {}

        for mapping in mappings:
            existing = deduplicated.get(
                mapping["id"]
            )

            if (
                existing is None
                or mapping["confidence"]
                > existing["confidence"]
            ):
                deduplicated[
                    mapping["id"]
                ] = mapping

        return list(deduplicated.values())

    def _extract_threat_findings(
        self,
        sources: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Extract compact threat-intelligence findings."""

        records = sources[
            "threat_intelligence"
        ].get("observables", [])

        if not isinstance(records, list):
            records = []

        findings: List[Dict[str, Any]] = []

        for record in records:
            if not isinstance(record, dict):
                continue

            findings.append(
                {
                    "observable": record.get(
                        "observable"
                    ),
                    "observable_type": record.get(
                        "observable_type"
                    ),
                    "verdict": str(
                        record.get(
                            "verdict",
                            "unknown",
                        )
                    ).lower(),
                    "risk_score": int(
                        record.get(
                            "risk_score",
                            0,
                        )
                        or 0
                    ),
                    "severity": str(
                        record.get(
                            "severity",
                            "UNKNOWN",
                        )
                    ).upper(),
                    "confidence": float(
                        record.get(
                            "confidence",
                            0.50,
                        )
                        or 0.50
                    ),
                }
            )

        task_findings = sources[
            "task_input"
        ].get(
            "threat_intelligence_results",
            [],
        )

        if isinstance(task_findings, dict):
            task_findings = [task_findings]

        if isinstance(task_findings, list):
            for record in task_findings:
                if (
                    isinstance(record, dict)
                    and record not in findings
                ):
                    findings.append(
                        dict(record)
                    )

        return findings

    def _build_attack_stages(
        self,
        searchable_text: str,
        mitre_mappings: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Build ordered attack-chain stages."""

        stages: Dict[str, Dict[str, Any]] = {}

        def add_stage(
            stage_name: str,
            evidence: str,
            confidence: float,
            technique_id: str | None = None,
        ) -> None:
            existing = stages.get(stage_name)

            if existing is None:
                existing = {
                    "stage": stage_name,
                    "evidence": [],
                    "technique_ids": [],
                    "confidence": confidence,
                }
                stages[stage_name] = existing

            if evidence not in existing["evidence"]:
                existing["evidence"].append(evidence)

            if (
                technique_id
                and technique_id
                not in existing["technique_ids"]
            ):
                existing["technique_ids"].append(
                    technique_id
                )

            existing["confidence"] = max(
                existing["confidence"],
                confidence,
            )

        for mapping in mitre_mappings:
            tactic = str(
                mapping.get(
                    "tactic",
                    "Unknown",
                )
            ).title()

            if tactic not in self.STAGE_ORDER:
                tactic = "Unknown"

            add_stage(
                stage_name=tactic,
                evidence=(
                    f"{mapping['id']} - "
                    f"{mapping['name']}"
                ),
                confidence=float(
                    mapping.get(
                        "confidence",
                        0.70,
                    )
                ),
                technique_id=mapping["id"],
            )

        behavior_rules = [
            {
                "stage": "Initial Access",
                "keywords": [
                    "phishing",
                    "malicious attachment",
                    "exploit public-facing",
                    "drive-by compromise",
                    "valid accounts",
                    "external remote service",
                ],
                "confidence": 0.72,
            },
            {
                "stage": "Execution",
                "keywords": [
                    "powershell",
                    "command execution",
                    "script execution",
                    "payload executed",
                    "encodedcommand",
                    "cmd.exe",
                ],
                "confidence": 0.88,
            },
            {
                "stage": "Persistence",
                "keywords": [
                    "scheduled task",
                    "run key",
                    "startup folder",
                    "service creation",
                    "persistence",
                ],
                "confidence": 0.80,
            },
            {
                "stage": "Privilege Escalation",
                "keywords": [
                    "privilege escalation",
                    "elevated privilege",
                    "system privilege",
                    "administrator access",
                ],
                "confidence": 0.78,
            },
            {
                "stage": "Defense Evasion",
                "keywords": [
                    "disable defender",
                    "disable antivirus",
                    "clear logs",
                    "obfuscation",
                    "encoded command",
                ],
                "confidence": 0.82,
            },
            {
                "stage": "Credential Access",
                "keywords": [
                    "credential dump",
                    "mimikatz",
                    "lsass",
                    "procdump",
                    "password spraying",
                ],
                "confidence": 0.88,
            },
            {
                "stage": "Discovery",
                "keywords": [
                    "systeminfo",
                    "whoami",
                    "net user",
                    "account discovery",
                    "host discovery",
                ],
                "confidence": 0.75,
            },
            {
                "stage": "Lateral Movement",
                "keywords": [
                    "psexec",
                    "remote desktop",
                    "rdp",
                    "smb",
                    "remote service",
                    "lateral movement",
                ],
                "confidence": 0.82,
            },
            {
                "stage": "Command and Control",
                "keywords": [
                    "command and control",
                    "command-and-control",
                    "c2",
                    "beacon",
                    "callback",
                    "outbound connection",
                ],
                "confidence": 0.90,
            },
            {
                "stage": "Exfiltration",
                "keywords": [
                    "exfiltration",
                    "data theft",
                    "large outbound transfer",
                    "upload archive",
                ],
                "confidence": 0.88,
            },
            {
                "stage": "Impact",
                "keywords": [
                    "ransomware",
                    "data destruction",
                    "service disruption",
                    "encryption",
                    "impact",
                ],
                "confidence": 0.90,
            },
        ]

        for rule in behavior_rules:
            matched_keywords = [
                keyword
                for keyword in rule["keywords"]
                if keyword in searchable_text
            ]

            if matched_keywords:
                add_stage(
                    stage_name=rule["stage"],
                    evidence=(
                        "Observed behavior: "
                        + ", ".join(
                            matched_keywords
                        )
                    ),
                    confidence=rule["confidence"],
                )

        return sorted(
            stages.values(),
            key=lambda stage: (
                self.STAGE_ORDER.get(
                    stage["stage"],
                    99,
                ),
                stage["stage"],
            ),
        )

    def _determine_initial_access(
        self,
        searchable_text: str,
        attack_stages: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Determine the most likely initial-access mechanism."""

        candidates = [
            {
                "method": "Phishing",
                "keywords": [
                    "phishing",
                    "malicious email",
                    "malicious attachment",
                    "spearphishing",
                ],
                "confidence": 0.86,
            },
            {
                "method": "Exploitation of public-facing application",
                "keywords": [
                    "public-facing application",
                    "web exploit",
                    "remote code execution",
                    "vulnerable service",
                ],
                "confidence": 0.82,
            },
            {
                "method": "Compromised or valid account",
                "keywords": [
                    "valid account",
                    "compromised account",
                    "password spraying",
                    "brute force",
                    "stolen credential",
                ],
                "confidence": 0.80,
            },
            {
                "method": "External remote service",
                "keywords": [
                    "external remote service",
                    "remote desktop",
                    "rdp",
                    "vpn login",
                ],
                "confidence": 0.75,
            },
            {
                "method": "Malicious script or downloaded payload",
                "keywords": [
                    "download payload",
                    "payload download",
                    "powershell",
                    "downloadstring",
                    "invoke-webrequest",
                ],
                "confidence": 0.72,
            },
        ]

        ranked_candidates: List[Dict[str, Any]] = []

        for candidate in candidates:
            matched = [
                keyword
                for keyword in candidate[
                    "keywords"
                ]
                if keyword in searchable_text
            ]

            if matched:
                ranked_candidates.append(
                    {
                        "method": candidate[
                            "method"
                        ],
                        "confidence": min(
                            candidate[
                                "confidence"
                            ]
                            + (
                                len(matched) - 1
                            )
                            * 0.03,
                            0.95,
                        ),
                        "evidence": matched,
                    }
                )

        if ranked_candidates:
            return max(
                ranked_candidates,
                key=lambda item: item[
                    "confidence"
                ],
            )

        has_execution = any(
            stage["stage"] == "Execution"
            for stage in attack_stages
        )

        if has_execution:
            return {
                "method": (
                    "Unknown initial access preceding "
                    "confirmed execution"
                ),
                "confidence": 0.45,
                "evidence": [
                    "Execution was observed, but initial access "
                    "telemetry is unavailable."
                ],
            }

        return {
            "method": "Undetermined",
            "confidence": 0.30,
            "evidence": [
                "Insufficient initial-access evidence."
            ],
        }

    def _determine_root_cause(
        self,
        searchable_text: str,
        attack_stages: List[Dict[str, Any]],
        threat_findings: List[Dict[str, Any]],
        correlation: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Determine the probable root cause."""

        candidates: List[Dict[str, Any]] = []

        def add_candidate(
            cause: str,
            score: int,
            evidence: List[str],
        ) -> None:
            candidates.append(
                {
                    "cause": cause,
                    "score": min(
                        max(score, 0),
                        100,
                    ),
                    "evidence": evidence,
                }
            )

        credential_keywords = [
            "brute force",
            "password spraying",
            "valid account",
            "stolen credential",
            "compromised account",
        ]

        matched_credentials = [
            keyword
            for keyword in credential_keywords
            if keyword in searchable_text
        ]

        if matched_credentials:
            add_candidate(
                cause=(
                    "Compromised credentials or weak "
                    "authentication controls"
                ),
                score=78
                + min(
                    len(matched_credentials) * 3,
                    12,
                ),
                evidence=matched_credentials,
            )

        script_keywords = [
            "powershell",
            "encodedcommand",
            "downloadstring",
            "invoke-expression",
            "malicious script",
        ]

        matched_scripts = [
            keyword
            for keyword in script_keywords
            if keyword in searchable_text
        ]

        if matched_scripts:
            add_candidate(
                cause=(
                    "Malicious PowerShell or script execution "
                    "was permitted without sufficient prevention"
                ),
                score=74
                + min(
                    len(matched_scripts) * 3,
                    15,
                ),
                evidence=matched_scripts,
            )

        vulnerability_keywords = [
            "vulnerable service",
            "unpatched",
            "remote code execution",
            "public-facing application",
            "exploit",
        ]

        matched_vulnerabilities = [
            keyword
            for keyword in vulnerability_keywords
            if keyword in searchable_text
        ]

        if matched_vulnerabilities:
            add_candidate(
                cause=(
                    "Exploitation of an exposed or "
                    "insufficiently patched system"
                ),
                score=76
                + min(
                    len(
                        matched_vulnerabilities
                    )
                    * 3,
                    15,
                ),
                evidence=matched_vulnerabilities,
            )

        phishing_keywords = [
            "phishing",
            "malicious attachment",
            "malicious email",
            "spearphishing",
        ]

        matched_phishing = [
            keyword
            for keyword in phishing_keywords
            if keyword in searchable_text
        ]

        if matched_phishing:
            add_candidate(
                cause=(
                    "User execution of phishing-delivered "
                    "malicious content"
                ),
                score=80
                + min(
                    len(matched_phishing) * 3,
                    12,
                ),
                evidence=matched_phishing,
            )

        malicious_observables = [
            finding
            for finding in threat_findings
            if str(
                finding.get(
                    "verdict",
                    "",
                )
            ).lower()
            in {
                "malicious",
                "confirmed_malicious",
            }
        ]

        if malicious_observables:
            add_candidate(
                cause=(
                    "Execution or communication involving "
                    "confirmed malicious infrastructure"
                ),
                score=72
                + min(
                    len(
                        malicious_observables
                    )
                    * 5,
                    18,
                ),
                evidence=[
                    str(
                        finding.get(
                            "observable"
                        )
                    )
                    for finding
                    in malicious_observables
                ],
            )

        if correlation.get(
            "is_repeat_offender",
            False,
        ):
            add_candidate(
                cause=(
                    "Previously observed malicious "
                    "infrastructure or recurring attacker activity"
                ),
                score=max(
                    int(
                        correlation.get(
                            "correlation_score",
                            0,
                        )
                        or 0
                    ),
                    75,
                ),
                evidence=self._flatten_values(
                    correlation.get(
                        "repeated_entities",
                        {},
                    )
                ),
            )

        if not candidates:
            has_c2 = any(
                stage["stage"]
                == "Command and Control"
                for stage in attack_stages
            )

            if has_c2:
                add_candidate(
                    cause=(
                        "Unauthorized code execution followed "
                        "by command-and-control communication"
                    ),
                    score=62,
                    evidence=[
                        "Execution and command-and-control stages "
                        "were observed."
                    ],
                )
            else:
                add_candidate(
                    cause=(
                        "Insufficient evidence to determine a "
                        "specific technical root cause"
                    ),
                    score=35,
                    evidence=[
                        "Additional endpoint, identity, and network "
                        "telemetry is required."
                    ],
                )

        ranked = sorted(
            candidates,
            key=lambda item: (
                -item["score"],
                item["cause"],
            ),
        )

        primary = ranked[0]

        return {
            "primary_cause": primary["cause"],
            "confidence": round(
                primary["score"] / 100,
                2,
            ),
            "supporting_evidence": primary[
                "evidence"
            ],
            "alternative_causes": [
                {
                    "cause": item["cause"],
                    "confidence": round(
                        item["score"] / 100,
                        2,
                    ),
                    "evidence": item[
                        "evidence"
                    ],
                }
                for item in ranked[1:4]
            ],
        }

    @staticmethod
    def _calculate_overall_confidence(
        attack_stages: List[Dict[str, Any]],
        initial_access: Dict[str, Any],
        root_cause: Dict[str, Any],
        threat_findings: List[Dict[str, Any]],
        correlation: Dict[str, Any],
    ) -> float:
        """Calculate confidence in the complete root-cause assessment."""

        values = [
            float(
                root_cause.get(
                    "confidence",
                    0.30,
                )
            ),
            float(
                initial_access.get(
                    "confidence",
                    0.30,
                )
            ),
        ]

        if attack_stages:
            values.append(
                sum(
                    float(
                        stage.get(
                            "confidence",
                            0.50,
                        )
                    )
                    for stage in attack_stages
                )
                / len(attack_stages)
            )

        if threat_findings:
            values.append(
                sum(
                    float(
                        finding.get(
                            "confidence",
                            0.50,
                        )
                    )
                    for finding
                    in threat_findings
                )
                / len(threat_findings)
            )

        correlation_confidence = correlation.get(
            "confidence"
        )

        if isinstance(
            correlation_confidence,
            (int, float),
        ):
            values.append(
                float(correlation_confidence)
            )

        return min(
            max(
                round(
                    sum(values)
                    / len(values),
                    2,
                ),
                0.30,
            ),
            0.98,
        )

    @staticmethod
    def _severity_from_assessment(
        root_cause: Dict[str, Any],
        attack_stages: List[Dict[str, Any]],
        threat_findings: List[Dict[str, Any]],
    ) -> str:
        """Determine finding severity."""

        if any(
            finding.get("severity")
            == "CRITICAL"
            for finding in threat_findings
        ):
            return "CRITICAL"

        if any(
            stage["stage"]
            in {
                "Credential Access",
                "Lateral Movement",
                "Exfiltration",
                "Impact",
            }
            for stage in attack_stages
        ):
            return "CRITICAL"

        if root_cause.get(
            "confidence",
            0,
        ) >= 0.75:
            return "HIGH"

        return "MEDIUM"

    def _build_response_task(
        self,
        task: InvestigationTask,
        assessment: Dict[str, Any],
    ) -> InvestigationTask:
        """Build the response-advisor task."""

        severity = assessment["severity"]

        priority = (
            TaskPriority.P1
            if severity == "CRITICAL"
            else TaskPriority.P2
            if severity == "HIGH"
            else TaskPriority.P3
        )

        return InvestigationTask(
            task_type="response_recommendation",
            assigned_agent="response_advisor_agent",
            description=(
                "Recommend evidence-based response actions using "
                "the completed root-cause assessment."
            ),
            priority=priority,
            input_data={
                "root_cause_assessment": assessment,
            },
            dependencies=[task.task_id],
        )

    def execute_task(
        self,
        task: InvestigationTask,
    ) -> AgentExecutionResult:
        """Reconstruct the attack chain and determine root cause."""

        sources = self._collect_sources(task)

        searchable_text = (
            self._build_searchable_text(
                sources
            )
        )

        mitre_mappings = (
            self._collect_mitre_mappings(
                sources
            )
        )

        threat_findings = (
            self._extract_threat_findings(
                sources
            )
        )

        correlation = sources["correlation"]

        task_correlation = sources[
            "task_input"
        ].get(
            "historical_correlation",
            {},
        )

        if (
            not correlation
            and isinstance(
                task_correlation,
                dict,
            )
        ):
            correlation = task_correlation

        attack_stages = self._build_attack_stages(
            searchable_text=searchable_text,
            mitre_mappings=mitre_mappings,
        )

        initial_access = (
            self._determine_initial_access(
                searchable_text=searchable_text,
                attack_stages=attack_stages,
            )
        )

        root_cause = self._determine_root_cause(
            searchable_text=searchable_text,
            attack_stages=attack_stages,
            threat_findings=threat_findings,
            correlation=correlation,
        )

        overall_confidence = (
            self._calculate_overall_confidence(
                attack_stages=attack_stages,
                initial_access=initial_access,
                root_cause=root_cause,
                threat_findings=threat_findings,
                correlation=correlation,
            )
        )

        severity = self._severity_from_assessment(
            root_cause=root_cause,
            attack_stages=attack_stages,
            threat_findings=threat_findings,
        )

        attack_chain_names = [
            stage["stage"]
            for stage in attack_stages
        ]

        assessment = {
            "primary_root_cause": (
                root_cause["primary_cause"]
            ),
            "root_cause_confidence": (
                root_cause["confidence"]
            ),
            "overall_confidence": (
                overall_confidence
            ),
            "severity": severity,
            "probable_initial_access": (
                initial_access
            ),
            "attack_chain": attack_stages,
            "attack_chain_stages": (
                attack_chain_names
            ),
            "mitre_techniques": (
                mitre_mappings
            ),
            "threat_intelligence_findings": (
                threat_findings
            ),
            "historical_correlation": (
                correlation
            ),
            "supporting_evidence": (
                root_cause[
                    "supporting_evidence"
                ]
            ),
            "alternative_causes": (
                root_cause[
                    "alternative_causes"
                ]
            ),
        }

        if attack_chain_names:
            chain_text = " → ".join(
                attack_chain_names
            )
        else:
            chain_text = (
                "No complete attack chain established"
            )

        summary = (
            f"Root-cause analysis identified "
            f"'{root_cause['primary_cause']}' as the most probable "
            f"cause with {root_cause['confidence']:.0%} root-cause "
            f"confidence and {overall_confidence:.0%} overall "
            f"assessment confidence. Reconstructed attack chain: "
            f"{chain_text}."
        )

        evidence: List[Evidence] = []

        evidence.append(
            Evidence(
                evidence_type=(
                    EvidenceType.AGENT_FINDING
                ),
                source=self.agent_name,
                value={
                    "primary_root_cause": (
                        root_cause[
                            "primary_cause"
                        ]
                    ),
                    "confidence": (
                        root_cause[
                            "confidence"
                        ]
                    ),
                    "supporting_evidence": (
                        root_cause[
                            "supporting_evidence"
                        ]
                    ),
                },
                description=(
                    "Deterministic root-cause assessment."
                ),
                confidence=overall_confidence,
                tags=[
                    "root_cause",
                    "causal_analysis",
                    severity.lower(),
                ],
            )
        )

        for index, stage in enumerate(
            attack_stages,
            start=1,
        ):
            evidence.append(
                Evidence(
                    evidence_type=(
                        EvidenceType.AGENT_FINDING
                    ),
                    source=self.agent_name,
                    value={
                        "sequence": index,
                        **stage,
                    },
                    description=(
                        f"Attack-chain stage {index}: "
                        f"{stage['stage']}."
                    ),
                    confidence=float(
                        stage["confidence"]
                    ),
                    tags=[
                        "attack_chain",
                        stage["stage"]
                        .lower()
                        .replace(" ", "_"),
                    ],
                )
            )

        finding = AgentFinding(
            agent_name=self.agent_name,
            title="Root-Cause and Attack-Chain Assessment",
            summary=summary,
            severity=severity,
            confidence=overall_confidence,
            evidence_ids=[
                item.evidence_id
                for item in evidence
            ],
            recommendations=[
                (
                    "Preserve endpoint, identity, and network "
                    "telemetry supporting the reconstructed chain."
                ),
                (
                    "Address the identified root control failure "
                    "before closing the incident."
                ),
                (
                    "Validate the probable initial-access method "
                    "using authentication and endpoint evidence."
                ),
                (
                    "Use the reconstructed attack stages to select "
                    "containment and eradication actions."
                ),
            ],
            metadata=assessment,
        )

        hypothesis_status = (
            HypothesisStatus.CONFIRMED
            if overall_confidence >= 0.85
            else HypothesisStatus.SUPPORTED
            if overall_confidence >= 0.65
            else HypothesisStatus.INCONCLUSIVE
        )

        hypothesis = InvestigationHypothesis(
            title="Primary root-cause hypothesis",
            description=(
                root_cause["primary_cause"]
            ),
            proposed_by=self.agent_name,
            confidence=overall_confidence,
            status=hypothesis_status,
            supporting_evidence_ids=[
                item.evidence_id
                for item in evidence
            ],
            required_evidence=(
                []
                if hypothesis_status
                == HypothesisStatus.CONFIRMED
                else [
                    (
                        "Initial-access telemetry confirming "
                        "the entry mechanism"
                    ),
                    (
                        "Endpoint process ancestry and command-line "
                        "evidence"
                    ),
                    (
                        "Identity and authentication logs for "
                        "affected users"
                    ),
                ]
            ),
            metadata={
                "root_cause": root_cause,
                "initial_access": initial_access,
                "attack_chain_stages": (
                    attack_chain_names
                ),
            },
        )

        self.set_shared_value(
            key="root_cause_assessment",
            value=assessment,
        )

        self.set_shared_value(
            key="attack_chain",
            value=attack_stages,
        )

        self.send_message(
            recipient_agent=(
                "response_advisor_agent"
            ),
            subject=(
                "Root-cause assessment ready"
            ),
            content=summary,
            message_type="root_cause_result",
            related_task_id=task.task_id,
            related_evidence_ids=[
                item.evidence_id
                for item in evidence
            ],
            metadata={
                "primary_root_cause": (
                    root_cause[
                        "primary_cause"
                    ]
                ),
                "severity": severity,
                "overall_confidence": (
                    overall_confidence
                ),
                "attack_chain_stages": (
                    attack_chain_names
                ),
            },
        )

        response_task = (
            self._build_response_task(
                task=task,
                assessment=assessment,
            )
        )

        return self.create_success_result(
            summary=summary,
            findings=[finding],
            evidence=evidence,
            proposed_tasks=[response_task],
            proposed_hypotheses=[
                hypothesis
            ],
            metadata=assessment,
        )