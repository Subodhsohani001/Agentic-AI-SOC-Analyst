from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from ..agent_base import BaseInvestigationAgent
from ..investigation_models import (
    AgentExecutionResult,
    AgentFinding,
    Evidence,
    EvidenceType,
    InvestigationTask,
    TaskPriority,
)


class MITREAgent(BaseInvestigationAgent):
    """
    Performs deterministic MITRE ATT&CK mapping.

    The agent:
    - Reads behavior signals from task input and shared triage context
    - Matches observed behavior against trusted local mappings
    - Validates technique IDs
    - Prevents unsupported or hallucinated ATT&CK mappings
    - Produces evidence, findings, and shared ATT&CK state
    """

    agent_name = "mitre_agent"
    description = (
        "Maps observed incident behavior to trusted MITRE ATT&CK "
        "techniques using deterministic evidence-based matching."
    )
    version = "0.7.0"

    TECHNIQUE_ID_PATTERN = re.compile(
        r"^T\d{4}(?:\.\d{3})?$",
        re.IGNORECASE,
    )

    DEFAULT_TECHNIQUES: Dict[str, Dict[str, Any]] = {
        "T1059.001": {
            "id": "T1059.001",
            "name": "PowerShell",
            "tactic": "Execution",
            "keywords": [
                "powershell",
                "powershell.exe",
                "encodedcommand",
                "-enc",
                "invoke-expression",
                "iex",
                "downloadstring",
            ],
        },
        "T1003": {
            "id": "T1003",
            "name": "OS Credential Dumping",
            "tactic": "Credential Access",
            "keywords": [
                "credential dump",
                "credential dumping",
                "mimikatz",
                "lsass",
                "sekurlsa",
                "procdump",
                "sam database",
            ],
        },
        "T1110": {
            "id": "T1110",
            "name": "Brute Force",
            "tactic": "Credential Access",
            "keywords": [
                "brute force",
                "password spraying",
                "failed login",
                "authentication failure",
                "multiple login attempts",
                "credential stuffing",
            ],
        },
        "T1105": {
            "id": "T1105",
            "name": "Ingress Tool Transfer",
            "tactic": "Command and Control",
            "keywords": [
                "payload download",
                "download payload",
                "remote payload transfer",
                "downloadstring",
                "invoke-webrequest",
                "curl",
                "wget",
                "bitsadmin",
                "certutil",
            ],
        },
        "T1071.001": {
            "id": "T1071.001",
            "name": "Web Protocols",
            "tactic": "Command and Control",
            "keywords": [
                "http callback",
                "https callback",
                "web protocol",
                "command and control",
                "command-and-control",
                "c2",
                "beacon",
                "callback",
                "outbound http",
                "outbound https",
            ],
        },
        "T1021.001": {
            "id": "T1021.001",
            "name": "Remote Desktop Protocol",
            "tactic": "Lateral Movement",
            "keywords": [
                "remote desktop",
                "rdp",
                "port 3389",
                "mstsc",
            ],
        },
        "T1021.002": {
            "id": "T1021.002",
            "name": "SMB/Windows Admin Shares",
            "tactic": "Lateral Movement",
            "keywords": [
                "smb",
                "admin share",
                "c$",
                "ipc$",
                "psexec",
                "windows admin share",
            ],
        },
        "T1569.002": {
            "id": "T1569.002",
            "name": "Service Execution",
            "tactic": "Execution",
            "keywords": [
                "service execution",
                "remote service",
                "service creation",
                "psexec",
                "sc.exe",
            ],
        },
        "T1053.005": {
            "id": "T1053.005",
            "name": "Scheduled Task/Job: Scheduled Task",
            "tactic": "Persistence",
            "keywords": [
                "scheduled task",
                "schtasks",
                "task scheduler",
            ],
        },
        "T1060": {
            "id": "T1060",
            "name": "Registry Run Keys / Startup Folder",
            "tactic": "Persistence",
            "keywords": [
                "registry run key",
                "startup folder",
                "runonce",
                "currentversion\\run",
            ],
        },
        "T1070.001": {
            "id": "T1070.001",
            "name": "Clear Windows Event Logs",
            "tactic": "Defense Evasion",
            "keywords": [
                "clear event logs",
                "clear logs",
                "wevtutil cl",
                "event log deletion",
            ],
        },
        "T1562.001": {
            "id": "T1562.001",
            "name": "Impair Defenses",
            "tactic": "Defense Evasion",
            "keywords": [
                "disable antivirus",
                "disable defender",
                "impair defenses",
                "tamper protection",
                "stop security service",
            ],
        },
        "T1027": {
            "id": "T1027",
            "name": "Obfuscated Files or Information",
            "tactic": "Defense Evasion",
            "keywords": [
                "obfuscated command",
                "encoded command",
                "base64 command",
                "encodedcommand",
                "obfuscation",
            ],
        },
        "T1048": {
            "id": "T1048",
            "name": "Exfiltration Over Alternative Protocol",
            "tactic": "Exfiltration",
            "keywords": [
                "data exfiltration",
                "large outbound transfer",
                "stolen data",
                "upload archive",
                "alternative protocol",
            ],
        },
        "T1087": {
            "id": "T1087",
            "name": "Account Discovery",
            "tactic": "Discovery",
            "keywords": [
                "account discovery",
                "net user",
                "whoami",
                "local users",
                "domain users",
            ],
        },
        "T1082": {
            "id": "T1082",
            "name": "System Information Discovery",
            "tactic": "Discovery",
            "keywords": [
                "systeminfo",
                "hostname discovery",
                "system information",
                "os version",
            ],
        },
        "T1018": {
            "id": "T1018",
            "name": "Remote System Discovery",
            "tactic": "Discovery",
            "keywords": [
                "remote system discovery",
                "network hosts",
                "net view",
                "arp scan",
                "host discovery",
            ],
        },
        "T1068": {
            "id": "T1068",
            "name": "Exploitation for Privilege Escalation",
            "tactic": "Privilege Escalation",
            "keywords": [
                "privilege escalation",
                "elevated privileges",
                "exploit privilege",
                "local privilege escalation",
            ],
        },
    }

    @property
    def supported_task_types(self) -> Set[str]:
        return {
            "mitre_mapping",
            "attack_mapping",
            "technique_mapping",
            "behavior_mapping",
        }

    @staticmethod
    def _flatten_text(value: Any) -> List[str]:
        """Convert nested values into searchable strings."""

        flattened: List[str] = []

        if value is None:
            return flattened

        if isinstance(value, str):
            normalized = value.strip()

            if normalized:
                flattened.append(normalized)

            return flattened

        if isinstance(value, dict):
            for key, nested_value in value.items():
                flattened.extend(
                    MITREAgent._flatten_text(key)
                )
                flattened.extend(
                    MITREAgent._flatten_text(nested_value)
                )

            return flattened

        if isinstance(value, (list, tuple, set)):
            for item in value:
                flattened.extend(
                    MITREAgent._flatten_text(item)
                )

            return flattened

        flattened.append(str(value))

        return flattened

    @classmethod
    def _normalize_technique_id(
        cls,
        technique_id: Any,
    ) -> Optional[str]:
        """Normalize and validate a MITRE technique ID."""

        normalized = str(
            technique_id or ""
        ).strip().upper()

        if not cls.TECHNIQUE_ID_PATTERN.fullmatch(
            normalized
        ):
            return None

        return normalized

    @staticmethod
    def _normalize_tactic(value: Any) -> str:
        """Normalize tactic names."""

        tactic = str(
            value or "Unknown"
        ).strip()

        return tactic.title() if tactic else "Unknown"

    def _load_external_knowledge(
        self,
    ) -> Dict[str, Dict[str, Any]]:
        """
        Load optional trusted MITRE mappings from mitre_knowledge.json.

        The loader accepts several common structures:
        - A dictionary keyed by technique ID
        - A list of technique objects
        - A dictionary containing "techniques"
        """

        configured_path = self.get_configuration(
            "mitre_knowledge_path"
        )

        candidate_paths: List[Path] = []

        if configured_path:
            candidate_paths.append(
                Path(str(configured_path))
            )

        project_root = Path(__file__).resolve().parents[2]

        candidate_paths.extend(
            [
                project_root / "mitre_knowledge.json",
                project_root
                / "knowledge"
                / "mitre_knowledge.json",
                project_root
                / "data"
                / "mitre_knowledge.json",
            ]
        )

        knowledge_path = next(
            (
                path
                for path in candidate_paths
                if path.is_file()
            ),
            None,
        )

        if knowledge_path is None:
            return {}

        try:
            raw_data = json.loads(
                knowledge_path.read_text(
                    encoding="utf-8"
                )
            )
        except (
            OSError,
            UnicodeDecodeError,
            json.JSONDecodeError,
        ):
            return {}

        if isinstance(raw_data, dict):
            if isinstance(
                raw_data.get("techniques"),
                list,
            ):
                records = raw_data["techniques"]
            elif isinstance(
                raw_data.get("techniques"),
                dict,
            ):
                records = [
                    {
                        "id": technique_id,
                        **(
                            value
                            if isinstance(value, dict)
                            else {"name": str(value)}
                        ),
                    }
                    for technique_id, value
                    in raw_data["techniques"].items()
                ]
            else:
                records = [
                    {
                        "id": technique_id,
                        **(
                            value
                            if isinstance(value, dict)
                            else {"name": str(value)}
                        ),
                    }
                    for technique_id, value
                    in raw_data.items()
                    if self._normalize_technique_id(
                        technique_id
                    )
                ]
        elif isinstance(raw_data, list):
            records = raw_data
        else:
            return {}

        loaded: Dict[str, Dict[str, Any]] = {}

        for record in records:
            if not isinstance(record, dict):
                continue

            technique_id = self._normalize_technique_id(
                record.get(
                    "id",
                    record.get(
                        "technique_id",
                        record.get("mitre_id"),
                    ),
                )
            )

            if technique_id is None:
                continue

            name = str(
                record.get(
                    "name",
                    record.get(
                        "technique_name",
                        "Unknown Technique",
                    ),
                )
            ).strip()

            tactic = self._normalize_tactic(
                record.get(
                    "tactic",
                    record.get("tactics", "Unknown"),
                )
            )

            keywords = record.get(
                "keywords",
                record.get(
                    "indicators",
                    record.get("patterns", []),
                ),
            )

            if isinstance(keywords, str):
                keyword_list = [
                    keywords.strip().lower()
                ]
            elif isinstance(keywords, list):
                keyword_list = [
                    str(keyword).strip().lower()
                    for keyword in keywords
                    if str(keyword).strip()
                ]
            else:
                keyword_list = []

            loaded[technique_id] = {
                "id": technique_id,
                "name": name,
                "tactic": tactic,
                "keywords": keyword_list,
                "source": str(knowledge_path),
            }

        return loaded

    def _get_trusted_knowledge(
        self,
    ) -> Dict[str, Dict[str, Any]]:
        """Combine built-in and external trusted mappings."""

        knowledge = {
            technique_id: dict(record)
            for technique_id, record
            in self.DEFAULT_TECHNIQUES.items()
        }

        external_knowledge = (
            self._load_external_knowledge()
        )

        for technique_id, record in external_knowledge.items():
            existing = knowledge.get(
                technique_id,
                {},
            )

            existing_keywords = {
                str(keyword).lower()
                for keyword in existing.get(
                    "keywords",
                    []
                )
            }

            external_keywords = {
                str(keyword).lower()
                for keyword in record.get(
                    "keywords",
                    []
                )
            }

            merged_keywords = sorted(
                existing_keywords
                | external_keywords
            )

            knowledge[technique_id] = {
                "id": technique_id,
                "name": record.get(
                    "name",
                    existing.get(
                        "name",
                        "Unknown Technique",
                    ),
                ),
                "tactic": record.get(
                    "tactic",
                    existing.get(
                        "tactic",
                        "Unknown",
                    ),
                ),
                "keywords": merged_keywords,
                "source": record.get(
                    "source",
                    "built_in",
                ),
            }

        return knowledge

    def _collect_behavior_input(
        self,
        task: InvestigationTask,
    ) -> Tuple[str, List[Dict[str, Any]]]:
        """Collect behavior evidence from task and shared context."""

        input_data = dict(task.input_data or {})

        triage_data = self.get_shared_value(
            "triage_assessment",
            {},
        )

        if not isinstance(triage_data, dict):
            triage_data = {}

        behavior_signals: List[Dict[str, Any]] = []

        task_signals = input_data.get(
            "behavior_signals",
            [],
        )

        shared_signals = triage_data.get(
            "behavior_signals",
            [],
        )

        for source_signals in (
            task_signals,
            shared_signals,
        ):
            if isinstance(source_signals, dict):
                source_signals = [
                    source_signals
                ]

            if not isinstance(source_signals, list):
                continue

            for signal in source_signals:
                if isinstance(signal, dict):
                    behavior_signals.append(
                        dict(signal)
                    )
                else:
                    behavior_signals.append(
                        {
                            "name": str(signal),
                            "matched_keywords": [
                                str(signal)
                            ],
                        }
                    )

        text_parts: List[str] = []

        text_parts.extend(
            self._flatten_text(input_data)
        )

        text_parts.extend(
            self._flatten_text(
                self.context.investigation.title
            )
        )

        text_parts.extend(
            self._flatten_text(
                self.context.investigation.description
            )
        )

        text_parts.extend(
            self._flatten_text(
                behavior_signals
            )
        )

        searchable_text = " ".join(
            text_parts
        ).lower()

        return searchable_text, behavior_signals

    @staticmethod
    def _score_match(
        matched_keywords: List[str],
        behavior_signals: List[Dict[str, Any]],
    ) -> int:
        """Calculate deterministic mapping score."""

        score = len(matched_keywords) * 2

        normalized_matches = {
            keyword.lower()
            for keyword in matched_keywords
        }

        for signal in behavior_signals:
            signal_name = str(
                signal.get("name", "")
            ).lower()

            signal_keywords = {
                str(keyword).lower()
                for keyword in signal.get(
                    "matched_keywords",
                    []
                )
            }

            if any(
                keyword in signal_name
                for keyword in normalized_matches
            ):
                score += 2

            overlap = (
                normalized_matches
                & signal_keywords
            )

            score += len(overlap) * 2

        return score

    @staticmethod
    def _confidence_from_score(score: int) -> float:
        """Convert mapping score into confidence."""

        if score >= 8:
            return 0.95

        if score >= 6:
            return 0.90

        if score >= 4:
            return 0.82

        if score >= 2:
            return 0.72

        return 0.60

    def _map_techniques(
        self,
        searchable_text: str,
        behavior_signals: List[Dict[str, Any]],
        trusted_knowledge: Dict[str, Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Match observed behavior against trusted techniques."""

        mappings: List[Dict[str, Any]] = []

        for technique_id, technique in (
            trusted_knowledge.items()
        ):
            keywords = [
                str(keyword).strip().lower()
                for keyword in technique.get(
                    "keywords",
                    []
                )
                if str(keyword).strip()
            ]

            matched_keywords = [
                keyword
                for keyword in keywords
                if keyword in searchable_text
            ]

            if not matched_keywords:
                continue

            score = self._score_match(
                matched_keywords=matched_keywords,
                behavior_signals=behavior_signals,
            )

            mappings.append(
                {
                    "id": technique_id,
                    "name": technique.get(
                        "name",
                        "Unknown Technique",
                    ),
                    "tactic": technique.get(
                        "tactic",
                        "Unknown",
                    ),
                    "matched_keywords": sorted(
                        set(matched_keywords)
                    ),
                    "match_score": score,
                    "confidence": (
                        self._confidence_from_score(
                            score
                        )
                    ),
                    "source": technique.get(
                        "source",
                        "built_in",
                    ),
                }
            )

        return sorted(
            mappings,
            key=lambda mapping: (
                -mapping["match_score"],
                mapping["id"],
            ),
        )

    def _validate_requested_ids(
        self,
        input_data: Dict[str, Any],
        trusted_knowledge: Dict[str, Dict[str, Any]],
    ) -> Tuple[List[Dict[str, Any]], List[str]]:
        """
        Validate explicit technique IDs supplied by upstream components.

        Explicit IDs are accepted only when present in trusted knowledge.
        """

        requested_values = input_data.get(
            "mitre_ids",
            input_data.get(
                "technique_ids",
                [],
            ),
        )

        if isinstance(requested_values, str):
            requested_values = [
                requested_values
            ]

        if not isinstance(requested_values, list):
            requested_values = []

        accepted: List[Dict[str, Any]] = []
        rejected: List[str] = []

        for raw_id in requested_values:
            normalized_id = self._normalize_technique_id(
                raw_id
            )

            if (
                normalized_id is None
                or normalized_id
                not in trusted_knowledge
            ):
                rejected.append(str(raw_id))
                continue

            record = trusted_knowledge[
                normalized_id
            ]

            accepted.append(
                {
                    "id": normalized_id,
                    "name": record.get(
                        "name",
                        "Unknown Technique",
                    ),
                    "tactic": record.get(
                        "tactic",
                        "Unknown",
                    ),
                    "matched_keywords": [],
                    "match_score": 1,
                    "confidence": 0.70,
                    "source": (
                        "validated_explicit_input"
                    ),
                }
            )

        return accepted, rejected

    @staticmethod
    def _deduplicate_mappings(
        mappings: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Deduplicate mappings by technique ID."""

        deduplicated: Dict[str, Dict[str, Any]] = {}

        for mapping in mappings:
            technique_id = mapping["id"]
            existing = deduplicated.get(
                technique_id
            )

            if existing is None:
                deduplicated[technique_id] = mapping
                continue

            if (
                mapping["match_score"]
                > existing["match_score"]
            ):
                deduplicated[technique_id] = mapping

        return sorted(
            deduplicated.values(),
            key=lambda mapping: (
                -mapping["match_score"],
                mapping["id"],
            ),
        )

    def _build_follow_up_tasks(
        self,
        task: InvestigationTask,
        mappings: List[Dict[str, Any]],
    ) -> List[InvestigationTask]:
        """Create MITRE-dependent follow-up tasks."""

        if not mappings:
            return []

        compact_mappings = [
            {
                "id": mapping["id"],
                "name": mapping["name"],
                "tactic": mapping["tactic"],
                "confidence": mapping["confidence"],
            }
            for mapping in mappings
        ]

        priority = (
            TaskPriority.P1
            if self.context.investigation.severity
            == "CRITICAL"
            else task.priority
        )

        return [
            InvestigationTask(
                task_type="root_cause_analysis",
                assigned_agent="root_cause_agent",
                description=(
                    "Use validated ATT&CK techniques to reconstruct "
                    "the likely attack chain and root cause."
                ),
                priority=priority,
                input_data={
                    "mitre_mappings": compact_mappings,
                },
                dependencies=[task.task_id],
            ),
            InvestigationTask(
                task_type="response_recommendation",
                assigned_agent="response_advisor_agent",
                description=(
                    "Use validated ATT&CK techniques to recommend "
                    "proportionate response actions."
                ),
                priority=priority,
                input_data={
                    "mitre_mappings": compact_mappings,
                },
                dependencies=[task.task_id],
            ),
        ]

    def execute_task(
        self,
        task: InvestigationTask,
    ) -> AgentExecutionResult:
        """Perform deterministic MITRE ATT&CK mapping."""

        input_data = dict(task.input_data or {})

        trusted_knowledge = (
            self._get_trusted_knowledge()
        )

        searchable_text, behavior_signals = (
            self._collect_behavior_input(task)
        )

        matched_mappings = self._map_techniques(
            searchable_text=searchable_text,
            behavior_signals=behavior_signals,
            trusted_knowledge=trusted_knowledge,
        )

        explicit_mappings, rejected_ids = (
            self._validate_requested_ids(
                input_data=input_data,
                trusted_knowledge=trusted_knowledge,
            )
        )

        mappings = self._deduplicate_mappings(
            matched_mappings
            + explicit_mappings
        )

        technique_ids = [
            mapping["id"]
            for mapping in mappings
        ]

        tactics = sorted(
            {
                mapping["tactic"]
                for mapping in mappings
            }
        )

        average_confidence = (
            round(
                sum(
                    mapping["confidence"]
                    for mapping in mappings
                )
                / len(mappings),
                2,
            )
            if mappings
            else 0.35
        )

        if mappings:
            summary = (
                f"MITRE ATT&CK analysis mapped "
                f"{len(mappings)} trusted technique(s) across "
                f"{len(tactics)} tactic(s): "
                f"{', '.join(technique_ids)}."
            )
        else:
            summary = (
                "MITRE ATT&CK analysis found no sufficiently "
                "supported trusted technique mappings."
            )

        if rejected_ids:
            summary += (
                f" Rejected {len(rejected_ids)} unsupported or "
                "untrusted technique ID value(s)."
            )

        evidence: List[Evidence] = []

        for mapping in mappings:
            evidence.append(
                Evidence(
                    evidence_type=(
                        EvidenceType.MITRE_TECHNIQUE
                    ),
                    source=self.agent_name,
                    value={
                        "id": mapping["id"],
                        "name": mapping["name"],
                        "tactic": mapping["tactic"],
                        "matched_keywords": (
                            mapping[
                                "matched_keywords"
                            ]
                        ),
                        "match_score": (
                            mapping["match_score"]
                        ),
                        "source": mapping["source"],
                    },
                    description=(
                        f"Trusted MITRE ATT&CK mapping: "
                        f"{mapping['id']} - "
                        f"{mapping['name']}."
                    ),
                    confidence=mapping["confidence"],
                    tags=[
                        "mitre",
                        "attack",
                        mapping["id"].lower(),
                        mapping["tactic"]
                        .lower()
                        .replace(" ", "_"),
                    ],
                )
            )

        severity = (
            self.context.investigation.severity
            if mappings
            else "INFORMATIONAL"
        )

        finding = AgentFinding(
            agent_name=self.agent_name,
            title="Trusted MITRE ATT&CK Mapping",
            summary=summary,
            severity=severity,
            confidence=average_confidence,
            evidence_ids=[
                item.evidence_id
                for item in evidence
            ],
            recommendations=[
                (
                    "Use only validated ATT&CK technique IDs "
                    "in analyst reports and response plans."
                ),
                (
                    "Correlate mapped techniques with historical "
                    "incident timelines."
                ),
                (
                    "Use mapped tactics to reconstruct the likely "
                    "attack chain."
                ),
            ],
            metadata={
                "technique_ids": technique_ids,
                "tactics": tactics,
                "mappings": mappings,
                "rejected_ids": rejected_ids,
                "trusted_knowledge_count": len(
                    trusted_knowledge
                ),
            },
        )

        shared_mapping = {
            "technique_ids": technique_ids,
            "tactics": tactics,
            "mappings": mappings,
            "rejected_ids": rejected_ids,
            "confidence": average_confidence,
            "trusted_knowledge_count": len(
                trusted_knowledge
            ),
        }

        self.set_shared_value(
            key="mitre_attack_mapping",
            value=shared_mapping,
        )

        self.send_message(
            recipient_agent="root_cause_agent",
            subject="Trusted ATT&CK mapping ready",
            content=summary,
            message_type="mitre_result",
            related_task_id=task.task_id,
            related_evidence_ids=[
                item.evidence_id
                for item in evidence
            ],
            metadata={
                "technique_ids": technique_ids,
                "tactics": tactics,
            },
        )

        self.send_message(
            recipient_agent="response_advisor_agent",
            subject="ATT&CK techniques ready for response planning",
            content=summary,
            message_type="mitre_result",
            related_task_id=task.task_id,
            related_evidence_ids=[
                item.evidence_id
                for item in evidence
            ],
            metadata={
                "technique_ids": technique_ids,
                "tactics": tactics,
            },
        )

        proposed_tasks = self._build_follow_up_tasks(
            task=task,
            mappings=mappings,
        )

        return self.create_success_result(
            summary=summary,
            findings=[finding],
            evidence=evidence,
            proposed_tasks=proposed_tasks,
            metadata={
                "technique_ids": technique_ids,
                "tactics": tactics,
                "mappings": mappings,
                "rejected_ids": rejected_ids,
                "mapping_count": len(mappings),
                "confidence": average_confidence,
            },
        )