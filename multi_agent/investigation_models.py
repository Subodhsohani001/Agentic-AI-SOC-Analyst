from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4


def utc_now() -> str:
    """Return the current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def generate_identifier(prefix: str) -> str:
    """Generate a readable unique identifier."""
    return f"{prefix}-{uuid4().hex[:10].upper()}"


class InvestigationStatus(str, Enum):
    CREATED = "created"
    TRIAGING = "triaging"
    INVESTIGATING = "investigating"
    AWAITING_EVIDENCE = "awaiting_evidence"
    ANALYZING = "analyzing"
    COMPLETED = "completed"
    FAILED = "failed"


class TaskStatus(str, Enum):
    PENDING = "pending"
    ASSIGNED = "assigned"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"
    SKIPPED = "skipped"


class TaskPriority(str, Enum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


class EvidenceType(str, Enum):
    LOG = "log"
    IOC = "ioc"
    THREAT_INTELLIGENCE = "threat_intelligence"
    MITRE_TECHNIQUE = "mitre_technique"
    HISTORICAL_INCIDENT = "historical_incident"
    PROCESS = "process"
    NETWORK = "network"
    USER_ACTIVITY = "user_activity"
    HOST_ACTIVITY = "host_activity"
    AGENT_FINDING = "agent_finding"
    OTHER = "other"


class HypothesisStatus(str, Enum):
    PROPOSED = "proposed"
    INVESTIGATING = "investigating"
    SUPPORTED = "supported"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"


@dataclass
class Evidence:
    evidence_type: EvidenceType
    source: str
    value: Any
    description: str = ""
    confidence: float = 0.5
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    evidence_id: str = field(
        default_factory=lambda: generate_identifier("EVD")
    )
    created_at: str = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("Evidence confidence must be between 0.0 and 1.0.")

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["evidence_type"] = self.evidence_type.value
        return data


@dataclass
class AgentFinding:
    agent_name: str
    title: str
    summary: str
    severity: str
    confidence: float
    evidence_ids: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    finding_id: str = field(
        default_factory=lambda: generate_identifier("FND")
    )
    created_at: str = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        if not self.agent_name.strip():
            raise ValueError("agent_name cannot be empty.")

        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("Finding confidence must be between 0.0 and 1.0.")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class InvestigationTask:
    task_type: str
    assigned_agent: str
    description: str
    priority: TaskPriority = TaskPriority.P3
    input_data: Dict[str, Any] = field(default_factory=dict)
    dependencies: List[str] = field(default_factory=list)
    status: TaskStatus = TaskStatus.PENDING
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    task_id: str = field(
        default_factory=lambda: generate_identifier("TSK")
    )
    created_at: str = field(default_factory=utc_now)
    started_at: Optional[str] = None
    completed_at: Optional[str] = None

    def mark_running(self) -> None:
        self.status = TaskStatus.RUNNING
        self.started_at = utc_now()

    def mark_completed(self, result: Dict[str, Any]) -> None:
        self.status = TaskStatus.COMPLETED
        self.result = result
        self.error = None
        self.completed_at = utc_now()

    def mark_failed(self, error: str) -> None:
        self.status = TaskStatus.FAILED
        self.error = error
        self.completed_at = utc_now()

    def mark_blocked(self, reason: str) -> None:
        self.status = TaskStatus.BLOCKED
        self.error = reason

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["priority"] = self.priority.value
        data["status"] = self.status.value
        return data


@dataclass
class InvestigationHypothesis:
    title: str
    description: str
    proposed_by: str
    confidence: float = 0.5
    status: HypothesisStatus = HypothesisStatus.PROPOSED
    supporting_evidence_ids: List[str] = field(default_factory=list)
    contradicting_evidence_ids: List[str] = field(default_factory=list)
    required_evidence: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    hypothesis_id: str = field(
        default_factory=lambda: generate_identifier("HYP")
    )
    created_at: str = field(default_factory=utc_now)
    updated_at: str = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(
                "Hypothesis confidence must be between 0.0 and 1.0."
            )

    def update_confidence(self, confidence: float) -> None:
        if not 0.0 <= confidence <= 1.0:
            raise ValueError(
                "Hypothesis confidence must be between 0.0 and 1.0."
            )

        self.confidence = confidence
        self.updated_at = utc_now()

    def set_status(self, status: HypothesisStatus) -> None:
        self.status = status
        self.updated_at = utc_now()

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        return data


@dataclass
class AgentExecutionResult:
    agent_name: str
    success: bool
    summary: str
    findings: List[AgentFinding] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)
    proposed_tasks: List[InvestigationTask] = field(default_factory=list)
    proposed_hypotheses: List[InvestigationHypothesis] = field(
        default_factory=list
    )
    metadata: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    execution_id: str = field(
        default_factory=lambda: generate_identifier("EXE")
    )
    created_at: str = field(default_factory=utc_now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "agent_name": self.agent_name,
            "success": self.success,
            "summary": self.summary,
            "findings": [finding.to_dict() for finding in self.findings],
            "evidence": [item.to_dict() for item in self.evidence],
            "proposed_tasks": [
                task.to_dict() for task in self.proposed_tasks
            ],
            "proposed_hypotheses": [
                hypothesis.to_dict()
                for hypothesis in self.proposed_hypotheses
            ],
            "metadata": self.metadata,
            "error": self.error,
            "created_at": self.created_at,
        }


@dataclass
class Investigation:
    incident_id: str
    title: str
    description: str
    severity: str = "UNKNOWN"
    priority: TaskPriority = TaskPriority.P3
    status: InvestigationStatus = InvestigationStatus.CREATED
    tasks: List[InvestigationTask] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)
    findings: List[AgentFinding] = field(default_factory=list)
    hypotheses: List[InvestigationHypothesis] = field(default_factory=list)
    participating_agents: List[str] = field(default_factory=list)
    final_assessment: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    investigation_id: str = field(
        default_factory=lambda: generate_identifier("INV")
    )
    created_at: str = field(default_factory=utc_now)
    updated_at: str = field(default_factory=utc_now)
    completed_at: Optional[str] = None

    def add_task(self, task: InvestigationTask) -> None:
        if any(existing.task_id == task.task_id for existing in self.tasks):
            return

        self.tasks.append(task)
        self.updated_at = utc_now()

    def add_evidence(self, evidence: Evidence) -> None:
        if any(
            existing.evidence_id == evidence.evidence_id
            for existing in self.evidence
        ):
            return

        self.evidence.append(evidence)
        self.updated_at = utc_now()

    def add_finding(self, finding: AgentFinding) -> None:
        if any(
            existing.finding_id == finding.finding_id
            for existing in self.findings
        ):
            return

        self.findings.append(finding)

        if finding.agent_name not in self.participating_agents:
            self.participating_agents.append(finding.agent_name)

        self.updated_at = utc_now()

    def add_hypothesis(
        self,
        hypothesis: InvestigationHypothesis,
    ) -> None:
        if any(
            existing.hypothesis_id == hypothesis.hypothesis_id
            for existing in self.hypotheses
        ):
            return

        self.hypotheses.append(hypothesis)
        self.updated_at = utc_now()

    def set_status(self, status: InvestigationStatus) -> None:
        self.status = status
        self.updated_at = utc_now()

        if status == InvestigationStatus.COMPLETED:
            self.completed_at = utc_now()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "investigation_id": self.investigation_id,
            "incident_id": self.incident_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "priority": self.priority.value,
            "status": self.status.value,
            "tasks": [task.to_dict() for task in self.tasks],
            "evidence": [item.to_dict() for item in self.evidence],
            "findings": [finding.to_dict() for finding in self.findings],
            "hypotheses": [
                hypothesis.to_dict()
                for hypothesis in self.hypotheses
            ],
            "participating_agents": self.participating_agents,
            "final_assessment": self.final_assessment,
            "metadata": self.metadata,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "completed_at": self.completed_at,
        }