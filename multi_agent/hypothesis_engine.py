from __future__ import annotations

from typing import Any, Dict, List, Optional, Set

from .investigation_models import (
    Evidence,
    HypothesisStatus,
    InvestigationHypothesis,
    utc_now,
)
from .shared_context import SharedInvestigationContext


class HypothesisEngineError(Exception):
    """Raised when hypothesis processing cannot be completed."""


class HypothesisEngine:
    """
    Manages investigation hypotheses.

    Responsibilities:
    - Create and register hypotheses
    - Link supporting and contradicting evidence
    - Recalculate confidence deterministically
    - Rank competing hypotheses
    - Promote, reject, or mark hypotheses inconclusive
    - Identify missing evidence
    - Produce a compact hypothesis assessment
    """

    def __init__(
        self,
        context: SharedInvestigationContext,
        configuration: Optional[Dict[str, Any]] = None,
    ) -> None:
        if not isinstance(context, SharedInvestigationContext):
            raise TypeError(
                "context must be a SharedInvestigationContext instance."
            )

        self.context = context
        self.configuration = configuration or {}

    @staticmethod
    def _clamp_confidence(value: float) -> float:
        """Clamp confidence into the supported range."""

        return min(
            max(round(float(value), 2), 0.0),
            1.0,
        )

    @staticmethod
    def _deduplicate(values: List[str]) -> List[str]:
        """Deduplicate strings while preserving order."""

        seen: Set[str] = set()
        results: List[str] = []

        for value in values:
            normalized = str(value).strip()

            if normalized and normalized not in seen:
                seen.add(normalized)
                results.append(normalized)

        return results

    def create_hypothesis(
        self,
        title: str,
        description: str,
        proposed_by: str,
        confidence: float = 0.50,
        required_evidence: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> InvestigationHypothesis:
        """Create and register a new hypothesis."""

        if not title.strip():
            raise ValueError(
                "Hypothesis title cannot be empty."
            )

        if not description.strip():
            raise ValueError(
                "Hypothesis description cannot be empty."
            )

        if not proposed_by.strip():
            raise ValueError(
                "proposed_by cannot be empty."
            )

        hypothesis = InvestigationHypothesis(
            title=title.strip(),
            description=description.strip(),
            proposed_by=proposed_by.strip(),
            confidence=self._clamp_confidence(
                confidence
            ),
            required_evidence=self._deduplicate(
                required_evidence or []
            ),
            metadata=metadata or {},
        )

        self.context.add_hypothesis(
            hypothesis=hypothesis,
            actor=proposed_by,
        )

        return hypothesis

    def get_hypothesis(
        self,
        hypothesis_id: str,
    ) -> InvestigationHypothesis:
        """Return a hypothesis or raise an error."""

        hypothesis = self.context.get_hypothesis(
            hypothesis_id
        )

        if hypothesis is None:
            raise KeyError(
                f"Hypothesis not found: {hypothesis_id}"
            )

        return hypothesis

    def _get_evidence(
        self,
        evidence_id: str,
    ) -> Evidence:
        """Return evidence or raise an error."""

        evidence = self.context.get_evidence(
            evidence_id
        )

        if evidence is None:
            raise KeyError(
                f"Evidence not found: {evidence_id}"
            )

        return evidence

    def add_supporting_evidence(
        self,
        hypothesis_id: str,
        evidence_id: str,
        actor: str = "hypothesis_engine",
    ) -> InvestigationHypothesis:
        """Attach supporting evidence to a hypothesis."""

        hypothesis = self.get_hypothesis(
            hypothesis_id
        )

        self._get_evidence(evidence_id)

        if (
            evidence_id
            not in hypothesis.supporting_evidence_ids
        ):
            hypothesis.supporting_evidence_ids.append(
                evidence_id
            )

        if (
            evidence_id
            in hypothesis.contradicting_evidence_ids
        ):
            hypothesis.contradicting_evidence_ids.remove(
                evidence_id
            )

        hypothesis.updated_at = utc_now()

        self.context.set_shared_value(
            key="latest_hypothesis_update",
            value={
                "hypothesis_id": hypothesis_id,
                "action": "supporting_evidence_added",
                "evidence_id": evidence_id,
                "actor": actor,
            },
            actor=actor,
        )

        return hypothesis

    def add_contradicting_evidence(
        self,
        hypothesis_id: str,
        evidence_id: str,
        actor: str = "hypothesis_engine",
    ) -> InvestigationHypothesis:
        """Attach contradicting evidence to a hypothesis."""

        hypothesis = self.get_hypothesis(
            hypothesis_id
        )

        self._get_evidence(evidence_id)

        if (
            evidence_id
            not in hypothesis.contradicting_evidence_ids
        ):
            hypothesis.contradicting_evidence_ids.append(
                evidence_id
            )

        if (
            evidence_id
            in hypothesis.supporting_evidence_ids
        ):
            hypothesis.supporting_evidence_ids.remove(
                evidence_id
            )

        hypothesis.updated_at = utc_now()

        self.context.set_shared_value(
            key="latest_hypothesis_update",
            value={
                "hypothesis_id": hypothesis_id,
                "action": "contradicting_evidence_added",
                "evidence_id": evidence_id,
                "actor": actor,
            },
            actor=actor,
        )

        return hypothesis

    def remove_evidence_link(
        self,
        hypothesis_id: str,
        evidence_id: str,
        actor: str = "hypothesis_engine",
    ) -> bool:
        """Remove an evidence relationship from a hypothesis."""

        hypothesis = self.get_hypothesis(
            hypothesis_id
        )

        removed = False

        if (
            evidence_id
            in hypothesis.supporting_evidence_ids
        ):
            hypothesis.supporting_evidence_ids.remove(
                evidence_id
            )
            removed = True

        if (
            evidence_id
            in hypothesis.contradicting_evidence_ids
        ):
            hypothesis.contradicting_evidence_ids.remove(
                evidence_id
            )
            removed = True

        if removed:
            hypothesis.updated_at = utc_now()

            self.context.set_shared_value(
                key="latest_hypothesis_update",
                value={
                    "hypothesis_id": hypothesis_id,
                    "action": "evidence_link_removed",
                    "evidence_id": evidence_id,
                    "actor": actor,
                },
                actor=actor,
            )

        return removed

    def _evidence_weight(
        self,
        evidence: Evidence,
    ) -> float:
        """Calculate the contribution of one evidence item."""

        type_weights = {
            "log": 1.00,
            "ioc": 0.90,
            "threat_intelligence": 1.10,
            "mitre_technique": 0.85,
            "historical_incident": 1.05,
            "process": 1.10,
            "network": 1.00,
            "user_activity": 1.00,
            "host_activity": 1.00,
            "agent_finding": 0.80,
            "other": 0.60,
        }

        evidence_type = evidence.evidence_type.value

        return (
            float(evidence.confidence)
            * type_weights.get(
                evidence_type,
                0.70,
            )
        )

    def calculate_confidence(
        self,
        hypothesis: InvestigationHypothesis,
    ) -> float:
        """
        Recalculate confidence from supporting and contradicting evidence.

        Formula:
        - Begin with the hypothesis's current confidence
        - Supporting evidence raises confidence
        - Contradicting evidence lowers confidence
        - Evidence confidence and type influence its strength
        """

        base_confidence = float(
            hypothesis.metadata.get(
                "base_confidence",
                hypothesis.confidence,
            )
        )

        if "base_confidence" not in hypothesis.metadata:
            hypothesis.metadata[
                "base_confidence"
            ] = base_confidence

        supporting_weights = []

        for evidence_id in (
            hypothesis.supporting_evidence_ids
        ):
            evidence = self.context.get_evidence(
                evidence_id
            )

            if evidence is not None:
                supporting_weights.append(
                    self._evidence_weight(
                        evidence
                    )
                )

        contradicting_weights = []

        for evidence_id in (
            hypothesis.contradicting_evidence_ids
        ):
            evidence = self.context.get_evidence(
                evidence_id
            )

            if evidence is not None:
                contradicting_weights.append(
                    self._evidence_weight(
                        evidence
                    )
                )

        support_score = min(
            sum(supporting_weights) * 0.12,
            0.45,
        )

        contradiction_score = min(
            sum(contradicting_weights) * 0.15,
            0.60,
        )

        confidence = (
            base_confidence
            + support_score
            - contradiction_score
        )

        if (
            len(hypothesis.supporting_evidence_ids)
            >= 3
        ):
            confidence += 0.05

        if (
            len(
                hypothesis.contradicting_evidence_ids
            )
            >= 2
        ):
            confidence -= 0.08

        return self._clamp_confidence(
            confidence
        )

    def _determine_status(
        self,
        hypothesis: InvestigationHypothesis,
        confidence: float,
    ) -> HypothesisStatus:
        """Determine hypothesis status from evidence and confidence."""

        support_count = len(
            hypothesis.supporting_evidence_ids
        )

        contradiction_count = len(
            hypothesis.contradicting_evidence_ids
        )

        if (
            contradiction_count >= 2
            and confidence < 0.35
        ):
            return HypothesisStatus.REJECTED

        if (
            confidence >= 0.85
            and support_count >= 2
            and contradiction_count == 0
        ):
            return HypothesisStatus.CONFIRMED

        if (
            confidence >= 0.65
            and support_count >= 1
        ):
            return HypothesisStatus.SUPPORTED

        if (
            support_count == 0
            and contradiction_count == 0
        ):
            return HypothesisStatus.PROPOSED

        if confidence < 0.40:
            return HypothesisStatus.INCONCLUSIVE

        return HypothesisStatus.INVESTIGATING

    def evaluate_hypothesis(
        self,
        hypothesis_id: str,
        actor: str = "hypothesis_engine",
    ) -> InvestigationHypothesis:
        """Recalculate one hypothesis's confidence and status."""

        hypothesis = self.get_hypothesis(
            hypothesis_id
        )

        confidence = self.calculate_confidence(
            hypothesis
        )

        status = self._determine_status(
            hypothesis=hypothesis,
            confidence=confidence,
        )

        hypothesis.update_confidence(
            confidence
        )

        hypothesis.set_status(status)

        hypothesis.metadata[
            "last_evaluation"
        ] = {
            "supporting_evidence_count": len(
                hypothesis.supporting_evidence_ids
            ),
            "contradicting_evidence_count": len(
                hypothesis.contradicting_evidence_ids
            ),
            "confidence": confidence,
            "status": status.value,
            "evaluated_at": utc_now(),
            "actor": actor,
        }

        self.context.set_shared_value(
            key="latest_hypothesis_evaluation",
            value={
                "hypothesis_id": hypothesis_id,
                "confidence": confidence,
                "status": status.value,
            },
            actor=actor,
        )

        return hypothesis

    def evaluate_all(
        self,
        actor: str = "hypothesis_engine",
    ) -> List[InvestigationHypothesis]:
        """Evaluate every hypothesis in the investigation."""

        evaluated = []

        for hypothesis in (
            self.context.investigation.hypotheses
        ):
            evaluated.append(
                self.evaluate_hypothesis(
                    hypothesis_id=(
                        hypothesis.hypothesis_id
                    ),
                    actor=actor,
                )
            )

        return evaluated

    def identify_missing_evidence(
        self,
        hypothesis_id: str,
    ) -> List[str]:
        """Return unresolved evidence requirements."""

        hypothesis = self.get_hypothesis(
            hypothesis_id
        )

        satisfied_requirements = set(
            self._flatten_evidence_descriptions(
                hypothesis.supporting_evidence_ids
            )
        )

        missing = []

        for requirement in hypothesis.required_evidence:
            normalized_requirement = (
                requirement.strip().lower()
            )

            requirement_satisfied = any(
                normalized_requirement
                in description.lower()
                or description.lower()
                in normalized_requirement
                for description
                in satisfied_requirements
            )

            if not requirement_satisfied:
                missing.append(requirement)

        return missing

    def _flatten_evidence_descriptions(
        self,
        evidence_ids: List[str],
    ) -> List[str]:
        """Collect descriptions and tags for evidence items."""

        descriptions: List[str] = []

        for evidence_id in evidence_ids:
            evidence = self.context.get_evidence(
                evidence_id
            )

            if evidence is None:
                continue

            descriptions.append(
                evidence.description
            )

            descriptions.extend(
                evidence.tags
            )

            if isinstance(evidence.value, str):
                descriptions.append(
                    evidence.value
                )

        return self._deduplicate(
            descriptions
        )

    def rank_hypotheses(
        self,
        include_rejected: bool = False,
    ) -> List[InvestigationHypothesis]:
        """Rank hypotheses from strongest to weakest."""

        hypotheses = list(
            self.context.investigation.hypotheses
        )

        if not include_rejected:
            hypotheses = [
                hypothesis
                for hypothesis in hypotheses
                if hypothesis.status
                != HypothesisStatus.REJECTED
            ]

        status_priority = {
            HypothesisStatus.CONFIRMED: 1,
            HypothesisStatus.SUPPORTED: 2,
            HypothesisStatus.INVESTIGATING: 3,
            HypothesisStatus.PROPOSED: 4,
            HypothesisStatus.INCONCLUSIVE: 5,
            HypothesisStatus.REJECTED: 6,
        }

        return sorted(
            hypotheses,
            key=lambda hypothesis: (
                status_priority.get(
                    hypothesis.status,
                    99,
                ),
                -hypothesis.confidence,
                -len(
                    hypothesis.supporting_evidence_ids
                ),
                len(
                    hypothesis.contradicting_evidence_ids
                ),
                hypothesis.title,
            ),
        )

    def get_leading_hypothesis(
        self,
    ) -> Optional[InvestigationHypothesis]:
        """Return the strongest non-rejected hypothesis."""

        ranked = self.rank_hypotheses(
            include_rejected=False
        )

        return ranked[0] if ranked else None

    def compare_hypotheses(
        self,
        hypothesis_ids: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Compare competing hypotheses."""

        hypotheses = (
            [
                self.get_hypothesis(
                    hypothesis_id
                )
                for hypothesis_id
                in hypothesis_ids
            ]
            if hypothesis_ids
            else list(
                self.context.investigation.hypotheses
            )
        )

        ranked = sorted(
            hypotheses,
            key=lambda hypothesis: (
                -hypothesis.confidence,
                -len(
                    hypothesis.supporting_evidence_ids
                ),
                len(
                    hypothesis.contradicting_evidence_ids
                ),
            ),
        )

        leading = ranked[0] if ranked else None

        return {
            "hypothesis_count": len(ranked),
            "leading_hypothesis": (
                leading.to_dict()
                if leading
                else None
            ),
            "ranked_hypotheses": [
                {
                    "rank": index,
                    "hypothesis_id": (
                        hypothesis.hypothesis_id
                    ),
                    "title": hypothesis.title,
                    "status": (
                        hypothesis.status.value
                    ),
                    "confidence": (
                        hypothesis.confidence
                    ),
                    "supporting_evidence_count": len(
                        hypothesis
                        .supporting_evidence_ids
                    ),
                    "contradicting_evidence_count": len(
                        hypothesis
                        .contradicting_evidence_ids
                    ),
                    "missing_evidence": (
                        self.identify_missing_evidence(
                            hypothesis.hypothesis_id
                        )
                    ),
                }
                for index, hypothesis
                in enumerate(
                    ranked,
                    start=1,
                )
            ],
        }

    def reject_hypothesis(
        self,
        hypothesis_id: str,
        reason: str,
        actor: str = "hypothesis_engine",
    ) -> InvestigationHypothesis:
        """Manually reject a hypothesis with justification."""

        hypothesis = self.get_hypothesis(
            hypothesis_id
        )

        hypothesis.set_status(
            HypothesisStatus.REJECTED
        )

        hypothesis.metadata[
            "rejection"
        ] = {
            "reason": reason,
            "actor": actor,
            "rejected_at": utc_now(),
        }

        return hypothesis

    def confirm_hypothesis(
        self,
        hypothesis_id: str,
        reason: str,
        actor: str = "hypothesis_engine",
    ) -> InvestigationHypothesis:
        """Manually confirm a hypothesis with justification."""

        hypothesis = self.get_hypothesis(
            hypothesis_id
        )

        hypothesis.update_confidence(
            max(
                hypothesis.confidence,
                0.85,
            )
        )

        hypothesis.set_status(
            HypothesisStatus.CONFIRMED
        )

        hypothesis.metadata[
            "confirmation"
        ] = {
            "reason": reason,
            "actor": actor,
            "confirmed_at": utc_now(),
        }

        return hypothesis

    def build_assessment(self) -> Dict[str, Any]:
        """Build the current hypothesis assessment."""

        self.evaluate_all()

        comparison = self.compare_hypotheses()

        status_counts = {
            status.value: sum(
                1
                for hypothesis
                in self.context.investigation.hypotheses
                if hypothesis.status == status
            )
            for status in HypothesisStatus
        }

        assessment = {
            "investigation_id": (
                self.context.investigation
                .investigation_id
            ),
            "incident_id": (
                self.context.investigation
                .incident_id
            ),
            "status_counts": status_counts,
            "comparison": comparison,
            "confirmed_hypotheses": [
                hypothesis.to_dict()
                for hypothesis
                in self.context.investigation.hypotheses
                if hypothesis.status
                == HypothesisStatus.CONFIRMED
            ],
            "rejected_hypotheses": [
                hypothesis.to_dict()
                for hypothesis
                in self.context.investigation.hypotheses
                if hypothesis.status
                == HypothesisStatus.REJECTED
            ],
            "generated_at": utc_now(),
        }

        self.context.set_shared_value(
            key="hypothesis_assessment",
            value=assessment,
            actor="hypothesis_engine",
        )

        return assessment