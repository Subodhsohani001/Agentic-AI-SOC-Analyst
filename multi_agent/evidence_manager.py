from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional, Set

from .investigation_models import (
    Evidence,
    EvidenceType,
    InvestigationHypothesis,
    utc_now,
)
from .shared_context import SharedInvestigationContext


class EvidenceManagerError(Exception):
    """Raised when evidence management fails."""


class EvidenceValidationError(EvidenceManagerError):
    """Raised when evidence does not meet validation requirements."""


class EvidenceManager:
    """
    Manages investigation evidence.

    Responsibilities:
    - Validate evidence
    - Generate deterministic evidence fingerprints
    - Prevent duplicate evidence
    - Rank evidence by confidence
    - Filter evidence by source, type, tags, and confidence
    - Link evidence to hypotheses
    - Build evidence chains
    - Produce investigation evidence summaries
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

        self.minimum_confidence = float(
            self.configuration.get(
                "minimum_confidence",
                0.0,
            )
        )

        self.reject_empty_values = bool(
            self.configuration.get(
                "reject_empty_values",
                True,
            )
        )

        self._fingerprint_index: Dict[str, str] = {}

        self._rebuild_fingerprint_index()

    @staticmethod
    def _normalize_value(value: Any) -> Any:
        """
        Normalize nested values for deterministic hashing.

        Dictionaries are sorted by key and sets are converted into
        sorted lists.
        """

        if isinstance(value, dict):
            return {
                str(key): EvidenceManager._normalize_value(
                    nested_value
                )
                for key, nested_value
                in sorted(
                    value.items(),
                    key=lambda item: str(item[0]),
                )
            }

        if isinstance(value, list):
            return [
                EvidenceManager._normalize_value(item)
                for item in value
            ]

        if isinstance(value, tuple):
            return [
                EvidenceManager._normalize_value(item)
                for item in value
            ]

        if isinstance(value, set):
            return sorted(
                EvidenceManager._normalize_value(item)
                for item in value
            )

        if isinstance(value, bytes):
            return value.hex()

        return value

    @staticmethod
    def _is_empty_value(value: Any) -> bool:
        """Determine whether an evidence value is empty."""

        if value is None:
            return True

        if isinstance(value, str):
            return not value.strip()

        if isinstance(
            value,
            (list, tuple, set, dict),
        ):
            return len(value) == 0

        return False

    def validate_evidence(
        self,
        evidence: Evidence,
    ) -> None:
        """Validate one evidence item."""

        if not isinstance(evidence, Evidence):
            raise EvidenceValidationError(
                "evidence must be an Evidence instance."
            )

        if not evidence.source.strip():
            raise EvidenceValidationError(
                "Evidence source cannot be empty."
            )

        if not isinstance(
            evidence.evidence_type,
            EvidenceType,
        ):
            raise EvidenceValidationError(
                "Evidence must use a valid EvidenceType."
            )

        if not 0.0 <= evidence.confidence <= 1.0:
            raise EvidenceValidationError(
                "Evidence confidence must be between 0.0 and 1.0."
            )

        if evidence.confidence < self.minimum_confidence:
            raise EvidenceValidationError(
                "Evidence confidence is below the configured minimum."
            )

        if (
            self.reject_empty_values
            and self._is_empty_value(
                evidence.value
            )
        ):
            raise EvidenceValidationError(
                "Evidence value cannot be empty."
            )

    def generate_fingerprint(
        self,
        evidence: Evidence,
    ) -> str:
        """
        Generate a deterministic SHA-256 fingerprint.

        The fingerprint excludes:
        - evidence_id
        - created_at

        This allows semantically identical evidence to be recognized
        even when generated at different times.
        """

        self.validate_evidence(evidence)

        payload = {
            "evidence_type": (
                evidence.evidence_type.value
            ),
            "source": evidence.source.strip().lower(),
            "value": self._normalize_value(
                evidence.value
            ),
            "description": (
                evidence.description.strip()
            ),
            "tags": sorted(
                {
                    tag.strip().lower()
                    for tag in evidence.tags
                    if tag.strip()
                }
            ),
            "metadata": self._normalize_value(
                evidence.metadata
            ),
        }

        serialized = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=str,
        )

        return hashlib.sha256(
            serialized.encode("utf-8")
        ).hexdigest()

    def _rebuild_fingerprint_index(self) -> None:
        """Rebuild the fingerprint-to-evidence lookup."""

        self._fingerprint_index = {}

        for evidence in (
            self.context.investigation.evidence
        ):
            try:
                fingerprint = self.generate_fingerprint(
                    evidence
                )
            except EvidenceValidationError:
                continue

            self._fingerprint_index[
                fingerprint
            ] = evidence.evidence_id

    def find_duplicate(
        self,
        evidence: Evidence,
    ) -> Optional[Evidence]:
        """Find equivalent evidence already in the investigation."""

        fingerprint = self.generate_fingerprint(
            evidence
        )

        evidence_id = self._fingerprint_index.get(
            fingerprint
        )

        if evidence_id is None:
            return None

        return self.context.get_evidence(
            evidence_id
        )

    def add_evidence(
        self,
        evidence: Evidence,
        actor: str,
        allow_duplicates: bool = False,
    ) -> Evidence:
        """
        Validate and add evidence.

        When equivalent evidence already exists and duplicates are not
        allowed, the existing item is returned.
        """

        self.validate_evidence(evidence)

        fingerprint = self.generate_fingerprint(
            evidence
        )

        if not allow_duplicates:
            existing_id = self._fingerprint_index.get(
                fingerprint
            )

            if existing_id is not None:
                existing = self.context.get_evidence(
                    existing_id
                )

                if existing is not None:
                    return existing

        added = self.context.add_evidence(
            evidence=evidence,
            actor=actor,
        )

        if not added:
            existing = self.context.get_evidence(
                evidence.evidence_id
            )

            if existing is not None:
                return existing

            raise EvidenceManagerError(
                "Evidence could not be added."
            )

        evidence.metadata.setdefault(
            "fingerprint",
            fingerprint,
        )

        evidence.metadata.setdefault(
            "managed_by",
            "evidence_manager",
        )

        self._fingerprint_index[
            fingerprint
        ] = evidence.evidence_id

        return evidence

    def add_many(
        self,
        evidence_items: List[Evidence],
        actor: str,
        allow_duplicates: bool = False,
        continue_on_error: bool = True,
    ) -> Dict[str, Any]:
        """Add multiple evidence items."""

        added: List[Evidence] = []
        duplicates: List[Evidence] = []
        failures: List[Dict[str, str]] = []

        for evidence in evidence_items:
            try:
                existing = self.find_duplicate(
                    evidence
                )

                result = self.add_evidence(
                    evidence=evidence,
                    actor=actor,
                    allow_duplicates=allow_duplicates,
                )

                if (
                    existing is not None
                    and result.evidence_id
                    == existing.evidence_id
                ):
                    duplicates.append(result)
                else:
                    added.append(result)

            except Exception as exc:
                failures.append(
                    {
                        "evidence_id": getattr(
                            evidence,
                            "evidence_id",
                            "unknown",
                        ),
                        "error": (
                            f"{type(exc).__name__}: {exc}"
                        ),
                    }
                )

                if not continue_on_error:
                    raise

        return {
            "added_count": len(added),
            "duplicate_count": len(
                duplicates
            ),
            "failure_count": len(failures),
            "added_evidence_ids": [
                item.evidence_id
                for item in added
            ],
            "duplicate_evidence_ids": [
                item.evidence_id
                for item in duplicates
            ],
            "failures": failures,
        }

    def get_evidence(
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

    def query(
        self,
        evidence_types: Optional[
            Set[EvidenceType]
        ] = None,
        sources: Optional[Set[str]] = None,
        tags: Optional[Set[str]] = None,
        minimum_confidence: Optional[
            float
        ] = None,
        maximum_confidence: Optional[
            float
        ] = None,
    ) -> List[Evidence]:
        """Query evidence using multiple filters."""

        results = list(
            self.context.investigation.evidence
        )

        if evidence_types is not None:
            results = [
                evidence
                for evidence in results
                if evidence.evidence_type
                in evidence_types
            ]

        if sources is not None:
            normalized_sources = {
                source.strip().lower()
                for source in sources
            }

            results = [
                evidence
                for evidence in results
                if evidence.source.strip().lower()
                in normalized_sources
            ]

        if tags is not None:
            normalized_tags = {
                tag.strip().lower()
                for tag in tags
            }

            results = [
                evidence
                for evidence in results
                if normalized_tags.intersection(
                    {
                        tag.strip().lower()
                        for tag in evidence.tags
                    }
                )
            ]

        if minimum_confidence is not None:
            results = [
                evidence
                for evidence in results
                if evidence.confidence
                >= minimum_confidence
            ]

        if maximum_confidence is not None:
            results = [
                evidence
                for evidence in results
                if evidence.confidence
                <= maximum_confidence
            ]

        return results

    def rank_evidence(
        self,
        evidence_items: Optional[
            List[Evidence]
        ] = None,
    ) -> List[Evidence]:
        """Rank evidence by confidence and source strength."""

        items = (
            evidence_items
            if evidence_items is not None
            else list(
                self.context.investigation.evidence
            )
        )

        type_priority = {
            EvidenceType.PROCESS: 1,
            EvidenceType.NETWORK: 2,
            EvidenceType.LOG: 3,
            EvidenceType.THREAT_INTELLIGENCE: 4,
            EvidenceType.HISTORICAL_INCIDENT: 5,
            EvidenceType.USER_ACTIVITY: 6,
            EvidenceType.HOST_ACTIVITY: 7,
            EvidenceType.IOC: 8,
            EvidenceType.MITRE_TECHNIQUE: 9,
            EvidenceType.AGENT_FINDING: 10,
            EvidenceType.OTHER: 11,
        }

        return sorted(
            items,
            key=lambda evidence: (
                -evidence.confidence,
                type_priority.get(
                    evidence.evidence_type,
                    99,
                ),
                evidence.created_at,
                evidence.evidence_id,
            ),
        )

    def link_to_hypothesis(
        self,
        evidence_id: str,
        hypothesis_id: str,
        relationship: str,
        actor: str = "evidence_manager",
    ) -> InvestigationHypothesis:
        """
        Link evidence to a hypothesis.

        Supported relationships:
        - supporting
        - contradicting
        """

        evidence = self.get_evidence(
            evidence_id
        )

        hypothesis = self.context.get_hypothesis(
            hypothesis_id
        )

        if hypothesis is None:
            raise KeyError(
                f"Hypothesis not found: {hypothesis_id}"
            )

        normalized_relationship = (
            relationship.strip().lower()
        )

        if normalized_relationship not in {
            "supporting",
            "contradicting",
        }:
            raise ValueError(
                "relationship must be supporting or contradicting."
            )

        if normalized_relationship == "supporting":
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

        else:
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

        evidence.metadata.setdefault(
            "hypothesis_links",
            [],
        )

        link = {
            "hypothesis_id": hypothesis_id,
            "relationship": (
                normalized_relationship
            ),
            "actor": actor,
            "linked_at": utc_now(),
        }

        if (
            link
            not in evidence.metadata[
                "hypothesis_links"
            ]
        ):
            evidence.metadata[
                "hypothesis_links"
            ].append(link)

        self.context.set_shared_value(
            key="latest_evidence_link",
            value={
                "evidence_id": evidence_id,
                "hypothesis_id": hypothesis_id,
                "relationship": (
                    normalized_relationship
                ),
            },
            actor=actor,
        )

        return hypothesis

    def unlink_from_hypothesis(
        self,
        evidence_id: str,
        hypothesis_id: str,
        actor: str = "evidence_manager",
    ) -> bool:
        """Remove an evidence-hypothesis relationship."""

        hypothesis = self.context.get_hypothesis(
            hypothesis_id
        )

        if hypothesis is None:
            raise KeyError(
                f"Hypothesis not found: {hypothesis_id}"
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
                key="latest_evidence_unlink",
                value={
                    "evidence_id": evidence_id,
                    "hypothesis_id": hypothesis_id,
                },
                actor=actor,
            )

        return removed

    def build_evidence_chain(
        self,
        evidence_ids: Optional[
            List[str]
        ] = None,
    ) -> List[Dict[str, Any]]:
        """
        Build a chronological evidence chain.

        If no IDs are supplied, all investigation evidence is used.
        """

        if evidence_ids is None:
            evidence_items = list(
                self.context.investigation.evidence
            )
        else:
            evidence_items = [
                self.get_evidence(
                    evidence_id
                )
                for evidence_id in evidence_ids
            ]

        ordered = sorted(
            evidence_items,
            key=lambda evidence: (
                evidence.created_at,
                evidence.evidence_id,
            ),
        )

        return [
            {
                "sequence": index,
                "evidence_id": (
                    evidence.evidence_id
                ),
                "evidence_type": (
                    evidence.evidence_type.value
                ),
                "source": evidence.source,
                "description": (
                    evidence.description
                ),
                "confidence": (
                    evidence.confidence
                ),
                "tags": list(evidence.tags),
                "created_at": evidence.created_at,
                "fingerprint": (
                    evidence.metadata.get(
                        "fingerprint"
                    )
                    or self.generate_fingerprint(
                        evidence
                    )
                ),
            }
            for index, evidence
            in enumerate(
                ordered,
                start=1,
            )
        ]

    def get_hypothesis_evidence(
        self,
        hypothesis_id: str,
    ) -> Dict[str, List[Evidence]]:
        """Return supporting and contradicting evidence."""

        hypothesis = self.context.get_hypothesis(
            hypothesis_id
        )

        if hypothesis is None:
            raise KeyError(
                f"Hypothesis not found: {hypothesis_id}"
            )

        supporting = [
            evidence
            for evidence_id
            in hypothesis.supporting_evidence_ids
            if (
                evidence := self.context.get_evidence(
                    evidence_id
                )
            )
            is not None
        ]

        contradicting = [
            evidence
            for evidence_id
            in hypothesis.contradicting_evidence_ids
            if (
                evidence := self.context.get_evidence(
                    evidence_id
                )
            )
            is not None
        ]

        return {
            "supporting": self.rank_evidence(
                supporting
            ),
            "contradicting": self.rank_evidence(
                contradicting
            ),
        }

    def calculate_integrity_score(self) -> int:
        """
        Calculate a basic evidence integrity score.

        The score considers:
        - Valid evidence values
        - Valid fingerprints
        - Confidence presence
        - Source attribution
        - Duplicate rate
        """

        evidence_items = list(
            self.context.investigation.evidence
        )

        if not evidence_items:
            return 0

        valid_count = 0
        fingerprint_count = 0
        source_count = 0
        confidence_count = 0
        fingerprints: List[str] = []

        for evidence in evidence_items:
            try:
                self.validate_evidence(
                    evidence
                )
                valid_count += 1
            except EvidenceValidationError:
                pass

            try:
                fingerprint = (
                    self.generate_fingerprint(
                        evidence
                    )
                )
                fingerprints.append(fingerprint)
                fingerprint_count += 1
            except EvidenceValidationError:
                pass

            if evidence.source.strip():
                source_count += 1

            if 0.0 <= evidence.confidence <= 1.0:
                confidence_count += 1

        total = len(evidence_items)

        duplicate_count = (
            len(fingerprints)
            - len(set(fingerprints))
        )

        duplicate_ratio = (
            duplicate_count / total
        )

        score = (
            (valid_count / total) * 30
            + (
                fingerprint_count / total
            )
            * 25
            + (source_count / total) * 20
            + (
                confidence_count / total
            )
            * 15
            + (
                1.0 - duplicate_ratio
            )
            * 10
        )

        return min(
            max(round(score), 0),
            100,
        )

    def build_summary(self) -> Dict[str, Any]:
        """Build evidence statistics for the investigation."""

        evidence_items = list(
            self.context.investigation.evidence
        )

        type_counts = {
            evidence_type.value: sum(
                1
                for evidence in evidence_items
                if evidence.evidence_type
                == evidence_type
            )
            for evidence_type in EvidenceType
        }

        source_counts: Dict[str, int] = {}

        for evidence in evidence_items:
            source_counts[evidence.source] = (
                source_counts.get(
                    evidence.source,
                    0,
                )
                + 1
            )

        high_confidence_count = sum(
            1
            for evidence in evidence_items
            if evidence.confidence >= 0.80
        )

        low_confidence_count = sum(
            1
            for evidence in evidence_items
            if evidence.confidence < 0.50
        )

        ranked = self.rank_evidence(
            evidence_items
        )

        summary = {
            "investigation_id": (
                self.context.investigation
                .investigation_id
            ),
            "incident_id": (
                self.context.investigation
                .incident_id
            ),
            "evidence_count": len(
                evidence_items
            ),
            "type_counts": type_counts,
            "source_counts": source_counts,
            "high_confidence_count": (
                high_confidence_count
            ),
            "low_confidence_count": (
                low_confidence_count
            ),
            "average_confidence": (
                round(
                    sum(
                        evidence.confidence
                        for evidence
                        in evidence_items
                    )
                    / len(evidence_items),
                    2,
                )
                if evidence_items
                else 0.0
            ),
            "integrity_score": (
                self.calculate_integrity_score()
            ),
            "highest_ranked_evidence": (
                ranked[0].to_dict()
                if ranked
                else None
            ),
            "evidence_chain": (
                self.build_evidence_chain()
            ),
            "generated_at": utc_now(),
        }

        self.context.set_shared_value(
            key="evidence_summary",
            value=summary,
            actor="evidence_manager",
        )

        return summary