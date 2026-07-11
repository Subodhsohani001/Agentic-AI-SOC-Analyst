from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class PolicyDecision:
    severity: str
    confidence: str
    recommended_tool: str
    reason: str


class PolicyEngine:
    """
    Applies deterministic response policies after AI analysis.

    The AI may suggest severity, confidence, and a tool.
    This engine can override those values when trusted MITRE evidence
    and required log indicators satisfy a configured rule.
    """

    POLICIES: dict[str, dict[str, Any]] = {
        "T1059.001": {
            "severity": "High",
            "confidence": "High",
            "default_tool": "create_ticket",
            "required_any": [
                "-enc",
                "encodedcommand",
                "invoke-expression",
            ],
            "reason": (
                "Suspicious PowerShell execution indicators were observed, "
                "including encoded or expression-based execution."
            ),
        },
        "T1003": {
            "severity": "High",
            "confidence": "High",
            "default_tool": "create_ticket",
            "required_any": [
                "mimikatz",
                "lsass",
                "procdump",
                "ntds.dit",
                "sam dump",
            ],
            "reason": "Credential-dumping indicators were observed in the log.",
        },
        "T1110": {
            "severity": "Medium",
            "confidence": "High",
            "default_tool": "create_ticket",
            "required_any": [
                "failed password",
                "failed login",
                "invalid user",
                "authentication failure",
            ],
            "reason": (
                "Multiple authentication-failure indicators matched "
                "a brute-force pattern."
            ),
        },
    }

    @staticmethod
    def _matches_required_any(log_lower: str, indicators: list[str]) -> bool:
        if not indicators:
            return True
        return any(indicator.lower() in log_lower for indicator in indicators)

    def apply(
        self,
        *,
        technique_id: str,
        log_data: str,
        current_severity: str,
        current_confidence: str,
        current_tool: str,
    ) -> PolicyDecision:
        policy = self.POLICIES.get(technique_id)

        if not policy:
            return PolicyDecision(
                severity=current_severity,
                confidence=current_confidence,
                recommended_tool=current_tool,
                reason="No deterministic policy matched this MITRE technique.",
            )

        log_lower = log_data.lower()
        required_any = [
            str(value)
            for value in policy.get("required_any", [])
        ]

        if not self._matches_required_any(log_lower, required_any):
            return PolicyDecision(
                severity=current_severity,
                confidence=current_confidence,
                recommended_tool=current_tool,
                reason=(
                    "A MITRE policy existed, but the required evidence "
                    "was not present in the log."
                ),
            )

        tool = current_tool
        if tool == "none":
            tool = str(policy.get("default_tool", "none"))

        return PolicyDecision(
            severity=str(policy.get("severity", current_severity)),
            confidence=str(policy.get("confidence", current_confidence)),
            recommended_tool=tool,
            reason=str(policy.get("reason", "Deterministic policy applied.")),
        )
