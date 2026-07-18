from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, List, Set
from urllib.parse import urlparse

from ..agent_base import BaseInvestigationAgent
from ..investigation_models import (
    AgentExecutionResult,
    AgentFinding,
    Evidence,
    EvidenceType,
    InvestigationTask,
    TaskPriority,
)


class IOCAgent(BaseInvestigationAgent):
    """
    Extracts, normalizes, validates, deduplicates, and defangs
    indicators of compromise.

    Supported IOC types:
    - IPv4 and IPv6 addresses
    - Domains
    - URLs
    - MD5 hashes
    - SHA-1 hashes
    - SHA-256 hashes
    """

    agent_name = "ioc_agent"
    description = (
        "Extracts, validates, normalizes, deduplicates, and safely "
        "defangs indicators of compromise."
    )
    version = "0.7.0"

    IPV4_PATTERN = re.compile(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    )

    IPV6_PATTERN = re.compile(
        r"\b(?:[0-9A-Fa-f]{1,4}:){2,7}"
        r"[0-9A-Fa-f]{0,4}\b"
    )

    DOMAIN_PATTERN = re.compile(
        r"\b(?:[A-Za-z0-9]"
        r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
        r"[A-Za-z]{2,63}\b"
    )

    URL_PATTERN = re.compile(
        r"\bhttps?://[^\s<>\"']+",
        re.IGNORECASE,
    )

    MD5_PATTERN = re.compile(
        r"\b[a-fA-F0-9]{32}\b"
    )

    SHA1_PATTERN = re.compile(
        r"\b[a-fA-F0-9]{40}\b"
    )

    SHA256_PATTERN = re.compile(
        r"\b[a-fA-F0-9]{64}\b"
    )

    @property
    def supported_task_types(self) -> Set[str]:
        return {
            "ioc_analysis",
            "ioc_extraction",
            "ioc_validation",
            "indicator_analysis",
        }

    @staticmethod
    def _flatten_values(value: Any) -> List[str]:
        """
        Convert nested input values into strings for IOC extraction.
        """

        flattened: List[str] = []

        if value is None:
            return flattened

        if isinstance(value, str):
            if value.strip():
                flattened.append(value.strip())

            return flattened

        if isinstance(value, dict):
            for key, nested_value in value.items():
                flattened.extend(
                    IOCAgent._flatten_values(key)
                )
                flattened.extend(
                    IOCAgent._flatten_values(nested_value)
                )

            return flattened

        if isinstance(value, (list, tuple, set)):
            for item in value:
                flattened.extend(
                    IOCAgent._flatten_values(item)
                )

            return flattened

        flattened.append(str(value))

        return flattened

    @staticmethod
    def _strip_terminal_punctuation(value: str) -> str:
        """Remove punctuation commonly attached to extracted IOCs."""

        return value.strip().rstrip(
            ".,;:!?)]}>\"'"
        ).lstrip(
            "([{<\"'"
        )

    @staticmethod
    def _normalize_domain(domain: str) -> str:
        """Normalize a domain into lowercase form."""

        normalized = domain.strip().lower().rstrip(".")

        if normalized.startswith("www."):
            normalized = normalized[4:]

        return normalized

    @staticmethod
    def _normalize_url(url: str) -> str:
        """Normalize a URL without changing path case."""

        normalized = IOCAgent._strip_terminal_punctuation(
            url.strip()
        )

        parsed = urlparse(normalized)

        if not parsed.scheme:
            return normalized

        scheme = parsed.scheme.lower()
        hostname = (
            parsed.hostname.lower()
            if parsed.hostname
            else ""
        )

        port = ""

        try:
            if parsed.port is not None:
                port = f":{parsed.port}"
        except ValueError:
            return normalized

        path = parsed.path or ""
        query = f"?{parsed.query}" if parsed.query else ""
        fragment = (
            f"#{parsed.fragment}"
            if parsed.fragment
            else ""
        )

        return (
            f"{scheme}://{hostname}{port}"
            f"{path}{query}{fragment}"
        )

    @staticmethod
    def _normalize_hash(file_hash: str) -> str:
        """Normalize a cryptographic hash into lowercase."""

        return file_hash.strip().lower()

    @staticmethod
    def _validate_ip(ip_value: str) -> bool:
        """Validate IPv4 or IPv6 values."""

        try:
            ipaddress.ip_address(ip_value)
            return True
        except ValueError:
            return False

    @staticmethod
    def _classify_ip(ip_value: str) -> Dict[str, Any]:
        """Classify an IP address for analyst context."""

        ip_object = ipaddress.ip_address(ip_value)

        return {
            "version": ip_object.version,
            "is_private": ip_object.is_private,
            "is_global": ip_object.is_global,
            "is_loopback": ip_object.is_loopback,
            "is_multicast": ip_object.is_multicast,
            "is_reserved": ip_object.is_reserved,
            "is_unspecified": ip_object.is_unspecified,
            "is_link_local": ip_object.is_link_local,
        }

    @staticmethod
    def _validate_domain(domain: str) -> bool:
        """Validate a normalized domain name."""

        if not domain or len(domain) > 253:
            return False

        if "." not in domain:
            return False

        labels = domain.split(".")

        if len(labels[-1]) < 2:
            return False

        label_pattern = re.compile(
            r"^[A-Za-z0-9]"
            r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
        )

        return all(
            label_pattern.fullmatch(label) is not None
            for label in labels
        )

    @staticmethod
    def _validate_url(url: str) -> bool:
        """Validate HTTP and HTTPS URLs."""

        try:
            parsed = urlparse(url)
        except ValueError:
            return False

        return (
            parsed.scheme.lower() in {"http", "https"}
            and bool(parsed.hostname)
        )

    @staticmethod
    def _classify_hash(file_hash: str) -> str:
        """Return the algorithm represented by a hash length."""

        hash_length = len(file_hash)

        if hash_length == 32:
            return "md5"

        if hash_length == 40:
            return "sha1"

        if hash_length == 64:
            return "sha256"

        return "unknown"

    @staticmethod
    def _validate_hash(file_hash: str) -> bool:
        """Validate supported hexadecimal hash formats."""

        return (
            len(file_hash) in {32, 40, 64}
            and re.fullmatch(
                r"[a-fA-F0-9]+",
                file_hash,
            )
            is not None
        )

    @staticmethod
    def defang_ip(ip_value: str) -> str:
        """Defang an IP address for safe analyst display."""

        if ":" in ip_value:
            return ip_value.replace(":", "[:]")

        return ip_value.replace(".", "[.]")

    @staticmethod
    def defang_domain(domain: str) -> str:
        """Defang a domain for safe analyst display."""

        return domain.replace(".", "[.]")

    @staticmethod
    def defang_url(url: str) -> str:
        """Defang a URL for safe analyst display."""

        defanged = re.sub(
            r"^http://",
            "hxxp://",
            url,
            flags=re.IGNORECASE,
        )

        defanged = re.sub(
            r"^https://",
            "hxxps://",
            defanged,
            flags=re.IGNORECASE,
        )

        return defanged.replace(".", "[.]")

    @staticmethod
    def _deduplicate(values: List[str]) -> List[str]:
        """Deduplicate values while preserving order."""

        seen: Set[str] = set()
        results: List[str] = []

        for value in values:
            if value not in seen:
                seen.add(value)
                results.append(value)

        return results

    def _extract_from_text(
        self,
        text: str,
    ) -> Dict[str, List[str]]:
        """Extract IOC candidates from unstructured text."""

        urls = [
            self._strip_terminal_punctuation(value)
            for value in self.URL_PATTERN.findall(text)
        ]

        hashes = (
            self.SHA256_PATTERN.findall(text)
            + self.SHA1_PATTERN.findall(text)
            + self.MD5_PATTERN.findall(text)
        )

        ipv4_addresses = self.IPV4_PATTERN.findall(text)
        ipv6_addresses = self.IPV6_PATTERN.findall(text)
        domains = self.DOMAIN_PATTERN.findall(text)

        return {
            "ips": ipv4_addresses + ipv6_addresses,
            "domains": domains,
            "urls": urls,
            "hashes": hashes,
        }

    def _collect_explicit_values(
        self,
        input_data: Dict[str, Any],
    ) -> Dict[str, List[str]]:
        """Collect explicitly supplied IOC fields."""

        field_groups = {
            "ips": {
                "ip",
                "ips",
                "source_ip",
                "source_ips",
                "destination_ip",
                "destination_ips",
                "ip_addresses",
            },
            "domains": {
                "domain",
                "domains",
                "host_domain",
            },
            "urls": {
                "url",
                "urls",
                "uri",
                "uris",
            },
            "hashes": {
                "hash",
                "hashes",
                "file_hash",
                "file_hashes",
                "md5",
                "sha1",
                "sha256",
            },
        }

        collected = {
            "ips": [],
            "domains": [],
            "urls": [],
            "hashes": [],
        }

        for result_type, keys in field_groups.items():
            for key in keys:
                if key not in input_data:
                    continue

                collected[result_type].extend(
                    self._flatten_values(
                        input_data.get(key)
                    )
                )

        return collected

    def _collect_shared_triage_values(
        self,
    ) -> Dict[str, List[str]]:
        """Collect IOCs already identified by the triage agent."""

        triage_data = self.get_shared_value(
            "triage_assessment",
            {},
        )

        if not isinstance(triage_data, dict):
            return {
                "ips": [],
                "domains": [],
                "urls": [],
                "hashes": [],
            }

        return {
            "ips": self._flatten_values(
                triage_data.get("source_ips", [])
            ),
            "domains": self._flatten_values(
                triage_data.get("domains", [])
            ),
            "urls": self._flatten_values(
                triage_data.get("urls", [])
            ),
            "hashes": self._flatten_values(
                triage_data.get("hashes", [])
            ),
        }

    def _normalize_and_validate(
        self,
        candidates: Dict[str, List[str]],
    ) -> Dict[str, Any]:
        """Normalize, validate, classify, and reject IOC candidates."""

        valid_ips: List[Dict[str, Any]] = []
        valid_domains: List[Dict[str, Any]] = []
        valid_urls: List[Dict[str, Any]] = []
        valid_hashes: List[Dict[str, Any]] = []
        invalid_values: List[Dict[str, str]] = []

        normalized_ip_values: List[str] = []

        for candidate in candidates["ips"]:
            value = self._strip_terminal_punctuation(
                candidate
            )

            if not value:
                continue

            if self._validate_ip(value):
                normalized_ip = str(
                    ipaddress.ip_address(value)
                )

                if normalized_ip not in normalized_ip_values:
                    normalized_ip_values.append(
                        normalized_ip
                    )

                    valid_ips.append(
                        {
                            "value": normalized_ip,
                            "defanged": self.defang_ip(
                                normalized_ip
                            ),
                            "classification": (
                                self._classify_ip(
                                    normalized_ip
                                )
                            ),
                        }
                    )
            else:
                invalid_values.append(
                    {
                        "type": "ip",
                        "value": value,
                        "reason": "Invalid IP address",
                    }
                )

        normalized_url_values: List[str] = []

        for candidate in candidates["urls"]:
            normalized_url = self._normalize_url(
                candidate
            )

            if not normalized_url:
                continue

            if self._validate_url(normalized_url):
                if (
                    normalized_url
                    not in normalized_url_values
                ):
                    normalized_url_values.append(
                        normalized_url
                    )

                    valid_urls.append(
                        {
                            "value": normalized_url,
                            "defanged": self.defang_url(
                                normalized_url
                            ),
                        }
                    )
            else:
                invalid_values.append(
                    {
                        "type": "url",
                        "value": candidate,
                        "reason": "Invalid HTTP or HTTPS URL",
                    }
                )

        normalized_domain_values: List[str] = []

        for candidate in candidates["domains"]:
            normalized_domain = (
                self._normalize_domain(candidate)
            )

            if not normalized_domain:
                continue

            try:
                ipaddress.ip_address(
                    normalized_domain
                )
                continue
            except ValueError:
                pass

            if self._validate_domain(
                normalized_domain
            ):
                if (
                    normalized_domain
                    not in normalized_domain_values
                ):
                    normalized_domain_values.append(
                        normalized_domain
                    )

                    valid_domains.append(
                        {
                            "value": normalized_domain,
                            "defanged": self.defang_domain(
                                normalized_domain
                            ),
                        }
                    )
            else:
                invalid_values.append(
                    {
                        "type": "domain",
                        "value": candidate,
                        "reason": "Invalid domain",
                    }
                )

        normalized_hash_values: List[str] = []

        for candidate in candidates["hashes"]:
            normalized_hash = self._normalize_hash(
                candidate
            )

            if not normalized_hash:
                continue

            if self._validate_hash(normalized_hash):
                if (
                    normalized_hash
                    not in normalized_hash_values
                ):
                    normalized_hash_values.append(
                        normalized_hash
                    )

                    valid_hashes.append(
                        {
                            "value": normalized_hash,
                            "algorithm": (
                                self._classify_hash(
                                    normalized_hash
                                )
                            ),
                            "defanged": normalized_hash,
                        }
                    )
            else:
                invalid_values.append(
                    {
                        "type": "hash",
                        "value": candidate,
                        "reason": (
                            "Unsupported or malformed hash"
                        ),
                    }
                )

        url_hostnames = []

        for url_record in valid_urls:
            hostname = urlparse(
                url_record["value"]
            ).hostname

            if hostname:
                hostname = hostname.lower()

                try:
                    ipaddress.ip_address(hostname)

                    if hostname not in normalized_ip_values:
                        normalized_ip_values.append(hostname)
                        valid_ips.append(
                            {
                                "value": hostname,
                                "defanged": self.defang_ip(
                                    hostname
                                ),
                                "classification": (
                                    self._classify_ip(
                                        hostname
                                    )
                                ),
                                "derived_from_url": True,
                            }
                        )
                except ValueError:
                    normalized_hostname = (
                        self._normalize_domain(
                            hostname
                        )
                    )

                    if (
                        self._validate_domain(
                            normalized_hostname
                        )
                        and normalized_hostname
                        not in normalized_domain_values
                    ):
                        normalized_domain_values.append(
                            normalized_hostname
                        )
                        url_hostnames.append(
                            normalized_hostname
                        )
                        valid_domains.append(
                            {
                                "value": normalized_hostname,
                                "defanged": (
                                    self.defang_domain(
                                        normalized_hostname
                                    )
                                ),
                                "derived_from_url": True,
                            }
                        )

        return {
            "ips": valid_ips,
            "domains": valid_domains,
            "urls": valid_urls,
            "hashes": valid_hashes,
            "invalid_values": invalid_values,
            "derived_url_hostnames": url_hostnames,
        }

    @staticmethod
    def _calculate_confidence(
        valid_count: int,
        invalid_count: int,
        explicit_input_present: bool,
    ) -> float:
        """Calculate deterministic IOC extraction confidence."""

        if valid_count == 0:
            return 0.30

        confidence = 0.70

        if explicit_input_present:
            confidence += 0.15

        if valid_count >= 3:
            confidence += 0.05

        if invalid_count == 0:
            confidence += 0.05

        return min(confidence, 0.95)

    def _build_follow_up_tasks(
        self,
        task: InvestigationTask,
        normalized_iocs: Dict[str, Any],
    ) -> List[InvestigationTask]:
        """Create IOC-dependent enrichment and correlation tasks."""

        observable_count = sum(
            len(normalized_iocs[key])
            for key in (
                "ips",
                "domains",
                "urls",
                "hashes",
            )
        )

        if observable_count == 0:
            return []

        priority = (
            TaskPriority.P1
            if self.context.investigation.severity
            == "CRITICAL"
            else task.priority
        )

        compact_iocs = {
            "ips": [
                item["value"]
                for item in normalized_iocs["ips"]
            ],
            "domains": [
                item["value"]
                for item in normalized_iocs["domains"]
            ],
            "urls": [
                item["value"]
                for item in normalized_iocs["urls"]
            ],
            "hashes": [
                item["value"]
                for item in normalized_iocs["hashes"]
            ],
        }

        return [
            InvestigationTask(
                task_type="threat_intelligence",
                assigned_agent="threat_intel_agent",
                description=(
                    "Enrich normalized indicators using configured "
                    "threat-intelligence providers."
                ),
                priority=priority,
                input_data=compact_iocs,
                dependencies=[task.task_id],
            ),
            InvestigationTask(
                task_type="historical_correlation",
                assigned_agent="correlation_agent",
                description=(
                    "Correlate normalized indicators with historical "
                    "incidents and repeat offenders."
                ),
                priority=priority,
                input_data=compact_iocs,
                dependencies=[task.task_id],
            ),
        ]

    def execute_task(
        self,
        task: InvestigationTask,
    ) -> AgentExecutionResult:
        """Perform deterministic IOC extraction and validation."""

        input_data = dict(task.input_data or {})

        explicit_values = self._collect_explicit_values(
            input_data
        )

        shared_values = (
            self._collect_shared_triage_values()
        )

        all_text_values = self._flatten_values(
            input_data
        )

        all_text_values.extend(
            self._flatten_values(
                self.context.investigation.description
            )
        )

        combined_text = "\n".join(all_text_values)
        extracted_values = self._extract_from_text(
            combined_text
        )

        candidates = {
            "ips": self._deduplicate(
                explicit_values["ips"]
                + shared_values["ips"]
                + extracted_values["ips"]
            ),
            "domains": self._deduplicate(
                explicit_values["domains"]
                + shared_values["domains"]
                + extracted_values["domains"]
            ),
            "urls": self._deduplicate(
                explicit_values["urls"]
                + shared_values["urls"]
                + extracted_values["urls"]
            ),
            "hashes": self._deduplicate(
                explicit_values["hashes"]
                + shared_values["hashes"]
                + extracted_values["hashes"]
            ),
        }

        normalized_iocs = self._normalize_and_validate(
            candidates
        )

        valid_count = sum(
            len(normalized_iocs[key])
            for key in (
                "ips",
                "domains",
                "urls",
                "hashes",
            )
        )

        invalid_count = len(
            normalized_iocs["invalid_values"]
        )

        explicit_input_present = any(
            explicit_values[key]
            for key in explicit_values
        )

        confidence = self._calculate_confidence(
            valid_count=valid_count,
            invalid_count=invalid_count,
            explicit_input_present=explicit_input_present,
        )

        compact_iocs = {
            "ips": [
                item["value"]
                for item in normalized_iocs["ips"]
            ],
            "domains": [
                item["value"]
                for item in normalized_iocs["domains"]
            ],
            "urls": [
                item["value"]
                for item in normalized_iocs["urls"]
            ],
            "hashes": [
                item["value"]
                for item in normalized_iocs["hashes"]
            ],
        }

        defanged_iocs = {
            "ips": [
                item["defanged"]
                for item in normalized_iocs["ips"]
            ],
            "domains": [
                item["defanged"]
                for item in normalized_iocs["domains"]
            ],
            "urls": [
                item["defanged"]
                for item in normalized_iocs["urls"]
            ],
            "hashes": [
                item["defanged"]
                for item in normalized_iocs["hashes"]
            ],
        }

        severity = (
            self.context.investigation.severity
            if valid_count > 0
            else "INFORMATIONAL"
        )

        summary = (
            f"IOC analysis identified {valid_count} valid unique "
            f"indicator(s): "
            f"{len(normalized_iocs['ips'])} IP address(es), "
            f"{len(normalized_iocs['domains'])} domain(s), "
            f"{len(normalized_iocs['urls'])} URL(s), and "
            f"{len(normalized_iocs['hashes'])} hash(es). "
            f"{invalid_count} invalid candidate(s) were rejected."
        )

        evidence: List[Evidence] = []

        for record in normalized_iocs["ips"]:
            evidence.append(
                Evidence(
                    evidence_type=EvidenceType.IOC,
                    source=self.agent_name,
                    value={
                        "type": "ip",
                        **record,
                    },
                    description=(
                        "Validated IP indicator identified during "
                        "IOC analysis."
                    ),
                    confidence=confidence,
                    tags=[
                        "ioc",
                        "ip",
                        "validated",
                    ],
                )
            )

        for record in normalized_iocs["domains"]:
            evidence.append(
                Evidence(
                    evidence_type=EvidenceType.IOC,
                    source=self.agent_name,
                    value={
                        "type": "domain",
                        **record,
                    },
                    description=(
                        "Validated domain indicator identified during "
                        "IOC analysis."
                    ),
                    confidence=confidence,
                    tags=[
                        "ioc",
                        "domain",
                        "validated",
                    ],
                )
            )

        for record in normalized_iocs["urls"]:
            evidence.append(
                Evidence(
                    evidence_type=EvidenceType.IOC,
                    source=self.agent_name,
                    value={
                        "type": "url",
                        **record,
                    },
                    description=(
                        "Validated URL indicator identified during "
                        "IOC analysis."
                    ),
                    confidence=confidence,
                    tags=[
                        "ioc",
                        "url",
                        "validated",
                    ],
                )
            )

        for record in normalized_iocs["hashes"]:
            evidence.append(
                Evidence(
                    evidence_type=EvidenceType.IOC,
                    source=self.agent_name,
                    value={
                        "type": "hash",
                        **record,
                    },
                    description=(
                        "Validated file-hash indicator identified "
                        "during IOC analysis."
                    ),
                    confidence=confidence,
                    tags=[
                        "ioc",
                        "hash",
                        record["algorithm"],
                        "validated",
                    ],
                )
            )

        finding = AgentFinding(
            agent_name=self.agent_name,
            title="Normalized Indicator Analysis",
            summary=summary,
            severity=severity,
            confidence=confidence,
            evidence_ids=[
                item.evidence_id
                for item in evidence
            ],
            recommendations=[
                (
                    "Enrich public indicators using trusted "
                    "threat-intelligence providers."
                ),
                (
                    "Correlate indicators with historical incident "
                    "memory and repeat-offender activity."
                ),
                (
                    "Use defanged values in analyst-facing reports "
                    "and communications."
                ),
            ],
            metadata={
                "normalized_iocs": compact_iocs,
                "defanged_iocs": defanged_iocs,
                "invalid_values": (
                    normalized_iocs["invalid_values"]
                ),
                "valid_indicator_count": valid_count,
                "invalid_indicator_count": invalid_count,
            },
        )

        proposed_tasks = self._build_follow_up_tasks(
            task=task,
            normalized_iocs=normalized_iocs,
        )

        shared_result = {
            "normalized": compact_iocs,
            "defanged": defanged_iocs,
            "detailed": {
                "ips": normalized_iocs["ips"],
                "domains": normalized_iocs["domains"],
                "urls": normalized_iocs["urls"],
                "hashes": normalized_iocs["hashes"],
            },
            "invalid_values": (
                normalized_iocs["invalid_values"]
            ),
            "valid_indicator_count": valid_count,
            "invalid_indicator_count": invalid_count,
            "confidence": confidence,
        }

        self.set_shared_value(
            key="normalized_iocs",
            value=shared_result,
        )

        self.send_message(
            recipient_agent="threat_intel_agent",
            subject="Normalized IOCs ready",
            content=(
                f"{valid_count} validated indicator(s) are ready "
                "for threat-intelligence enrichment."
            ),
            message_type="ioc_result",
            related_task_id=task.task_id,
            related_evidence_ids=[
                item.evidence_id
                for item in evidence
            ],
            metadata={
                "normalized_iocs": compact_iocs,
                "defanged_iocs": defanged_iocs,
            },
        )

        self.send_message(
            recipient_agent="correlation_agent",
            subject="IOCs ready for historical correlation",
            content=(
                f"{valid_count} validated indicator(s) are ready "
                "for incident-memory correlation."
            ),
            message_type="ioc_result",
            related_task_id=task.task_id,
            related_evidence_ids=[
                item.evidence_id
                for item in evidence
            ],
            metadata={
                "normalized_iocs": compact_iocs,
            },
        )

        return self.create_success_result(
            summary=summary,
            findings=[finding],
            evidence=evidence,
            proposed_tasks=proposed_tasks,
            metadata={
                "normalized_iocs": compact_iocs,
                "defanged_iocs": defanged_iocs,
                "valid_indicator_count": valid_count,
                "invalid_indicator_count": invalid_count,
                "confidence": confidence,
            },
        )