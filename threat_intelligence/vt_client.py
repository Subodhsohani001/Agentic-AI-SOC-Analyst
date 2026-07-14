"""
VirusTotal API client for IOC enrichment.

Supported IOC types:
- IPv4 and IPv6 addresses
- Domains
- URLs
- MD5, SHA-1, and SHA-256 hashes

Workflow:
IOC validation
→ cache lookup
→ VirusTotal API request
→ deterministic response normalization
→ cache storage
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import os
import re
from typing import Any
from urllib.parse import urlparse

import requests

try:
    from .cache import ThreatIntelCache
except ImportError:
    # Allows direct execution:
    # python .\threat_intelligence\vt_client.py
    from cache import ThreatIntelCache


class VirusTotalError(Exception):
    """Base exception for VirusTotal client failures."""


class VirusTotalAuthenticationError(VirusTotalError):
    """Raised when the VirusTotal API key is invalid or missing."""


class VirusTotalRateLimitError(VirusTotalError):
    """Raised when the VirusTotal API rate limit is exceeded."""


class VirusTotalNotFoundError(VirusTotalError):
    """Raised when an IOC is not found in VirusTotal."""


class VirusTotalClient:
    """Retrieve and normalize IOC intelligence from VirusTotal API v3."""

    BASE_URL = "https://www.virustotal.com/api/v3"

    HASH_PATTERNS = {
        "md5": re.compile(r"^[a-fA-F0-9]{32}$"),
        "sha1": re.compile(r"^[a-fA-F0-9]{40}$"),
        "sha256": re.compile(r"^[a-fA-F0-9]{64}$"),
    }

    def __init__(
        self,
        api_key: str | None = None,
        cache: ThreatIntelCache | None = None,
        timeout_seconds: int = 20,
        cache_ttl_hours: int = 24,
    ) -> None:
        """
        Initialize the VirusTotal client.

        Args:
            api_key:
                VirusTotal API key. When omitted, the client reads
                the VT_API_KEY environment variable.

            cache:
                Optional existing ThreatIntelCache instance.

            timeout_seconds:
                Maximum time to wait for an API response.

            cache_ttl_hours:
                Number of hours VirusTotal results remain cached.
        """
        self.api_key = api_key or os.getenv("VT_API_KEY")

        if not self.api_key:
            raise VirusTotalAuthenticationError(
                "VirusTotal API key is missing. Set the VT_API_KEY "
                "environment variable or pass api_key explicitly."
            )

        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero.")

        if cache_ttl_hours <= 0:
            raise ValueError("cache_ttl_hours must be greater than zero.")

        self.timeout_seconds = timeout_seconds
        self.cache_ttl_hours = cache_ttl_hours
        self.cache = cache or ThreatIntelCache()

        self.session = requests.Session()
        self.session.headers.update(
            {
                "x-apikey": self.api_key,
                "Accept": "application/json",
                "User-Agent": "Agentic-AI-SOC-Analyst/0.5.0",
            }
        )

    @staticmethod
    def _normalize_ioc(ioc: str) -> str:
        """Strip surrounding whitespace from an IOC."""
        if not isinstance(ioc, str):
            raise TypeError("IOC must be a string.")

        normalized = ioc.strip()

        if not normalized:
            raise ValueError("IOC cannot be empty.")

        return normalized

    @classmethod
    def detect_ioc_type(cls, ioc: str) -> str:
        """
        Determine the IOC type.

        Returns:
            One of:
            - ipv4
            - ipv6
            - domain
            - url
            - md5
            - sha1
            - sha256
        """
        normalized = cls._normalize_ioc(ioc)

        for hash_type, pattern in cls.HASH_PATTERNS.items():
            if pattern.fullmatch(normalized):
                return hash_type

        try:
            parsed_ip = ipaddress.ip_address(normalized)
            return "ipv4" if parsed_ip.version == 4 else "ipv6"
        except ValueError:
            pass

        parsed_url = urlparse(normalized)

        if (
            parsed_url.scheme.lower() in {"http", "https"}
            and parsed_url.netloc
        ):
            return "url"

        if cls._is_valid_domain(normalized):
            return "domain"

        raise ValueError(f"Unsupported or invalid IOC: {ioc!r}")

    @staticmethod
    def _is_valid_domain(value: str) -> bool:
        """Return True when the value resembles a valid domain name."""
        domain = value.rstrip(".").lower()

        if len(domain) > 253:
            return False

        labels = domain.split(".")

        if len(labels) < 2:
            return False

        label_pattern = re.compile(
            r"^(?!-)[a-z0-9-]{1,63}(?<!-)$",
            re.IGNORECASE,
        )

        return all(label_pattern.fullmatch(label) for label in labels)

    @staticmethod
    def _url_identifier(url: str) -> str:
        """
        Generate the URL-safe Base64 identifier required by VirusTotal.

        VirusTotal URL identifiers omit trailing '=' padding.
        """
        encoded = base64.urlsafe_b64encode(url.encode("utf-8"))
        return encoded.decode("ascii").rstrip("=")

    @classmethod
    def _build_endpoint(cls, ioc: str, ioc_type: str) -> str:
        """Build the VirusTotal API endpoint for an IOC."""
        if ioc_type in {"ipv4", "ipv6"}:
            return f"/ip_addresses/{ioc}"

        if ioc_type == "domain":
            return f"/domains/{ioc.lower()}"

        if ioc_type in {"md5", "sha1", "sha256"}:
            return f"/files/{ioc.lower()}"

        if ioc_type == "url":
            return f"/urls/{cls._url_identifier(ioc)}"

        raise ValueError(f"Unsupported IOC type: {ioc_type!r}")

    def lookup(
        self,
        ioc: str,
        force_refresh: bool = False,
    ) -> dict[str, Any]:
        """
        Enrich one IOC using VirusTotal.

        Args:
            ioc:
                IP, domain, URL, or file hash.

            force_refresh:
                Skip the cache and query VirusTotal directly.

        Returns:
            Deterministically normalized VirusTotal intelligence.
        """
        normalized_ioc = self._normalize_ioc(ioc)
        ioc_type = self.detect_ioc_type(normalized_ioc)

        if not force_refresh:
            cached_result = self.cache.get(
                source="virustotal",
                ioc=normalized_ioc,
            )

            if cached_result is not None:
                return {
                    **cached_result,
                    "cache_hit": True,
                }

        endpoint = self._build_endpoint(normalized_ioc, ioc_type)
        raw_response = self._request(endpoint)

        normalized_result = self._normalize_response(
            ioc=normalized_ioc,
            ioc_type=ioc_type,
            response=raw_response,
        )

        self.cache.set(
            source="virustotal",
            ioc=normalized_ioc,
            data=normalized_result,
            ttl_hours=self.cache_ttl_hours,
        )

        return {
            **normalized_result,
            "cache_hit": False,
        }

    def _request(self, endpoint: str) -> dict[str, Any]:
        """Send a GET request to VirusTotal and handle known failures."""
        url = f"{self.BASE_URL}{endpoint}"

        try:
            response = self.session.get(
                url,
                timeout=self.timeout_seconds,
            )

        except requests.Timeout as exc:
            raise VirusTotalError(
                f"VirusTotal request timed out after "
                f"{self.timeout_seconds} seconds."
            ) from exc

        except requests.ConnectionError as exc:
            raise VirusTotalError(
                "Unable to connect to VirusTotal."
            ) from exc

        except requests.RequestException as exc:
            raise VirusTotalError(
                f"VirusTotal request failed: {exc}"
            ) from exc

        if response.status_code == 401:
            raise VirusTotalAuthenticationError(
                "VirusTotal rejected the API key."
            )

        if response.status_code == 403:
            raise VirusTotalAuthenticationError(
                "VirusTotal denied access to this resource."
            )

        if response.status_code == 404:
            raise VirusTotalNotFoundError(
                "The IOC was not found in VirusTotal."
            )

        if response.status_code == 429:
            raise VirusTotalRateLimitError(
                "VirusTotal API rate limit exceeded."
            )

        if not response.ok:
            raise VirusTotalError(
                f"VirusTotal returned HTTP {response.status_code}: "
                f"{self._extract_error_message(response)}"
            )

        try:
            payload = response.json()
        except ValueError as exc:
            raise VirusTotalError(
                "VirusTotal returned invalid JSON."
            ) from exc

        if not isinstance(payload, dict):
            raise VirusTotalError(
                "VirusTotal response must be a JSON object."
            )

        return payload

    @staticmethod
    def _extract_error_message(response: requests.Response) -> str:
        """Extract a readable error message from a failed API response."""
        try:
            payload = response.json()

            error = payload.get("error", {})

            if isinstance(error, dict):
                message = error.get("message")

                if isinstance(message, str) and message:
                    return message

        except ValueError:
            pass

        return response.text[:300] or "Unknown VirusTotal error"

    @classmethod
    def _normalize_response(
        cls,
        ioc: str,
        ioc_type: str,
        response: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Convert a VirusTotal response into a stable internal schema.

        Only verified API fields are included. No AI-generated conclusions
        are added at this stage.
        """
        data = response.get("data", {})

        if not isinstance(data, dict):
            raise VirusTotalError(
                "VirusTotal response is missing the data object."
            )

        attributes = data.get("attributes", {})

        if not isinstance(attributes, dict):
            attributes = {}

        stats = attributes.get("last_analysis_stats", {})

        if not isinstance(stats, dict):
            stats = {}

        normalized_stats = {
            "malicious": cls._safe_int(stats.get("malicious")),
            "suspicious": cls._safe_int(stats.get("suspicious")),
            "harmless": cls._safe_int(stats.get("harmless")),
            "undetected": cls._safe_int(stats.get("undetected")),
            "timeout": cls._safe_int(stats.get("timeout")),
        }

        total_engines = sum(normalized_stats.values())
        malicious_count = normalized_stats["malicious"]
        suspicious_count = normalized_stats["suspicious"]

        detection_ratio = (
            round(
                ((malicious_count + suspicious_count) / total_engines) * 100,
                2,
            )
            if total_engines > 0
            else 0.0
        )

        result: dict[str, Any] = {
            "source": "virustotal",
            "ioc": ioc,
            "ioc_type": ioc_type,
            "resource_id": data.get("id"),
            "analysis_stats": normalized_stats,
            "total_engines": total_engines,
            "detection_ratio_percent": detection_ratio,
            "reputation": cls._safe_int(attributes.get("reputation")),
            "last_analysis_date": attributes.get("last_analysis_date"),
            "first_submission_date": attributes.get(
                "first_submission_date"
            ),
            "last_submission_date": attributes.get(
                "last_submission_date"
            ),
            "last_modification_date": attributes.get(
                "last_modification_date"
            ),
            "tags": cls._safe_string_list(attributes.get("tags")),
            "categories": cls._normalize_categories(
                attributes.get("categories")
            ),
            "popular_threat_classification": (
                cls._normalize_threat_classification(
                    attributes.get("popular_threat_classification")
                )
            ),
            "file_details": cls._extract_file_details(
                attributes,
                ioc_type,
            ),
        }

        result["verdict"] = cls._derive_verdict(normalized_stats)

        return result

    @staticmethod
    def _safe_int(value: Any) -> int:
        """Convert a value to int, returning zero when conversion fails."""
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0

    @staticmethod
    def _safe_string_list(value: Any) -> list[str]:
        """Return a cleaned list containing only non-empty strings."""
        if not isinstance(value, list):
            return []

        return [
            item.strip()
            for item in value
            if isinstance(item, str) and item.strip()
        ]

    @staticmethod
    def _normalize_categories(value: Any) -> dict[str, str]:
        """Normalize VirusTotal category mappings."""
        if not isinstance(value, dict):
            return {}

        return {
            str(engine): str(category)
            for engine, category in value.items()
            if category is not None
        }

    @staticmethod
    def _normalize_threat_classification(
        value: Any,
    ) -> dict[str, Any]:
        """Normalize popular threat classification data."""
        if not isinstance(value, dict):
            return {}

        suggested_label = value.get("suggested_threat_label")
        threat_category = value.get("popular_threat_category")
        threat_name = value.get("popular_threat_name")

        return {
            "suggested_threat_label": (
                suggested_label
                if isinstance(suggested_label, str)
                else None
            ),
            "popular_threat_category": (
                threat_category
                if isinstance(threat_category, list)
                else []
            ),
            "popular_threat_name": (
                threat_name
                if isinstance(threat_name, list)
                else []
            ),
        }

    @staticmethod
    def _extract_file_details(
        attributes: dict[str, Any],
        ioc_type: str,
    ) -> dict[str, Any] | None:
        """Extract file-specific fields only for hash lookups."""
        if ioc_type not in {"md5", "sha1", "sha256"}:
            return None

        return {
            "meaningful_name": attributes.get("meaningful_name"),
            "type_description": attributes.get("type_description"),
            "type_tag": attributes.get("type_tag"),
            "size": attributes.get("size"),
            "md5": attributes.get("md5"),
            "sha1": attributes.get("sha1"),
            "sha256": attributes.get("sha256"),
            "names": VirusTotalClient._safe_string_list(
                attributes.get("names")
            ),
        }

    @staticmethod
    def _derive_verdict(stats: dict[str, int]) -> str:
        """
        Derive a deterministic preliminary verdict from engine statistics.

        This is not the final multi-source reputation verdict.
        """
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        if malicious >= 10:
            return "malicious"

        if malicious >= 3:
            return "likely_malicious"

        if malicious >= 1 or suspicious >= 2:
            return "suspicious"

        return "no_malicious_detection"

    def close(self) -> None:
        """Close the underlying HTTP session."""
        self.session.close()

    def __enter__(self) -> VirusTotalClient:
        """Support use as a context manager."""
        return self

    def __exit__(self, *_: object) -> None:
        """Close the HTTP session when leaving a context block."""
        self.close()

