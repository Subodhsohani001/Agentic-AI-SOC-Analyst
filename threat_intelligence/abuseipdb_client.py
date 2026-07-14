"""
AbuseIPDB API client for IP reputation enrichment.

Workflow:
IP validation
→ private/reserved IP rejection
→ cache lookup
→ AbuseIPDB API request
→ deterministic response normalization
→ cache storage
"""

from __future__ import annotations

import ipaddress
import os
from typing import Any

import requests

try:
    from .cache import ThreatIntelCache
except ImportError:
    # Supports direct execution:
    # python .\threat_intelligence\abuseipdb_client.py
    from cache import ThreatIntelCache


class AbuseIPDBError(Exception):
    """Base exception for AbuseIPDB client failures."""


class AbuseIPDBAuthenticationError(AbuseIPDBError):
    """Raised when the API key is missing or rejected."""


class AbuseIPDBRateLimitError(AbuseIPDBError):
    """Raised when the AbuseIPDB API quota is exhausted."""


class AbuseIPDBNotFoundError(AbuseIPDBError):
    """Raised when AbuseIPDB has no data for the requested IP."""


class AbuseIPDBClient:
    """Retrieve and normalize IP intelligence from AbuseIPDB API v2."""

    BASE_URL = "https://api.abuseipdb.com/api/v2"
    CHECK_ENDPOINT = "/check"

    def __init__(
        self,
        api_key: str | None = None,
        cache: ThreatIntelCache | None = None,
        timeout_seconds: int = 20,
        cache_ttl_hours: int = 24,
        max_age_days: int = 90,
    ) -> None:
        """
        Initialize the AbuseIPDB client.

        Args:
            api_key:
                AbuseIPDB API key. Defaults to the
                ABUSEIPDB_API_KEY environment variable.

            cache:
                Optional shared ThreatIntelCache instance.

            timeout_seconds:
                Maximum duration for an HTTP request.

            cache_ttl_hours:
                Number of hours results remain cached.

            max_age_days:
                How far back AbuseIPDB should check reports.
        """
        self.api_key = api_key or os.getenv("ABUSEIPDB_API_KEY")

        if not self.api_key:
            raise AbuseIPDBAuthenticationError(
                "AbuseIPDB API key is missing. Set the "
                "ABUSEIPDB_API_KEY environment variable or pass "
                "api_key explicitly."
            )

        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero.")

        if cache_ttl_hours <= 0:
            raise ValueError("cache_ttl_hours must be greater than zero.")

        if not 1 <= max_age_days <= 365:
            raise ValueError("max_age_days must be between 1 and 365.")

        self.timeout_seconds = timeout_seconds
        self.cache_ttl_hours = cache_ttl_hours
        self.max_age_days = max_age_days
        self.cache = cache or ThreatIntelCache()

        self.session = requests.Session()
        self.session.headers.update(
            {
                "Key": self.api_key,
                "Accept": "application/json",
                "User-Agent": "Agentic-AI-SOC-Analyst/0.5.0",
            }
        )

    @staticmethod
    def validate_ip(ip_address: str) -> str:
        """
        Validate and normalize an IPv4 or IPv6 address.

        AbuseIPDB enrichment is restricted to globally routable addresses.
        Local, loopback, multicast, reserved, and unspecified IPs are rejected.
        """
        if not isinstance(ip_address, str):
            raise TypeError("IP address must be a string.")

        normalized = ip_address.strip()

        if not normalized:
            raise ValueError("IP address cannot be empty.")

        try:
            parsed_ip = ipaddress.ip_address(normalized)
        except ValueError as exc:
            raise ValueError(
                f"Invalid IP address: {ip_address!r}"
            ) from exc

        if not parsed_ip.is_global:
            raise ValueError(
                f"AbuseIPDB lookup skipped for non-global IP: {normalized}"
            )

        return parsed_ip.compressed

    def lookup(
        self,
        ip_address: str,
        force_refresh: bool = False,
    ) -> dict[str, Any]:
        """
        Enrich one public IP address with AbuseIPDB.

        Args:
            ip_address:
                Public IPv4 or IPv6 address.

            force_refresh:
                Skip a valid cache entry and query the API directly.

        Returns:
            Normalized AbuseIPDB intelligence.
        """
        normalized_ip = self.validate_ip(ip_address)

        if not force_refresh:
            cached_result = self.cache.get(
                source="abuseipdb",
                ioc=normalized_ip,
            )

            if cached_result is not None:
                return {
                    **cached_result,
                    "cache_hit": True,
                }

        raw_response = self._request(normalized_ip)

        normalized_result = self._normalize_response(
            ip_address=normalized_ip,
            response=raw_response,
        )

        self.cache.set(
            source="abuseipdb",
            ioc=normalized_ip,
            data=normalized_result,
            ttl_hours=self.cache_ttl_hours,
        )

        return {
            **normalized_result,
            "cache_hit": False,
        }

    def _request(self, ip_address: str) -> dict[str, Any]:
        """Call the AbuseIPDB check endpoint."""
        url = f"{self.BASE_URL}{self.CHECK_ENDPOINT}"

        parameters = {
            "ipAddress": ip_address,
            "maxAgeInDays": self.max_age_days,
        }

        try:
            response = self.session.get(
                url,
                params=parameters,
                timeout=self.timeout_seconds,
            )

        except requests.Timeout as exc:
            raise AbuseIPDBError(
                f"AbuseIPDB request timed out after "
                f"{self.timeout_seconds} seconds."
            ) from exc

        except requests.ConnectionError as exc:
            raise AbuseIPDBError(
                "Unable to connect to AbuseIPDB."
            ) from exc

        except requests.RequestException as exc:
            raise AbuseIPDBError(
                f"AbuseIPDB request failed: {exc}"
            ) from exc

        if response.status_code in {401, 403}:
            raise AbuseIPDBAuthenticationError(
                "AbuseIPDB rejected the API key or denied access."
            )

        if response.status_code == 404:
            raise AbuseIPDBNotFoundError(
                f"No AbuseIPDB data found for {ip_address}."
            )

        if response.status_code == 429:
            raise AbuseIPDBRateLimitError(
                "AbuseIPDB API rate limit exceeded."
            )

        if not response.ok:
            raise AbuseIPDBError(
                f"AbuseIPDB returned HTTP {response.status_code}: "
                f"{self._extract_error_message(response)}"
            )

        try:
            payload = response.json()
        except ValueError as exc:
            raise AbuseIPDBError(
                "AbuseIPDB returned invalid JSON."
            ) from exc

        if not isinstance(payload, dict):
            raise AbuseIPDBError(
                "AbuseIPDB response must be a JSON object."
            )

        return payload

    @staticmethod
    def _extract_error_message(response: requests.Response) -> str:
        """Extract a readable message from an unsuccessful response."""
        try:
            payload = response.json()

            errors = payload.get("errors")

            if isinstance(errors, list) and errors:
                first_error = errors[0]

                if isinstance(first_error, dict):
                    detail = first_error.get("detail")

                    if isinstance(detail, str) and detail:
                        return detail

            error = payload.get("error")

            if isinstance(error, str) and error:
                return error

        except ValueError:
            pass

        return response.text[:300] or "Unknown AbuseIPDB error"

    @classmethod
    def _normalize_response(
        cls,
        ip_address: str,
        response: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Convert an AbuseIPDB response into a stable internal schema.

        No AI-generated conclusions are introduced here.
        """
        data = response.get("data")

        if not isinstance(data, dict):
            raise AbuseIPDBError(
                "AbuseIPDB response is missing the data object."
            )

        abuse_score = cls._clamp_score(
            data.get("abuseConfidenceScore")
        )

        total_reports = cls._safe_int(data.get("totalReports"))
        num_distinct_users = cls._safe_int(
            data.get("numDistinctUsers")
        )

        result: dict[str, Any] = {
            "source": "abuseipdb",
            "ioc": ip_address,
            "ioc_type": (
                "ipv4"
                if ipaddress.ip_address(ip_address).version == 4
                else "ipv6"
            ),
            "is_public": bool(data.get("isPublic", True)),
            "ip_version": cls._safe_int(data.get("ipVersion")),
            "is_whitelisted": cls._safe_bool_or_none(
                data.get("isWhitelisted")
            ),
            "abuse_confidence_score": abuse_score,
            "country_code": cls._safe_string(data.get("countryCode")),
            "country_name": cls._safe_string(data.get("countryName")),
            "usage_type": cls._safe_string(data.get("usageType")),
            "isp": cls._safe_string(data.get("isp")),
            "domain": cls._safe_string(data.get("domain")),
            "hostnames": cls._safe_string_list(data.get("hostnames")),
            "total_reports": total_reports,
            "num_distinct_users": num_distinct_users,
            "last_reported_at": cls._safe_string(
                data.get("lastReportedAt")
            ),
        }

        result["verdict"] = cls._derive_verdict(
            abuse_score=abuse_score,
            total_reports=total_reports,
            is_whitelisted=result["is_whitelisted"],
        )

        return result

    @staticmethod
    def _safe_int(value: Any) -> int:
        """Convert a value to int, returning zero on failure."""
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0

    @staticmethod
    def _clamp_score(value: Any) -> int:
        """Convert an abuse score into the inclusive range 0–100."""
        try:
            score = int(value)
        except (TypeError, ValueError):
            return 0

        return max(0, min(score, 100))

    @staticmethod
    def _safe_string(value: Any) -> str | None:
        """Return a stripped string or None."""
        if not isinstance(value, str):
            return None

        stripped = value.strip()
        return stripped or None

    @staticmethod
    def _safe_string_list(value: Any) -> list[str]:
        """Return only cleaned non-empty strings from a list."""
        if not isinstance(value, list):
            return []

        return [
            item.strip()
            for item in value
            if isinstance(item, str) and item.strip()
        ]

    @staticmethod
    def _safe_bool_or_none(value: Any) -> bool | None:
        """Preserve a Boolean value while rejecting unrelated types."""
        return value if isinstance(value, bool) else None

    @staticmethod
    def _derive_verdict(
        abuse_score: int,
        total_reports: int,
        is_whitelisted: bool | None,
    ) -> str:
        """
        Produce a deterministic preliminary AbuseIPDB verdict.

        The final multi-source verdict will be generated later by
        reputation_engine.py.
        """
        if is_whitelisted is True and abuse_score < 25:
            return "trusted"

        if abuse_score >= 90:
            return "confirmed_abusive"

        if abuse_score >= 70:
            return "likely_abusive"

        if abuse_score >= 25:
            return "suspicious"

        if total_reports > 0:
            return "reported_low_confidence"

        return "no_abuse_evidence"

    def close(self) -> None:
        """Close the HTTP session."""
        self.session.close()

    def __enter__(self) -> AbuseIPDBClient:
        """Support context-manager usage."""
        return self

    def __exit__(self, *_: object) -> None:
        """Close the session when leaving a context block."""
        self.close()


