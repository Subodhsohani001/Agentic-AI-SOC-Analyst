from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, asdict
from typing import Any

import requests


@dataclass
class ProviderResult:
    provider: str
    status: str
    data: dict[str, Any]
    error: str = ""


@dataclass
class ThreatIntelResult:
    observable: str
    observable_type: str
    is_private: bool
    providers: list[ProviderResult]
    combined_risk_score: int
    verdict: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "observable": self.observable,
            "observable_type": self.observable_type,
            "is_private": self.is_private,
            "providers": [asdict(item) for item in self.providers],
            "combined_risk_score": self.combined_risk_score,
            "verdict": self.verdict,
        }


class ThreatIntelClient:
    """
    Read-only threat-intelligence enrichment.

    Supported lookups:
    - Public IPv4 addresses through VirusTotal
    - Public IPv4 addresses through AbuseIPDB

    Safety rules:
    - Private, loopback, link-local, multicast, reserved, and unspecified
      IP addresses are not sent to external services.
    - This module never submits files, URLs, domains, or IPs for analysis.
    - This module never blacklists anything.
    """

    def __init__(
        self,
        virustotal_api_key: str | None = None,
        abuseipdb_api_key: str | None = None,
        timeout_seconds: int = 15,
    ) -> None:
        self.virustotal_api_key = (
            virustotal_api_key or os.getenv("VIRUSTOTAL_API_KEY", "")
        ).strip()
        self.abuseipdb_api_key = (
            abuseipdb_api_key or os.getenv("ABUSEIPDB_API_KEY", "")
        ).strip()
        self.timeout_seconds = timeout_seconds

        # Kept configurable because provider APIs can change.
        self.virustotal_base_url = os.getenv(
            "VIRUSTOTAL_BASE_URL",
            "https://www.virustotal.com/api/v3",
        ).rstrip("/")

        self.abuseipdb_base_url = os.getenv(
            "ABUSEIPDB_BASE_URL",
            "https://api.abuseipdb.com/api/v2",
        ).rstrip("/")

    @staticmethod
    def _classify_ip(ip_value: str) -> ipaddress.IPv4Address:
        parsed = ipaddress.ip_address(ip_value)
        if not isinstance(parsed, ipaddress.IPv4Address):
            raise ValueError("Only IPv4 enrichment is currently supported.")
        return parsed

    @staticmethod
    def _must_stay_local(ip_obj: ipaddress.IPv4Address) -> bool:
        return any(
            (
                ip_obj.is_private,
                ip_obj.is_loopback,
                ip_obj.is_link_local,
                ip_obj.is_multicast,
                ip_obj.is_reserved,
                ip_obj.is_unspecified,
            )
        )

    def lookup_virustotal_ip(self, ip_value: str) -> ProviderResult:
        if not self.virustotal_api_key:
            return ProviderResult(
                provider="VirusTotal",
                status="not_configured",
                data={},
                error="VIRUSTOTAL_API_KEY is not configured.",
            )

        url = f"{self.virustotal_base_url}/ip_addresses/{ip_value}"
        headers = {"x-apikey": self.virustotal_api_key}

        try:
            response = requests.get(
                url,
                headers=headers,
                timeout=self.timeout_seconds,
            )
            response.raise_for_status()
            payload = response.json()

            attributes = payload.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})

            return ProviderResult(
                provider="VirusTotal",
                status="ok",
                data={
                    "harmless": int(stats.get("harmless", 0)),
                    "malicious": int(stats.get("malicious", 0)),
                    "suspicious": int(stats.get("suspicious", 0)),
                    "undetected": int(stats.get("undetected", 0)),
                    "timeout": int(stats.get("timeout", 0)),
                    "reputation": int(attributes.get("reputation", 0)),
                    "country": attributes.get("country", ""),
                    "asn": attributes.get("asn"),
                    "as_owner": attributes.get("as_owner", ""),
                    "network": attributes.get("network", ""),
                },
            )
        except requests.RequestException as exc:
            return ProviderResult(
                provider="VirusTotal",
                status="error",
                data={},
                error=str(exc),
            )
        except (TypeError, ValueError) as exc:
            return ProviderResult(
                provider="VirusTotal",
                status="error",
                data={},
                error=f"Invalid provider response: {exc}",
            )

    def lookup_abuseipdb_ip(self, ip_value: str) -> ProviderResult:
        if not self.abuseipdb_api_key:
            return ProviderResult(
                provider="AbuseIPDB",
                status="not_configured",
                data={},
                error="ABUSEIPDB_API_KEY is not configured.",
            )

        url = f"{self.abuseipdb_base_url}/check"
        headers = {
            "Key": self.abuseipdb_api_key,
            "Accept": "application/json",
        }
        params = {
            "ipAddress": ip_value,
            "maxAgeInDays": 90,
            "verbose": "",
        }

        try:
            response = requests.get(
                url,
                headers=headers,
                params=params,
                timeout=self.timeout_seconds,
            )
            response.raise_for_status()
            payload = response.json()
            data = payload.get("data", {})

            return ProviderResult(
                provider="AbuseIPDB",
                status="ok",
                data={
                    "abuse_confidence_score": int(
                        data.get("abuseConfidenceScore", 0)
                    ),
                    "total_reports": int(data.get("totalReports", 0)),
                    "last_reported_at": data.get("lastReportedAt"),
                    "country_code": data.get("countryCode", ""),
                    "usage_type": data.get("usageType", ""),
                    "isp": data.get("isp", ""),
                    "domain": data.get("domain", ""),
                    "is_tor": bool(data.get("isTor", False)),
                    "is_whitelisted": data.get("isWhitelisted"),
                },
            )
        except requests.RequestException as exc:
            return ProviderResult(
                provider="AbuseIPDB",
                status="error",
                data={},
                error=str(exc),
            )
        except (TypeError, ValueError) as exc:
            return ProviderResult(
                provider="AbuseIPDB",
                status="error",
                data={},
                error=f"Invalid provider response: {exc}",
            )

    @staticmethod
    def _calculate_risk(providers: list[ProviderResult]) -> tuple[int, str]:
        score = 0

        for result in providers:
            if result.status != "ok":
                continue

            if result.provider == "VirusTotal":
                malicious = int(result.data.get("malicious", 0))
                suspicious = int(result.data.get("suspicious", 0))
                reputation = int(result.data.get("reputation", 0))

                score += min(malicious * 8, 50)
                score += min(suspicious * 4, 20)

                if reputation < 0:
                    score += min(abs(reputation), 20)

            elif result.provider == "AbuseIPDB":
                abuse_score = int(
                    result.data.get("abuse_confidence_score", 0)
                )
                total_reports = int(result.data.get("total_reports", 0))
                is_whitelisted = result.data.get("is_whitelisted") is True

                if not is_whitelisted:
                    score += round(abuse_score * 0.4)

                    #Report count should only influence risk when ABUSEIPDB already
                    # shows some confidence that the IP is abusive
                    if abuse_score > 0:
                        score += min(total_reports, 10)       
                

        score = max(0, min(score, 100))

        if score >= 80:
            verdict = "Critical Risk"
        elif score >= 60:
            verdict = "High Risk"
        elif score >= 30:
            verdict = "Medium Risk"
        elif score > 0:
            verdict = "Low Risk"
        else:
            verdict = "No External Risk Signal"

        return score, verdict

    def enrich_ip(self, ip_value: str) -> ThreatIntelResult:
        ip_obj = self._classify_ip(ip_value)
        local_only = self._must_stay_local(ip_obj)

        if local_only:
            providers = [
                ProviderResult(
                    provider="Local Safety Check",
                    status="skipped",
                    data={},
                    error=(
                        "The IP is private or non-routable and was not sent "
                        "to external threat-intelligence providers."
                    ),
                )
            ]

            return ThreatIntelResult(
                observable=ip_value,
                observable_type="ipv4",
                is_private=True,
                providers=providers,
                combined_risk_score=0,
                verdict="Internal IP - External Lookup Skipped",
            )

        providers = [
            self.lookup_virustotal_ip(ip_value),
            self.lookup_abuseipdb_ip(ip_value),
        ]
        risk_score, verdict = self._calculate_risk(providers)

        return ThreatIntelResult(
            observable=ip_value,
            observable_type="ipv4",
            is_private=False,
            providers=providers,
            combined_risk_score=risk_score,
            verdict=verdict,
        )

    def enrich_facts(
        self,
        facts: dict[str, list[str]],
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        for ip_value in facts.get("ip_addresses", []):
            try:
                result = self.enrich_ip(ip_value)
                results.append(result.to_dict())
            except ValueError as exc:
                results.append(
                    {
                        "observable": ip_value,
                        "observable_type": "ipv4",
                        "is_private": False,
                        "providers": [],
                        "combined_risk_score": 0,
                        "verdict": "Invalid IP",
                        "error": str(exc),
                    }
                )

        return results
