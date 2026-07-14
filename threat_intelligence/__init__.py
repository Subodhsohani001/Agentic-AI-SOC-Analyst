"""
Threat-intelligence subsystem for Agentic AI SOC Analyst v0.5.0.

Exports:
- Cache management
- VirusTotal enrichment
- AbuseIPDB enrichment
- Deterministic reputation scoring
- Historical intelligence correlation
- Analyst-ready intelligence summaries
"""

from .abuseipdb_client import (
    AbuseIPDBAuthenticationError,
    AbuseIPDBClient,
    AbuseIPDBError,
    AbuseIPDBNotFoundError,
    AbuseIPDBRateLimitError,
)
from .cache import ThreatIntelCache
from .intelligence_correlator import IntelligenceCorrelator
from .intelligence_summary import IntelligenceSummaryBuilder
from .reputation_engine import ReputationEngine
from .vt_client import (
    VirusTotalAuthenticationError,
    VirusTotalClient,
    VirusTotalError,
    VirusTotalNotFoundError,
    VirusTotalRateLimitError,
)

__all__ = [
    "ThreatIntelCache",
    "VirusTotalClient",
    "VirusTotalError",
    "VirusTotalAuthenticationError",
    "VirusTotalRateLimitError",
    "VirusTotalNotFoundError",
    "AbuseIPDBClient",
    "AbuseIPDBError",
    "AbuseIPDBAuthenticationError",
    "AbuseIPDBRateLimitError",
    "AbuseIPDBNotFoundError",
    "ReputationEngine",
    "IntelligenceCorrelator",
    "IntelligenceSummaryBuilder",
]

__version__ = "0.5.0"