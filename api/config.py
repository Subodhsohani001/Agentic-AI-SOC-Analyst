"""
api/config.py

Central configuration for the Agentic AI SOC Analyst API.

This module stores application-wide settings so they are
defined in one place instead of being scattered throughout
the codebase.
"""

from pathlib import Path


# ---------------------------------------------------------
# Project Directories
# ---------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent

REPORTS_DIR = PROJECT_ROOT / "reports"
LOGS_DIR = PROJECT_ROOT / "logs"
CACHE_DIR = PROJECT_ROOT / "cache"

MEMORY_DIR = PROJECT_ROOT / "memory"
THREAT_INTELLIGENCE_DIR = PROJECT_ROOT / "threat_intelligence"
MULTI_AGENT_DIR = PROJECT_ROOT / "multi_agent"
RESPONSE_ENGINE_DIR = PROJECT_ROOT / "response_engine"


# ---------------------------------------------------------
# API Configuration
# ---------------------------------------------------------

API_TITLE = "Agentic AI SOC Analyst API"

API_DESCRIPTION = (
    "REST API for the Agentic AI SOC Analyst platform. "
    "Provides incident analysis, threat intelligence, "
    "multi-agent investigation, response orchestration, "
    "and analyst-ready reporting."
)

API_VERSION = "0.8.0"

API_PREFIX = "/api/v1"


# ---------------------------------------------------------
# Server Configuration
# ---------------------------------------------------------

HOST = "127.0.0.1"
PORT = 8000


# ---------------------------------------------------------
# Analysis Configuration
# ---------------------------------------------------------

DEFAULT_MODEL = "llama3.2"

MAX_UPLOAD_SIZE_MB = 10

SUPPORTED_LOG_EXTENSIONS = {
    ".log",
    ".txt",
    ".json",
}


# ---------------------------------------------------------
# Report Configuration
# ---------------------------------------------------------

REPORT_RETENTION_DAYS = 30

AUTO_GENERATE_PDF = True


# ---------------------------------------------------------
# Security
# ---------------------------------------------------------

ENABLE_SWAGGER = True

ENABLE_REDOC = True

DEBUG = False