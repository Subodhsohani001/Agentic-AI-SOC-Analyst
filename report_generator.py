from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any
import re
from html import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


class PDFReportGenerator:
    """
    Generates analyst-facing SOC incident reports.

    Security rule:
    - Use defanged/display IOCs in the PDF.
    - Do not expose raw clickable URLs or domains in analyst-facing sections.
    """

    def __init__(self, output_dir: str | Path = "reports") -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.styles = getSampleStyleSheet()
        self.styles.add(
            ParagraphStyle(
                name="ReportTitle",
                parent=self.styles["Title"],
                fontSize=20,
                leading=24,
                alignment=TA_CENTER,
                spaceAfter=12,
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="SectionHeading",
                parent=self.styles["Heading2"],
                fontSize=13,
                leading=16,
                spaceBefore=10,
                spaceAfter=6,
                textColor=colors.HexColor("#1F3A5F"),
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="ReportBody",
                parent=self.styles["BodyText"],
                fontSize=9.5,
                leading=13,
                alignment=TA_LEFT,
                spaceAfter=6,
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="SmallText",
                parent=self.styles["BodyText"],
                fontSize=8,
                leading=10,
            )
        )

    @staticmethod
    def _safe_text(value: Any) -> str:
        if value is None:
            return "Not available"
        text = str(value).strip()

        if not text:
            return "Not Available"
        return escape(text, quote=True)
    
    @classmethod
    def _defang_observable(cls, value: Any) -> str:
        """Return an analyst-safe representation of an observable."""
        text = cls._safe_text(value)

        text = text.replace("https://", "hxxps://")
        text = text.replace("http://", "hxxp://")
        text = text.replace(".", "[.]")

        return text

    @staticmethod
    def _slugify(value: str) -> str:
        value = re.sub(r"[^A-Za-z0-9_-]+", "_", value.strip())
        return value.strip("_") or "incident"

    @staticmethod
    def _severity_color(severity: str):
        mapping = {
            "Low": colors.HexColor("#2E7D32"),
            "Medium": colors.HexColor("#F9A825"),
            "High": colors.HexColor("#EF6C00"),
            "Critical": colors.HexColor("#C62828"),
        }
        return mapping.get(severity, colors.HexColor("#546E7A"))

    @staticmethod
    def _page_number(canvas, doc) -> None:
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.drawString(18 * mm, 12 * mm, "SOC Agentic AI - Incident Report")
        canvas.drawRightString(
            A4[0] - 18 * mm,
            12 * mm,
            f"Page {doc.page}",
        )
        canvas.restoreState()

    def _key_value_table(self, rows: list[tuple[str, str]]) -> Table:
        data = [
            [
                Paragraph(f"<b>{self._safe_text(key)}</b>", self.styles["SmallText"]),
                Paragraph(self._safe_text(value), self.styles["SmallText"]),
            ]
            for key, value in rows
        ]

        table = Table(data, colWidths=[48 * mm, 122 * mm], hAlign="LEFT")
        table.setStyle(
            TableStyle(
                [
                    ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#B0BEC5")),
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#ECEFF1")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )
        return table

    def _ioc_table(self, display_facts: dict[str, list[str]]) -> Table:
        rows = [["IOC Type", "Defanged / Analyst-safe Values"]]

        field_labels = {
            "ip_addresses": "IP Addresses",
            "domains": "Domains",
            "urls": "URLs",
            "hashes": "Hashes",
            "file_names": "Files",
            "process_names": "Processes",
            "event_ids": "Event IDs",
            "email_addresses": "Email Addresses",
        }

        for field, label in field_labels.items():
            values = display_facts.get(field, [])
            if values:
                value_text = "<br/>".join(self._safe_text(item) for item in values)
                rows.append(
                    [
                        Paragraph(f"<b>{label}</b>", self.styles["SmallText"]),
                        Paragraph(value_text, self.styles["SmallText"]),
                    ]
                )

        if len(rows) == 1:
            rows.append(
                [
                    Paragraph("<b>Observed IOCs</b>", self.styles["SmallText"]),
                    Paragraph("No IOCs were extracted.", self.styles["SmallText"]),
                ]
            )

        table = Table(rows, colWidths=[43 * mm, 127 * mm], repeatRows=1, hAlign="LEFT")
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#263238")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#B0BEC5")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )
        return table
    
    def _threat_intel_table(
            self,
            threat_intel: list[dict[str, Any]],
        ) -> Table:
            rows = [
                [
                    Paragraph(
                        "<b>Observable</b>",
                        self.styles["SmallText"],
                    ),
                    Paragraph(
                        "<b>Verdict</b>",
                        self.styles["SmallText"],
                    ),
                    Paragraph(
                        "<b>Risk Score</b>",
                        self.styles["SmallText"],
                    ),
                    Paragraph(
                        "<b>Provider Status</b>",
                        self.styles["SmallText"],
                    ),
                ]
            ]

            for item in threat_intel:
                if not isinstance(item, dict):
                    continue

                observable = self._defang_observable(
                    item.get("observable")
                )

                verdict = self._safe_text(
                    item.get("verdict")
                )

                risk_score = (
                    f"{item.get('combined_risk_score', 0)} / 100"
                )

                provider_lines: list[str] = []

                providers = item.get("providers", [])

                if not isinstance(providers, list):
                    providers = []

                for provider in providers:
                    if not isinstance(provider, dict):
                        continue

                    provider_name = self._safe_text(
                        provider.get("provider")
                    )

                    provider_status = self._safe_text(
                        provider.get("status")
                    )

                    provider_lines.append(
                        f"{provider_name} ({provider_status})"
                    )

                provider_text = (
                    "<br/>".join(provider_lines)
                    if provider_lines
                    else "No provider results"
                )

                rows.append(
                    [
                        Paragraph(
                            observable,
                            self.styles["SmallText"],
                        ),
                        Paragraph(
                            verdict,
                            self.styles["SmallText"],
                        ),
                        Paragraph(
                            risk_score,
                            self.styles["SmallText"],
                        ),
                        Paragraph(
                            provider_text,
                            self.styles["SmallText"],
                        ),
                    ]
                )

            if len(rows) == 1:
                rows.append(
                    [
                        Paragraph(
                            "No observables",
                            self.styles["SmallText"],
                        ),
                        Paragraph(
                            "No threat-intelligence results were available.",
                            self.styles["SmallText"],
                        ),
                        Paragraph(
                            "0 / 100",
                            self.styles["SmallText"],
                        ),
                        Paragraph(
                            "Not available",
                            self.styles["SmallText"],
                        ),
                    ]
                )

            table = Table(
                rows,
                colWidths=[
                    38 * mm,
                    55 * mm,
                    25 * mm,
                    52 * mm,
                ],
                repeatRows=1,
                hAlign="LEFT",
            )

            table.setStyle(
                TableStyle(
                    [
                        (
                            "BACKGROUND",
                            (0, 0),
                            (-1, 0),
                            colors.HexColor("#263238"),
                        ),
                        (
                            "TEXTCOLOR",
                            (0, 0),
                            (-1, 0),
                            colors.white,
                        ),
                        (
                            "GRID",
                            (0, 0),
                            (-1, -1),
                            0.35,
                            colors.HexColor("#B0BEC5"),
                        ),
                        (
                            "VALIGN",
                            (0, 0),
                            (-1, -1),
                            "TOP",
                        ),
                        (
                            "LEFTPADDING",
                            (0, 0),
                            (-1, -1),
                            5,
                        ),
                        (
                            "RIGHTPADDING",
                            (0, 0),
                            (-1, -1),
                            5,
                        ),
                        (
                            "TOPPADDING",
                            (0, 0),
                            (-1, -1),
                            6,
                        ),
                        (
                            "BOTTOMPADDING",
                            (0, 0),
                            (-1, -1),
                            6,
                        ),
                    ]
                )
            )

            return table

    def _intelligence_overview_table(
        self,
        intelligence_results: list[dict[str, Any]],
    ) -> Table:
        """Build the v0.5.0 multi-source intelligence overview table."""
        rows = [
            [
                Paragraph("<b>Observable</b>", self.styles["SmallText"]),
                Paragraph("<b>Risk</b>", self.styles["SmallText"]),
                Paragraph("<b>Verdict</b>", self.styles["SmallText"]),
                Paragraph("<b>Correlation</b>", self.styles["SmallText"]),
                Paragraph("<b>Action</b>", self.styles["SmallText"]),
            ]
        ]

        for item in intelligence_results:
            if not isinstance(item, dict):
                continue

            summary = item.get("summary", {})
            correlation = item.get("correlation", {})

            if not isinstance(summary, dict):
                summary = {}

            if not isinstance(correlation, dict):
                correlation = {}

            observable = self._defang_observable(
                item.get("ioc", item.get("observable"))
            )

            risk_score = self._safe_text(
                summary.get(
                    "risk_score",
                    item.get("reputation", {}).get("risk_score", 0)
                    if isinstance(item.get("reputation"), dict)
                    else 0,
                )
            )

            verdict = self._safe_text(
                summary.get("verdict")
            )

            severity = self._safe_text(
                summary.get("severity")
            )

            match_level = self._safe_text(
                correlation.get("match_level")
            )

            priority = self._safe_text(
                correlation.get("investigation_priority")
            )

            action = self._safe_text(
                summary.get(
                    "recommended_action",
                    correlation.get("recommended_action"),
                )
            )

            rows.append(
                [
                    Paragraph(observable, self.styles["SmallText"]),
                    Paragraph(
                        f"{risk_score} / 100<br/>{severity}",
                        self.styles["SmallText"],
                    ),
                    Paragraph(verdict, self.styles["SmallText"]),
                    Paragraph(
                        f"{match_level}<br/>{priority}",
                        self.styles["SmallText"],
                    ),
                    Paragraph(action, self.styles["SmallText"]),
                ]
            )

        if len(rows) == 1:
            rows.append(
                [
                    Paragraph(
                        "No observables",
                        self.styles["SmallText"],
                    ),
                    Paragraph("0 / 100", self.styles["SmallText"]),
                    Paragraph("Not available", self.styles["SmallText"]),
                    Paragraph("NONE", self.styles["SmallText"]),
                    Paragraph("Manual review", self.styles["SmallText"]),
                ]
            )

        table = Table(
            rows,
            colWidths=[
                42 * mm,
                27 * mm,
                36 * mm,
                30 * mm,
                35 * mm,
            ],
            repeatRows=1,
            hAlign="LEFT",
        )

        table.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, 0),
                        colors.HexColor("#1B263B"),
                    ),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        0.35,
                        colors.HexColor("#B0BEC5"),
                    ),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 5),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )

        return table

    def _correlation_matches_table(
        self,
        matches: list[dict[str, Any]],
    ) -> Table:
        rows = [
            [
                Paragraph(
                    "<b>Incident ID</b>",
                    self.styles["SmallText"],
                ),
                Paragraph(
                    "<b>Similarity</b>",
                    self.styles["SmallText"],
                ),
                Paragraph(
                    "<b>Match Level</b>",
                    self.styles["SmallText"],
                ),
                Paragraph(
                    "<b>Shared Evidence</b>",
                    self.styles["SmallText"],
                ),
            ]
        ]

        if not isinstance(matches, list):
            matches = []

        for match in matches:
            if not isinstance(match, dict):
                continue

            evidence = match.get("evidence", [])

            if not isinstance(evidence, list):
                evidence = []

            evidence_text = (
                "<br/>".join(
                    self._safe_text(item)
                    for item in evidence
                )
                if evidence
                else "No shared evidence"
            )

            rows.append(
                [
                    Paragraph(
                        self._safe_text(
                            match.get("incident_id")
                        ),
                        self.styles["SmallText"],
                    ),
                    Paragraph(
                        (
                            f"{match.get('similarity_score', 0)}%"
                        ),
                        self.styles["SmallText"],
                    ),
                    Paragraph(
                        self._safe_text(
                            match.get("match_level")
                        ),
                        self.styles["SmallText"],
                    ),
                    Paragraph(
                        evidence_text,
                        self.styles["SmallText"],
                    ),
                ]
            )

        if len(rows) == 1:
            rows.append(
                [
                    Paragraph(
                        "No match",
                        self.styles["SmallText"],
                    ),
                    Paragraph(
                        "0%",
                        self.styles["SmallText"],
                    ),
                    Paragraph(
                        "NONE",
                        self.styles["SmallText"],
                    ),
                    Paragraph(
                        "No historical incident met the correlation threshold.",
                        self.styles["SmallText"],
                    ),
                ]
            )

        table = Table(
            rows,
            colWidths=[
                35 * mm,
                25 * mm,
                28 * mm,
                82 * mm,
            ],
            repeatRows=1,
            hAlign="LEFT",
        )

        table.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, 0),
                        colors.HexColor("#263238"),
                    ),
                    (
                        "TEXTCOLOR",
                        (0, 0),
                        (-1, 0),
                        colors.white,
                    ),
                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        0.35,
                        colors.HexColor("#B0BEC5"),
                    ),
                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "TOP",
                    ),
                    (
                        "LEFTPADDING",
                        (0, 0),
                        (-1, -1),
                        5,
                    ),
                    (
                        "RIGHTPADDING",
                        (0, 0),
                        (-1, -1),
                        5,
                    ),
                    (
                        "TOPPADDING",
                        (0, 0),
                        (-1, -1),
                        5,
                    ),
                    (
                        "BOTTOMPADDING",
                        (0, 0),
                        (-1, -1),
                        5,
                    ),
                ]
            )
        )

        return table
    
    def _provider_findings_table(
        self,
        intelligence_results: list[dict[str, Any]],
    ) -> Table:
        """Display normalized VirusTotal and AbuseIPDB findings."""
        rows = [
            [
                Paragraph("<b>Observable</b>", self.styles["SmallText"]),
                Paragraph("<b>Provider</b>", self.styles["SmallText"]),
                Paragraph("<b>Verdict</b>", self.styles["SmallText"]),
                Paragraph("<b>Key Findings</b>", self.styles["SmallText"]),
            ]
        ]

        for item in intelligence_results:
            if not isinstance(item, dict):
                continue

            observable = self._defang_observable(
                item.get("ioc", item.get("observable"))
            )

            virustotal = item.get("virustotal")
            abuseipdb = item.get("abuseipdb")

            if isinstance(virustotal, dict):
                stats = virustotal.get("analysis_stats", {})

                if not isinstance(stats, dict):
                    stats = {}

                vt_findings = (
                    f"Malicious engines: "
                    f"{self._safe_text(stats.get('malicious', 0))}<br/>"
                    f"Suspicious engines: "
                    f"{self._safe_text(stats.get('suspicious', 0))}<br/>"
                    f"Detection ratio: "
                    f"{self._safe_text(virustotal.get('detection_ratio_percent', 0))}%<br/>"
                    f"Reputation: "
                    f"{self._safe_text(virustotal.get('reputation', 0))}"
                )

                rows.append(
                    [
                        Paragraph(observable, self.styles["SmallText"]),
                        Paragraph("VirusTotal", self.styles["SmallText"]),
                        Paragraph(
                            self._safe_text(virustotal.get("verdict")),
                            self.styles["SmallText"],
                        ),
                        Paragraph(vt_findings, self.styles["SmallText"]),
                    ]
                )

            if isinstance(abuseipdb, dict):
                abuse_findings = (
                    f"Abuse confidence: "
                    f"{self._safe_text(abuseipdb.get('abuse_confidence_score', 0))}/100<br/>"
                    f"Whitelisted: "
                    f"{self._safe_text(abuseipdb.get('is_whitelisted'))}<br/>"
                    f"Reports: "
                    f"{self._safe_text(abuseipdb.get('total_reports', 0))}<br/>"
                    f"ISP: "
                    f"{self._safe_text(abuseipdb.get('isp'))}"
                )

                rows.append(
                    [
                        Paragraph(observable, self.styles["SmallText"]),
                        Paragraph("AbuseIPDB", self.styles["SmallText"]),
                        Paragraph(
                            self._safe_text(abuseipdb.get("verdict")),
                            self.styles["SmallText"],
                        ),
                        Paragraph(abuse_findings, self.styles["SmallText"]),
                    ]
                )

            provider_errors = item.get("provider_errors", [])

            if isinstance(provider_errors, list) and provider_errors:
                rows.append(
                    [
                        Paragraph(observable, self.styles["SmallText"]),
                        Paragraph(
                            "Provider status",
                            self.styles["SmallText"],
                        ),
                        Paragraph("Partial", self.styles["SmallText"]),
                        Paragraph(
                            "<br/>".join(
                                self._safe_text(error)
                                for error in provider_errors
                            ),
                            self.styles["SmallText"],
                        ),
                    ]
                )

        if len(rows) == 1:
            rows.append(
                [
                    Paragraph("No observables", self.styles["SmallText"]),
                    Paragraph("No providers", self.styles["SmallText"]),
                    Paragraph("Not available", self.styles["SmallText"]),
                    Paragraph(
                        "No v0.5.0 provider findings were available.",
                        self.styles["SmallText"],
                    ),
                ]
            )

        table = Table(
            rows,
            colWidths=[
                42 * mm,
                28 * mm,
                35 * mm,
                65 * mm,
            ],
            repeatRows=1,
            hAlign="LEFT",
        )

        table.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, 0),
                        colors.HexColor("#263238"),
                    ),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        0.35,
                        colors.HexColor("#B0BEC5"),
                    ),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 5),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )

        return table

    def _ioc_history_table(
        self,
        timelines: list[dict[str, Any]],
    ) -> Table:
        rows = [
            [
                Paragraph(
                    "<b>IOC</b>",
                    self.styles["SmallText"],
                ),
                Paragraph(
                    "<b>Type</b>",
                    self.styles["SmallText"],
                ),
                Paragraph(
                    "<b>Occurrences</b>",
                    self.styles["SmallText"],
                ),
                Paragraph(
                    "<b>First Seen</b>",
                    self.styles["SmallText"],
                ),
                Paragraph(
                    "<b>Last Seen</b>",
                    self.styles["SmallText"],
                ),
                Paragraph(
                    "<b>Repeat</b>",
                    self.styles["SmallText"],
                ),
            ]
        ]

        if not isinstance(timelines, list):
            timelines = []

        for item in timelines:
            if not isinstance(item, dict):
                continue

            ioc_value = self._safe_text(
                item.get("ioc")
            )

            # Defang IOC before showing it in the PDF.
            ioc_value = ioc_value.replace(".", "[.]")

            rows.append(
                [
                    Paragraph(
                        ioc_value,
                        self.styles["SmallText"],
                    ),
                    Paragraph(
                        self._safe_text(
                            item.get("ioc_type_filter")
                        ),
                        self.styles["SmallText"],
                    ),
                    Paragraph(
                        self._safe_text(
                            item.get("occurrence_count", 0)
                        ),
                        self.styles["SmallText"],
                    ),
                    Paragraph(
                        self._safe_text(
                            item.get("first_seen")
                        ),
                        self.styles["SmallText"],
                    ),
                    Paragraph(
                        self._safe_text(
                            item.get("last_seen")
                        ),
                        self.styles["SmallText"],
                    ),
                    Paragraph(
                        (
                            "YES"
                            if item.get("is_repeat_offender")
                            else "NO"
                        ),
                        self.styles["SmallText"],
                    ),
                ]
            )

        if len(rows) == 1:
            rows.append(
                [
                    Paragraph(
                        "No IOC history",
                        self.styles["SmallText"],
                    ),
                    Paragraph(
                        "N/A",
                        self.styles["SmallText"],
                    ),
                    Paragraph(
                        "0",
                        self.styles["SmallText"],
                    ),
                    Paragraph(
                        "Not available",
                        self.styles["SmallText"],
                    ),
                    Paragraph(
                        "Not available",
                        self.styles["SmallText"],
                    ),
                    Paragraph(
                        "NO",
                        self.styles["SmallText"],
                    ),
                ]
            )

        table = Table(
            rows,
            colWidths=[
                42 * mm,
                23 * mm,
                22 * mm,
                32 * mm,
                32 * mm,
                19 * mm,
            ],
            repeatRows=1,
            hAlign="LEFT",
        )

        table.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, 0),
                        colors.HexColor("#263238"),
                    ),
                    (
                        "TEXTCOLOR",
                        (0, 0),
                        (-1, 0),
                        colors.white,
                    ),
                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        0.35,
                        colors.HexColor("#B0BEC5"),
                    ),
                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "TOP",
                    ),
                    (
                        "LEFTPADDING",
                        (0, 0),
                        (-1, -1),
                        4,
                    ),
                    (
                        "RIGHTPADDING",
                        (0, 0),
                        (-1, -1),
                        4,
                    ),
                    (
                        "TOPPADDING",
                        (0, 0),
                        (-1, -1),
                        5,
                    ),
                    (
                        "BOTTOMPADDING",
                        (0, 0),
                        (-1, -1),
                        5,
                    ),
                ]
            )
        )

        return table

    def generate(
        self,
        analysis: dict[str, Any],
        profile: dict[str, Any],
        display_facts: dict[str, list[str]],
        mitre_candidates: list[dict[str, Any]] | None = None,
        threat_intel: list[dict[str, Any]] | None = None,
        intelligence_results: list[dict[str, Any]] | None = None,
        source_log: str | Path | None = None,
        memory_context: dict[str, Any] | None = None,
    ) -> Path:
        threat_intel = threat_intel or []
        intelligence_results = intelligence_results or []
        memory_context = memory_context or {}

        created_at = datetime.now()
        attack_type = self._safe_text(analysis.get("attack_type"))
        severity = self._safe_text(analysis.get("severity"))
        confidence = self._safe_text(analysis.get("confidence"))
        mitre = analysis.get("mitre_attack", {}) or {}

        incident_name = self._slugify(attack_type)
        filename = (
            f"incident_{created_at.strftime('%Y%m%d_%H%M%S')}_{incident_name}.pdf"
        )
        output_path = self.output_dir / filename

        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=A4,
            rightMargin=18 * mm,
            leftMargin=18 * mm,
            topMargin=18 * mm,
            bottomMargin=20 * mm,
            title="SOC Incident Report",
            author="SOC Agentic AI",
        )

        story: list[Any] = []

        story.append(Paragraph("SOC INCIDENT REPORT", self.styles["ReportTitle"]))
        story.append(
            Paragraph(
                f"Generated: {created_at.strftime('%Y-%m-%d %H:%M:%S')}",
                self.styles["SmallText"],
            )
        )
        story.append(Spacer(1, 6))

        severity_box = Table(
            [[
                Paragraph("<b>Severity</b>", self.styles["SmallText"]),
                Paragraph(f"<b>{severity}</b>", self.styles["SmallText"]),
                Paragraph("<b>Confidence</b>", self.styles["SmallText"]),
                Paragraph(f"<b>{confidence}</b>", self.styles["SmallText"]),
            ]],
            colWidths=[28 * mm, 45 * mm, 35 * mm, 45 * mm],
            hAlign="LEFT",
        )
        severity_box.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#ECEFF1")),
                    ("BACKGROUND", (2, 0), (2, 0), colors.HexColor("#ECEFF1")),
                    ("BACKGROUND", (1, 0), (1, 0), self._severity_color(severity)),
                    ("TEXTCOLOR", (1, 0), (1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#90A4AE")),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("TOPPADDING", (0, 0), (-1, -1), 7),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                ]
            )
        )
        story.append(severity_box)
        story.append(Spacer(1, 10))

        story.append(Paragraph("Incident Overview", self.styles["SectionHeading"]))
        overview_rows = [
            (
                "Incident ID",
                self._safe_text(
                    analysis.get("incident_id")
                ),
            ),
            ("Attack Type", attack_type),
            ("Summary", self._safe_text(analysis.get("summary"))),
            ("Recommended Tool", self._safe_text(analysis.get("recommended_tool"))),
            ("Source IP", self._safe_text(analysis.get("source_ip"))),
            ("Source Log", self._safe_text(source_log)),
        ]
        story.append(self._key_value_table(overview_rows))

        story.append(Paragraph("MITRE ATT&CK Mapping", self.styles["SectionHeading"]))
        mitre_rows = [
            ("Technique ID", self._safe_text(mitre.get("technique_id"))),
            ("Technique Name", self._safe_text(mitre.get("technique_name"))),
            ("Tactic", self._safe_text(mitre.get("tactic"))),
        ]
        story.append(self._key_value_table(mitre_rows))

        story.append(Paragraph("Log Profile", self.styles["SectionHeading"]))
        profile_rows = [
            ("Probable Source", self._safe_text(profile.get("probable_source"))),
            ("Format", self._safe_text(profile.get("format"))),
            ("Line Count", self._safe_text(profile.get("line_count"))),
            ("Contains Timestamp", self._safe_text(profile.get("contains_timestamp"))),
            ("Contains IP", self._safe_text(profile.get("contains_ip"))),
            ("Contains URL", self._safe_text(profile.get("contains_url"))),
            ("Contains Process", self._safe_text(profile.get("contains_process"))),
            ("Contains Event ID", self._safe_text(profile.get("contains_event_id"))),
            ("Contains Hash", self._safe_text(profile.get("contains_hash"))),
        ]
        story.append(self._key_value_table(profile_rows))

        story.append(Paragraph("Defanged Indicators", self.styles["SectionHeading"]))
        story.append(
            Paragraph(
                "The values below are intentionally defanged to reduce accidental clicks or execution.",
                self.styles["ReportBody"],
            )
        )
        story.append(self._ioc_table(display_facts))

        story.append(Paragraph("Analyst Assessment", self.styles["SectionHeading"]))
        assessment = analysis.get("verified_fact_assessment", {}) or {}
        analyst_rows = [
            ("Notes", self._safe_text(assessment.get("notes"))),
            ("Recommendation", self._safe_text(analysis.get("recommendation"))),
            ("Policy Reason", self._safe_text(analysis.get("policy_reason"))),
        ]
        story.append(self._key_value_table(analyst_rows))

        story.append(
            Paragraph(
                "Threat Intelligence",
                    self.styles["SectionHeading"],
            )
        )

        story.append(
            Paragraph(
                "External enrichment results are read-only and do not "
                "automatically blacklist or submit observables.",
                    self.styles["ReportBody"],
            )
        )

        story.append(
            self._threat_intel_table(threat_intel)
        )

        story.append(
            Paragraph(
                "Deterministic Intelligence Investigation",
                self.styles["SectionHeading"],
            )
        )

        story.append(
            Paragraph(
                "This section combines VirusTotal, AbuseIPDB, current detection "
                "context, and persistent incident memory into a deterministic "
                "risk assessment. Provider failures are recorded without stopping "
                "the investigation.",
                self.styles["ReportBody"],
            )
        )

        story.append(
            self._intelligence_overview_table(
                intelligence_results
            )
        )

        story.append(
            Paragraph(
                "External Provider Findings",
                self.styles["SectionHeading"],
            )
        )

        story.append(
            self._provider_findings_table(
                intelligence_results
            )
        )

        story.append(
            Paragraph(
                "Intelligence Summaries and Analyst Guidance",
                self.styles["SectionHeading"],
            )
        )

        if intelligence_results:
            for item in intelligence_results:
                if not isinstance(item, dict):
                    continue

                summary = item.get("summary", {})

                if not isinstance(summary, dict):
                    continue

                observable = self._defang_observable(
                    item.get("ioc", item.get("observable"))
                )

                story.append(
                    Paragraph(
                        f"<b>Observable: {observable}</b>",
                        self.styles["ReportBody"],
                    )
                )

                story.append(
                    Paragraph(
                        self._safe_text(
                            summary.get("executive_summary")
                        ),
                        self.styles["ReportBody"],
                    )
                )

                analyst_notes = summary.get("analyst_notes", [])

                if isinstance(analyst_notes, list):
                    for note in analyst_notes:
                        story.append(
                            Paragraph(
                                f"• {self._safe_text(note)}",
                                self.styles["ReportBody"],
                            )
                        )

                contradictions = summary.get("contradictions", [])

                if isinstance(contradictions, list) and contradictions:
                    story.append(
                        Paragraph(
                            "<b>Provider contradictions:</b>",
                            self.styles["ReportBody"],
                        )
                    )

                    for contradiction in contradictions:
                        story.append(
                            Paragraph(
                                f"• {self._safe_text(contradiction)}",
                                self.styles["ReportBody"],
                            )
                        )

                story.append(Spacer(1, 6))
        else:
            story.append(
                Paragraph(
                    "No v0.5.0 intelligence summaries were produced.",
                    self.styles["ReportBody"],
                )
            )

        correlation = memory_context.get(
            "correlation",
            {},
        )

        if not isinstance(correlation, dict):
            correlation = {}

        story.append(
            Paragraph(
                "Historical Correlation",
                self.styles["SectionHeading"],
            )
        )

        correlation_rows = [
            (
                "Current Incident ID",
                self._safe_text(
                    memory_context.get("incident_id")
                ),
            ),
            (
                "Historical Incidents Checked",
                self._safe_text(
                    correlation.get(
                        "historical_incidents_checked",
                        0,
                    )
                ),
            ),
            (
                "Historical Match Found",
                (
                    "YES"
                    if correlation.get("has_historical_match")
                    else "NO"
                ),
            ),
            (
                "Matching Incidents",
                self._safe_text(
                    correlation.get(
                        "matching_incidents_found",
                        0,
                    )
                ),
            ),
            (
                "Highest Similarity Score",
                (
                    f"{correlation.get('highest_similarity_score', 0)}%"
                ),
            ),
        ]

        story.append(
            self._key_value_table(
                correlation_rows
            )
        )

        story.append(Spacer(1, 6))

        story.append(
            self._correlation_matches_table(
                correlation.get("matches", [])
            )
        )

        story.append(
            Paragraph(
                "IOC Historical Timeline",
                self.styles["SectionHeading"],
            )
        )

        story.append(
            Paragraph(
                "This table records historical IOC sightings, including "
                "first seen, last seen, occurrence count, and repeat-offender status.",
                self.styles["ReportBody"],
            )
        )

        story.append(
            self._ioc_history_table(
                memory_context.get(
                    "ioc_timelines",
                    [],
                )
            )
        )

        story.append(
            Paragraph(
                "MITRE Technique History",
                self.styles["SectionHeading"],
            )
        )

        mitre_timelines = memory_context.get(
            "mitre_timelines",
            [],
        )

        if not isinstance(mitre_timelines, list):
            mitre_timelines = []

        if mitre_timelines:
            for mitre_history in mitre_timelines:
                if not isinstance(mitre_history, dict):
                    continue

                story.append(
                    self._key_value_table(
                        [
                            (
                                "Technique ID",
                                self._safe_text(
                                    mitre_history.get(
                                        "technique_id"
                                    )
                                ),
                            ),
                            (
                                "Occurrences",
                                self._safe_text(
                                    mitre_history.get(
                                        "occurrence_count",
                                        0,
                                    )
                                ),
                            ),
                            (
                                "Repeated Technique",
                                (
                                    "YES"
                                    if mitre_history.get(
                                        "is_repeated"
                                    )
                                    else "NO"
                                ),
                            ),
                            (
                                "First Seen",
                                self._safe_text(
                                    mitre_history.get(
                                        "first_seen"
                                    )
                                ),
                            ),
                            (
                                "Last Seen",
                                self._safe_text(
                                    mitre_history.get(
                                        "last_seen"
                                    )
                                ),
                            ),
                        ]
                    )
                )

                story.append(
                    Spacer(1, 6)
                )
        else:
            story.append(
                Paragraph(
                    "No trusted MITRE technique was available for historical analysis.",
                    self.styles["ReportBody"],
                )
            )

        if mitre_candidates:
            story.append(Paragraph("MITRE Candidate Evidence", self.styles["SectionHeading"]))
            candidate_rows = [["Technique", "Score", "Matched Keywords"]]
            for candidate in mitre_candidates[:5]:
                candidate_rows.append(
                    [
                        Paragraph(
                            f"{self._safe_text(candidate.get('technique_id'))} - "
                            f"{self._safe_text(candidate.get('technique_name'))}",
                            self.styles["SmallText"],
                        ),
                        
                        Paragraph(
                            self._safe_text(candidate.get("score")),
                            self.styles["SmallText"],
                        ),

                        Paragraph(
                            ", ".join(candidate.get("matched_keywords", []))
                            or "Not available",
                            self.styles["SmallText"],
                        ),
                    ]
                )

            candidate_table = Table(
                candidate_rows,
                colWidths=[70 * mm, 20 * mm, 80 * mm],
                repeatRows=1,
                hAlign="LEFT",
            )
            candidate_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#37474F")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#B0BEC5")),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("LEFTPADDING", (0, 0), (-1, -1), 5),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                        ("TOPPADDING", (0, 0), (-1, -1), 5),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                    ]
                )
            )
            story.append(candidate_table)

        story.append(Spacer(1, 12))
        story.append(
            KeepTogether(
                [
                    Paragraph("Important Notice", self.styles["SectionHeading"]),
                    Paragraph(
                        "This report is generated by an automated SOC analysis workflow. "
                        "All recommended actions should be reviewed by an authorized analyst "
                        "before execution in a production environment.",
                        self.styles["ReportBody"],
                    ),
                ]
            )
        )

        doc.build(
            story,
            onFirstPage=self._page_number,
            onLaterPages=self._page_number,
        )

        return output_path
