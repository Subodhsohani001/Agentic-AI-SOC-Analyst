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

    @staticmethod
    def _as_dict(value: Any) -> dict[str, Any]:
        """Return a dictionary or an empty dictionary."""
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _as_list(value: Any) -> list[Any]:
        """Return a list or an empty list."""
        return value if isinstance(value, list) else []

    @staticmethod
    def _percentage(value: Any) -> str:
        """Convert confidence values such as 0.85 into 85%."""
        try:
            number = float(value)

            if number <= 1:
                number *= 100

            return f"{number:.0f}%"

        except (TypeError, ValueError):
            return "Not available"

    def _list_text(
        self,
        values: Any,
        *,
        defang: bool = False,
    ) -> str:
        """Convert list values into safe ReportLab line-break text."""
        items = self._as_list(values)

        if not items:
            return "Not available"

        formatted: list[str] = []

        for item in items:
            if isinstance(item, dict):
                text = ", ".join(
                    f"{self._safe_text(key)}: {self._safe_text(value)}"
                    for key, value in item.items()
                    if not isinstance(value, (dict, list))
                )
            else:
                text = (
                    self._defang_observable(item)
                    if defang
                    else self._safe_text(item)
                )

            if text:
                formatted.append(text)

        return "<br/>".join(formatted) or "Not available"

    def _attack_chain_table(
        self,
        attack_chain: list[dict[str, Any]],
    ) -> Table:
        rows = [
            [
                Paragraph("<b>Stage</b>", self.styles["SmallText"]),
                Paragraph("<b>MITRE Techniques</b>", self.styles["SmallText"]),
                Paragraph("<b>Confidence</b>", self.styles["SmallText"]),
                Paragraph("<b>Supporting Evidence</b>", self.styles["SmallText"]),
            ]
        ]

        for stage in self._as_list(attack_chain):
            if not isinstance(stage, dict):
                continue

            rows.append(
                [
                    Paragraph(
                        self._safe_text(stage.get("stage")),
                        self.styles["SmallText"],
                    ),
                    Paragraph(
                        self._list_text(stage.get("technique_ids")),
                        self.styles["SmallText"],
                    ),
                    Paragraph(
                        self._percentage(stage.get("confidence")),
                        self.styles["SmallText"],
                    ),
                    Paragraph(
                        self._list_text(
                            stage.get("evidence"),
                            defang=True,
                        ),
                        self.styles["SmallText"],
                    ),
                ]
            )

        if len(rows) == 1:
            rows.append(
                [
                    Paragraph("No stage", self.styles["SmallText"]),
                    Paragraph("Not available", self.styles["SmallText"]),
                    Paragraph("Not available", self.styles["SmallText"]),
                    Paragraph(
                        "No attack-chain stages were reconstructed.",
                        self.styles["SmallText"],
                    ),
                ]
            )

        table = Table(
            rows,
            colWidths=[
                30 * mm,
                38 * mm,
                25 * mm,
                77 * mm,
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
        multi_agent_report: dict[str, Any] | None = None,
        response_output: dict[str, Any] | None = None,
    ) -> Path:
        threat_intel = threat_intel or []
        intelligence_results = intelligence_results or []
        memory_context = memory_context or {}
        multi_agent_report = multi_agent_report or {}
        response_output = response_output or {}

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

        # =====================================================
        # v0.7.0 MULTI-AGENT INVESTIGATION
        # =====================================================

        if multi_agent_report:
            story.append(PageBreak())

            story.append(
                Paragraph(
                    "Multi-Agent Investigation — v0.7.0",
                    self.styles["SectionHeading"],
                )
            )

            story.append(
                Paragraph(
                    "This section summarizes the coordinated investigation "
                    "performed by the root-cause and response-advisory agents "
                    "using validated evidence from the deterministic SOC pipeline.",
                    self.styles["ReportBody"],
                )
            )

            investigation = self._as_dict(
                multi_agent_report.get("investigation")
            )

            completion = self._as_dict(
                multi_agent_report.get("completion_assessment")
            )

            agent_summary = self._as_dict(
                multi_agent_report.get("agent_summary")
            )

            evidence_summary = self._as_dict(
                multi_agent_report.get("evidence_summary")
            )

            report_metadata = self._as_dict(
                multi_agent_report.get("report_metadata")
            )

            investigation_rows = [
                (
                    "Investigation ID",
                    self._safe_text(
                        investigation.get(
                            "investigation_id",
                            report_metadata.get("investigation_id"),
                        )
                    ),
                ),
                (
                    "Incident ID",
                    self._safe_text(
                        investigation.get(
                            "incident_id",
                            report_metadata.get("incident_id"),
                        )
                    ),
                ),
                (
                    "Investigation Status",
                    self._safe_text(
                        investigation.get(
                            "status",
                            completion.get("readiness"),
                        )
                    ),
                ),
                (
                    "Readiness",
                    self._safe_text(
                        completion.get("readiness")
                    ),
                ),
                (
                    "Incomplete Tasks",
                    self._safe_text(
                        completion.get(
                            "incomplete_task_count",
                            0,
                        )
                    ),
                ),
                (
                    "Failed Tasks",
                    self._safe_text(
                        completion.get(
                            "failed_task_count",
                            0,
                        )
                    ),
                ),
                (
                    "Confirmed Hypotheses",
                    self._safe_text(
                        completion.get(
                            "confirmed_hypothesis_count",
                            0,
                        )
                    ),
                ),
                (
                    "Root Cause Available",
                    (
                        "YES"
                        if completion.get("root_cause_present")
                        else "NO"
                    ),
                ),
                (
                    "Response Advisory Available",
                    (
                        "YES"
                        if completion.get(
                            "response_advisory_present"
                        )
                        else "NO"
                    ),
                ),
                (
                    "Participating Agents",
                    self._safe_text(
                        agent_summary.get(
                            "participating_agent_count",
                            0,
                        )
                    ),
                ),
                (
                    "Evidence Count",
                    self._safe_text(
                        evidence_summary.get(
                            "evidence_count",
                            0,
                        )
                    ),
                ),
                (
                    "Evidence Integrity Score",
                    (
                        f"{self._safe_text(
                            evidence_summary.get(
                                'integrity_score',
                                0,
                            )
                        )}%"
                    ),
                ),
                (
                    "Average Evidence Confidence",
                    self._percentage(
                        evidence_summary.get(
                            "average_confidence"
                        )
                    ),
                ),
            ]

            story.append(
                self._key_value_table(
                    investigation_rows
                )
            )

            # =================================================
            # EXECUTIVE SUMMARY
            # =================================================

            executive_summary = multi_agent_report.get(
                "executive_summary"
            )

            story.append(
                Paragraph(
                    "Multi-Agent Executive Summary",
                    self.styles["SectionHeading"],
                )
            )

            if isinstance(executive_summary, dict):
                executive_text = (
                    executive_summary.get("summary")
                    or executive_summary.get(
                        "executive_summary"
                    )
                    or executive_summary.get(
                        "assessment"
                    )
                )

                story.append(
                    Paragraph(
                        self._safe_text(executive_text),
                        self.styles["ReportBody"],
                    )
                )

                executive_rows = []

                for label, key in (
                    ("Severity", "severity"),
                    ("Confidence", "confidence"),
                    ("Status", "status"),
                    ("Risk Score", "risk_score"),
                    ("Primary Finding", "primary_finding"),
                ):
                    if key in executive_summary:
                        value = executive_summary.get(key)

                        if key == "confidence":
                            value = self._percentage(value)

                        executive_rows.append(
                            (
                                label,
                                self._safe_text(value),
                            )
                        )

                if executive_rows:
                    story.append(
                        self._key_value_table(
                            executive_rows
                        )
                    )

            elif executive_summary:
                story.append(
                    Paragraph(
                        self._safe_text(
                            executive_summary
                        ),
                        self.styles["ReportBody"],
                    )
                )

            else:
                story.append(
                    Paragraph(
                        "No separate executive summary was generated.",
                        self.styles["ReportBody"],
                    )
                )

            # =================================================
            # ROOT-CAUSE ASSESSMENT
            # =================================================

            root_cause = self._as_dict(
                multi_agent_report.get(
                    "root_cause_assessment"
                )
            )

            story.append(
                Paragraph(
                    "Root-Cause Assessment",
                    self.styles["SectionHeading"],
                )
            )

            if root_cause:
                probable_initial_access = self._as_dict(
                    root_cause.get(
                        "probable_initial_access"
                    )
                )

                root_cause_rows = [
                    (
                        "Primary Root Cause",
                        self._safe_text(
                            root_cause.get(
                                "primary_root_cause"
                            )
                        ),
                    ),
                    (
                        "Severity",
                        self._safe_text(
                            root_cause.get("severity")
                        ),
                    ),
                    (
                        "Root-Cause Confidence",
                        self._percentage(
                            root_cause.get(
                                "root_cause_confidence"
                            )
                        ),
                    ),
                    (
                        "Overall Confidence",
                        self._percentage(
                            root_cause.get(
                                "overall_confidence"
                            )
                        ),
                    ),
                    (
                        "Probable Initial Access",
                        self._safe_text(
                            probable_initial_access.get(
                                "method"
                            )
                        ),
                    ),
                    (
                        "Initial-Access Confidence",
                        self._percentage(
                            probable_initial_access.get(
                                "confidence"
                            )
                        ),
                    ),
                    (
                        "Initial-Access Evidence",
                        self._list_text(
                            probable_initial_access.get(
                                "evidence"
                            ),
                            defang=True,
                        ),
                    ),
                ]

                story.append(
                    self._key_value_table(
                        root_cause_rows
                    )
                )

                supporting_evidence = root_cause.get(
                    "supporting_evidence"
                )

                if supporting_evidence:
                    story.append(
                        Paragraph(
                            "<b>Supporting Evidence</b>",
                            self.styles["ReportBody"],
                        )
                    )

                    story.append(
                        Paragraph(
                            self._list_text(
                                supporting_evidence,
                                defang=True,
                            ),
                            self.styles["ReportBody"],
                        )
                    )

                alternative_causes = self._as_list(
                    root_cause.get(
                        "alternative_causes"
                    )
                )

                if alternative_causes:
                    story.append(
                        Paragraph(
                            "Alternative Root-Cause Possibilities",
                            self.styles["SectionHeading"],
                        )
                    )

                    for cause in alternative_causes:
                        if not isinstance(cause, dict):
                            continue

                        story.append(
                            self._key_value_table(
                                [
                                    (
                                        "Possible Cause",
                                        self._safe_text(
                                            cause.get("cause")
                                        ),
                                    ),
                                    (
                                        "Confidence",
                                        self._percentage(
                                            cause.get(
                                                "confidence"
                                            )
                                        ),
                                    ),
                                    (
                                        "Evidence",
                                        self._list_text(
                                            cause.get(
                                                "evidence"
                                            ),
                                            defang=True,
                                        ),
                                    ),
                                ]
                            )
                        )

                        story.append(
                            Spacer(1, 5)
                        )

            else:
                story.append(
                    Paragraph(
                        "No root-cause assessment was produced.",
                        self.styles["ReportBody"],
                    )
                )

            # =================================================
            # ATTACK CHAIN
            # =================================================

            story.append(
                Paragraph(
                    "Reconstructed Attack Chain",
                    self.styles["SectionHeading"],
                )
            )

            story.append(
                self._attack_chain_table(
                    self._as_list(
                        multi_agent_report.get(
                            "attack_chain"
                        )
                    )
                )
            )

            # =================================================
            # HYPOTHESIS SUMMARY
            # =================================================

            hypothesis_summary = self._as_dict(
                multi_agent_report.get(
                    "hypothesis_summary"
                )
            )

            story.append(
                Paragraph(
                    "Investigation Hypothesis Summary",
                    self.styles["SectionHeading"],
                )
            )

            if hypothesis_summary:
                hypothesis_rows = [
                    (
                        "Total Hypotheses",
                        self._safe_text(
                            hypothesis_summary.get(
                                "total_hypotheses",
                                hypothesis_summary.get(
                                    "hypothesis_count",
                                    0,
                                ),
                            )
                        ),
                    ),
                    (
                        "Confirmed",
                        self._safe_text(
                            hypothesis_summary.get(
                                "confirmed_count",
                                hypothesis_summary.get(
                                    "confirmed_hypothesis_count",
                                    0,
                                ),
                            )
                        ),
                    ),
                    (
                        "Rejected",
                        self._safe_text(
                            hypothesis_summary.get(
                                "rejected_count",
                                0,
                            )
                        ),
                    ),
                    (
                        "Under Investigation",
                        self._safe_text(
                            hypothesis_summary.get(
                                "under_investigation_count",
                                0,
                            )
                        ),
                    ),
                    (
                        "Highest Confidence",
                        self._percentage(
                            hypothesis_summary.get(
                                "highest_confidence"
                            )
                        ),
                    ),
                ]

                story.append(
                    self._key_value_table(
                        hypothesis_rows
                    )
                )

                hypotheses = self._as_list(
                    hypothesis_summary.get(
                        "hypotheses"
                    )
                )

                for hypothesis in hypotheses:
                    if not isinstance(hypothesis, dict):
                        continue

                    story.append(
                        Spacer(1, 5)
                    )

                    story.append(
                        self._key_value_table(
                            [
                                (
                                    "Hypothesis",
                                    self._safe_text(
                                        hypothesis.get(
                                            "title",
                                            hypothesis.get(
                                                "description"
                                            ),
                                        )
                                    ),
                                ),
                                (
                                    "Status",
                                    self._safe_text(
                                        hypothesis.get(
                                            "status"
                                        )
                                    ),
                                ),
                                (
                                    "Confidence",
                                    self._percentage(
                                        hypothesis.get(
                                            "confidence"
                                        )
                                    ),
                                ),
                                (
                                    "Proposed By",
                                    self._safe_text(
                                        hypothesis.get(
                                            "proposed_by"
                                        )
                                    ),
                                ),
                            ]
                        )
                    )

            else:
                story.append(
                    Paragraph(
                        (
                            f"Confirmed hypotheses: "
                            f"{self._safe_text(
                                completion.get(
                                    'confirmed_hypothesis_count',
                                    0,
                                )
                            )}."
                        ),
                        self.styles["ReportBody"],
                    )
                )

            # =================================================
            # RESPONSE ADVISORY
            # =================================================

            response_advisory = self._as_dict(
                multi_agent_report.get(
                    "response_advisory"
                )
            )

            story.append(
                Paragraph(
                    "Multi-Agent Response Advisory",
                    self.styles["SectionHeading"],
                )
            )

            if response_advisory:
                advisory_rows = [
                    (
                        "Severity",
                        self._safe_text(
                            response_advisory.get(
                                "severity"
                            )
                        ),
                    ),
                    (
                        "Recommended Mode",
                        self._safe_text(
                            response_advisory.get(
                                "recommended_mode"
                            )
                        ),
                    ),
                    (
                        "Action Count",
                        self._safe_text(
                            response_advisory.get(
                                "action_count",
                                len(
                                    self._as_list(
                                        response_advisory.get(
                                            "actions"
                                        )
                                    )
                                ),
                            )
                        ),
                    ),
                    (
                        "Requires Approval",
                        self._safe_text(
                            response_advisory.get(
                                "requires_approval_count",
                                0,
                            )
                        ),
                    ),
                    (
                        "Confidence",
                        self._percentage(
                            response_advisory.get(
                                "confidence"
                            )
                        ),
                    ),
                ]

                story.append(
                    self._key_value_table(
                        advisory_rows
                    )
                )

                advisory_actions = self._as_list(
                    response_advisory.get(
                        "actions",
                        response_advisory.get(
                            "recommendations"
                        ),
                    )
                )

                if advisory_actions:
                    story.append(
                        Paragraph(
                            "<b>Recommended Actions</b>",
                            self.styles["ReportBody"],
                        )
                    )

                    for action in advisory_actions:
                        if isinstance(action, dict):
                            action_name = (
                                action.get("action")
                                or action.get("action_type")
                                or action.get("title")
                                or action.get("name")
                            )

                            action_text = (
                                action.get("description")
                                or action.get("reason")
                                or action.get(
                                    "recommendation"
                                )
                            )

                            priority_value = action.get(
                                "priority"
                            )

                            approval_required = action.get(
                                "requires_approval"
                            )

                            story.append(
                                self._key_value_table(
                                    [
                                        (
                                            "Action",
                                            self._safe_text(
                                                action_name
                                            ),
                                        ),
                                        (
                                            "Description",
                                            self._safe_text(
                                                action_text
                                            ),
                                        ),
                                        (
                                            "Priority",
                                            self._safe_text(
                                                priority_value
                                            ),
                                        ),
                                        (
                                            "Human Approval",
                                            (
                                                "REQUIRED"
                                                if approval_required
                                                else "NOT REQUIRED"
                                            ),
                                        ),
                                    ]
                                )
                            )

                            story.append(
                                Spacer(1, 5)
                            )

                        else:
                            story.append(
                                Paragraph(
                                    f"• {self._safe_text(action)}",
                                    self.styles["ReportBody"],
                                )
                            )

            else:
                story.append(
                    Paragraph(
                        "No multi-agent response advisory was available.",
                        self.styles["ReportBody"],
                    )
                )

        else:
            story.append(
                Paragraph(
                    "Multi-Agent Investigation — v0.7.0",
                    self.styles["SectionHeading"],
                )
            )

            story.append(
                Paragraph(
                    "No multi-agent investigation report was supplied.",
                    self.styles["ReportBody"],
                )
            )

        # =====================================================
        # v0.6.0 RESPONSE ORCHESTRATION
        # =====================================================

        if response_output:
            story.append(PageBreak())

            story.append(
                Paragraph(
                    "Response Orchestration — v0.6.0",
                    self.styles["SectionHeading"],
                )
            )

            story.append(
                Paragraph(
                    "This section records the policy decision, planned response "
                    "actions, approval requirements, ticket creation, simulated "
                    "execution results, and audit-trail location.",
                    self.styles["ReportBody"],
                )
            )

            response_decision = self._as_dict(
                response_output.get("decision")
            )

            response_plan = self._as_dict(
                response_output.get("plan")
            )

            approval_requests = self._as_list(
                response_output.get("approval_requests")
            )

            ticket = self._as_dict(
                response_output.get("ticket")
            )

            execution_results = self._as_list(
                response_output.get("execution_results")
            )

            response_context = self._as_dict(
                response_output.get("context")
            )

            # =================================================
            # RESPONSE DECISION
            # =================================================

            story.append(
                Paragraph(
                    "Policy Decision",
                    self.styles["SectionHeading"],
                )
            )

            decision_rows = [
                (
                    "Operating Mode",
                    self._safe_text(
                        response_output.get(
                            "mode",
                            "simulation",
                        )
                    ),
                ),
                (
                    "Incident ID",
                    self._safe_text(
                        response_context.get(
                            "incident_id",
                            response_plan.get("incident_id"),
                        )
                    ),
                ),
                (
                    "Priority",
                    self._safe_text(
                        response_decision.get(
                            "priority"
                        )
                    ),
                ),
                (
                    "Severity",
                    self._safe_text(
                        response_context.get(
                            "severity"
                        )
                    ),
                ),
                (
                    "Confidence",
                    self._safe_text(
                        response_context.get(
                            "confidence"
                        )
                    ),
                ),
                (
                    "Combined Risk Score",
                    (
                        f"{self._safe_text(
                            response_context.get(
                                'combined_risk_score',
                                response_context.get(
                                    'risk_score',
                                    0,
                                ),
                            )
                        )} / 100"
                    ),
                ),
                (
                    "Intelligence Verdict",
                    self._safe_text(
                        response_context.get(
                            "intelligence_verdict",
                            response_context.get(
                                "verdict"
                            ),
                        )
                    ),
                ),
                (
                    "Repeat Offender",
                    (
                        "YES"
                        if response_context.get(
                            "is_repeat_offender",
                            response_context.get(
                                "repeat_offender",
                                False,
                            ),
                        )
                        else "NO"
                    ),
                ),
                (
                    "Correlation Level",
                    self._safe_text(
                        response_context.get(
                            "correlation_level"
                        )
                    ),
                ),
                (
                    "Decision Reason",
                    self._safe_text(
                        response_decision.get(
                            "reason",
                            response_decision.get(
                                "decision_reason"
                            ),
                        )
                    ),
                ),
            ]

            story.append(
                self._key_value_table(
                    decision_rows
                )
            )

            recommended_actions = self._as_list(
                response_decision.get(
                    "recommended_actions",
                    response_decision.get(
                        "actions"
                    ),
                )
            )

            if recommended_actions:
                story.append(
                    Paragraph(
                        "<b>Policy-Recommended Actions</b>",
                        self.styles["ReportBody"],
                    )
                )

                story.append(
                    Paragraph(
                        self._list_text(
                            recommended_actions
                        ),
                        self.styles["ReportBody"],
                    )
                )

            # =================================================
            # RESPONSE PLAN
            # =================================================

            story.append(
                Paragraph(
                    "Response Plan",
                    self.styles["SectionHeading"],
                )
            )

            plan_rows = [
                (
                    "Plan ID",
                    self._safe_text(
                        response_plan.get("plan_id")
                    ),
                ),
                (
                    "Incident ID",
                    self._safe_text(
                        response_plan.get("incident_id")
                    ),
                ),
                (
                    "Plan Status",
                    self._safe_text(
                        response_plan.get("status")
                    ),
                ),
                (
                    "Priority",
                    self._safe_text(
                        response_plan.get(
                            "priority",
                            response_decision.get(
                                "priority"
                            ),
                        )
                    ),
                ),
                (
                    "Simulation Mode",
                    (
                        "YES"
                        if response_plan.get(
                            "simulation_mode",
                            True,
                        )
                        else "NO"
                    ),
                ),
                (
                    "Created At",
                    self._safe_text(
                        response_plan.get("created_at")
                    ),
                ),
                (
                    "Updated At",
                    self._safe_text(
                        response_plan.get("updated_at")
                    ),
                ),
            ]

            story.append(
                self._key_value_table(
                    plan_rows
                )
            )

            planned_actions = self._as_list(
                response_plan.get("actions")
            )

            story.append(
                Paragraph(
                    "Planned Actions",
                    self.styles["SectionHeading"],
                )
            )

            if planned_actions:
                for index, action in enumerate(
                    planned_actions,
                    start=1,
                ):
                    if not isinstance(action, dict):
                        continue

                    action_type = (
                        action.get("action_type")
                        or action.get("type")
                        or action.get("name")
                    )

                    action_rows = [
                        (
                            "Action Number",
                            str(index),
                        ),
                        (
                            "Action ID",
                            self._safe_text(
                                action.get("action_id")
                            ),
                        ),
                        (
                            "Action Type",
                            self._safe_text(
                                action_type
                            ),
                        ),
                        (
                            "Status",
                            self._safe_text(
                                action.get("status")
                            ),
                        ),
                        (
                            "Priority",
                            self._safe_text(
                                action.get("priority")
                            ),
                        ),
                        (
                            "Requires Approval",
                            (
                                "YES"
                                if action.get(
                                    "requires_approval"
                                )
                                else "NO"
                            ),
                        ),
                        (
                            "Description",
                            self._safe_text(
                                action.get(
                                    "description"
                                )
                            ),
                        ),
                        (
                            "Reason",
                            self._safe_text(
                                action.get(
                                    "reason"
                                )
                            ),
                        ),
                        (
                            "Target",
                            self._defang_observable(
                                action.get(
                                    "target",
                                    action.get(
                                        "target_value"
                                    ),
                                )
                            ),
                        ),
                    ]

                    story.append(
                        self._key_value_table(
                            action_rows
                        )
                    )

                    story.append(
                        Spacer(1, 6)
                    )

            else:
                story.append(
                    Paragraph(
                        "No response actions were included in the plan.",
                        self.styles["ReportBody"],
                    )
                )

            # =================================================
            # APPROVAL REQUESTS
            # =================================================

            story.append(
                Paragraph(
                    "Approval Requests",
                    self.styles["SectionHeading"],
                )
            )

            if approval_requests:
                for index, request in enumerate(
                    approval_requests,
                    start=1,
                ):
                    if not isinstance(request, dict):
                        continue

                    approval_rows = [
                        (
                            "Request Number",
                            str(index),
                        ),
                        (
                            "Approval ID",
                            self._safe_text(
                                request.get(
                                    "approval_id",
                                    request.get(
                                        "request_id"
                                    ),
                                )
                            ),
                        ),
                        (
                            "Action ID",
                            self._safe_text(
                                request.get("action_id")
                            ),
                        ),
                        (
                            "Action Type",
                            self._safe_text(
                                request.get(
                                    "action_type"
                                )
                            ),
                        ),
                        (
                            "Status",
                            self._safe_text(
                                request.get("status")
                            ),
                        ),
                        (
                            "Requested By",
                            self._safe_text(
                                request.get(
                                    "requested_by"
                                )
                            ),
                        ),
                        (
                            "Requested At",
                            self._safe_text(
                                request.get(
                                    "requested_at",
                                    request.get(
                                        "created_at"
                                    ),
                                )
                            ),
                        ),
                        (
                            "Reason",
                            self._safe_text(
                                request.get("reason")
                            ),
                        ),
                    ]

                    story.append(
                        self._key_value_table(
                            approval_rows
                        )
                    )

                    story.append(
                        Spacer(1, 6)
                    )

            else:
                story.append(
                    Paragraph(
                        "No approval requests were created for this response plan.",
                        self.styles["ReportBody"],
                    )
                )

            # =================================================
            # SOC TICKET
            # =================================================

            story.append(
                Paragraph(
                    "SOC Ticket",
                    self.styles["SectionHeading"],
                )
            )

            if ticket:
                ticket_rows = [
                    (
                        "Ticket ID",
                        self._safe_text(
                            ticket.get("ticket_id")
                        ),
                    ),
                    (
                        "Incident ID",
                        self._safe_text(
                            ticket.get("incident_id")
                        ),
                    ),
                    (
                        "Title",
                        self._safe_text(
                            ticket.get(
                                "title",
                                ticket.get("summary"),
                            )
                        ),
                    ),
                    (
                        "Severity",
                        self._safe_text(
                            ticket.get("severity")
                        ),
                    ),
                    (
                        "Priority",
                        self._safe_text(
                            ticket.get("priority")
                        ),
                    ),
                    (
                        "Status",
                        self._safe_text(
                            ticket.get("status")
                        ),
                    ),
                    (
                        "Created At",
                        self._safe_text(
                            ticket.get("created_at")
                        ),
                    ),
                ]

                story.append(
                    self._key_value_table(
                        ticket_rows
                    )
                )

            else:
                story.append(
                    Paragraph(
                        "No SOC ticket was created for this response plan.",
                        self.styles["ReportBody"],
                    )
                )

            # =================================================
            # SIMULATED EXECUTION RESULTS
            # =================================================

            story.append(
                Paragraph(
                    "Simulated Action Execution",
                    self.styles["SectionHeading"],
                )
            )

            if execution_results:
                for index, execution in enumerate(
                    execution_results,
                    start=1,
                ):
                    if not isinstance(execution, dict):
                        continue

                    execution_rows = [
                        (
                            "Execution Number",
                            str(index),
                        ),
                        (
                            "Action ID",
                            self._safe_text(
                                execution.get("action_id")
                            ),
                        ),
                        (
                            "Action Type",
                            self._safe_text(
                                execution.get(
                                    "action_type"
                                )
                            ),
                        ),
                        (
                            "Status",
                            self._safe_text(
                                execution.get("status")
                            ),
                        ),
                        (
                            "Success",
                            (
                                "YES"
                                if execution.get(
                                    "success"
                                )
                                else "NO"
                            ),
                        ),
                        (
                            "Simulation",
                            (
                                "YES"
                                if execution.get(
                                    "simulation",
                                    execution.get(
                                        "simulation_mode",
                                        True,
                                    ),
                                )
                                else "NO"
                            ),
                        ),
                        (
                            "Message",
                            self._safe_text(
                                execution.get(
                                    "message",
                                    execution.get(
                                        "result"
                                    ),
                                )
                            ),
                        ),
                        (
                            "Error",
                            self._safe_text(
                                execution.get("error")
                            ),
                        ),
                    ]

                    story.append(
                        self._key_value_table(
                            execution_rows
                        )
                    )

                    story.append(
                        Spacer(1, 6)
                    )

            else:
                story.append(
                    Paragraph(
                        "No action execution results were recorded.",
                        self.styles["ReportBody"],
                    )
                )

            # =================================================
            # AUDIT TRAIL
            # =================================================

            story.append(
                Paragraph(
                    "Response Audit Trail",
                    self.styles["SectionHeading"],
                )
            )

            story.append(
                self._key_value_table(
                    [
                        (
                            "Audit Log Path",
                            self._safe_text(
                                response_output.get(
                                    "audit_log_path"
                                )
                            ),
                        ),
                        (
                            "Execution Mode",
                            self._safe_text(
                                response_output.get(
                                    "mode",
                                    "simulation",
                                )
                            ),
                        ),
                        (
                            "Recorded Approval Requests",
                            str(
                                len(
                                    approval_requests
                                )
                            ),
                        ),
                        (
                            "Recorded Execution Results",
                            str(
                                len(
                                    execution_results
                                )
                            ),
                        ),
                    ]
                )
            )

        else:
            story.append(
                Paragraph(
                    "Response Orchestration — v0.6.0",
                    self.styles["SectionHeading"],
                )
            )

            story.append(
                Paragraph(
                    "No response-orchestration output was supplied.",
                    self.styles["ReportBody"],
                )
            )

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
