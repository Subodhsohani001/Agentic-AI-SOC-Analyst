from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any
import re

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
        return text or "Not available"

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
                Paragraph("<b>Observable</b>", self.styles["SmallText"]),
                Paragraph("<b>Verdict</b>", self.styles["SmallText"]),
                Paragraph("<b>Risk Score</b>", self.styles["SmallText"]),
                Paragraph("<b>Provider Status</b>", self.styles["SmallText"]),
            ]
        ]

        for item in threat_intel:
            observable = self._safe_text(item.get("observable"))

            # Defang analyst-facing observable
            observable = observable.replace(".", "[.]")

            verdict = self._safe_text(item.get("verdict"))
            risk_score = f"{item.get('combined_risk_score', 0)} / 100"

            provider_lines: list[str] = []

            providers = item.get("providers", [])
            if not isinstance(providers, list):
                providers = []

            for provider in providers:
                if not isinstance(provider, dict):
                    continue

                provider_name = self._safe_text(provider.get("provider"))
                provider_status = self._safe_text(provider.get("status"))

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
                    Paragraph(observable, self.styles["SmallText"]),
                    Paragraph(verdict, self.styles["SmallText"]),
                    Paragraph(risk_score, self.styles["SmallText"]),
                    Paragraph(provider_text, self.styles["SmallText"]),
                ]
            )

        if len(rows) == 1:
            rows.append(
                [
                    Paragraph("No observables", self.styles["SmallText"]),
                    Paragraph(
                        "No threat-intelligence results were available.",
                        self.styles["SmallText"],
                    ),
                    Paragraph("0 / 100", self.styles["SmallText"]),
                    Paragraph("Not available", self.styles["SmallText"]),
                ]
            )

        table = Table(
            rows,
            colWidths=[38 * mm, 55 * mm, 25 * mm, 52 * mm],
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
        source_log: str | Path | None = None,
    ) -> Path:
        threat_intel = threat_intel or []

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
