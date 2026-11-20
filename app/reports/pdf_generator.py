
from io import BytesIO
from datetime import datetime, timezone
from html import escape
import re

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)


def safe_text(value):
    """Escape text before adding it to a ReportLab paragraph."""
    return escape(str(value))


def redact_identifier(value):
    """Hide UUID-style identifiers in shared reports."""
    return re.sub(
        r"\b[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\b",
        "[REDACTED]",
        str(value)
    )


def add_formatted_analysis(story, analysis, body_style):
    """Convert basic Markdown formatting into readable PDF paragraphs."""

    heading_style = ParagraphStyle(
        "AISectionHeading",
        parent=body_style,
        fontName="Helvetica-Bold",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#17365D"),
        spaceBefore=8,
        spaceAfter=5
    )

    for line in str(analysis).splitlines():
        line = line.strip()

        if not line:
            story.append(Spacer(1, 4))
            continue

        # Convert Markdown heading
        if line.startswith("#"):
            heading = line.lstrip("#").strip()

            story.append(
                Paragraph(
                    escape(heading),
                    heading_style
                )
            )
            continue

        # Convert bold Markdown text
        formatted_line = escape(line)

        formatted_line = re.sub(
            r"\*\*(.*?)\*\*",
            r"<b>\1</b>",
            formatted_line
        )

        # Convert bullet points
        if formatted_line.startswith("- "):
            formatted_line = "&bull; " + formatted_line[2:]

        # Convert numbered recommendations
        story.append(
            Paragraph(
                formatted_line,
                body_style
            )
        )



def generate_security_report(scan_report: dict) -> BytesIO:
    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        textColor=colors.HexColor("#17365D")
    )

    heading_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        textColor=colors.HexColor("#17365D"),
        spaceBefore=12,
        spaceAfter=8
    )

    body_style = styles["BodyText"]

    story = []

    findings = scan_report.get("findings", [])

    # Report title
    story.append(
        Paragraph("CloudGuard AI", title_style)
    )

    story.append(
        Paragraph(
            "Cloud Security & Compliance Report",
            styles["Heading2"]
        )
    )

    story.append(Spacer(1, 12))

    # Report metadata
    generated_at = datetime.now(timezone.utc).strftime(
        "%d %B %Y, %H:%M UTC"
    )

    story.append(
        Paragraph(
            f"<b>Generated:</b> {generated_at}",
            body_style
        )
    )

    story.append(Spacer(1, 16))

    # Security scan summary
    story.append(
        Paragraph("1. Security Scan Summary", heading_style)
    )

    summary_data = [
        ["Metric", "Count"],
        ["Azure Resources", scan_report.get("total_resources_scanned", 0)],
        ["Storage Accounts", scan_report.get("storage_accounts_scanned", 0)],
        ["Network Security Groups", scan_report.get("network_security_groups_scanned", 0)],
        ["Key Vaults", scan_report.get("keyvaults_scanned", 0)],
        ["RBAC Role Assignments", scan_report.get("role_assignments_scanned", 0)],
        ["App Services", scan_report.get("app_services_scanned", 0)],
        ["Total Security Findings", len(findings)]
    ]

    summary_table = Table(
        summary_data,
        colWidths=[350, 120]
    )

    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#17365D")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 8),
        ("ALIGN", (1, 1), (1, -1), "CENTER")
    ]))

    story.append(summary_table)
    story.append(Spacer(1, 20))

    # Risk summary
    story.append(
        Paragraph("2. Risk Summary", heading_style)
    )

    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0
    }

    for finding in findings:
        severity = str(
            finding.get("severity", "unknown")
        ).lower()

        if severity in severity_counts:
            severity_counts[severity] += 1

    risk_data = [["Severity", "Findings"]]

    for severity, count in severity_counts.items():
        risk_data.append([severity.title(), count])

    risk_table = Table(
        risk_data,
        colWidths=[350, 120]
    )

    risk_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#17365D")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 8)
    ]))

    story.append(risk_table)

    # Security findings and AI analysis
    story.append(
        Paragraph(
            "3. Security Findings, Compliance & AI Analysis",
            heading_style
        )
    )

    if not findings:
        story.append(
            Paragraph(
                "No security findings were returned by this scan.",
                body_style
            )
        )

    for index, finding in enumerate(findings, start=1):
        story.append(
            Paragraph(
                f"<b>{index}. {safe_text(finding.get('issue', 'Unknown issue'))}</b>",
                body_style
            )
        )

        resource_name = redact_identifier(
            finding.get("resource_name", "Unknown")
        )

        story.append(
            Paragraph(
                f"<b>Resource:</b> {safe_text(resource_name)}",
                body_style
            )
        )

        story.append(
            Paragraph(
                f"<b>Severity:</b> {safe_text(finding.get('severity', 'Unknown'))}",
                body_style
            )
        )

        # Compliance references
        compliance = finding.get("compliance", [])

        if compliance:
            story.append(
                Paragraph("<b>Compliance References:</b>", body_style)
            )

            for framework in compliance:
                reference = (
                    f"{framework.get('name', 'Unknown')} | "
                    f"{framework.get('control', 'Unknown')} | "
                    f"{framework.get('description', '')}"
                )

                story.append(
                    Paragraph(
                        f"- {safe_text(reference)}",
                        body_style
                    )
                )


        # AI-generated analysis
        story.append(
            Paragraph("<b>AI Security Analysis:</b>", body_style)
        )

        analysis = finding.get("analysis")

        if analysis:
            add_formatted_analysis(
                story,
                analysis,
                body_style
            )
        else:
            story.append(
                Paragraph(
                    "AI analysis is not available for this finding.",
                    body_style
                )
            )

        story.append(Spacer(1, 14))


    # Build the PDF
    document.build(story)

    buffer.seek(0)

    return buffer
