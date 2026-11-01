from __future__ import annotations

from datetime import datetime, timedelta, timezone
from html import escape
from io import BytesIO
from typing import Literal

from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.shapes import Drawing
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.app.database import AlertRow, AuditLogRow, EventRow, IncidentRow


ReportPeriod = Literal["daily", "weekly", "monthly", "all"]


def _period_start(period: ReportPeriod, now: datetime) -> datetime | None:
    if period == "daily":
        return now - timedelta(days=1)
    if period == "weekly":
        return now - timedelta(days=7)
    if period == "monthly":
        return now - timedelta(days=30)
    return None


def _rows(session: Session, statement):
    return session.execute(statement).all()


def _table(data: list[list[str]], widths: list[float]) -> Table:
    table = Table(data, colWidths=widths, repeatRows=1, hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#253021")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#d8f39a")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("TEXTCOLOR", (0, 1), (-1, -1), colors.HexColor("#20251d")),
                ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#cdd3c5")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f1f4ec")]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    return table


def _bar_chart(labels: list[str], values: list[int]) -> Drawing:
    drawing = Drawing(470, 160)
    chart = VerticalBarChart()
    chart.x = 52
    chart.y = 35
    chart.width = 390
    chart.height = 105
    chart.data = [values or [0]]
    chart.categoryAxis.categoryNames = labels or ["No alerts"]
    chart.categoryAxis.labels.boxAnchor = "ne"
    chart.categoryAxis.labels.angle = 25
    chart.categoryAxis.labels.fontSize = 7
    chart.valueAxis.valueMin = 0
    chart.valueAxis.valueMax = max(values, default=1) or 1
    chart.valueAxis.valueStep = max(1, (max(values, default=1) + 3) // 4)
    chart.bars[0].fillColor = colors.HexColor("#84a946")
    drawing.add(chart)
    return drawing


def generate_soc_pdf(session: Session, period: ReportPeriod = "all") -> bytes:
    now = datetime.now(timezone.utc)
    start = _period_start(period, now)
    event_filters = [EventRow.timestamp >= start] if start else []
    alert_filters = [AlertRow.timestamp >= start] if start else []
    incident_filters = [IncidentRow.created_at >= start] if start else []

    total_events = session.scalar(
        select(func.count()).select_from(EventRow).where(*event_filters)
    ) or 0
    total_alerts = session.scalar(
        select(func.count()).select_from(AlertRow).where(*alert_filters)
    ) or 0
    severity_rows = _rows(
        session,
        select(AlertRow.severity, func.count())
        .where(*alert_filters)
        .group_by(AlertRow.severity)
        .order_by(AlertRow.severity),
    )
    severity_counts = dict(severity_rows)
    top_sources = _rows(
        session,
        select(EventRow.source_ip, func.count())
        .where(*event_filters)
        .group_by(EventRow.source_ip)
        .order_by(func.count().desc())
        .limit(5),
    )
    top_destinations = _rows(
        session,
        select(EventRow.destination_ip, func.count())
        .where(*event_filters)
        .group_by(EventRow.destination_ip)
        .order_by(func.count().desc())
        .limit(5),
    )
    top_ports = _rows(
        session,
        select(EventRow.destination_port, func.count())
        .where(*event_filters, EventRow.destination_port.is_not(None))
        .group_by(EventRow.destination_port)
        .order_by(func.count().desc())
        .limit(10),
    )
    rule_name = AlertRow.payload["rule_name"].as_string()
    rule_rows = _rows(
        session,
        select(rule_name, func.count())
        .where(*alert_filters)
        .group_by(rule_name)
        .order_by(func.count().desc())
        .limit(10),
    )
    incident_rows = _rows(
        session,
        select(IncidentRow.status, func.count())
        .where(*incident_filters)
        .group_by(IncidentRow.status)
        .order_by(IncidentRow.status),
    )
    audit_filters = [AuditLogRow.action.in_(["updated", "status_changed"])]
    if start:
        audit_filters.append(AuditLogRow.created_at >= start)
    audit_rows = session.scalars(
        select(AuditLogRow)
        .where(*audit_filters)
        .order_by(AuditLogRow.created_at.desc())
        .limit(100)
    ).all()
    notes = [
        (row.actor, row.details.get("note"), row.created_at)
        for row in audit_rows
        if isinstance(row.details, dict) and row.details.get("note")
    ][:20]

    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=22 * mm,
        bottomMargin=18 * mm,
        title=f"SentinelSOC {period.title()} Security Report",
        author="SentinelSOC",
    )
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="Section",
            parent=styles["Heading2"],
            textColor=colors.HexColor("#26331d"),
            fontSize=12,
            leading=15,
            spaceBefore=12,
            spaceAfter=6,
        )
    )
    styles.add(
        ParagraphStyle(
            name="SmallNote",
            parent=styles["BodyText"],
            fontSize=8,
            leading=11,
            alignment=TA_LEFT,
            textColor=colors.HexColor("#555d50"),
        )
    )
    story = [
        Paragraph("SentinelSOC — Security Operations Report", styles["Title"]),
        Paragraph(f"Reporting period: {period.title()}", styles["Heading2"]),
        Paragraph(f"Generated (UTC): {now.isoformat(timespec='seconds')}", styles["BodyText"]),
    ]
    if start:
        story.append(Paragraph(f"Records since: {start.isoformat(timespec='seconds')}", styles["BodyText"]))
    story.extend(
        [
            Spacer(1, 8),
            Paragraph("Executive summary", styles["Section"]),
            _table(
                [
                    ["Metric", "Count"],
                    ["Network events", str(total_events)],
                    ["Security alerts", str(total_alerts)],
                    ["Critical alerts", str(severity_counts.get("Critical", 0))],
                    ["High alerts", str(severity_counts.get("High", 0))],
                    ["Medium alerts", str(severity_counts.get("Medium", 0))],
                    ["Low alerts", str(severity_counts.get("Low", 0))],
                ],
                [105 * mm, 55 * mm],
            ),
            Paragraph("Alert severity distribution", styles["Section"]),
            _bar_chart(
                [str(level) for level, _ in severity_rows],
                [int(count) for _, count in severity_rows],
            ),
        ]
    )

    def add_ranked_table(title: str, heading: str, rows, width: float = 160 * mm) -> None:
        story.append(Paragraph(escape(title), styles["Section"]))
        values = [[heading, "Events"]]
        values.extend([[escape(str(label)), str(count)] for label, count in rows])
        if len(values) == 1:
            values.append(["No records", "0"])
        story.append(_table(values, [width - 30 * mm, 30 * mm]))

    add_ranked_table("Top source IP addresses", "Source IP", top_sources)
    add_ranked_table("Top destination IP addresses", "Destination IP", top_destinations)
    add_ranked_table("Most targeted destination ports", "Port", top_ports, 160 * mm)
    add_ranked_table("Detection rule distribution", "Detection rule", rule_rows)
    add_ranked_table("Incident status distribution", "Incident status", incident_rows)

    story.append(Paragraph("Analyst investigation notes", styles["Section"]))
    if notes:
        story.append(
            _table(
                [["Analyst", "Recorded (UTC)", "Note"]]
                + [
                    [
                        escape(str(actor)),
                        escape(created_at.isoformat(timespec="seconds")),
                        Paragraph(escape(str(note)), styles["SmallNote"]),
                    ]
                    for actor, note, created_at in notes
                ],
                [35 * mm, 45 * mm, 80 * mm],
            )
        )
    else:
        story.append(Paragraph("No analyst notes were recorded in the selected period.", styles["SmallNote"]))
    story.extend(
        [
            Paragraph("Methodology and limitations", styles["Section"]),
            Paragraph(
                "Metrics are calculated from persisted SentinelSOC database records for the selected period. "
                "Data may include clearly labeled synthetic scenarios and offline log uploads. The platform "
                "does not currently provide live packet capture or independently validated detection accuracy. "
                "Severity and confidence reflect heuristic rules and must be reviewed by an analyst.",
                styles["SmallNote"],
            ),
        ]
    )

    def draw_page(canvas, doc) -> None:
        canvas.saveState()
        canvas.setStrokeColor(colors.HexColor("#84a946"))
        canvas.setLineWidth(1)
        canvas.line(doc.leftMargin, 15 * mm, A4[0] - doc.rightMargin, 15 * mm)
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#5f6659"))
        canvas.drawString(doc.leftMargin, 10 * mm, "SentinelSOC · Local/offline telemetry report")
        canvas.drawRightString(A4[0] - doc.rightMargin, 10 * mm, f"Page {doc.page}")
        canvas.restoreState()

    document.build(story, onFirstPage=draw_page, onLaterPages=draw_page)
    return buffer.getvalue()
