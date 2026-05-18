# SPDX-License-Identifier: Apache-2.0
"""PDFEmitter — branded, client-ready PDF compliance report.

Renders an :class:`~compliance_assess.models.AssessmentResult` to a
professional, Auvex-branded PDF using ReportLab.

ReportLab is an *optional* dependency. Install it with the ``pdf`` extra::

    pip install 'compliance-assess[pdf]'

This module imports ReportLab at module load time, so it must only be
imported once the caller has confirmed the ``pdf`` extra is present. The CLI
imports it lazily and turns a missing ReportLab into a friendly error.
"""

from __future__ import annotations

import html
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from reportlab.lib.colors import Color, HexColor
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas as _canvas
from reportlab.platypus import (
    Flowable,
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from .emitters import _resolve_output_path
from .models import AssessmentResult, Control, Finding

# ---------------------------------------------------------------------------
# Brand palette — teal/navy, matching the Auvex sample report.
# ---------------------------------------------------------------------------

_WHITE = HexColor("#FFFFFF")  # table header text
_NAVY = HexColor("#123B4F")  # cover title, table header band
_TEAL = HexColor("#1A6E8E")  # section headings, brand wordmark
_INK = HexColor("#1F2933")  # body text
_MUTED = HexColor("#5B6770")  # captions, secondary text
_RULE = HexColor("#C9D4DA")  # hairline dividers / table grid
_ZEBRA = HexColor("#F2F6F8")  # alternating row / label cell fill
_HIGH = HexColor("#B00020")  # high / critical severity
_MED = HexColor("#B5651D")  # medium severity
_LOW = HexColor("#4B5563")  # low severity
_OK = HexColor("#1E7A4D")  # pass / clean posture
_DISCLAIMER_BG = HexColor("#FFF4E5")  # tinted disclaimer panel
_DISCLAIMER_INK = HexColor("#7A4A00")

_PAGE_W, _PAGE_H = LETTER
_MARGIN = 0.9 * inch
_CONTENT_W = _PAGE_W - 2 * _MARGIN

# Severity render order (most to least severe) + display metadata.
_SEV_ORDER = ("critical", "high", "medium", "low", "info")
_SEV_META: dict[str, tuple[str, Color, str]] = {
    "critical": (
        "Critical",
        _HIGH,
        "Launch blocker — must be remediated before the system goes to production.",
    ),
    "high": (
        "High",
        _HIGH,
        "Significant compliance risk — remediate before release.",
    ),
    "medium": (
        "Medium",
        _MED,
        "Important hardening — schedule remediation within the launch quarter.",
    ),
    "low": (
        "Low",
        _LOW,
        "Minor item — schedule in the compliance roadmap.",
    ),
    "info": (
        "Informational",
        _MUTED,
        "For awareness; no remediation strictly required.",
    ),
}


def _esc(text: str) -> str:
    """Escape text for ReportLab's Paragraph mini-markup ('&', '<', '>')."""
    return html.escape(text, quote=False)


# ---------------------------------------------------------------------------
# Posture — the headline numbers, computed once and reused.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Posture:
    controls_assessed: int
    controls_passed: int
    controls_with_findings: int
    pass_pct: int
    finding_pct: int
    total_findings: int
    sev_counts: dict[str, int]
    label: str
    label_color: Color
    degraded: bool


def _compute_posture(result: AssessmentResult) -> _Posture:
    """Derive the headline compliance posture from an assessment result."""
    assessed = result.controls_assessed
    with_findings = result.controls_with_findings
    passed = max(0, assessed - with_findings)
    pass_pct = round(passed / assessed * 100) if assessed else 0
    finding_pct = round(with_findings / assessed * 100) if assessed else 0

    sev_counts: dict[str, int] = {}
    for f in result.findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

    blocking = sev_counts.get("critical", 0) + sev_counts.get("high", 0)
    if result.scan_degraded:
        label, color = "Degraded — scan incomplete", _MED
    elif blocking:
        label, color = "Action required", _HIGH
    elif sev_counts.get("medium"):
        label, color = "Review recommended", _MED
    elif sev_counts.get("low") or sev_counts.get("info"):
        label, color = "Minor items", _LOW
    else:
        label, color = "Pass", _OK

    return _Posture(
        controls_assessed=assessed,
        controls_passed=passed,
        controls_with_findings=with_findings,
        pass_pct=pass_pct,
        finding_pct=finding_pct,
        total_findings=len(result.findings),
        sev_counts=sev_counts,
        label=label,
        label_color=color,
        degraded=result.scan_degraded,
    )


# ---------------------------------------------------------------------------
# Paragraph styles
# ---------------------------------------------------------------------------


def _build_styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()["Normal"]

    def style(name: str, **kw: Any) -> ParagraphStyle:
        return ParagraphStyle(name, parent=base, **kw)

    return {
        "wordmark": style(
            "wordmark", fontName="Helvetica-Bold", fontSize=26, textColor=_TEAL,
            leading=28,
        ),
        "wordmark_sub": style(
            "wordmark_sub", fontName="Helvetica", fontSize=10, textColor=_MUTED,
            leading=14, spaceBefore=2,
        ),
        "cover_title": style(
            "cover_title", fontName="Helvetica-Bold", fontSize=27, textColor=_NAVY,
            leading=32, spaceBefore=10,
        ),
        "cover_sub": style(
            "cover_sub", fontName="Helvetica-Oblique", fontSize=13, textColor=_MUTED,
            leading=18, spaceBefore=6,
        ),
        "cover_meta": style(
            "cover_meta", fontName="Helvetica", fontSize=10, textColor=_INK,
            leading=15,
        ),
        "h1": style(
            "h1", fontName="Helvetica-Bold", fontSize=15, textColor=_TEAL,
            leading=20, spaceBefore=18, spaceAfter=8,
        ),
        "h2": style(
            "h2", fontName="Helvetica-Bold", fontSize=11.5, textColor=_NAVY,
            leading=15, spaceBefore=12, spaceAfter=4,
        ),
        "finding_title": style(
            "finding_title", fontName="Helvetica-Bold", fontSize=11, textColor=_NAVY,
            leading=15, spaceBefore=14, spaceAfter=4,
        ),
        "sev_heading": style(
            "sev_heading", fontName="Helvetica-Bold", fontSize=12.5, leading=16,
            spaceBefore=16, spaceAfter=2,
        ),
        "body": style(
            "body", fontName="Helvetica", fontSize=9.5, textColor=_INK,
            leading=14, spaceAfter=6,
        ),
        "label": style(
            "label", fontName="Helvetica-Bold", fontSize=8.5, textColor=_NAVY,
            leading=12,
        ),
        "cell": style(
            "cell", fontName="Helvetica", fontSize=8.5, textColor=_INK, leading=12,
        ),
        "cell_head": style(
            "cell_head", fontName="Helvetica-Bold", fontSize=8.5, textColor=_WHITE,
            leading=12,
        ),
        "field_label": style(
            "field_label", fontName="Helvetica-Bold", fontSize=8, textColor=_TEAL,
            leading=12, spaceBefore=6, spaceAfter=1,
        ),
        "caption": style(
            "caption", fontName="Helvetica", fontSize=8.5, textColor=_MUTED,
            leading=12, spaceAfter=4,
        ),
        "disclaimer": style(
            "disclaimer", fontName="Helvetica", fontSize=8.5, textColor=_DISCLAIMER_INK,
            leading=12,
        ),
    }


# ---------------------------------------------------------------------------
# Table helpers
# ---------------------------------------------------------------------------


def _data_table(
    header: list[str],
    rows: list[list[Any]],
    col_widths: list[float],
    styles: dict[str, ParagraphStyle],
) -> Table:
    """Build a header-banded, zebra-striped table."""
    head_cells = [Paragraph(_esc(h), styles["cell_head"]) for h in header]
    table = Table([head_cells, *rows], colWidths=col_widths, hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), _NAVY),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [None, _ZEBRA]),
                ("GRID", (0, 0), (-1, -1), 0.5, _RULE),
                ("LINEABOVE", (0, 0), (-1, 0), 0.5, _NAVY),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
            ]
        )
    )
    return table


def _field_table(
    rows: list[tuple[str, Any]],
    styles: dict[str, ParagraphStyle],
    label_w: float = 1.45 * inch,
) -> Table:
    """Build a two-column label/value table (no header band)."""
    body: list[list[Any]] = []
    for label, value in rows:
        value_cell = (
            value
            if isinstance(value, (Paragraph, Table))
            else Paragraph(_esc(str(value)), styles["cell"])
        )
        body.append([Paragraph(_esc(label), styles["label"]), value_cell])
    table = Table(body, colWidths=[label_w, _CONTENT_W - label_w], hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), _ZEBRA),
                ("GRID", (0, 0), (-1, -1), 0.5, _RULE),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
            ]
        )
    )
    return table


# ---------------------------------------------------------------------------
# Page furniture — running header (body pages) and numbered footer.
# ---------------------------------------------------------------------------


def _cover_page(canvas_obj: Any, _doc: Any) -> None:
    """First-page decoration: a clean accent band, no running header."""
    canvas_obj.saveState()
    canvas_obj.setFillColor(_NAVY)
    canvas_obj.rect(0, _PAGE_H - 0.34 * inch, _PAGE_W, 0.34 * inch, stroke=0, fill=1)
    canvas_obj.setFillColor(_TEAL)
    canvas_obj.rect(0, _PAGE_H - 0.40 * inch, _PAGE_W, 0.06 * inch, stroke=0, fill=1)
    canvas_obj.restoreState()


def _body_page(canvas_obj: Any, _doc: Any) -> None:
    """Later-page decoration: running header with the Auvex wordmark."""
    canvas_obj.saveState()
    canvas_obj.setFont("Helvetica-Bold", 8.5)
    canvas_obj.setFillColor(_TEAL)
    canvas_obj.drawString(_MARGIN, _PAGE_H - 0.62 * inch, "AUVEX")
    canvas_obj.setFont("Helvetica", 8)
    canvas_obj.setFillColor(_MUTED)
    canvas_obj.drawRightString(
        _PAGE_W - _MARGIN, _PAGE_H - 0.62 * inch, "Compliance Assessment Report"
    )
    canvas_obj.setStrokeColor(_RULE)
    canvas_obj.setLineWidth(0.5)
    canvas_obj.line(
        _MARGIN, _PAGE_H - 0.70 * inch, _PAGE_W - _MARGIN, _PAGE_H - 0.70 * inch
    )
    canvas_obj.restoreState()


def _numbered_canvas(footer_left: str) -> type[_canvas.Canvas]:
    """Return a Canvas subclass that stamps 'Page N of M' once the total is known."""

    class _NumberedCanvas(_canvas.Canvas):  # type: ignore[misc]
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            # ReportLab page state is the canvas __dict__ — genuinely untyped.
            self._page_states: list[dict[str, Any]] = []

        def showPage(self) -> None:  # noqa: N802 — ReportLab API name
            self._page_states.append(dict(self.__dict__))
            self._startPage()

        def save(self) -> None:
            total = len(self._page_states)
            for state in self._page_states:
                self.__dict__.update(state)
                self._draw_footer(total)
                super().showPage()
            super().save()

        def _draw_footer(self, total: int) -> None:
            self.saveState()
            self.setFont("Helvetica", 7.5)
            self.setFillColor(_MUTED)
            self.drawString(_MARGIN, 0.55 * inch, footer_left)
            self.drawRightString(
                _PAGE_W - _MARGIN,
                0.55 * inch,
                f"Page {self._pageNumber} of {total}",
            )
            self.setStrokeColor(_RULE)
            self.setLineWidth(0.5)
            self.line(_MARGIN, 0.72 * inch, _PAGE_W - _MARGIN, 0.72 * inch)
            self.restoreState()

    return _NumberedCanvas


# ---------------------------------------------------------------------------
# Report builder
# ---------------------------------------------------------------------------


class _Report:
    """Assembles the flowable story for one assessment result."""

    def __init__(self, result: AssessmentResult, version: str) -> None:
        self._result = result
        self._version = version
        self._styles = _build_styles()
        self._posture = _compute_posture(result)
        self._controls: dict[str, Control] = {
            c.id: c for c in result.resolved_controls
        }

    # -- public --------------------------------------------------------------

    def story(self) -> list[Flowable]:
        story: list[Flowable] = []
        story += self._cover()
        story += self._executive_summary()
        story += self._findings()
        story += self._appendix()
        story += self._disclaimer()
        return story

    # -- sections ------------------------------------------------------------

    def _cover(self) -> list[Flowable]:
        s = self._styles
        r = self._result
        scan_date = r.timestamp.strftime("%Y-%m-%d")
        meta = (
            f"<b>Profile</b>&nbsp;&nbsp;{_esc(r.profile_title)}<br/>"
            f"<b>Generated</b>&nbsp;&nbsp;{_esc(scan_date)}<br/>"
            f"<b>Target</b>&nbsp;&nbsp;{_esc(r.target)}<br/>"
            f"<b>Scanner</b>&nbsp;&nbsp;Auvex compliance-assess v{_esc(self._version)}"
        )
        return [
            Spacer(1, 1.5 * inch),
            Paragraph("AUVEX", s["wordmark"]),
            Paragraph("compliance-assess", s["wordmark_sub"]),
            Spacer(1, 0.10 * inch),
            HRFlowable(width=1.7 * inch, thickness=2, color=_TEAL, spaceAfter=2),
            Spacer(1, 0.55 * inch),
            Paragraph("Compliance Assessment Report", s["cover_title"]),
            Paragraph(_esc(self._result.profile_title), s["cover_sub"]),
            Spacer(1, 0.5 * inch),
            Paragraph(meta, s["cover_meta"]),
            Spacer(1, 1.5 * inch),
            self._disclaimer_panel(compact=True),
            PageBreak(),
        ]

    def _executive_summary(self) -> list[Flowable]:
        s = self._styles
        p = self._posture
        r = self._result

        narrative = (
            f"This report presents the results of an automated compliance "
            f"assessment of <b>{_esc(r.target)}</b>, performed with Auvex "
            f"compliance-assess. The assessment evaluated <b>{p.controls_assessed}</b> "
            f"control(s) from the <b>{_esc(r.profile_title)}</b> profile. "
            f"<b>{p.controls_with_findings}</b> control(s) raised one or more "
            f"findings that warrant review, while <b>{p.controls_passed}</b> were "
            f"satisfied with no findings."
        )
        if p.degraded:
            narrative += (
                " <b>Note:</b> the scan was reported as degraded — one or more "
                "detection engines did not complete, so these results may be "
                "incomplete and should be re-run before relying on them."
            )

        return [
            KeepTogether(
                [
                    Paragraph("Executive Summary", s["h1"]),
                    Paragraph(narrative, s["body"]),
                ]
            ),
            Spacer(1, 0.08 * inch),
            KeepTogether(
                [
                    Paragraph("Overall Compliance Posture", s["h2"]),
                    self._posture_table(),
                ]
            ),
            Spacer(1, 0.16 * inch),
            KeepTogether(
                [
                    Paragraph("Severity Legend", s["h2"]),
                    self._legend_table(),
                ]
            ),
        ]

    def _posture_table(self) -> Table:
        s = self._styles
        p = self._posture
        rows: list[list[Any]] = [
            [
                Paragraph("Controls assessed", s["cell"]),
                Paragraph(str(p.controls_assessed), s["cell"]),
                Paragraph(
                    _esc(f"Evaluated against the {self._result.profile_title} profile"),
                    s["cell"],
                ),
            ],
            [
                Paragraph("Passed", s["cell"]),
                Paragraph(f"{p.controls_passed} ({p.pass_pct}%)", s["cell"]),
                Paragraph("Controls with no findings", s["cell"]),
            ],
            [
                Paragraph("With findings", s["cell"]),
                Paragraph(
                    f"{p.controls_with_findings} ({p.finding_pct}%)", s["cell"]
                ),
                Paragraph("See findings by severity below", s["cell"]),
            ],
            [
                Paragraph("Total findings", s["cell"]),
                Paragraph(str(p.total_findings), s["cell"]),
                Paragraph(
                    _esc(
                        f"Across {p.controls_with_findings} control(s)"
                    ),
                    s["cell"],
                ),
            ],
            [
                Paragraph("Overall posture", s["cell"]),
                Paragraph(
                    f'<font color="#{_color_hex(p.label_color)}"><b>'
                    f"{_esc(p.label)}</b></font>",
                    s["cell"],
                ),
                Paragraph(_esc(self._posture_note()), s["cell"]),
            ],
        ]
        return _data_table(
            ["Dimension", "Value", "Notes"],
            rows,
            [1.55 * inch, 1.35 * inch, _CONTENT_W - 2.9 * inch],
            s,
        )

    def _posture_note(self) -> str:
        p = self._posture
        if p.degraded:
            return "Re-run the scan — detection was incomplete."
        if p.sev_counts.get("critical", 0) + p.sev_counts.get("high", 0):
            return "Resolve high-severity findings before release."
        if p.sev_counts.get("medium"):
            return "No release blockers; medium findings to schedule."
        if p.total_findings:
            return "Only low-severity items outstanding."
        return "No findings raised against the assessed controls."

    def _legend_table(self) -> Table:
        s = self._styles
        counts = self._posture.sev_counts
        rows: list[list[Any]] = []
        for sev in _SEV_ORDER:
            count = counts.get(sev, 0)
            # Always show high/medium/low; show critical/info only when present.
            if sev in ("critical", "info") and count == 0:
                continue
            name, color, meaning = _SEV_META[sev]
            rows.append(
                [
                    Paragraph(
                        f'<font color="#{_color_hex(color)}"><b>{name}</b></font>',
                        s["cell"],
                    ),
                    Paragraph(str(count), s["cell"]),
                    Paragraph(_esc(meaning), s["cell"]),
                ]
            )
        return _data_table(
            ["Severity", "Count", "Meaning"],
            rows,
            [1.15 * inch, 0.7 * inch, _CONTENT_W - 1.85 * inch],
            s,
        )

    def _findings(self) -> list[Flowable]:
        s = self._styles

        if not self._result.findings:
            return [
                KeepTogether(
                    [
                        Paragraph("Findings", s["h1"]),
                        Paragraph(
                            "No compliance findings were raised. Every assessed "
                            "control was satisfied. Review the scan metadata in "
                            "the appendix to confirm the intended profile and "
                            "target were used.",
                            s["body"],
                        ),
                    ]
                )
            ]

        story: list[Flowable] = [
            KeepTogether(
                [
                    Paragraph("Findings", s["h1"]),
                    Paragraph(
                        "Findings are grouped by severity. Each entry cites the "
                        "control and source regulation, what the control "
                        "requires, what the scan detected, and recommended "
                        "remediation.",
                        s["body"],
                    ),
                ]
            )
        ]

        by_sev: dict[str, list[Finding]] = {}
        for f in self._result.findings:
            by_sev.setdefault(f.severity, []).append(f)

        index = 0
        for sev in _SEV_ORDER:
            sev_findings = by_sev.get(sev, [])
            if not sev_findings:
                continue
            name, color, descriptor = _SEV_META[sev]
            heading_style = ParagraphStyle(
                f"sev_{sev}", parent=s["sev_heading"], textColor=color
            )
            section_intro: list[Flowable] = [
                Paragraph(f"{name} severity ({len(sev_findings)})", heading_style),
                Paragraph(_esc(descriptor), s["caption"]),
            ]
            for offset, finding in enumerate(sev_findings):
                index += 1
                head = self._finding_head(index, finding)
                # Bind the section heading to the first finding's title and
                # table so the heading never dangles at the foot of a page.
                # One flat KeepTogether — never nest KeepTogether flowables.
                if offset == 0:
                    story.append(KeepTogether([*section_intro, *head]))
                else:
                    story.append(KeepTogether(head))
                story.extend(self._finding_body(finding))
        return story

    def _finding_head(self, index: int, finding: Finding) -> list[Flowable]:
        """A finding's title paragraph and field table, as a flat list.

        Returned flat (not pre-wrapped in KeepTogether) so the caller can put
        it straight into a single KeepTogether — nesting one KeepTogether
        inside another triggers a ReportLab blank-page bug.
        """
        s = self._styles
        control = self._controls.get(finding.control_id)
        title = finding.control_title or (control.title if control else "")
        heading = (
            f"F-{index} &nbsp; {_esc(finding.control_id)}"
            f"{' — ' + _esc(title) if title else ''}"
        )

        if finding.file:
            location = (
                f"{finding.file}:{finding.line}" if finding.line else finding.file
            )
        else:
            location = "Manual review — no specific code location"

        regulation = (control.regulation_short_code if control else "") or "—"
        source = (control.source_section if control else "") or "—"
        detail = _field_table(
            [
                ("Control", finding.control_id),
                ("Severity", _SEV_META[finding.severity][0]),
                ("Regulation", regulation),
                ("Source section", source),
                ("Detection method", finding.method),
                ("Location", location),
            ],
            s,
        )
        return [Paragraph(heading, s["finding_title"]), detail]

    def _finding_body(self, finding: Finding) -> list[Flowable]:
        """The labelled narrative that flows below a finding's field table.

        Each label is bound to its paragraph with KeepTogether so a label
        never dangles alone at the foot of a page.
        """
        s = self._styles
        control = self._controls.get(finding.control_id)
        requires = control.statement if control and control.statement else ""
        guidance = control.guidance if control and control.guidance else ""
        remediation = (
            _esc(guidance)
            if guidance
            else (
                "Review this control against the cited regulation and "
                "remediate the gap, then re-scan to confirm closure."
            )
        )

        sections: list[tuple[str, str]] = []
        if requires:
            sections.append(("WHAT THIS CONTROL REQUIRES", _esc(requires)))
        sections.append(("WHAT THE SCAN DETECTED", _esc(finding.message)))
        sections.append(("RECOMMENDED REMEDIATION", remediation))

        block: list[Flowable] = [
            KeepTogether(
                [
                    Paragraph(label, s["field_label"]),
                    Paragraph(text, s["body"]),
                ]
            )
            for label, text in sections
        ]
        block.append(Spacer(1, 0.14 * inch))
        return block

    def _appendix(self) -> list[Flowable]:
        s = self._styles
        r = self._result
        p = self._posture
        status = (
            "Degraded — detection incomplete, re-run recommended"
            if p.degraded
            else "Complete"
        )
        table = _field_table(
            [
                ("Scanner", f"Auvex compliance-assess v{self._version}"),
                ("Scan date", r.timestamp.strftime("%Y-%m-%d %H:%M UTC")),
                ("Profile", f"{r.profile_title}"),
                ("Profile ID", r.profile_id or "—"),
                ("Target", r.target),
                ("Controls assessed", str(p.controls_assessed)),
                ("Total findings", str(p.total_findings)),
                ("Scan status", status),
            ],
            s,
            label_w=1.8 * inch,
        )
        return [
            PageBreak(),
            KeepTogether(
                [
                    Paragraph("Appendix — Scan Metadata", s["h1"]),
                    Paragraph(
                        "The values below identify exactly how this assessment "
                        "was produced. Retain them with the report for audit "
                        "traceability.",
                        s["body"],
                    ),
                    table,
                ]
            ),
            *self._coverage(),
        ]

    def _coverage(self) -> list[Flowable]:
        """Appendix subsection listing files static analysis could not parse.

        Returns an empty list when the scan had full coverage, so the section
        is omitted entirely in that case. The heading+intro are kept together;
        the file list is left to flow so a long list cannot break layout.
        """
        r = self._result
        if not r.skipped_files:
            return []
        s = self._styles
        head = KeepTogether(
            [
                Paragraph("Scan Coverage", s["h2"]),
                Paragraph(
                    f"{len(r.skipped_files)} file(s) could not be parsed by "
                    "static analysis and were excluded from automated coverage. "
                    "Findings in this report do not reflect these files.",
                    s["body"],
                ),
            ]
        )
        rows: list[Flowable] = [
            Paragraph(
                f"&bull;&nbsp;{_esc(sf.path)}"
                + (f" &mdash; {_esc(sf.reason)}" if sf.reason else ""),
                s["body"],
            )
            for sf in r.skipped_files
        ]
        return [Spacer(1, 0.18 * inch), head, *rows]

    def _disclaimer(self) -> list[Flowable]:
        return [
            Spacer(1, 0.2 * inch),
            KeepTogether(
                [
                    Paragraph("Important — Not Legal Advice", self._styles["h2"]),
                    self._disclaimer_panel(compact=False),
                ]
            ),
        ]

    def _disclaimer_panel(self, *, compact: bool) -> Table:
        s = self._styles
        text = (
            "This report is generated by automated software analysis. It "
            "identifies <i>potential</i> compliance gaps in source code and "
            "configuration; it does not constitute legal advice and does not "
            "certify or guarantee regulatory compliance. Outputs are technical "
            "findings, not legal determinations. Review all findings with your "
            "privacy officer and qualified legal counsel before making "
            "compliance decisions."
        )
        cell = Paragraph(text, s["disclaimer"])
        table = Table([[cell]], colWidths=[_CONTENT_W], hAlign="LEFT")
        pad = 8 if compact else 10
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), _DISCLAIMER_BG),
                    ("LINEBEFORE", (0, 0), (0, -1), 3, _MED),
                    ("TOPPADDING", (0, 0), (-1, -1), pad),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), pad),
                    ("LEFTPADDING", (0, 0), (-1, -1), 11),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 11),
                ]
            )
        )
        return table


def _color_hex(color: Color) -> str:
    """Return a 6-digit hex string (no leading '#') for a ReportLab Color."""
    return "".join(f"{round(c * 255):02X}" for c in (color.red, color.green, color.blue))


# ---------------------------------------------------------------------------
# Emitter
# ---------------------------------------------------------------------------


class PDFEmitter:
    """Render an AssessmentResult to a branded, client-ready PDF."""

    extension: str = "pdf"

    def emit(self, result: AssessmentResult, output_path: Path) -> None:
        from . import __version__

        output_path = _resolve_output_path(output_path, self.extension)
        footer_left = f"Auvex compliance-assess v{__version__}"

        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=LETTER,
            leftMargin=_MARGIN,
            rightMargin=_MARGIN,
            topMargin=1.0 * inch,
            bottomMargin=0.95 * inch,
            title="Compliance Assessment Report",
            author="Auvex compliance-assess",
        )
        story = _Report(result, __version__).story()
        doc.build(
            story,
            onFirstPage=_cover_page,
            onLaterPages=_body_page,
            canvasmaker=_numbered_canvas(footer_left),
        )
