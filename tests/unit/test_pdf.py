# SPDX-License-Identifier: Apache-2.0
"""Load-bearing tests for the PDF emitter (pdf.py).

The PDF render path is the realistic failure surface: a malformed flowable,
table, or paragraph style raises only when ReportLab actually lays the
document out. These tests build an AssessmentResult and assert a real,
finalised PDF is produced for both the populated and clean-scan paths, plus
the posture arithmetic that drives the report's headline numbers.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from compliance_assess.models import AssessmentResult, Control, Finding, SkippedFile
from compliance_assess.pdf import PDFEmitter, _compute_posture


def _control(cid: str) -> Control:
    return Control(
        id=cid,
        title=f"Control {cid}",
        statement="The organisation must honour the individual's right of access.",
        guidance="Complete the export path and add a regression test, then re-scan.",
        severity="high",
        source_section="s.52",
        regulation_short_code="PHIPA",
    )


@pytest.fixture()
def populated_result() -> AssessmentResult:
    """A result with resolved controls and mixed-severity findings."""
    return AssessmentResult(
        profile_id="ca-on-v1",
        profile_title="Ontario Healthcare Profile",
        target="/repo/src",
        timestamp=datetime(2026, 5, 18, 9, 30, tzinfo=UTC),
        controls_assessed=4,
        controls_with_findings=2,
        resolved_controls=[_control(f"CTRL-{i}") for i in range(1, 5)],
        # exercises the appendix Scan Coverage section in the PDF render path
        skipped_files=[SkippedFile(path="src/legacy/cdanet.ts", reason="Syntax error")],
        findings=[
            Finding(
                control_id="CTRL-1",
                severity="high",
                method="semgrep",
                file="src/auth.py",
                line=42,
                message="Right-of-access export does not generate a file.",
            ),
            Finding(
                control_id="CTRL-2",
                severity="medium",
                method="questionnaire",
                message="Retention policy not confirmed by questionnaire.",
            ),
        ],
    )


def test_pdf_emitter_renders_finalised_pdf(
    populated_result: AssessmentResult, tmp_path: Path
) -> None:
    """emit() must lay out every section and write a complete PDF file."""
    out = tmp_path / "report.pdf"
    PDFEmitter().emit(populated_result, out)

    data = out.read_bytes()
    assert data.startswith(b"%PDF-"), "output is not a PDF"
    assert data.rstrip().endswith(b"%%EOF"), "PDF was not finalised (truncated)"
    # A multi-section branded report with tables is never trivially small;
    # guards against an 'empty story' regression that still emits valid PDF.
    assert len(data) > 3000


def test_pdf_emitter_renders_clean_scan(tmp_path: Path) -> None:
    """A zero-finding scan exercises the no-findings and all-zero-legend
    branches, which fail differently from the populated path."""
    result = AssessmentResult(
        profile_id="clean-v1",
        profile_title="Clean Profile",
        target="/repo",
        timestamp=datetime(2026, 5, 18, tzinfo=UTC),
        controls_assessed=3,
        controls_with_findings=0,
        resolved_controls=[_control(f"C-{i}") for i in range(1, 4)],
        findings=[],
    )
    out = tmp_path / "clean.pdf"
    PDFEmitter().emit(result, out)

    data = out.read_bytes()
    assert data.startswith(b"%PDF-")
    assert data.rstrip().endswith(b"%%EOF")


@pytest.mark.parametrize(
    ("findings", "expected_label"),
    [
        (
            [Finding(control_id="C-1", severity="high", method="semgrep", message="m")],
            "Action required",
        ),
        (
            [Finding(control_id="C-1", severity="medium", method="semgrep", message="m")],
            "Review recommended",
        ),
        ([], "Pass"),
    ],
)
def test_compute_posture_label_and_passed_count(
    findings: list[Finding], expected_label: str
) -> None:
    """_compute_posture derives the headline label and passed-control count
    shown in the report's 'Overall Compliance Posture' table."""
    result = AssessmentResult(
        profile_id="p",
        profile_title="P",
        target="/r",
        timestamp=datetime(2026, 5, 18, tzinfo=UTC),
        controls_assessed=10,
        controls_with_findings=len(findings),
        findings=findings,
    )

    posture = _compute_posture(result)

    assert posture.label == expected_label
    assert posture.controls_passed == 10 - len(findings)
    assert posture.pass_pct == round((10 - len(findings)) / 10 * 100)
