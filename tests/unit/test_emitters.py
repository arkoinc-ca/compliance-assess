"""Load-bearing tests for emitters.py (P2-T04 / P2-T05).

Four tests — one per emitter — covering the most important contract each
emitter must uphold.  Fixtures build AssessmentResult directly; no Assessor.
"""

from __future__ import annotations

import csv
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from compliance_assess.emitters import CSVEmitter, HTMLEmitter, MarkdownEmitter, SARIFEmitter
from compliance_assess.models import AssessmentResult, Finding

# ---------------------------------------------------------------------------
# Shared fixture
# ---------------------------------------------------------------------------


@pytest.fixture()
def sample_result() -> AssessmentResult:
    """AssessmentResult with one high and one medium finding."""
    return AssessmentResult(
        profile_id="ca-privacy-v1",
        profile_title="CA Privacy Profile",
        target="/repo/src",
        timestamp=datetime(2026, 5, 9, 12, 0, 0, tzinfo=UTC),
        controls_assessed=5,
        controls_with_findings=2,
        findings=[
            Finding(
                control_id="CTRL-001",
                severity="high",
                method="semgrep",
                file="src/auth.py",
                line=42,
                message="Hardcoded credential detected",
            ),
            Finding(
                control_id="CTRL-002",
                severity="medium",
                method="questionnaire",
                file=None,
                line=None,
                message="Privacy notice not reviewed",
            ),
        ],
    )


# ---------------------------------------------------------------------------
# P2-T04: SARIFEmitter
# ---------------------------------------------------------------------------


def test_sarif_emitter_maps_critical_to_error_level(tmp_path: Path) -> None:
    """A-H4: A finding with severity='critical' must map to SARIF level 'error'."""
    result = AssessmentResult(
        profile_id="crit-test",
        profile_title="Critical Profile",
        target="/repo",
        timestamp=datetime(2026, 5, 9, tzinfo=UTC),
        controls_assessed=1,
        controls_with_findings=1,
        findings=[
            Finding(
                control_id="CTRL-CRIT",
                severity="critical",
                method="semgrep",
                file="src/main.py",
                line=1,
                message="Critical issue detected",
            )
        ],
    )

    out = tmp_path / "critical.sarif"
    SARIFEmitter().emit(result, out)

    data = json.loads(out.read_text(encoding="utf-8"))
    levels = [r["level"] for r in data["runs"][0]["results"]]
    assert levels == ["error"], f"Expected ['error'] for critical severity, got {levels}"


def test_sarif_emitter_produces_valid_sarif_skeleton(
    sample_result: AssessmentResult,
    tmp_path: Path,
) -> None:
    """SARIF output has correct version, tool name, and one result per finding."""
    out = tmp_path / "report.sarif"
    SARIFEmitter().emit(sample_result, out)

    data = json.loads(out.read_text(encoding="utf-8"))

    assert data["version"] == "2.1.0"
    driver = data["runs"][0]["tool"]["driver"]
    assert driver["name"] == "compliance-assess"
    assert len(data["runs"][0]["results"]) == 2


# ---------------------------------------------------------------------------
# P2-T05: MarkdownEmitter
# ---------------------------------------------------------------------------


def test_markdown_emitter_renders_severity_groups(
    sample_result: AssessmentResult,
    tmp_path: Path,
) -> None:
    """Markdown has a section per severity; empty severity shows '_None._'."""
    out = tmp_path / "report.md"
    MarkdownEmitter().emit(sample_result, out)

    text = out.read_text(encoding="utf-8")
    assert "### High severity" in text
    assert "### Medium severity" in text
    # Low severity section must be present and flagged as empty
    assert "### Low severity" in text
    assert "_None._" in text


# ---------------------------------------------------------------------------
# P2-T05: HTMLEmitter
# ---------------------------------------------------------------------------


def test_html_emitter_escapes_user_content(tmp_path: Path) -> None:
    """User-controlled content in findings must be HTML-escaped."""
    result = AssessmentResult(
        profile_id="xss-test",
        profile_title="XSS Profile",
        target="/repo",
        timestamp=datetime(2026, 5, 9, tzinfo=UTC),
        controls_assessed=1,
        controls_with_findings=1,
        findings=[
            Finding(
                control_id="CTRL-XSS",
                severity="high",
                method="semgrep",
                file="src/main.py",
                line=1,
                message="<script>alert(1)</script>",
            )
        ],
    )

    out = tmp_path / "report.html"
    HTMLEmitter().emit(result, out)

    text = out.read_text(encoding="utf-8")
    # Raw script tag must NOT appear
    assert "<script>alert(1)</script>" not in text
    # Escaped version must appear
    assert "&lt;script&gt;" in text


# ---------------------------------------------------------------------------
# P2-T05: CSVEmitter
# ---------------------------------------------------------------------------


def test_csv_emitter_escapes_injection_formulas(tmp_path: Path) -> None:
    """A-H1: CSV cells starting with formula-triggering chars must be prefixed with '."""
    result = AssessmentResult(
        profile_id="inject-test",
        profile_title="Injection Profile",
        target="/repo",
        timestamp=datetime(2026, 5, 9, tzinfo=UTC),
        controls_assessed=1,
        controls_with_findings=1,
        findings=[
            Finding(
                control_id="CTRL-INJ",
                severity="high",
                method="semgrep",
                file="src/main.py",
                line=1,
                message="=cmd|'/C calc'!A0",
            )
        ],
    )

    out = tmp_path / "inject.csv"
    CSVEmitter().emit(result, out)

    with open(out, newline="", encoding="utf-8-sig") as fh:
        rows = list(csv.reader(fh))

    # The message cell must NOT start with '=' — it must be prefixed with '
    message_cell = rows[1][5]
    assert message_cell.startswith("'="), (
        f"Expected CSV injection escape, got: {message_cell!r}"
    )


def test_csv_emitter_round_trips_findings(tmp_path: Path) -> None:
    """CSV has a header row plus one data row per finding; messages survive round-trip."""
    messages = ["Finding one", "Finding, with comma", "Finding\nwith newline"]
    result = AssessmentResult(
        profile_id="csv-test",
        profile_title="CSV Profile",
        target="/repo",
        timestamp=datetime(2026, 5, 9, tzinfo=UTC),
        controls_assessed=3,
        controls_with_findings=3,
        findings=[
            Finding(
                control_id=f"CTRL-{i}",
                severity="low",
                method="semgrep",
                file=f"src/file{i}.py",
                line=i,
                message=msg,
            )
            for i, msg in enumerate(messages, start=1)
        ],
    )

    out = tmp_path / "report.csv"
    CSVEmitter().emit(result, out)

    # utf-8-sig BOM is transparent to csv.reader when opened with utf-8-sig
    with open(out, newline="", encoding="utf-8-sig") as fh:
        rows = list(csv.reader(fh))

    assert rows[0] == ["control_id", "severity", "method", "file", "line", "message"]
    assert len(rows) == 4  # header + 3 data rows
    emitted_messages = [row[5] for row in rows[1:]]
    assert emitted_messages == messages
