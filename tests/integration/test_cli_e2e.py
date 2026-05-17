"""CLI e2e integration test — catches HIGH #1 (scan never invoked emitters).

Regression test: before the fix, compliance-assess scan completed without
writing any output file; this test asserts the markdown file and summary JSON
are both produced by a real scan invocation.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from compliance_assess.cli import app

_REPO_ROOT = Path(__file__).parent.parent.parent
_CATALOG = _REPO_ROOT.parent / "compliance-catalog"
_SAMPLE_APP = _REPO_ROOT / "tests" / "fixtures" / "sample-app"
_PROFILE = _CATALOG / "profiles" / "use-case" / "saas-canada-b2c.yaml"

runner = CliRunner()


@pytest.mark.skipif(
    not _CATALOG.exists(),
    reason="compliance-catalog not found at ../compliance-catalog — skip e2e",
)
def test_scan_writes_markdown_and_summary_json(tmp_path: Path) -> None:
    """scan command must write compliance-assessment.md and compliance-summary.json.

    This test fails before HIGH #1 fix (no emitters called) and passes after.
    Exit code must be 0 (no findings) or 1 (high-severity findings) — never 2+.
    """
    result = runner.invoke(
        app,
        [
            "scan",
            str(_SAMPLE_APP),
            "--profile",
            str(_PROFILE),
            "--catalog",
            str(_CATALOG),
            "--format",
            "markdown",
            "--out",
            str(tmp_path),
        ],
    )

    # Exit code must be 0 or 1 (findings present/absent), not 2 (CLI error).
    assert result.exit_code in {0, 1}, (
        f"Unexpected exit code {result.exit_code}.\nOutput:\n{result.output}"
    )

    md_file = tmp_path / "compliance-assessment.md"
    assert md_file.exists(), "markdown report file was not written"
    assert "# Compliance Assessment Report" in md_file.read_text(encoding="utf-8")

    summary_file = tmp_path / "compliance-summary.json"
    assert summary_file.exists(), "compliance-summary.json was not written"
    summary = json.loads(summary_file.read_text(encoding="utf-8"))
    assert "total" in summary, f"summary JSON missing 'total' key: {summary}"
    # by_method is the breakdown CI consumers use to confirm automated detection
    # ran; its absence is what hid the F-1 silent-miss bug from operators.
    assert isinstance(summary.get("by_method"), dict), (
        f"summary JSON missing 'by_method' breakdown: {summary}"
    )
