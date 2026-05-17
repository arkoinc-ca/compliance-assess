"""Real-semgrep integration tests for SemgrepEngine.

These tests invoke the actual `semgrep` binary against purpose-built source
fixtures — they do NOT mock the subprocess. They are the load-bearing guard for
two shipped bugs:

  * F-1 — SemgrepEngine discarded findings whenever semgrep exited 0 (its default
    when findings exist) or >=2. `test_semgrep_surfaces_findings_*` fails if that
    regresses, because semgrep exits 0 here yet must still yield findings.
  * F-3 — the JS/TS rules matched any `.delete()` call. `test_semgrep_ignores_
    browser_delete_calls` fails if cookie/cache/IndexedDB deletes are flagged again.

semgrep does not run on Windows; the whole module is skipped when the binary is
not on PATH (developer machines), and runs in CI / Docker where it is installed.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from compliance_assess.cli import app
from compliance_assess.detection import SemgrepEngine
from compliance_assess.models import Control

_REPO_ROOT = Path(__file__).parent.parent.parent
_CATALOG = _REPO_ROOT.parent / "compliance-catalog"
_CORPUS = _REPO_ROOT / "tests" / "fixtures" / "corpus"
_PROFILE = _CATALOG / "profiles" / "use-case" / "saas-canada-b2c.yaml"

_AUDIT_RULE = "detection-rules/semgrep/missing-audit.yaml"
_DSR_RULE = "detection-rules/semgrep/missing-dsr.yaml"

pytestmark = [
    pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not on PATH"),
    pytest.mark.skipif(not _CATALOG.exists(), reason="compliance-catalog not found"),
]

runner = CliRunner()


def _control(control_id: str) -> Control:
    return Control(
        id=control_id,
        title="Test control",
        statement="Test control for the real-semgrep integration suite.",
        severity="high",
        regulation_short_code="TEST",
    )


def _engine_for(rule_files: list[str], control_id: str) -> SemgrepEngine:
    """Build a SemgrepEngine whose mapping points `control_id` at `rule_files`."""
    engine = SemgrepEngine(_CATALOG)
    engine._mapping = {
        control_id: [{"method": "semgrep", "file": rf} for rf in rule_files]
    }
    return engine


def test_semgrep_surfaces_findings_for_python_and_typescript(tmp_path: Path) -> None:
    """A real scan of the true-positive corpus must yield method='semgrep' findings.

    semgrep 1.95.0 exits 0 here (findings present, no --error flag). Before the
    F-1 fix the engine's `if rc == 0: pass` branch discarded every finding, so
    this test fails against the pre-fix engine. It also guards F-9 (a rule that
    fails to parse surfaces as a method='error' sentinel) and the F-3 raw-SQL
    detection branch (`raw_sql_delete.{ts,py}` must fire).
    """
    scan_dir = tmp_path / "scan"
    shutil.copytree(_CORPUS / "semgrep-positive", scan_dir)

    engine = _engine_for([_AUDIT_RULE, _DSR_RULE], "TEST-POS")
    findings = engine.detect(_control("TEST-POS"), scan_dir, [])

    semgrep_findings = [f for f in findings if f.method == "semgrep"]
    error_findings = [f for f in findings if f.method == "error"]

    assert error_findings == [], (
        f"rule parse error or scan failure: {[f.message for f in error_findings]}"
    )
    assert len(semgrep_findings) >= 2, (
        f"expected >=2 semgrep findings, got {len(semgrep_findings)}"
    )
    hit_files = {Path(f.file).name for f in semgrep_findings if f.file}
    suffixes = {Path(f.file).suffix for f in semgrep_findings if f.file}
    assert {".py", ".ts"} <= suffixes, f"both languages must be detected, got {suffixes}"
    # F-3 raw-SQL detection branch must fire for both languages.
    assert "raw_sql_delete.ts" in hit_files, "JS raw-SQL (DELETE FROM) detection did not fire"
    assert "raw_sql_delete.py" in hit_files, "Python raw-SQL (DELETE FROM) detection did not fire"


def test_semgrep_ignores_browser_delete_calls(tmp_path: Path) -> None:
    """The js-false-positive corpus (cookie/cache/IndexedDB/Map/Headers `.delete()`)
    must produce zero semgrep findings under both missing-audit and missing-dsr.

    Fails against the pre-F-3 rules, which matched any `.delete()` receiver.
    """
    scan_dir = tmp_path / "scan"
    shutil.copytree(_CORPUS / "js-false-positive", scan_dir)

    engine = _engine_for([_AUDIT_RULE, _DSR_RULE], "TEST-FP")
    findings = engine.detect(_control("TEST-FP"), scan_dir, [])

    semgrep_findings = [f for f in findings if f.method == "semgrep"]
    assert semgrep_findings == [], (
        "browser .delete() calls were flagged: "
        f"{[(f.file, f.line) for f in semgrep_findings]}"
    )


def test_cli_scan_surfaces_semgrep_findings(tmp_path: Path) -> None:
    """End-to-end: a CLI scan of source with a real violation must report >=1
    semgrep finding in compliance-summary.json's `by_method` breakdown.

    Before the F-1 fix the engine dropped every semgrep finding, leaving only
    questionnaire findings — exactly the degraded state this guards against.
    The corpus is copied into a plain temp dir because semgrep's default
    .semgrepignore skips any path under a `tests/` directory.
    """
    app_dir = tmp_path / "app"
    shutil.copytree(_CORPUS / "semgrep-positive", app_dir)
    out_dir = tmp_path / "out"

    result = runner.invoke(
        app,
        [
            "scan",
            str(app_dir),
            "--profile",
            str(_PROFILE),
            "--catalog",
            str(_CATALOG),
            "--format",
            "markdown",
            "--out",
            str(out_dir),
        ],
    )
    assert result.exit_code in {0, 1}, f"unexpected exit {result.exit_code}\n{result.output}"

    summary = json.loads((out_dir / "compliance-summary.json").read_text(encoding="utf-8"))
    by_method = summary.get("by_method", {})
    assert by_method.get("semgrep", 0) >= 1, (
        f"no semgrep findings surfaced end-to-end; by_method={by_method}"
    )
