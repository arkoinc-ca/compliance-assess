"""Load-bearing tests for detection engine backends."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

import pytest

from compliance_assess.detection import OtelEngine, QuestionnaireEngine, SemgrepEngine
from compliance_assess.models import Control

CATALOG = Path(__file__).parent.parent.parent.parent / "compliance-catalog"


@pytest.fixture
def pipeda_001() -> Control:
    return Control(
        id="CA-PIPEDA-001",
        title="Accountability",
        statement="An organization must designate a privacy officer.",
        severity="high",
        regulation_short_code="PIPEDA",
    )


def test_questionnaire_engine_emits_finding_for_mapped_control(
    pipeda_001: Control,
) -> None:
    engine = QuestionnaireEngine(CATALOG)
    findings = engine.detect(pipeda_001, CATALOG, [])
    assert len(findings) >= 1
    assert all(f.method == "questionnaire" for f in findings)
    assert all(f.control_id == "CA-PIPEDA-001" for f in findings)
    # A-H6: messages either reference an existing file+fragment OR fall back to runbook message.
    # Both are valid; assert the message is non-empty and starts with "Manual review required".
    assert all(f.message.startswith("Manual review required") for f in findings)


def test_questionnaire_mapping_refs_all_resolve() -> None:
    """Every questionnaire file referenced by mapping.yaml must exist on disk.

    A missing file silently degrades that control's finding to the generic
    'see runbook for control <id>' message instead of a precise
    'see <file>#<fragment-id>' link, hiding the real attestation question.
    """
    engine = QuestionnaireEngine(CATALOG)
    assert engine.validate_mapping_refs() == []


def test_otel_engine_returns_empty_list(pipeda_001: Control) -> None:
    engine = OtelEngine(CATALOG)
    findings = engine.detect(pipeda_001, CATALOG, [])
    assert findings == []


@pytest.mark.parametrize(
    "exc",
    [
        json.JSONDecodeError("bad json", doc="", pos=0),
        OSError("permission denied"),
        subprocess.TimeoutExpired(cmd="semgrep", timeout=30.0),
    ],
)
def test_semgrep_engine_emits_sentinel_on_subprocess_error(
    exc: Exception,
    pipeda_001: Control,
    tmp_path: Path,
) -> None:
    """A-H7: SemgrepEngine must emit a sentinel Finding(method='error') for each
    of the three error paths: JSONDecodeError, OSError, TimeoutExpired."""
    engine = SemgrepEngine(CATALOG)

    # Ensure the mapping has an entry that would trigger subprocess.run for PIPEDA-001
    engine._mapping = {
        "CA-PIPEDA-001": [
            {"method": "semgrep", "file": "detection-rules/semgrep/pii-in-logs.yaml"}
        ]
    }

    # Stub subprocess.run to raise the target exception; stub shutil.which so engine proceeds
    with (
        patch("compliance_assess.detection.shutil.which", return_value="/usr/bin/semgrep"),
        patch("compliance_assess.detection.subprocess.run", side_effect=exc),
    ):
        # Point rules_dir to the real semgrep dir so path-traversal guard passes
        engine._rules_dir = CATALOG / "detection-rules" / "semgrep"
        findings = engine.detect(pipeda_001, tmp_path, [])

    assert len(findings) == 1
    assert findings[0].method == "error", f"Expected method='error', got {findings[0].method!r}"
    assert findings[0].control_id == "CA-PIPEDA-001"


# ---------------------------------------------------------------------------
# Regression tests for the rc-as-gate bug.
#
# These mock subprocess.run to return canned (returncode, stdout) pairs. The
# CLAUDE.md "do not mock semgrep invocations" rule targets *rule* testing —
# proving a semgrep rule matches real source. It does not apply here: this bug
# lived purely in detect()'s exit-code/JSON handling, and a real-semgrep run
# cannot produce arbitrary returncode/stdout combinations on demand. The rules
# themselves are exercised against real semgrep in tests/integration/
# test_semgrep_real.py.
# ---------------------------------------------------------------------------

_SEMGREP_MAPPING = {
    "CA-PIPEDA-001": [
        {"method": "semgrep", "file": "detection-rules/semgrep/pii-in-logs.yaml"}
    ]
}

_ONE_RESULT_STDOUT = json.dumps(
    {
        "results": [
            {
                "check_id": "ca.pipeda.missing-dsr-python",
                "path": "backend/users.py",
                "start": {"line": 42, "col": 1},
                "end": {"line": 42, "col": 20},
                "extra": {"message": "DSR handler missing", "severity": "INFO"},
            }
        ],
        "errors": [],
        "paths": {"scanned": ["backend/users.py"]},
        "version": "1.95.0",
    }
).encode()


def _make_proc(
    returncode: int,
    stdout: bytes,
    stderr: bytes = b"",
) -> CompletedProcess[bytes]:
    return CompletedProcess(args=["semgrep"], returncode=returncode, stdout=stdout, stderr=stderr)


def _setup_engine(engine: SemgrepEngine) -> None:
    """Point engine at the real semgrep rules dir so path-traversal guard passes."""
    engine._mapping = _SEMGREP_MAPPING
    engine._rules_dir = CATALOG / "detection-rules" / "semgrep"


def test_semgrep_rc0_with_results_emits_finding(
    pipeda_001: Control,
    tmp_path: Path,
) -> None:
    """Core regression: rc==0 with a results array must produce a semgrep Finding.

    This test would fail against the old code because the old `if rc == 0: pass`
    branch discarded every result silently.
    """
    engine = SemgrepEngine(CATALOG)
    _setup_engine(engine)

    with (
        patch("compliance_assess.detection.shutil.which", return_value="/usr/bin/semgrep"),
        patch(
            "compliance_assess.detection.subprocess.run",
            return_value=_make_proc(returncode=0, stdout=_ONE_RESULT_STDOUT),
        ),
    ):
        findings = engine.detect(pipeda_001, tmp_path, [])

    assert len(findings) == 1
    f = findings[0]
    assert f.method == "semgrep"
    assert f.control_id == "CA-PIPEDA-001"
    assert f.file == "backend/users.py"
    assert f.line == 42


def test_semgrep_rc2_target_error_emits_finding_no_sentinel(
    pipeda_001: Control,
    tmp_path: Path,
) -> None:
    """rc==2 with a target-parse error in errors[] must yield the semgrep finding
    and NO method='error' sentinel — target errors are non-fatal for the scan.

    Old code: `else` branch on rc>=2 discarded findings and emitted a sentinel.
    """
    stdout = json.dumps(
        {
            "results": [
                {
                    "check_id": "ca.pipeda.missing-dsr-python",
                    "path": "backend/users.py",
                    "start": {"line": 10, "col": 1},
                    "end": {"line": 10, "col": 5},
                    "extra": {"message": "DSR missing", "severity": "INFO"},
                }
            ],
            "errors": [
                {
                    "code": 3,
                    "level": "error",
                    "type": "Syntax error",
                    "message": "Could not parse generated.py",
                    "path": "generated.py",
                }
            ],
            "paths": {"scanned": ["backend/users.py"]},
            "version": "1.95.0",
        }
    ).encode()

    engine = SemgrepEngine(CATALOG)
    _setup_engine(engine)

    with (
        patch("compliance_assess.detection.shutil.which", return_value="/usr/bin/semgrep"),
        patch(
            "compliance_assess.detection.subprocess.run",
            return_value=_make_proc(returncode=2, stdout=stdout),
        ),
    ):
        findings = engine.detect(pipeda_001, tmp_path, [])

    semgrep_findings = [f for f in findings if f.method == "semgrep"]
    error_sentinels = [f for f in findings if f.method == "error"]

    assert len(semgrep_findings) == 1, "expected the real finding to be returned"
    assert len(error_sentinels) == 0, "target-parse errors must not produce a sentinel"
    # The unparseable target file must be recorded as a coverage gap so the
    # report can surface it — without this it is invisible outside scan logs.
    assert [(sf.path, sf.reason) for sf in engine.skipped_files] == [
        ("generated.py", "Syntax error")
    ]


def test_semgrep_rc2_rule_error_emits_finding_and_sentinel(
    pipeda_001: Control,
    tmp_path: Path,
) -> None:
    """rc==2 with a rule-parse error must return the semgrep finding AND one
    method='error' sentinel so `scan_degraded` is set by the assessor.

    Old code: `else` branch discarded the real finding.  New code must coexist both.
    """
    stdout = json.dumps(
        {
            "results": [
                {
                    "check_id": "ca.pipeda.missing-dsr-python",
                    "path": "backend/users.py",
                    "start": {"line": 7, "col": 1},
                    "end": {"line": 7, "col": 5},
                    "extra": {"message": "DSR missing", "severity": "INFO"},
                }
            ],
            "errors": [
                {
                    "code": 2,
                    "level": "error",
                    "type": "Rule parse error",
                    "rule_id": "ca.pipeda.missing-audit-java",
                    "message": "Rule parse error in rule missing-audit-java: invalid pattern",
                    "path": "detection-rules/semgrep/missing-audit.yaml",
                }
            ],
            "paths": {"scanned": ["backend/users.py"]},
            "version": "1.95.0",
        }
    ).encode()

    engine = SemgrepEngine(CATALOG)
    _setup_engine(engine)

    with (
        patch("compliance_assess.detection.shutil.which", return_value="/usr/bin/semgrep"),
        patch(
            "compliance_assess.detection.subprocess.run",
            return_value=_make_proc(returncode=2, stdout=stdout),
        ),
    ):
        findings = engine.detect(pipeda_001, tmp_path, [])

    semgrep_findings = [f for f in findings if f.method == "semgrep"]
    error_sentinels = [f for f in findings if f.method == "error"]

    assert len(semgrep_findings) == 1, "real finding must be present alongside sentinel"
    assert len(error_sentinels) == 1, "exactly one sentinel per rule-error control"
    assert "could not be parsed" in error_sentinels[0].message


def test_semgrep_rc2_empty_stdout_emits_sentinel(
    pipeda_001: Control,
    tmp_path: Path,
) -> None:
    """rc==2 with completely empty stdout must emit one method='error' sentinel.

    Distinct from the existing TimeoutExpired/OSError/JSONDecodeError tests: those
    patch subprocess.run to *raise*.  This test returns a CompletedProcess with
    rc=2 and empty bytes — the code path that reads proc.returncode then checks
    raw_stdout.strip() == b''.
    """
    engine = SemgrepEngine(CATALOG)
    _setup_engine(engine)

    with (
        patch("compliance_assess.detection.shutil.which", return_value="/usr/bin/semgrep"),
        patch(
            "compliance_assess.detection.subprocess.run",
            return_value=_make_proc(returncode=2, stdout=b"", stderr=b"semgrep: fatal error"),
        ),
    ):
        findings = engine.detect(pipeda_001, tmp_path, [])

    assert len(findings) == 1
    assert findings[0].method == "error"
    assert findings[0].control_id == "CA-PIPEDA-001"
