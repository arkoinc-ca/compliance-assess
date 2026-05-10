"""Load-bearing tests for detection engine backends."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
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
