# SPDX-License-Identifier: Apache-2.0
"""Load-bearing tests for A-M1, A-M4, and A-M10 medium fixes."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from compliance_assess.emitters import SARIFEmitter
from compliance_assess.models import AssessmentResult, Control, Finding

# ---------------------------------------------------------------------------
# A-M1: catalog path resolution
# ---------------------------------------------------------------------------


def test_resolve_catalog_uses_env_var(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A-M1: When COMPLIANCE_CATALOG_PATH is set, _resolve_catalog returns that path
    even though no --catalog argument was supplied and the cwd default doesn't exist.

    This test would fail if the env var is silently ignored (the old CWD-relative
    _DEFAULT_CATALOG = Path('../compliance-catalog') could never pick up the env var).
    """
    catalog_dir = tmp_path / "my-catalog"
    catalog_dir.mkdir()
    monkeypatch.setenv("COMPLIANCE_CATALOG_PATH", str(catalog_dir))

    # Import inside test to avoid module-level side-effects from the env var.
    from compliance_assess.cli import _resolve_catalog  # noqa: PLC0415

    result = _resolve_catalog(None)
    assert result == Path(str(catalog_dir))


def test_resolve_catalog_explicit_arg_takes_precedence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A-M1: An explicit --catalog argument overrides COMPLIANCE_CATALOG_PATH."""
    monkeypatch.setenv("COMPLIANCE_CATALOG_PATH", str(tmp_path / "env-catalog"))
    explicit = str(tmp_path / "explicit-catalog")

    from compliance_assess.cli import _resolve_catalog  # noqa: PLC0415

    result = _resolve_catalog(explicit)
    assert result == Path(explicit)


# ---------------------------------------------------------------------------
# A-M4: SARIF severity escalation for mixed-severity controls
# ---------------------------------------------------------------------------


def test_sarif_severity_escalation_uses_highest_for_control(tmp_path: Path) -> None:
    """A-M4: When a control has multiple findings with different severities, the SARIF
    rule's defaultConfiguration.level must reflect the highest severity seen, not the
    first finding's severity.

    Without the fix the rule would use 'warning' (medium) instead of 'error' (high).
    """
    result = AssessmentResult(
        profile_id="escalation-test",
        profile_title="Escalation Profile",
        target="/repo",
        timestamp=datetime(2026, 5, 9, tzinfo=UTC),
        controls_assessed=1,
        controls_with_findings=1,
        findings=[
            # medium finding appears first in the list
            Finding(
                control_id="CTRL-MIXED",
                severity="medium",
                method="questionnaire",
                file=None,
                line=None,
                message="Questionnaire gap",
                control_title="Mixed-severity control",
            ),
            # high finding appears second — must escalate the rule level to 'error'
            Finding(
                control_id="CTRL-MIXED",
                severity="high",
                method="semgrep",
                file="src/auth.py",
                line=10,
                message="Critical auth bypass detected",
                control_title="Mixed-severity control",
            ),
        ],
    )

    out = tmp_path / "escalation.sarif"
    SARIFEmitter().emit(result, out)

    data = json.loads(out.read_text(encoding="utf-8"))
    rules = data["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) == 1, f"Expected 1 deduped rule, got {len(rules)}"

    rule = rules[0]
    assert rule["id"] == "CTRL-MIXED"
    level = rule["defaultConfiguration"]["level"]
    assert level == "error", (
        f"Expected 'error' (highest severity escalation), got '{level}'"
    )
    # A-M5: shortDescription should use the control title, not the bare control_id
    assert rule["shortDescription"]["text"] == "Mixed-severity control", (
        f"Expected control title in shortDescription, got: {rule['shortDescription']['text']!r}"
    )


# ---------------------------------------------------------------------------
# A-M10: QuestionnaireEngine gating
# ---------------------------------------------------------------------------


def test_questionnaire_suppressed_when_automated_finding_present(tmp_path: Path) -> None:
    """A-M10: When an automated engine produces a finding for a control, the
    QuestionnaireEngine must NOT also emit a finding for the same control.

    Without the fix, every control with a questionnaire mapping always gets a
    questionnaire finding even if semgrep already flagged it — doubling the noise.
    """
    from compliance_assess.assessor import Assessor
    from compliance_assess.detection import DetectionEngine, QuestionnaireEngine
    from compliance_assess.result import Ok

    # Build a minimal catalog with a mapping that includes both semgrep and questionnaire.
    catalog = tmp_path / "catalog"
    detection_rules = catalog / "detection-rules"
    detection_rules.mkdir(parents=True)

    # mapping.yaml: control TEST-001 has both semgrep and questionnaire methods.
    (detection_rules / "mapping.yaml").write_text(
        "mappings:\n"
        "  - control-id: TEST-001\n"
        "    detection-methods:\n"
        "      - method: semgrep\n"
        "        file: detection-rules/semgrep/test.yaml\n"
        "      - method: questionnaire\n"
        "        file: ''\n"
        "        fragment-id: ''\n",
        encoding="utf-8",
    )

    reg_yaml = catalog / "reg.yaml"
    reg_yaml.write_text(
        "catalog:\n"
        "  uuid: 00000000-0000-4000-8000-000000000070\n"
        "  metadata:\n"
        "    title: Reg\n"
        "    props:\n"
        "      - name: regulation-short-code\n"
        "        value: TEST\n"
        "      - name: jurisdiction\n"
        "        value: CA\n"
        "  groups:\n"
        "    - controls:\n"
        "        - id: TEST-001\n"
        "          title: Test Control\n"
        "          props: []\n"
        "          parts: []\n",
        encoding="utf-8",
    )

    profiles_dir = catalog / "profiles"
    profiles_dir.mkdir()
    profile_yaml = profiles_dir / "test.yaml"
    profile_yaml.write_text(
        "profile:\n"
        "  uuid: 00000000-0000-4000-8000-000000000080\n"
        "  metadata:\n"
        "    title: Test Profile\n"
        "    version: '0.1'\n"
        "    last-modified: '2026-01-01T00:00:00Z'\n"
        "  imports:\n"
        "    - href: ../reg.yaml\n"
        "      include-controls:\n"
        "        - with-ids: [TEST-001]\n",
        encoding="utf-8",
    )

    target = tmp_path / "target"
    target.mkdir()

    # Automated engine that always finds a finding for TEST-001
    class AlwaysFindsEngine:
        name: str = "always-finds"

        def detect(
            self,
            control: Control,
            target_dir: Path,
            source_files: list[Path],
            *,
            timeout_s: float = 30.0,
        ) -> list[Finding]:
            return [
                Finding(
                    control_id=control.id,
                    severity="high",
                    method="semgrep",
                    message="Automated finding",
                )
            ]

    assessor_obj = Assessor(catalog)
    profile_result = assessor_obj.load_profile(profile_yaml)
    assert isinstance(profile_result, Ok)

    questionnaire = QuestionnaireEngine(catalog)
    engines: list[DetectionEngine] = [
        AlwaysFindsEngine(),
        questionnaire,
    ]
    assessment = assessor_obj.assess(profile_result.value, target, engines)
    assert isinstance(assessment, Ok)

    findings = assessment.value.findings
    # Should have exactly 1 finding from the automated engine, not 2 (not also questionnaire)
    assert len(findings) == 1, (
        f"Expected 1 finding (automated suppresses questionnaire), got {len(findings)}: "
        f"{[f.method for f in findings]}"
    )
    assert findings[0].method == "semgrep"
