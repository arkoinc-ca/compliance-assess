# SPDX-License-Identifier: Apache-2.0
"""DetectionEngine protocol and backend implementations."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Protocol, runtime_checkable

import structlog
import yaml

from .models import Control, Finding, SeverityLiteral

_log = structlog.get_logger("compliance_assess.detection")

_SEVERITY_MAP: dict[str, SeverityLiteral] = {
    "info": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}


def _normalize_severity(raw: str) -> SeverityLiteral:
    """Coerce a free-form severity string from catalog/YAML to a valid SeverityLiteral.

    Falls back to 'medium' for unknown values so Finding validation passes.
    """
    return _SEVERITY_MAP.get(raw.strip().lower(), "medium")


def _is_inside_dir(child: Path, root: Path) -> bool:
    """Return True iff child is inside root (P0-06 guard for rule-file paths)."""
    try:
        child.relative_to(root)
        return True
    except ValueError:
        pass
    nc_child = os.path.normcase(str(child))
    nc_root = os.path.normcase(str(root))
    return nc_child == nc_root or nc_child.startswith(nc_root + os.sep)


def _load_mapping(catalog_path: Path) -> dict[str, list[dict[str, str]]]:
    """Return {control_id: [detection-method-dicts]} from mapping.yaml."""
    mapping_file = catalog_path / "detection-rules" / "mapping.yaml"
    if not mapping_file.exists():
        return {}
    data = yaml.safe_load(mapping_file.read_text(encoding="utf-8"))
    result: dict[str, list[dict[str, str]]] = {}
    for entry in data.get("mappings", []):
        cid = entry.get("control-id", "")
        result[cid] = entry.get("detection-methods", [])
    return result


@runtime_checkable
class DetectionEngine(Protocol):
    name: str

    def detect(
        self,
        control: Control,
        target_dir: Path,
        source_files: list[Path],
        *,
        timeout_s: float = 30.0,
    ) -> list[Finding]: ...


class SemgrepEngine:
    name: str = "semgrep"

    def __init__(
        self,
        catalog_path: Path,
        rules_dir: Path | None = None,
    ) -> None:
        self._catalog_path = catalog_path
        self._rules_dir = rules_dir or (catalog_path / "detection-rules" / "semgrep")
        self._mapping = _load_mapping(catalog_path)
        # A-M2: per-instance flag prevents module-global state from bleeding between
        # test cases that construct separate SemgrepEngine instances.
        self._semgrep_warned: bool = False

    def detect(
        self,
        control: Control,
        target_dir: Path,
        source_files: list[Path],
        *,
        timeout_s: float = 30.0,
    ) -> list[Finding]:
        methods = [m for m in self._mapping.get(control.id, []) if m.get("method") == "semgrep"]
        if not methods:
            return []

        if shutil.which("semgrep") is None:
            if not self._semgrep_warned:
                _log.warning(
                    "semgrep_not_found",
                    message="semgrep not found on PATH — skipping semgrep detection.",
                )
                self._semgrep_warned = True
            return []

        findings: list[Finding] = []
        rules_dir = self._rules_dir.resolve()
        for method in methods:
            rule_file_rel = method.get("file", "")
            rule_file = (self._catalog_path / rule_file_rel).resolve()
            # P0-06: guard rule-file path to stay inside the semgrep rules dir.
            if not _is_inside_dir(rule_file, rules_dir):
                _log.warning(
                    "semgrep_rule_path_traversal",
                    rule_file=str(rule_file),
                    control_id=control.id,
                )
                findings.append(
                    Finding(
                        control_id=control.id,
                        severity="medium",
                        method="error",
                        file=None,
                        line=None,
                        message="semgrep failed: rule file resolves outside rules directory",
                    )
                )
                continue
            if not rule_file.exists():
                continue
            try:
                proc = subprocess.run(
                    [
                        "semgrep",
                        "--config",
                        str(rule_file),
                        "--json",
                        "--quiet",
                        str(target_dir),
                    ],
                    capture_output=True,
                    timeout=max(1.0, timeout_s),
                )
                rc = proc.returncode
                if rc == 0:
                    # Success — no findings.
                    pass
                elif rc == 1:
                    # Success — findings present; parse JSON.
                    stdout = proc.stdout or b"{}"
                    if not stdout.strip():
                        # A-H7: empty stdout is anomalous — emit sentinel
                        _log.warning(
                            "semgrep_empty_stdout",
                            control_id=control.id,
                        )
                        findings.append(
                            Finding(
                                control_id=control.id,
                                severity="medium",
                                method="error",
                                file=None,
                                line=None,
                                message="semgrep failed: returned no output",
                            )
                        )
                        continue
                    output = json.loads(stdout)
                    for r in output.get("results", []):
                        raw_msg: str = r.get("extra", {}).get("message", "")
                        msg = raw_msg.strip() or "(semgrep returned no message)"
                        findings.append(
                            Finding(
                                control_id=control.id,
                                severity=_normalize_severity(control.severity),
                                method="semgrep",
                                file=r.get("path"),
                                line=r.get("start", {}).get("line"),
                                message=msg,
                                # A-M5: carry control title for SARIF shortDescription
                                control_title=control.title or None,
                            )
                        )
                else:
                    # A-H7: rc >= 2 — semgrep error; emit sentinel so it trips exit code 2.
                    stderr_snippet = proc.stderr.decode(errors="replace")[:500]
                    _log.warning(
                        "semgrep_error",
                        returncode=rc,
                        stderr=stderr_snippet,
                        control_id=control.id,
                    )
                    findings.append(
                        Finding(
                            control_id=control.id,
                            severity="medium",
                            method="error",
                            file=None,
                            line=None,
                            message=f"semgrep failed for control {control.id}: see logs",
                        )
                    )
            except subprocess.TimeoutExpired:
                # A-H7: timeout — emit sentinel
                _log.warning("semgrep_timeout", control_id=control.id)
                findings.append(
                    Finding(
                        control_id=control.id,
                        severity="medium",
                        method="error",
                        file=None,
                        line=None,
                        message=f"semgrep failed: timeout scanning control {control.id}",
                    )
                )
            except json.JSONDecodeError as exc:
                # A-H7: parse error — emit sentinel
                _log.warning("semgrep_json_error", control_id=control.id, error=str(exc))
                findings.append(
                    Finding(
                        control_id=control.id,
                        severity="medium",
                        method="error",
                        file=None,
                        line=None,
                        message=f"semgrep failed: JSON decode error for control {control.id}",
                    )
                )
            except OSError as exc:
                # A-H7: OS error — emit sentinel
                _log.warning("semgrep_os_error", control_id=control.id, error=str(exc))
                findings.append(
                    Finding(
                        control_id=control.id,
                        severity="medium",
                        method="error",
                        file=None,
                        line=None,
                        message=f"semgrep failed: OS error for control {control.id}",
                    )
                )

        return findings


class OtelEngine:
    name: str = "otel"

    def __init__(self, catalog_path: Path) -> None:
        self._catalog_path = catalog_path

    def detect(
        self,
        control: Control,
        target_dir: Path,
        source_files: list[Path],
        *,
        timeout_s: float = 30.0,
    ) -> list[Finding]:
        # v0 stub — runtime probe collection is Phase 5 work.
        return []


class QuestionnaireEngine:
    name: str = "questionnaire"

    def __init__(self, catalog_path: Path) -> None:
        self._catalog_path = catalog_path
        self._mapping = _load_mapping(catalog_path)

    def validate_mapping_refs(self) -> list[str]:
        """Return list of file_ref values in mapping that don't exist on disk.

        A-H6: startup-time validation lists missing file_refs once so operators
        know which questionnaire files need to be authored.
        """
        missing: list[str] = []
        for methods in self._mapping.values():
            for m in methods:
                if m.get("method") != "questionnaire":
                    continue
                file_ref = m.get("file", "")
                if not file_ref:
                    continue
                resolved = self._catalog_path / file_ref
                if not resolved.exists() and file_ref not in missing:
                    missing.append(file_ref)
        return missing

    def detect(
        self,
        control: Control,
        target_dir: Path,
        source_files: list[Path],
        *,
        timeout_s: float = 30.0,
    ) -> list[Finding]:
        methods = [
            m for m in self._mapping.get(control.id, []) if m.get("method") == "questionnaire"
        ]
        findings: list[Finding] = []
        for method in methods:
            file_ref = method.get("file", "")
            fragment = method.get("fragment-id", "")
            # A-H6: only include file_ref in the message when the file exists on disk.
            # Dead refs (questionnaire files not yet authored) fall back to a generic runbook
            # message rather than a broken link.
            ref_path = self._catalog_path / file_ref if file_ref else None
            if ref_path and ref_path.exists():
                message = f"Manual review required: see {file_ref}#{fragment}"
            else:
                message = f"Manual review required: see runbook for control {control.id}"
            findings.append(
                Finding(
                    control_id=control.id,
                    severity=_normalize_severity(control.severity),
                    method="questionnaire",
                    file=None,
                    line=None,
                    message=message,
                    # A-M5: carry control title for SARIF shortDescription
                    control_title=control.title or None,
                )
            )
        return findings
