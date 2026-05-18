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

from .models import Control, Finding, SeverityLiteral, SkippedFile

_log = structlog.get_logger("compliance_assess.detection")

_SEVERITY_MAP: dict[str, SeverityLiteral] = {
    "info": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}

# Error-type keywords in semgrep's errors[] that indicate one of *our* rules
# failed to parse, as opposed to a target source file semgrep could not parse.
# Each keyword matches exactly one semgrep rule-error `type` ("Rule parse error",
# "Pattern parse error", "Invalid rule schema") and none of the target-error
# types ("Syntax error", "Lexical error", "Timeout", "Out of memory", …).
_RULE_ERROR_KEYWORDS: frozenset[str] = frozenset({"rule", "pattern", "schema"})


def _is_semgrep_rule_error(err: dict[str, object]) -> bool:
    """Return True when a semgrep error entry represents a broken detection rule.

    Semgrep JSON errors[] entries whose `type` contains any of rule/pattern/
    schema, or whose `message` mentions "invalid yaml", indicate that one of our
    rules could not be loaded.  All other entries (Syntax error, Lexical error,
    Timeout, …) are target-file parse failures — non-fatal for the scan.
    """
    err_type = str(err.get("type", "")).lower()
    err_msg = str(err.get("message", "")).lower()
    return any(k in err_type for k in _RULE_ERROR_KEYWORDS) or "invalid yaml" in err_msg


def _semgrep_error_type(err: dict[str, object]) -> str:
    """Return the error type from a semgrep errors[] entry ("Syntax error", …)."""
    raw = err.get("type", "")
    return raw.strip() if isinstance(raw, str) else ""


def _semgrep_error_path(err: dict[str, object]) -> str:
    """Extract the target file path from a semgrep errors[] entry.

    The path is normally a top-level `path`; older payloads carry it only in
    the first `spans` entry. Return "" when neither is present.
    """
    path = err.get("path")
    if isinstance(path, str) and path:
        return path
    spans = err.get("spans")
    if isinstance(spans, list) and spans and isinstance(spans[0], dict):
        span_file = spans[0].get("file")
        if isinstance(span_file, str) and span_file:
            return span_file
    return ""


def _skipped_files_from_errors(
    target_errors: list[dict[str, object]],
) -> list[SkippedFile]:
    """Convert semgrep target-file parse errors into SkippedFile records.

    One record per distinct file path; the error `type` becomes the reason.
    Errors with no resolvable path are dropped — a path-less coverage note is
    not actionable for an operator.
    """
    seen: set[str] = set()
    result: list[SkippedFile] = []
    for err in target_errors:
        path = _semgrep_error_path(err)
        if not path or path in seen:
            continue
        seen.add(path)
        result.append(SkippedFile(path=path, reason=_semgrep_error_type(err) or "parse error"))
    return result


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
        # Coverage gaps accumulated across every detect() call on this instance:
        # target files semgrep could not parse. Deduplicated by path. Read by
        # the Assessor after the scan and surfaced in the report/summary.
        self.skipped_files: list[SkippedFile] = []

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
                semgrep_bin = shutil.which("semgrep") or "semgrep"
                proc = subprocess.run(
                    [
                        semgrep_bin,
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
                raw_stdout: bytes = proc.stdout or b""

                # --- JSON is authoritative; exit code is only a diagnostic. ---
                # semgrep always writes a complete JSON document to stdout with
                # --json regardless of exit code.  Reading findings only when
                # rc==1 (old contract) silently discards results on rc==0 and
                # rc>=2.  Read the JSON unconditionally and fall back to the
                # empty-stdout / error-only paths below.
                if not raw_stdout.strip():
                    # stdout completely absent or whitespace-only.
                    if rc != 0:
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
                    else:
                        # A-H7: rc==0 + empty stdout is anomalous — emit sentinel.
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

                output = json.loads(raw_stdout)  # JSONDecodeError caught below

                # Guard: semgrep --json always returns an object with a results
                # key.  Anything else (a bare list, a schema mismatch, a results
                # key dropped) must not be read as "no findings" — that would be
                # a silent miss.  Emit a sentinel so the scan is flagged degraded.
                if not isinstance(output, dict) or "results" not in output:
                    _log.warning(
                        "semgrep_unexpected_output",
                        control_id=control.id,
                        returncode=rc,
                    )
                    findings.append(
                        Finding(
                            control_id=control.id,
                            severity="medium",
                            method="error",
                            file=None,
                            line=None,
                            message=(
                                f"semgrep failed: unexpected JSON output for control "
                                f"{control.id} (no results key) — see logs"
                            ),
                        )
                    )
                    continue

                # --- Emit a Finding for every result entry ---
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

                # --- Inspect errors[] — partition into rule-errors vs target-errors ---
                semgrep_errors: list[dict[str, object]] = output.get("errors", [])
                rule_errors = [e for e in semgrep_errors if _is_semgrep_rule_error(e)]
                target_errors = [e for e in semgrep_errors if not _is_semgrep_rule_error(e)]

                if target_errors:
                    skipped = _skipped_files_from_errors(target_errors)
                    for sf in skipped:
                        if all(known.path != sf.path for known in self.skipped_files):
                            self.skipped_files.append(sf)
                    _log.warning(
                        "semgrep_partial_scan",
                        control_id=control.id,
                        error_count=len(target_errors),
                        skipped_files=[sf.path for sf in skipped],
                        error_types=sorted({sf.reason for sf in skipped}),
                    )

                if rule_errors:
                    first = rule_errors[0]
                    detail = (
                        f"{first.get('rule_id', '?')}: "
                        f"{(str(first.get('message', '')).splitlines() or [''])[0]}"
                    )
                    _log.error(
                        "semgrep_rule_error",
                        control_id=control.id,
                        error_count=len(rule_errors),
                        detail=detail,
                    )
                    findings.append(
                        Finding(
                            control_id=control.id,
                            severity="medium",
                            method="error",
                            file=None,
                            line=None,
                            message=(
                                f"semgrep failed: a detection rule for control "
                                f"{control.id} could not be parsed — see logs"
                            ),
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
