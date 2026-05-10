# SPDX-License-Identifier: Apache-2.0
"""Emitter protocol and output-format implementations.

Each emitter writes an AssessmentResult to a file at *output_path*.
If output_path is a directory the emitter appends its default filename.
"""

from __future__ import annotations

import csv
import hashlib
import html
import json
from pathlib import Path, PurePath
from typing import Protocol, cast, runtime_checkable

from .models import AssessmentResult, Finding

# A-M4: ordinal rank for severity levels; higher rank = more severe.
_SEVERITY_ORDER: dict[str, int] = {
    "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4
}


@runtime_checkable
class Emitter(Protocol):
    extension: str  # "sarif" | "md" | "html" | "csv"

    def emit(self, result: AssessmentResult, output_path: Path) -> None: ...


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _resolve_output_path(output_path: Path, extension: str) -> Path:
    """Return a file path, appending a default filename when output_path is a dir."""
    if output_path.is_dir():
        output_path = output_path / f"compliance-assessment.{extension}"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    return output_path


def _sarif_level(finding: Finding) -> str:
    """Map finding severity/method to a SARIF level string.

    Questionnaire findings are manual checklist items, not static detections.
    SARIF 'note' is the appropriate level for informational/advisory entries
    regardless of their declared severity — they cannot be pinned to a source
    location and should not block CI the same way automated findings would.
    A-H4: critical maps to 'error' same as high.
    """
    if finding.method == "questionnaire":
        return "note"
    # A-H4: critical -> error
    mapping = {"high": "error", "critical": "error", "medium": "warning", "low": "note"}
    return mapping.get(finding.severity.lower(), "warning")


# Classic formula-injection trigger chars (OWASP CSV injection)
_CSV_CLASSIC_TRIGGERS: frozenset[str] = frozenset(("=", "+", "-", "@", "\t", "\r"))
# Unicode chars that can disguise formula-injection payloads when prepended
_CSV_UNICODE_TRICKS: frozenset[str] = frozenset((
    "​",  # zero-width space
    "‌",  # zero-width non-joiner
    "‍",  # zero-width joiner
    "‮",  # right-to-left override
    "‭",  # left-to-right override
    "﻿",  # BOM (byte-order mark)
))


def _csv_safe(value: str) -> str:
    """A-H1: Prefix CSV injection-triggering characters with a single quote.

    Covers classic formula-injection chars (=+-@\\t\\r) and Unicode tricks:
    zero-width-space, zero-width-non-joiner, zero-width-joiner,
    right-to-left override, left-to-right override, and BOM.
    """
    if value and (value[0] in _CSV_CLASSIC_TRIGGERS or value[0] in _CSV_UNICODE_TRICKS):
        return "'" + value
    return value


def _group_by_severity(findings: list[Finding]) -> dict[str, list[Finding]]:
    groups: dict[str, list[Finding]] = {"high": [], "medium": [], "low": []}
    for f in findings:
        key = f.severity.lower()
        groups.setdefault(key, []).append(f)
    return groups


def _finding_location_label(f: Finding) -> str:
    """Return 'path/file.py:42' or '(questionnaire)' for display."""
    if f.file:
        return f"`{f.file}:{f.line}`" if f.line else f"`{f.file}`"
    return "_(questionnaire)_"


# ---------------------------------------------------------------------------
# SARIFEmitter  (P2-T04)
# ---------------------------------------------------------------------------


def _posix_uri(file_path: str) -> str:
    """A-H3: Convert any path to POSIX form for SARIF artifact URIs."""
    return PurePath(file_path).as_posix()


def _partial_fingerprint(
    rule_id: str, file_path: str | None, line: int | None, message: str
) -> str:
    """A-H3: Stable 16-char hex fingerprint for SARIF partialFingerprints."""
    key = f"{rule_id}:{file_path or ''}:{line or 0}:{message}"
    return hashlib.sha1(key.encode()).hexdigest()[:16]


class SARIFEmitter:
    extension: str = "sarif"

    def emit(self, result: AssessmentResult, output_path: Path) -> None:
        # Import here to avoid circular import; __init__ imports Assessor which
        # may not yet be fully initialised at module load time.
        from . import __version__

        output_path = _resolve_output_path(output_path, self.extension)

        # A-H3: sort findings deterministically before emitting
        sorted_findings = sorted(
            result.findings,
            key=lambda f: (f.control_id, f.file or "", f.line or 0, f.message),
        )

        # Build deduplicated rules sorted by id (A-H3: sort rules array).
        # A-M4: for mixed-severity controls, escalate to the highest severity seen.
        # First pass: collect highest-severity finding per control_id.
        control_max_severity: dict[str, Finding] = {}
        for f in sorted_findings:
            existing = control_max_severity.get(f.control_id)
            if existing is None or (
                _SEVERITY_ORDER.get(f.severity.lower(), 0)
                > _SEVERITY_ORDER.get(existing.severity.lower(), 0)
            ):
                control_max_severity[f.control_id] = f

        rules_unsorted: list[dict[str, object]] = []
        for ctrl_id, rep_finding in control_max_severity.items():
            # A-M5: use control_title for shortDescription when available;
            # fall back to control_id to avoid a useless stub.
            short_desc = rep_finding.control_title or ctrl_id
            rules_unsorted.append(
                {
                    "id": ctrl_id,
                    "name": ctrl_id,
                    "shortDescription": {"text": short_desc},
                    "fullDescription": {"text": short_desc},
                    "defaultConfiguration": {"level": _sarif_level(rep_finding)},
                    "properties": {
                        "severity": rep_finding.severity,
                        "method": rep_finding.method,
                    },
                }
            )
        # A-H3: sort rules by id for byte-equal output
        rules: list[dict[str, object]] = sorted(rules_unsorted, key=lambda r: str(r["id"]))

        sarif_results: list[dict[str, object]] = []
        for f in sorted_findings:
            posix_path = _posix_uri(f.file) if f.file else None
            entry: dict[str, object] = {
                "ruleId": f.control_id,
                "level": _sarif_level(f),
                "message": {"text": f.message},
                # A-H3: partialFingerprints for SARIF deduplication
                "partialFingerprints": {
                    "primaryLocationLineHash": _partial_fingerprint(
                        f.control_id, posix_path, f.line, f.message
                    )
                },
            }
            # Questionnaire findings have no source location; omit locations
            # entirely — SARIF 2.1.0 §3.27.12 makes locations optional.
            if posix_path:
                location: dict[str, object] = {
                    "physicalLocation": {
                        # A-H3: uriBaseId %SRCROOT% + POSIX relative path
                        "artifactLocation": {
                            "uri": posix_path,
                            "uriBaseId": "%SRCROOT%",
                        },
                    }
                }
                if f.line is not None:
                    region: dict[str, object] = {
                        "startLine": f.line,
                        "endLine": f.line,
                    }
                    phys = cast(dict[str, object], location["physicalLocation"])
                    phys["region"] = region
                entry["locations"] = [location]
            sarif_results.append(entry)

        payload: dict[str, object] = {
            "$schema": (
                "https://raw.githubusercontent.com/oasis-tcs/sarif-spec"
                "/master/Schemata/sarif-schema-2.1.0.json"
            ),
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "compliance-assess",
                            "version": __version__,
                            "informationUri": ("https://github.com/arkoinc-ca/compliance-assess"),
                            "rules": rules,
                        }
                    },
                    # A-H3: originalUriBaseIds declares %SRCROOT%
                    "originalUriBaseIds": {"%SRCROOT%": {"uri": "file:///"}},
                    "results": sarif_results,
                }
            ],
        }

        # A-H3: sort_keys=True for byte-equal output on identical input
        output_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


# ---------------------------------------------------------------------------
# MarkdownEmitter  (P2-T05)
# ---------------------------------------------------------------------------


class MarkdownEmitter:
    extension: str = "md"

    def emit(self, result: AssessmentResult, output_path: Path) -> None:
        from . import __version__

        output_path = _resolve_output_path(output_path, self.extension)

        groups = _group_by_severity(result.findings)
        n_high = len(groups.get("high", []))
        n_medium = len(groups.get("medium", []))
        n_low = len(groups.get("low", []))
        ts = result.timestamp.isoformat()

        lines: list[str] = [
            "# Compliance Assessment Report",
            "",
            f"**Profile:** {result.profile_title} (`{result.profile_id}`)",
            f"**Target:** `{result.target}`",
            f"**Generated:** {ts}",
            f"**Tool version:** compliance-assess {__version__}",
            "",
            "## Summary",
            "",
            "| Metric | Count |",
            "|---|---|",
            f"| Controls assessed | {result.controls_assessed} |",
            f"| Controls with findings | {result.controls_with_findings} |",
            f"| Findings — high | {n_high} |",
            f"| Findings — medium | {n_medium} |",
            f"| Findings — low | {n_low} |",
            f"| Findings — total | {len(result.findings)} |",
            "",
            "## Findings",
            "",
        ]

        for severity in ("high", "medium", "low"):
            heading = severity.capitalize()
            lines.append(f"### {heading} severity")
            lines.append("")
            sev_findings = groups.get(severity, [])
            if not sev_findings:
                lines.append("_None._")
                lines.append("")
                continue
            # Group by control_id within severity
            by_control: dict[str, list[Finding]] = {}
            for f in sev_findings:
                by_control.setdefault(f.control_id, []).append(f)
            for ctrl_id, ctrl_findings in by_control.items():
                lines.append(f"**{ctrl_id}**")
                lines.append("")
                for f in ctrl_findings:
                    loc = _finding_location_label(f)
                    lines.append(f"- {loc} — {f.message}")
                lines.append("")

        lines.extend(
            [
                "---",
                f"_Generated by [compliance-assess](https://github.com/arkoinc-ca/compliance-assess)"
                f" on {ts}._",
            ]
        )

        output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# HTMLEmitter  (P2-T05)
# ---------------------------------------------------------------------------

_CSS = """\
body { font-family: -apple-system, system-ui, sans-serif; max-width: 960px;
       margin: 2em auto; padding: 0 1em; color: #1a1a1a; }
h1, h2, h3 { color: #2a2a2a; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #ccc; padding: 6px 10px; text-align: left; }
.sev-high { color: #b00020; font-weight: 600; }
.sev-medium { color: #b06a00; }
.sev-low { color: #666; }
.finding { background: #fafafa; padding: 6px 10px; border-left: 3px solid #ccc; margin: 4px 0; }
.finding.sev-high { border-color: #b00020; }
.finding.sev-medium { border-color: #b06a00; }
code { background: #f0f0f0; padding: 1px 4px; border-radius: 3px; font-size: 0.9em; }
"""


def _html_finding_location(f: Finding) -> str:
    if f.file:
        loc = f"{f.file}:{f.line}" if f.line else f.file
        return f"<code>{html.escape(loc)}</code>"
    return "<em>(questionnaire)</em>"


def _html_severity_section(severity: str, findings: list[Finding]) -> str:
    heading = severity.capitalize()
    cls = f"sev-{severity}"
    parts = [f'<section>\n<h3 class="{cls}">{heading} severity</h3>']
    if not findings:
        parts.append("<p><em>None.</em></p>")
        parts.append("</section>")
        return "\n".join(parts)

    by_control: dict[str, list[Finding]] = {}
    for f in findings:
        by_control.setdefault(f.control_id, []).append(f)

    for ctrl_id, ctrl_findings in by_control.items():
        parts.append(f"<h4><code>{html.escape(ctrl_id)}</code></h4>")
        parts.append("<ul>")
        for f in ctrl_findings:
            loc_html = _html_finding_location(f)
            msg_html = html.escape(f.message)
            parts.append(f'  <li class="finding {cls}">{loc_html} — {msg_html}</li>')
        parts.append("</ul>")

    parts.append("</section>")
    return "\n".join(parts)


class HTMLEmitter:
    extension: str = "html"

    def emit(self, result: AssessmentResult, output_path: Path) -> None:
        from . import __version__

        output_path = _resolve_output_path(output_path, self.extension)

        groups = _group_by_severity(result.findings)
        n_high = len(groups.get("high", []))
        n_medium = len(groups.get("medium", []))
        n_low = len(groups.get("low", []))
        ts = html.escape(result.timestamp.isoformat())
        profile_title = html.escape(result.profile_title)
        profile_id = html.escape(result.profile_id)
        target = html.escape(result.target)
        version = html.escape(__version__)

        summary_rows = (
            f"<tr><td>Controls assessed</td><td>{result.controls_assessed}</td></tr>\n"
            f"<tr><td>Controls with findings</td><td>{result.controls_with_findings}</td></tr>\n"
            f'<tr><td class="sev-high">Findings — high</td><td>{n_high}</td></tr>\n'
            f'<tr><td class="sev-medium">Findings — medium</td><td>{n_medium}</td></tr>\n'
            f'<tr><td class="sev-low">Findings — low</td><td>{n_low}</td></tr>\n'
            f"<tr><td>Findings — total</td><td>{len(result.findings)}</td></tr>"
        )

        severity_sections = "\n".join(
            _html_severity_section(sev, groups.get(sev, [])) for sev in ("high", "medium", "low")
        )

        doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Compliance Assessment Report</title>
<style>
{_CSS}
</style>
</head>
<body>
<header>
  <h1>Compliance Assessment Report</h1>
  <p><strong>Profile:</strong> {profile_title} (<code>{profile_id}</code>)</p>
  <p><strong>Target:</strong> <code>{target}</code></p>
  <p><strong>Generated:</strong> {ts}</p>
  <p><strong>Tool version:</strong> compliance-assess {version}</p>
</header>

<h2>Summary</h2>
<table>
<thead><tr><th>Metric</th><th>Count</th></tr></thead>
<tbody>
{summary_rows}
</tbody>
</table>

<h2>Findings</h2>
{severity_sections}

<footer>
  <hr>
  <p><em>Generated by
    <a href="https://github.com/arkoinc-ca/compliance-assess">compliance-assess</a>
    on {ts}.</em></p>
</footer>
</body>
</html>
"""
        output_path.write_text(doc, encoding="utf-8")


# ---------------------------------------------------------------------------
# CSVEmitter  (P2-T05)
# ---------------------------------------------------------------------------


class CSVEmitter:
    extension: str = "csv"

    def emit(self, result: AssessmentResult, output_path: Path) -> None:
        output_path = _resolve_output_path(output_path, self.extension)

        # Open with newline="" per csv module docs to prevent double line-ending
        # translation.  utf-8-sig adds the BOM expected by Windows Excel.
        with open(output_path, "w", newline="", encoding="utf-8-sig") as fh:
            writer = csv.writer(fh, quoting=csv.QUOTE_MINIMAL)
            writer.writerow(["control_id", "severity", "method", "file", "line", "message"])
            for f in result.findings:
                # A-H1: escape CSV injection chars in all string columns
                writer.writerow(
                    [
                        _csv_safe(f.control_id),
                        _csv_safe(f.severity),
                        _csv_safe(f.method),
                        _csv_safe(f.file or ""),
                        f.line if f.line is not None else "",
                        _csv_safe(f.message),
                    ]
                )
