# SPDX-License-Identifier: Apache-2.0
"""Typer-based CLI entry point for compliance-assess."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Annotated

import structlog
import typer
import yaml

from .assessor import Assessor
from .detection import DetectionEngine, OtelEngine, QuestionnaireEngine, SemgrepEngine
from .emitters import CSVEmitter, Emitter, HTMLEmitter, MarkdownEmitter, SARIFEmitter
from .result import Err

# ---------------------------------------------------------------------------
# Structlog configuration
# ---------------------------------------------------------------------------
# When COMPLIANCE_ASSESS_LOG=json the processor chain emits JSON to stderr
# for machine-readable audit ingestion.  Otherwise, keep structlog's default
# human-readable ConsoleRenderer.  Raw scanned-code content must NEVER be
# passed to any log call — PII may appear in scanned source.
# ---------------------------------------------------------------------------

if os.environ.get("COMPLIANCE_ASSESS_LOG") == "json":
    structlog.configure(
        processors=[
            structlog.stdlib.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ],
        logger_factory=structlog.PrintLoggerFactory(file=__import__("sys").stderr),
        wrapper_class=structlog.BoundLogger,
        cache_logger_on_first_use=True,
    )

_log = structlog.get_logger("compliance_assess.cli")

# ---------------------------------------------------------------------------
# Format token → emitter map
# ---------------------------------------------------------------------------

_EMITTER_MAP: dict[str, type[Emitter]] = {
    "sarif": SARIFEmitter,
    "markdown": MarkdownEmitter,
    "html": HTMLEmitter,
    "csv": CSVEmitter,
}


def _version_callback(value: bool) -> None:
    if value:
        from . import __version__

        typer.echo(f"compliance-assess {__version__}")
        raise typer.Exit()


app = typer.Typer(no_args_is_help=True)
profile_app = typer.Typer(no_args_is_help=True)
app.add_typer(profile_app, name="profile")

@app.callback()
def _app_callback(
    version: Annotated[
        bool | None,
        typer.Option(
            "--version",
            callback=_version_callback,
            is_eager=True,
            help="Show version and exit.",
        ),
    ] = None,
) -> None:
    """Compliance gap-finder for CA/US/EU privacy and AI-governance regulations."""


def _resolve_catalog(catalog_raw: str | None) -> Path:
    """A-M1: Resolve the catalog path with a clear precedence chain.

    Priority:
      1. Explicit ``--catalog`` argument (any path the user supplies).
      2. ``COMPLIANCE_CATALOG_PATH`` environment variable.
      3. ``<cwd>/compliance-catalog`` directory (safe default, CWD-relative).

    Raises typer.BadParameter when none of the above resolves to an existing path.
    """
    if catalog_raw is not None:
        return Path(catalog_raw)

    env_val = os.environ.get("COMPLIANCE_CATALOG_PATH")
    if env_val:
        return Path(env_val)

    cwd_default = Path.cwd() / "compliance-catalog"
    if cwd_default.exists():
        return cwd_default

    raise typer.BadParameter(
        "Cannot locate the compliance-catalog directory. "
        "Set the COMPLIANCE_CATALOG_PATH environment variable or pass --catalog <path>.",
        param_hint="--catalog / COMPLIANCE_CATALOG_PATH",
    )


@app.command()
def scan(
    target: str = typer.Argument(..., help="Path to codebase or service to scan"),  # noqa: B008
    profile: str = typer.Option(..., "--profile", "-p", help="Path to profile YAML"),  # noqa: B008
    catalog: str | None = typer.Option(None, "--catalog", help="Path to catalog root"),  # noqa: B008
    out: str | None = typer.Option(None, "--out", help="Output directory for results"),  # noqa: B008
    fmt: str = typer.Option(
        "sarif,markdown", "--format", help="Output format(s): sarif,markdown,html,csv"
    ),  # noqa: B008 E501
    timeout: float = typer.Option(30.0, "--timeout", help="Per-scan timeout in seconds"),  # noqa: B008
) -> None:
    """Scan a codebase for compliance gaps."""
    catalog_path = _resolve_catalog(catalog)
    profile_path = Path(profile)
    target_dir = Path(target)

    # Validate and resolve format tokens before doing any work.
    out_dir = Path(out) if out else Path.cwd()
    out_dir.mkdir(parents=True, exist_ok=True)

    format_tokens = [t.strip().lower() for t in fmt.split(",") if t.strip()]
    for token in format_tokens:
        if token not in _EMITTER_MAP:
            raise typer.BadParameter(
                f"Unknown format '{token}'. Valid values: {', '.join(_EMITTER_MAP)}",
                param_hint="--format",
            )

    assessor = Assessor(catalog_path, timeout_s=timeout)
    profile_result = assessor.load_profile(profile_path)
    if isinstance(profile_result, Err):
        typer.echo(f"ERROR: {profile_result.error}", err=True)
        raise typer.Exit(1)

    loaded_profile = profile_result.value
    engines: list[DetectionEngine] = [
        SemgrepEngine(catalog_path),
        OtelEngine(catalog_path),
        QuestionnaireEngine(catalog_path),
    ]
    assessment = assessor.assess(loaded_profile, target_dir, engines)
    if isinstance(assessment, Err):
        typer.echo(f"ERROR: {assessment.error}", err=True)
        raise typer.Exit(1)

    ar = assessment.value
    severity_counts: dict[str, int] = {}
    for f in ar.findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    # Structured audit log — machine-readable summary (never logs raw code content).
    _log.info(
        "scan_summary",
        profile=ar.profile_title,
        target=ar.target,
        controls_assessed=ar.controls_assessed,
        controls_with_findings=ar.controls_with_findings,
        total_findings=len(ar.findings),
        severity_counts=severity_counts,
    )
    if severity_counts.get("high"):
        _log.warning("high_severity_findings", severity="high", count=severity_counts["high"])

    # Human-readable operator output (kept alongside structlog).
    typer.echo(f"Profile:            {ar.profile_title}")
    typer.echo(f"Target:             {ar.target}")
    typer.echo(f"Controls assessed:  {ar.controls_assessed}")
    typer.echo(f"Controls with findings: {ar.controls_with_findings}")
    typer.echo(f"Total findings:     {len(ar.findings)}")
    for sev in ("high", "medium", "low", "info"):
        count = severity_counts.get(sev, 0)
        if count:
            typer.echo(f"  {sev}: {count}")

    # Invoke emitters — one output file per requested format.
    for token in format_tokens:
        emitter_cls = _EMITTER_MAP[token]
        emitter = emitter_cls()
        output_path = out_dir / f"compliance-assessment.{emitter.extension}"
        emitter.emit(ar, output_path)
        typer.echo(f"Wrote: {output_path}")

    # Write machine-readable summary JSON for CI consumers (e.g. action.yml).
    summary = {
        "total": len(ar.findings),
        "high": severity_counts.get("high", 0),
        "medium": severity_counts.get("medium", 0),
        "low": severity_counts.get("low", 0),
        "controls_assessed": ar.controls_assessed,
    }
    summary_path = out_dir / "compliance-summary.json"
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    # A-H4: treat critical ≥ high for gating purposes
    # A-H2: exit 2 for scan-degradation (partial failure), 1 for ≥1 high/critical, 0 for clean
    has_high = bool(
        severity_counts.get("high", 0) + severity_counts.get("critical", 0) > 0
    )
    if ar.scan_degraded:
        raise typer.Exit(2)
    raise typer.Exit(1 if has_high else 0)


@profile_app.command("list")
def profile_list(
    catalog: str | None = typer.Option(None, "--catalog", help="Path to catalog root"),  # noqa: B008
) -> None:
    """List available compliance profiles."""
    catalog_path = _resolve_catalog(catalog)
    profiles_root = catalog_path / "profiles"

    if not profiles_root.exists():
        typer.echo(f"ERROR: Profiles directory not found: {profiles_root}", err=True)
        raise typer.Exit(1)

    pattern_dirs = ["region", "use-case"]
    rows: list[tuple[str, str, int]] = []

    for subdir in pattern_dirs:
        subdir_path = profiles_root / subdir
        if not subdir_path.exists():
            continue
        for yaml_file in sorted(subdir_path.glob("*.yaml")):
            try:
                data = yaml.safe_load(yaml_file.read_text(encoding="utf-8"))
            except Exception as e:
                _log.warning("profile_load_failed", path=str(yaml_file), error=str(e))
                typer.echo(f"WARN: failed to load {yaml_file}: {e}", err=True)
                continue

            profile_data = data.get("profile", {})
            meta = profile_data.get("metadata", {})
            title = meta.get("title", "(untitled)")

            count = 0
            for imp in profile_data.get("imports", []):
                for block in imp.get("include-controls", []):
                    count += len(block.get("with-ids", []))

            rel = str(Path(subdir) / yaml_file.name)
            rows.append((rel, title, count))

    for rel, title, count in rows:
        typer.echo(f"{rel}  {title}  ({count} controls)")


@profile_app.command("compose")
def profile_compose(
    profile: str = typer.Option(..., "--profile", "-p", help="Path to profile YAML"),  # noqa: B008
    catalog: str | None = typer.Option(None, "--catalog", help="Path to catalog root"),  # noqa: B008
    out: str | None = typer.Option(None, "--out", help="Output file (default: stdout)"),  # noqa: B008
) -> None:
    """Resolve and dump the flat control list from a profile."""
    catalog_path = _resolve_catalog(catalog)
    profile_path = Path(profile)

    assessor = Assessor(catalog_path)
    result = assessor.load_profile(profile_path)
    if isinstance(result, Err):
        typer.echo(f"ERROR: {result.error}", err=True)
        raise typer.Exit(1)

    loaded = result.value

    # A-M6: build and Pydantic-validate the control list before serialising.
    from pydantic import BaseModel
    from pydantic import Field as PField

    class _ControlRow(BaseModel):
        id: str
        title: str
        severity: str
        source_section: str
        regulation: str

    class _ComposeOutput(BaseModel):
        controls: list[_ControlRow] = PField(default_factory=list)

    compose_out = _ComposeOutput(
        controls=[
            _ControlRow(
                id=c.id,
                title=c.title,
                severity=c.severity,
                source_section=c.source_section,
                regulation=c.regulation_short_code,
            )
            for c in loaded.resolved_controls
        ]
    )

    # A-M6: emit canonical (block-style) YAML deterministically with sort_keys=True.
    output = yaml.dump(
        compose_out.model_dump(),
        allow_unicode=True,
        sort_keys=True,
        default_flow_style=False,
    )

    if out:
        Path(out).write_text(output, encoding="utf-8")
    else:
        typer.echo(output, nl=False)


def main() -> None:
    app()
