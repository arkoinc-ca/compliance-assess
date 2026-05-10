# SPDX-License-Identifier: Apache-2.0
"""Assessor: orchestrates profile loading and compliance assessment."""

from __future__ import annotations

import os
import time
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog
import yaml

from .detection import DetectionEngine, QuestionnaireEngine
from .exceptions import AppError, NotFoundError, ValidationError
from .models import AssessmentResult, Control, Finding, Profile, ProfileImport
from .result import Err, Ok, Result

_log = structlog.get_logger("compliance_assess.assessor")



def _prop_value(props: list[dict[str, str]], name: str) -> str:
    for p in props:
        if p.get("name") == name:
            return p.get("value", "")
    return ""


def _collect_controls_from_groups(
    groups: list[dict[str, Any]],
    short_code: str,
    jurisdiction: str,
) -> list[Control]:
    """Recursively collect controls from OSCAL group list."""
    controls: list[Control] = []
    for group in groups:
        for raw in group.get("controls", []):
            props = raw.get("props", [])
            parts = raw.get("parts", [])
            statement = " ".join(
                p.get("prose", "").strip() for p in parts if p.get("name") == "statement"
            )
            guidance = " ".join(
                p.get("prose", "").strip() for p in parts if p.get("name") == "guidance"
            )
            controls.append(
                Control(
                    id=raw["id"],
                    uuid=raw.get("uuid"),
                    title=raw.get("title", ""),
                    statement=statement,
                    guidance=guidance,
                    severity=_prop_value(props, "severity") or "medium",
                    source_section=_prop_value(props, "source-section"),
                    effective_date=_prop_value(props, "effective-date"),
                    jurisdiction=_prop_value(props, "jurisdiction") or jurisdiction,
                    regulation_short_code=short_code,
                )
            )
        # Recurse into sub-groups if any
        if "groups" in group:
            controls.extend(
                _collect_controls_from_groups(group["groups"], short_code, jurisdiction)
            )
    return controls


_ProfileRaw = tuple[str, str, str, datetime, list[dict[str, Any]]]


def _parse_profile_yaml(data: dict[str, Any]) -> _ProfileRaw:
    """Extract (uuid, title, version, last_modified, imports_raw) from profile YAML."""
    profile = data["profile"]
    meta = profile.get("metadata", {})
    last_modified_str = meta.get("last-modified", "1970-01-01T00:00:00Z")
    try:
        last_modified = datetime.fromisoformat(last_modified_str.replace("Z", "+00:00"))
    except ValueError:
        last_modified = datetime(1970, 1, 1, tzinfo=UTC)

    return (
        profile.get("uuid", ""),
        meta.get("title", ""),
        meta.get("version", "0.0.0"),
        last_modified,
        profile.get("imports", []),
    )


class Assessor:
    def __init__(self, catalog_path: Path, *, timeout_s: float = 30.0) -> None:
        if not catalog_path.exists():
            raise ValidationError(
                f"Catalog path does not exist: {catalog_path}",
                [str(catalog_path)],
            )
        self._catalog_path = catalog_path
        self._timeout_s = timeout_s

    def load_profile(self, profile_path: Path) -> Result[Profile, AppError]:
        if not profile_path.exists():
            return Err(NotFoundError("Profile", str(profile_path)))

        try:
            raw = yaml.safe_load(profile_path.read_text(encoding="utf-8"))
        except Exception as exc:
            return Err(AppError(f"Failed to parse profile YAML: {exc}", "PARSE_ERROR"))

        uuid, title, version, last_modified, imports_raw = _parse_profile_yaml(raw)

        profile_imports: list[ProfileImport] = []
        resolved_controls: list[Control] = []

        catalog_root = self._catalog_path.resolve()

        for imp in imports_raw:
            href: str = imp.get("href", "")
            reg_path = (profile_path.parent / href).resolve()

            # Guard: resolved regulation path must stay inside the catalog root.
            # P0-06: use is_relative_to (Python 3.9+) instead of str.startswith to
            # block crafted hrefs like /a/catalog-evil/x.yaml.  On Windows,
            # os.path.normcase both sides to handle case-insensitive drive letters.
            def _is_inside_catalog(child: Path, root: Path) -> bool:
                try:
                    child.relative_to(root)
                    return True
                except ValueError:
                    pass
                # Normcase fallback: covers Windows drive-letter case mismatch
                # where C:\ vs c:\ would fool a pure string startswith.
                # Use the same tokenisation as is_relative_to (parts comparison).
                nc_child = os.path.normcase(str(child))
                nc_root = os.path.normcase(str(root))
                return nc_child == nc_root or nc_child.startswith(nc_root + os.sep)

            if not _is_inside_catalog(reg_path, catalog_root):
                return Err(
                    ValidationError(
                        f"Regulation href '{href}' resolves outside the catalog root",
                        [href],
                    )
                )

            if not reg_path.exists():
                return Err(NotFoundError("Regulation", href))

            try:
                reg_data = yaml.safe_load(reg_path.read_text(encoding="utf-8"))
            except Exception as exc:
                msg = f"Failed to parse regulation YAML {href}: {exc}"
                return Err(AppError(msg, "PARSE_ERROR"))

            catalog = reg_data.get("catalog", {})
            meta = catalog.get("metadata", {})
            props = meta.get("props", [])
            short_code = _prop_value(props, "regulation-short-code")
            jurisdiction = _prop_value(props, "jurisdiction")

            all_controls = _collect_controls_from_groups(
                catalog.get("groups", []), short_code, jurisdiction
            )
            control_index = {c.id: c for c in all_controls}

            include_blocks: list[dict[str, Any]] = imp.get("include-controls", [])
            with_ids: list[str] = []
            for block in include_blocks:
                with_ids.extend(block.get("with-ids", []))

            for cid in with_ids:
                if cid not in control_index:
                    return Err(
                        ValidationError(
                            f"Control '{cid}' listed in profile but not found in {href}",
                            [cid],
                        )
                    )
                resolved_controls.append(control_index[cid])

            profile_imports.append(ProfileImport(href=href, control_ids=with_ids))

        return Ok(
            Profile(
                uuid=uuid,
                title=title,
                version=version,
                last_modified=last_modified,
                imports=profile_imports,
                resolved_controls=resolved_controls,
            )
        )

    def assess(
        self,
        profile: Profile,
        target_dir: Path,
        engines: Sequence[DetectionEngine],
    ) -> Result[AssessmentResult, AppError]:
        if not target_dir.exists():
            return Err(NotFoundError("Target directory", str(target_dir)))

        # source_files is intentionally empty: current engines (SemgrepEngine,
        # OtelEngine, QuestionnaireEngine) operate on target_dir directly.
        # Engines that need file-level traversal must do their own scoped walk
        # so we avoid loading all files (including .git / node_modules) into
        # memory eagerly.
        source_files: list[Path] = []

        # A-H6: log missing questionnaire file_refs once at assess time
        for engine in engines:
            if isinstance(engine, QuestionnaireEngine):
                missing_refs = engine.validate_mapping_refs()
                if missing_refs:
                    _log.warning(
                        "questionnaire_missing_refs",
                        count=len(missing_refs),
                        refs=missing_refs,
                    )

        all_findings: list[Finding] = []
        deadline = time.monotonic() + self._timeout_s

        # A-M10: separate questionnaire engines from automated engines so we can
        # gate questionnaire output: only emit when no automated engine produced a
        # finding for that control (questionnaire is a fallback, not a duplicate).
        automated_engines = [e for e in engines if not isinstance(e, QuestionnaireEngine)]
        questionnaire_engines = [e for e in engines if isinstance(e, QuestionnaireEngine)]

        for control in profile.resolved_controls:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break

            # Run automated engines first.
            control_findings: list[Finding] = []
            for engine in automated_engines:
                findings = engine.detect(
                    control, target_dir, source_files, timeout_s=max(1.0, remaining)
                )
                control_findings.extend(findings)

            # A-M10: only invoke questionnaire fallback when no automated engine
            # produced a real finding (method != "error") for this control.
            has_automated_finding = any(f.method != "error" for f in control_findings)
            if not has_automated_finding:
                for engine in questionnaire_engines:
                    remaining = deadline - time.monotonic()
                    findings = engine.detect(
                        control, target_dir, source_files, timeout_s=max(1.0, remaining)
                    )
                    control_findings.extend(findings)

            all_findings.extend(control_findings)

        controls_with_findings = len({f.control_id for f in all_findings})
        # A-H2: scan is degraded when any sentinel error finding is present
        scan_degraded = any(f.method == "error" for f in all_findings)

        return Ok(
            AssessmentResult(
                profile_id=profile.uuid,
                profile_title=profile.title,
                target=str(target_dir),
                timestamp=datetime.now(tz=UTC),
                findings=all_findings,
                controls_assessed=len(profile.resolved_controls),
                controls_with_findings=controls_with_findings,
                scan_degraded=scan_degraded,
            )
        )
