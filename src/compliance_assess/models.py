# SPDX-License-Identifier: Apache-2.0
"""Pydantic v2 domain models for compliance assessment."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class ProfileImport(BaseModel):
    href: str
    control_ids: list[str]


class Control(BaseModel):
    id: str
    uuid: str | None = None
    title: str
    statement: str
    guidance: str = ""
    severity: str = "medium"
    source_section: str = ""
    effective_date: str = ""
    jurisdiction: str = ""
    regulation_short_code: str = ""


class Profile(BaseModel):
    uuid: str
    title: str
    version: str
    last_modified: datetime
    imports: list[ProfileImport] = Field(default_factory=list)
    resolved_controls: list[Control] = Field(default_factory=list)


# A-H4: Severity Literal — validates severity values at the boundary.
SeverityLiteral = Literal["info", "low", "medium", "high", "critical"]


class Finding(BaseModel):
    control_id: str
    severity: SeverityLiteral  # A-H4: validated Literal type
    method: str  # "semgrep" | "otel" | "questionnaire" | "manual" | "error"
    file: str | None = None
    line: int | None = None
    message: str = Field(min_length=1)  # A-H7: non-empty message required
    # A-M5: control title for SARIF shortDescription; populated by engines when available.
    control_title: str | None = None


class AssessmentResult(BaseModel):
    profile_id: str
    profile_title: str
    target: str
    timestamp: datetime
    findings: list[Finding] = Field(default_factory=list)
    controls_assessed: int = 0
    controls_with_findings: int = 0
    # A-H2: True when any engine emitted a sentinel finding (method="error"),
    # indicating the scan partially failed. CLI exits 2 when scan_degraded=True.
    scan_degraded: bool = False
