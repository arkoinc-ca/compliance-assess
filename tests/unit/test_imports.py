"""Smoke test: package installs correctly and exports the expected public surface."""

from importlib.metadata import version as _pkg_version

import compliance_assess
from compliance_assess import AppError, AssessmentResult, Assessor, DetectionEngine


def test_package_imports_and_version_matches_pyproject() -> None:
    """V-C fix: assert __version__ is sourced from package metadata, not a hardcoded string."""
    assert compliance_assess.__version__ == _pkg_version("compliance-assess")
    _ = (Assessor, AssessmentResult, AppError, DetectionEngine)
