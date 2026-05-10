# SPDX-License-Identifier: Apache-2.0
"""compliance_assess — static and runtime compliance gap assessor."""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version

from .assessor import Assessor
from .detection import DetectionEngine, OtelEngine, QuestionnaireEngine, SemgrepEngine
from .exceptions import AppError, AssessmentError, NotFoundError, ValidationError
from .models import AssessmentResult, Control, Finding, Profile, ProfileImport
from .result import Err, Ok, Result

# V-C fix: source version dynamically from package metadata (pyproject.toml) so
# the runtime version cannot drift from the published version. Falls back only
# when the package is imported from a source tree without `pip install -e .`.
try:
    __version__ = _pkg_version("compliance-assess")
except PackageNotFoundError:  # pragma: no cover — only on raw source tree
    __version__ = "0.0.0+unknown"

__all__ = [
    "Assessor",
    "Profile",
    "ProfileImport",
    "Control",
    "Finding",
    "AssessmentResult",
    "DetectionEngine",
    "SemgrepEngine",
    "OtelEngine",
    "QuestionnaireEngine",
    "AppError",
    "ValidationError",
    "NotFoundError",
    "AssessmentError",
    "Ok",
    "Err",
    "Result",
    "__version__",
]
