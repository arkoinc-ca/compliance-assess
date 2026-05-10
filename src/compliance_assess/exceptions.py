# SPDX-License-Identifier: Apache-2.0
"""Typed error hierarchy for compliance_assess."""


class AppError(Exception):
    def __init__(self, message: str, code: str) -> None:
        super().__init__(message)
        self.code = code


class ValidationError(AppError):
    def __init__(self, message: str, details: list[str]) -> None:
        super().__init__(message, "VALIDATION_ERROR")
        self.details = details


class NotFoundError(AppError):
    def __init__(self, resource: str, id: str) -> None:
        super().__init__(f"{resource} not found: {id}", "NOT_FOUND")


class AssessmentError(AppError):
    def __init__(self, message: str) -> None:
        super().__init__(message, "ASSESSMENT_ERROR")
