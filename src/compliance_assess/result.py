# SPDX-License-Identifier: Apache-2.0
"""Ok/Err result types for operations that can fail."""

from dataclasses import dataclass
from typing import Generic, TypeVar

T = TypeVar("T")
E = TypeVar("E", bound=Exception)


@dataclass(frozen=True)
class Ok(Generic[T]):
    value: T

    @property
    def is_ok(self) -> bool:
        return True


@dataclass(frozen=True)
class Err(Generic[E]):
    error: E

    @property
    def is_ok(self) -> bool:
        return False


Result = Ok[T] | Err[E]
