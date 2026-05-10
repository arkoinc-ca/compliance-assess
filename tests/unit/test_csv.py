# SPDX-License-Identifier: Apache-2.0
"""Load-bearing tests for _csv_safe Unicode formula-injection guard.

Parametrized over 3 representative Unicode tricks that can disguise formula
payloads by prepending an invisible character before '=', '+', etc.
"""

from __future__ import annotations

import pytest

from compliance_assess.emitters import _csv_safe

# Unicode trick chars (representative sample of the 6 added in W3-A3)
_ZWSP = "​"   # zero-width space (U+200B)
_RTLO = "‮"   # right-to-left override (U+202E)
_BOM = "﻿"    # byte-order mark (U+FEFF)


@pytest.mark.parametrize(
    "cell",
    [
        f"{_ZWSP}=HYPERLINK(\"http://evil.test\",\"click\")",
        f"{_RTLO}=cmd|'/C calc'!A0",
        f"{_BOM}+malicious_formula",
    ],
)
def test_csv_safe_prefixes_unicode_trick_cells(cell: str) -> None:
    """Cells starting with a Unicode trick char must be prefixed with ' to defuse injection."""
    result = _csv_safe(cell)
    assert result.startswith("'"), (
        f"Expected _csv_safe to prefix with \"'\", got: {result!r}"
    )
    assert result[1:] == cell, "Prefix must not alter the rest of the cell value"


def test_csv_safe_leaves_safe_cell_untouched() -> None:
    """Sanity check: a normal cell value must pass through unchanged."""
    assert _csv_safe("hello world") == "hello world"
