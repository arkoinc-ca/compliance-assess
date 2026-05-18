# SPDX-License-Identifier: Apache-2.0
r"""Regression test for P0-07: action.yml catalog-version regex validation.

Bug: The original regex '^[a-z0-9-]+(\.[a-z0-9-]+)*(==[\w.+-]+)?$' rejects the
action's own default input value '>=0.1,<0.2' because the leading '>' character is
not in the allowed character class.

This test runs the exact bash check from action.yml against the documented
accepted/rejected fixture set, confirming the fixed regex admits valid version
specifiers and blocks injection strings.
"""

import subprocess

# Accepted specifiers (per action.yml inline comment after fix)
ACCEPTED = [
    "0.1.0",
    "==0.1.0",
    ">=0.1,<0.2",
    "~=0.1.5",
    "!=0.0.1",
]

# Rejected values (injection / empty / garbage)
REJECTED = [
    "; rm -rf /",
    "0.1.0 && curl evil",
    "\\\\",
    "",
]

# Fixed regex from action.yml — keep in sync.
# Uses explicit [a-zA-Z0-9_] rather than \w because not all grep -E implementations
# (notably some BSD/Windows variants) support \w.
_REGEX = r"^([<>=!~]=?|==)?[0-9][a-zA-Z0-9._+!,*<>=-]*$"


def _bash_grep(pattern: str, value: str) -> bool:
    """Return True if `grep -qE pattern` matches value in bash."""
    result = subprocess.run(
        ["bash", "-c", f"echo {value!r} | grep -qE {pattern!r}"],
        capture_output=True,
    )
    return result.returncode == 0


def test_catalog_version_regex_accepts_and_rejects_correct_values() -> None:
    """The fixed regex must accept all valid PEP 440 specifiers and reject injections.

    This is the exact regression test for V-C finding P0-07(c): the original regex
    rejected '>=0.1,<0.2' (the action's own default value), making catalog-version
    validation non-functional for the most common use-case.
    """
    failures: list[str] = []

    for spec in ACCEPTED:
        if not _bash_grep(_REGEX, spec):
            failures.append(f"ACCEPTED '{spec}' was incorrectly rejected")

    for spec in REJECTED:
        if _bash_grep(_REGEX, spec):
            failures.append(f"REJECTED '{spec}' was incorrectly accepted")

    assert not failures, "Regex fixture failures:\n" + "\n".join(failures)
