"""Load-bearing tests for Assessor.load_profile."""

import textwrap
from pathlib import Path

import pytest

from compliance_assess import Assessor, NotFoundError, ValidationError
from compliance_assess.models import Control, Finding
from compliance_assess.result import Err, Ok

CATALOG = Path(__file__).parent.parent.parent.parent / "compliance-catalog"
CA_ON_PROFILE = CATALOG / "profiles" / "region" / "ca-on.yaml"


@pytest.fixture
def assessor() -> Assessor:
    return Assessor(CATALOG)


def test_load_profile_resolves_controls(assessor: Assessor) -> None:
    result = assessor.load_profile(CA_ON_PROFILE)
    assert isinstance(result, Ok), f"Expected Ok, got Err: {result.error}"

    profile = result.value
    # ca-on.yaml imports PHIPA-ON (14) + PIPEDA (12) + CASL (6) = 32 controls
    # (PHIPA-ON was added by C-H1 fix)
    assert len(profile.resolved_controls) >= 18

    # CA-PIPEDA-001 statement must mention "designate"
    pipeda_001 = next(c for c in profile.resolved_controls if c.id == "CA-PIPEDA-001")
    assert "designate" in pipeda_001.statement.lower()
    assert pipeda_001.regulation_short_code == "PIPEDA"


def test_load_profile_missing_file(assessor: Assessor) -> None:
    result = assessor.load_profile(Path("/nonexistent/profile.yaml"))
    assert isinstance(result, Err)
    assert isinstance(result.error, NotFoundError)
    assert result.error.code == "NOT_FOUND"


def test_load_profile_rejects_path_traversal(tmp_path: Path) -> None:
    """An href that escapes the catalog root must be rejected (path traversal)."""
    catalog = tmp_path / "catalog"
    catalog.mkdir()

    # Write a sentinel file outside the catalog root
    secret = tmp_path / "secret.yaml"
    secret.write_text(
        "catalog:\n  uuid: 00000000-0000-4000-8000-000000000001\n"
        "  metadata:\n    title: secret\n"
    )

    # Craft a profile whose href traverses outside the catalog
    evil_profile = tmp_path / "evil.yaml"
    evil_profile.write_text(
        textwrap.dedent("""\
        profile:
          uuid: 00000000-0000-4000-8000-000000000002
          metadata:
            title: evil
            version: "0.0"
            last-modified: "2026-01-01T00:00:00Z"
          imports:
            - href: ../secret.yaml
              include-controls:
                - with-ids: []
        """)
    )

    assessor = Assessor(catalog)
    result = assessor.load_profile(evil_profile)
    assert isinstance(result, Err)
    assert isinstance(result.error, ValidationError), (
        f"Expected ValidationError for path traversal, got {type(result.error).__name__}"
    )


def test_assess_excludes_non_source_dirs(tmp_path: Path, assessor: Assessor) -> None:
    """assess() must not recurse into non-source directories."""
    # Build a shallow target dir with a .git and a python file
    target = tmp_path / "project"
    (target / ".git" / "objects").mkdir(parents=True)
    (target / ".git" / "objects" / "huge.bin").write_bytes(b"x" * 1024)
    (target / "app.py").write_text("print('hello')")

    profile = assessor.load_profile(CA_ON_PROFILE)
    assert isinstance(profile, Ok)

    result = assessor.assess(profile.value, target, [])
    assert isinstance(result, Ok)


def test_load_profile_nested_href_resolves(tmp_path: Path) -> None:
    """A profile href pointing to a sub-directory regulation file resolves correctly."""
    catalog = tmp_path / "catalog"
    regs = catalog / "regs" / "nested"
    regs.mkdir(parents=True)

    reg_yaml = regs / "reg-a.yaml"
    reg_yaml.write_text(
        "catalog:\n"
        "  uuid: 00000000-0000-4000-8000-000000000010\n"
        "  metadata:\n"
        "    title: Reg A\n"
        "    props:\n"
        "      - name: regulation-short-code\n"
        "        value: REG-A\n"
        "      - name: jurisdiction\n"
        "        value: CA\n"
        "  groups:\n"
        "    - controls:\n"
        "        - id: REG-A-001\n"
        "          title: Control one\n"
        "          props: []\n"
        "          parts: []\n",
        encoding="utf-8",
    )

    profiles_dir = catalog / "profiles"
    profiles_dir.mkdir()
    profile_yaml = profiles_dir / "test.yaml"
    profile_yaml.write_text(
        "profile:\n"
        "  uuid: 00000000-0000-4000-8000-000000000020\n"
        "  metadata:\n"
        "    title: Nested Test\n"
        "    version: '0.1'\n"
        "    last-modified: '2026-01-01T00:00:00Z'\n"
        "  imports:\n"
        "    - href: ../regs/nested/reg-a.yaml\n"
        "      include-controls:\n"
        "        - with-ids: [REG-A-001]\n",
        encoding="utf-8",
    )

    assessor = Assessor(catalog)
    result = assessor.load_profile(profile_yaml)
    assert isinstance(result, Ok), f"Expected Ok, got Err: {getattr(result, 'error', None)}"
    profile = result.value
    assert len(profile.resolved_controls) == 1
    assert profile.resolved_controls[0].id == "REG-A-001"


def test_assess_scan_degraded_when_error_sentinel_present(tmp_path: Path) -> None:
    """A-H2: AssessmentResult.scan_degraded=True when any Finding has method='error'."""
    from compliance_assess.detection import DetectionEngine

    # Minimal engine that always emits a sentinel error finding
    class AlwaysErrorEngine:
        name: str = "error-engine"

        def detect(
            self,
            control: Control,
            target_dir: Path,
            source_files: list[Path],
            *,
            timeout_s: float = 30.0,
        ) -> list[Finding]:
            return [
                Finding(
                    control_id=control.id,
                    severity="medium",
                    method="error",
                    message="semgrep failed: test error",
                )
            ]

    catalog = tmp_path / "catalog"
    catalog.mkdir()
    profiles_dir = catalog / "profiles"
    profiles_dir.mkdir()

    reg_yaml = catalog / "reg.yaml"
    reg_yaml.write_text(
        "catalog:\n"
        "  uuid: 00000000-0000-4000-8000-000000000050\n"
        "  metadata:\n"
        "    title: Reg\n"
        "    props:\n"
        "      - name: regulation-short-code\n"
        "        value: TEST\n"
        "      - name: jurisdiction\n"
        "        value: CA\n"
        "  groups:\n"
        "    - controls:\n"
        "        - id: TEST-001\n"
        "          title: Test Control\n"
        "          props: []\n"
        "          parts: []\n",
        encoding="utf-8",
    )

    profile_yaml = profiles_dir / "test.yaml"
    profile_yaml.write_text(
        "profile:\n"
        "  uuid: 00000000-0000-4000-8000-000000000060\n"
        "  metadata:\n"
        "    title: Test Profile\n"
        "    version: '0.1'\n"
        "    last-modified: '2026-01-01T00:00:00Z'\n"
        "  imports:\n"
        "    - href: ../reg.yaml\n"
        "      include-controls:\n"
        "        - with-ids: [TEST-001]\n",
        encoding="utf-8",
    )

    target = tmp_path / "target"
    target.mkdir()

    assessor_obj = Assessor(catalog)
    profile_result = assessor_obj.load_profile(profile_yaml)
    assert isinstance(profile_result, Ok)

    engines: list[DetectionEngine] = [AlwaysErrorEngine()]
    assessment = assessor_obj.assess(profile_result.value, target, engines)
    assert isinstance(assessment, Ok)
    assert assessment.value.scan_degraded is True


def test_load_profile_rejects_sibling_prefix_traversal(tmp_path: Path) -> None:
    """P0-06: A href resolving to a sibling directory with a catalog-prefixed name
    (e.g. /a/catalog-evil/x.yaml when root is /a/catalog) must be rejected.

    The prior str.startswith check was bypassable by this pattern.
    is_relative_to / os.sep-terminated normcase check closes it.
    """
    catalog = tmp_path / "catalog"
    catalog.mkdir()

    evil_sibling = tmp_path / "catalog-evil"
    evil_sibling.mkdir()
    evil_reg = evil_sibling / "x.yaml"
    evil_reg.write_text(
        "catalog:\n  uuid: 00000000-0000-4000-8000-000000000099\n  metadata:\n    title: evil\n"
    )

    # The href uses two levels of traversal to land in catalog-evil/
    evil_profile = tmp_path / "catalog" / "evil.yaml"
    evil_profile.write_text(
        "profile:\n"
        "  uuid: 00000000-0000-4000-8000-000000000098\n"
        "  metadata:\n"
        "    title: evil\n"
        "    version: '0.0'\n"
        "    last-modified: '2026-01-01T00:00:00Z'\n"
        "  imports:\n"
        "    - href: ../../catalog-evil/x.yaml\n"
        "      include-controls:\n"
        "        - with-ids: []\n"
    )

    assessor = Assessor(catalog)
    result = assessor.load_profile(evil_profile)
    assert isinstance(result, Err)
    assert isinstance(result.error, ValidationError), (
        f"Expected ValidationError for sibling-prefix traversal, got {type(result.error).__name__}"
    )


def test_load_profile_href_missing_file_returns_not_found(tmp_path: Path) -> None:
    """An href referencing a non-existent regulation file returns NotFoundError."""
    catalog = tmp_path / "catalog"
    catalog.mkdir()

    profiles_dir = catalog / "profiles"
    profiles_dir.mkdir()
    profile_yaml = profiles_dir / "missing-ref.yaml"
    profile_yaml.write_text(
        "profile:\n"
        "  uuid: 00000000-0000-4000-8000-000000000030\n"
        "  metadata:\n"
        "    title: Missing Ref\n"
        "    version: '0.1'\n"
        "    last-modified: '2026-01-01T00:00:00Z'\n"
        "  imports:\n"
        "    - href: ../regs/does-not-exist.yaml\n"
        "      include-controls:\n"
        "        - with-ids: []\n",
        encoding="utf-8",
    )

    assessor = Assessor(catalog)
    result = assessor.load_profile(profile_yaml)
    assert isinstance(result, Err)
    assert isinstance(result.error, NotFoundError), (
        f"Expected NotFoundError for missing href, got {type(result.error).__name__}"
    )
