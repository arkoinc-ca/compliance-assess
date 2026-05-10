"""Load-bearing CLI smoke tests."""

from pathlib import Path

from typer.testing import CliRunner

from compliance_assess.cli import app

CATALOG = Path(__file__).parent.parent.parent.parent / "compliance-catalog"

runner = CliRunner()


def test_profile_list_smoke() -> None:
    result = runner.invoke(app, ["profile", "list", "--catalog", str(CATALOG)])
    assert result.exit_code == 0
    # 8 region profiles: ca-ab, ca-bc, ca-on, ca-qc, eu-generic, us-ca, us-co, us-ny
    lines = [line for line in result.output.splitlines() if line.strip()]
    assert len(lines) >= 8
    # Each line should contain a .yaml reference
    assert all(".yaml" in line for line in lines)
