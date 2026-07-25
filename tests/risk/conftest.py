"""Shared sanitized engagement data for risk tests."""

from pathlib import Path
from shutil import copyfile

import pytest
import yaml

PROGRAM_FIXTURES = Path(__file__).parents[1] / "programs" / "fixtures"
RISK_FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def sample_engagement(tmp_path: Path) -> Path:
    engagement = tmp_path / "sample-engagement"
    engagement.mkdir()
    copyfile(PROGRAM_FIXTURES / "valid_program.yaml", engagement / "program.yaml")
    program = yaml.safe_load((engagement / "program.yaml").read_text(encoding="utf-8"))
    (engagement / "scope.yaml").write_text(
        yaml.safe_dump({"schema_version": 1, **program["scope"]}, sort_keys=False),
        encoding="utf-8",
    )
    copyfile(RISK_FIXTURES / "authorization-confirmed.json", engagement / "authorization.json")
    return engagement
