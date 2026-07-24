"""Shared sanitized engagement data for risk tests."""

from pathlib import Path
from shutil import copyfile

import pytest

PROGRAM_FIXTURES = Path(__file__).parents[1] / "programs" / "fixtures"
RISK_FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def sample_engagement(tmp_path: Path) -> Path:
    engagement = tmp_path / "sample-engagement"
    engagement.mkdir()
    copyfile(PROGRAM_FIXTURES / "valid_program.yaml", engagement / "program.yaml")
    copyfile(PROGRAM_FIXTURES / "valid_scope.yaml", engagement / "scope.yaml")
    copyfile(RISK_FIXTURES / "authorization-confirmed.json", engagement / "authorization.json")
    return engagement
