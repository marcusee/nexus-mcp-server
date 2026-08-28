import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "evals"))

import pytest
from aiaas_judge import AIaaSJudge


@pytest.fixture(scope="session")
def judge():
    return AIaaSJudge(temperature=0.0)


@pytest.fixture(scope="session")
def model():
    return AIaaSJudge(temperature=0.0)
