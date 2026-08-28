import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "evals"))

import pytest
from aiaas_judge import AIaaSJudge

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session")
def skill():
    path = Path(os.getenv("SKILL_PATH", "skills/general-usage-testing/SKILL.md"))
    if not path.is_absolute():
        path = ROOT / path
    if not path.is_file():
        pytest.skip(f"skill file not found: {path}")
    return path.read_text(encoding="utf-8")


@pytest.fixture(scope="session")
def judge():
    return AIaaSJudge(temperature=0.0)


@pytest.fixture(scope="session")
def model():
    return AIaaSJudge(temperature=0.0)
