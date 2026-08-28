"""Shared fixtures. Session-scoped so one token and one connection pool
serve the entire run."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

# Make the project root importable without an editable install.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aiaas_judge import AIaaSJudge  # noqa: E402
from skill_runner import SkillRunner, load_skill  # noqa: E402

REQUIRED_ENV = (
    "AIAAS_CLIENT_ID",
    "AIAAS_CLIENT_SECRET",
    "AIAAS_TENANT_ID",
    "AIAAS_SCOPE",
)


def pytest_configure(config):
    config.addinivalue_line("markers", "gateway: hits the live AIaaS gateway")
    config.addinivalue_line("markers", "eval: LLM-as-judge, slow and non-deterministic")
    config.addinivalue_line("markers", "slow: repeated runs for variance measurement")


@pytest.fixture(scope="session")
def _credentials():
    missing = [v for v in REQUIRED_ENV if not os.getenv(v)]
    if missing:
        pytest.skip(f"missing env vars: {', '.join(missing)}")


@pytest.fixture(scope="session")
def judge(_credentials) -> AIaaSJudge:
    """The evaluator. Kept separate from the system under test so the two can
    diverge later (a stronger judge, or A/B of two skill versions)."""
    return AIaaSJudge(temperature=0.0)


@pytest.fixture(scope="session")
def skill(_credentials):
    return load_skill()


@pytest.fixture(scope="session")
def runner(_credentials, skill) -> SkillRunner:
    """The system under test: your skill file, loaded into a model."""
    return SkillRunner(skill)
