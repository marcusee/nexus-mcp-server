"""
Output quality. Given the skill fired, is the result good? This is where
deepeval earns its place: GEval turns a prose criterion into a score.

    deepeval test run tests/test_quality.py -i -c

Use `deepeval test run` rather than plain pytest -- it aggregates results into
a run summary and caches passing cases so a partial rerun is cheap.
"""

from __future__ import annotations

import statistics

import pytest
from deepeval import assert_test
from deepeval.metrics import GEval
from deepeval.test_case import LLMTestCase, SingleTurnParams

from goldens import POSITIVE

pytestmark = [pytest.mark.gateway, pytest.mark.eval]

THRESHOLD = 0.6

BASE_CRITERIA = (
    "Determine whether the actual output follows the instructions and "
    "conventions defined by the skill. It should match the expected output in "
    "substance, structure, and level of detail. Wording may differ freely -- "
    "judge meaning, not phrasing. Penalise output that is generic, that "
    "ignores a stated convention, or that answers a different question."
)


def build_metric(judge, extra: str | None = None) -> GEval:
    return GEval(
        name="FollowsSkill",
        criteria=BASE_CRITERIA + (f" Additionally: {extra}" if extra else ""),
        evaluation_params=[
            SingleTurnParams.INPUT,
            SingleTurnParams.ACTUAL_OUTPUT,
            SingleTurnParams.EXPECTED_OUTPUT,
        ],
        threshold=THRESHOLD,
        model=judge,
    )


@pytest.mark.parametrize("golden", POSITIVE, ids=[g.id for g in POSITIVE])
def test_output_quality(runner, judge, golden):
    """Single-shot quality check. Fast, but one sample of a non-deterministic
    system -- treat a lone failure as a prompt to run the consistency test
    rather than as proof of a regression."""
    test_case = LLMTestCase(
        input=golden.task,
        actual_output=runner.run(golden.task),
        expected_output=golden.expected,
    )
    assert_test(test_case, [build_metric(judge, golden.extra_criteria)])


@pytest.mark.slow
@pytest.mark.parametrize("golden", POSITIVE, ids=[g.id for g in POSITIVE])
def test_output_consistency(runner, judge, golden, capsys):
    """Run each case several times and assert on the pass RATE.

    A single pass/fail on a stochastic system is close to meaningless. This is
    the test to trust when deciding whether a skill edit actually helped or you
    were looking at noise.

    Uses metric.measure() rather than assert_test() so the raw scores are
    available to aggregate.
    """
    runs = 5
    required = 4

    metric = build_metric(judge, golden.extra_criteria)
    scores = []
    for _ in range(runs):
        test_case = LLMTestCase(
            input=golden.task,
            actual_output=runner.run(golden.task),
            expected_output=golden.expected,
        )
        metric.measure(test_case)
        scores.append(metric.score)

    passed = sum(s >= THRESHOLD for s in scores)
    spread = max(scores) - min(scores)

    with capsys.disabled():
        print(
            f"\n{golden.id}: {passed}/{runs} passed | "
            f"mean {statistics.mean(scores):.2f} | spread {spread:.2f}"
        )

    assert passed >= required, (
        f"only {passed}/{runs} runs passed. scores={[round(s, 2) for s in scores]}"
    )
