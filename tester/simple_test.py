import os
from pathlib import Path

from deepeval import assert_test
from deepeval.metrics import GEval
from deepeval.test_case import LLMTestCase, SingleTurnParams

SKILL = Path(os.getenv("SKILL_PATH", "skills/general-usage-testing/SKILL.md"))

TASK = "Write a unit test for a function that parses ISO dates."

EXPECTED = (
    "A pytest test function with arrange/act/assert structure, covering a "
    "valid input and a malformed one, using plain asserts."
)


def test_skill(model, judge):
    prompt = (
        "Follow the instructions in this skill when responding.\n\n"
        f"<skill>\n{SKILL.read_text()}\n</skill>\n\n"
        f"User request: {TASK}"
    )

    metric = GEval(
        name="FollowsSkill",
        criteria="Determine whether the actual output matches the expected output in substance and structure. Wording may differ.",
        evaluation_params=[
            SingleTurnParams.INPUT,
            SingleTurnParams.ACTUAL_OUTPUT,
            SingleTurnParams.EXPECTED_OUTPUT,
        ],
        threshold=0.5,
        model=judge,
    )

    assert_test(
        LLMTestCase(
            input=TASK,
            actual_output=model.generate(prompt),
            expected_output=EXPECTED,
        ),
        [metric],
    )
