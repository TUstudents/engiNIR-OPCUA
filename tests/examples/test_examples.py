"""The examples in examples/ run to the end and report success; each is started as its own process."""

from collections.abc import Callable
from pathlib import Path

import pytest

from tests.examples.conftest import EXAMPLES, ExampleRun

SCRIPTS = sorted(EXAMPLES.glob("[0-9][0-9]_*.py"))


def example(script: Path) -> object:
    relative = script.relative_to(EXAMPLES.parent).as_posix()
    return pytest.param(
        script,
        id=script.stem,
        marks=pytest.mark.slow(relative, "examples/_common.py", "enginir_opcua/config.py", "enginir_opcua/server"),
    )


def test_the_set_has_sixteen_examples() -> None:
    assert [script.name[:2] for script in SCRIPTS] == [f"{number:02d}" for number in range(1, 17)]


@pytest.mark.parametrize("script", [example(script) for script in SCRIPTS])
def test_example_runs_and_reports_ok(script: Path, run_example: Callable[[Path], ExampleRun]) -> None:
    result = run_example(script)
    assert result.returncode == 0, result.output
    assert f"OK {script.stem}" in result.lines, result.output
    assert result.lines.count(f"OK {script.stem}") == 1
