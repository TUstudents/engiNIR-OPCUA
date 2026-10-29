import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "examples"
TIMEOUT = 60


def _text(data: bytes | str | None) -> str:
    return data.decode(errors="replace") if isinstance(data, bytes) else data or ""


class ExampleRun:
    def __init__(self, returncode: int, output: str) -> None:
        self.returncode = returncode
        self.output = output

    @property
    def lines(self) -> list[str]:
        return [line for line in self.output.splitlines() if line.strip()]


@pytest.fixture
def run_example(tmp_path: Path) -> Callable[[Path], ExampleRun]:
    """Run an example as its own process, in an empty working directory, and collect its output."""

    def run(script: Path) -> ExampleRun:
        environment = {**os.environ, "PYTHONUNBUFFERED": "1"}
        try:
            done = subprocess.run(
                [sys.executable, str(script)],
                cwd=tmp_path,
                env=environment,
                capture_output=True,
                text=True,
                timeout=TIMEOUT,
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            pytest.fail(f"{script.name} did not end within {TIMEOUT} s\n{_text(error.stdout)}\n{_text(error.stderr)}")
        return ExampleRun(done.returncode, f"{done.stdout}\n{done.stderr}")

    return run
