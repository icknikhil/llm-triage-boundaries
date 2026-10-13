"""pytest bootstrap: make the project root importable and share fixtures."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# The modules (schema, guardrails, prompts, ...) live one directory up. Put the
# project root on sys.path so `import schema` works regardless of CWD.
_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from schema import ScenarioDataset, load_dataset  # noqa: E402


@pytest.fixture(scope="session")
def dataset() -> ScenarioDataset:
    return load_dataset(_PROJECT_ROOT / "dataset.json")
