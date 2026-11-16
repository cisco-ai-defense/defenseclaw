"""Windows CI runs every standalone PowerShell smoke of this group on each installed engine
(Windows PowerShell 5.1 and 7); see tests/enterprise_standalone_smokes.py."""

from __future__ import annotations

import sys

import pytest

from tests.enterprise_standalone_smokes import SMOKES_C, engine_id, run_standalone_smoke, standalone_smoke_engines


@pytest.mark.skipif(sys.platform != "win32", reason="requires native Windows PowerShell")
@pytest.mark.parametrize("smoke", SMOKES_C)
@pytest.mark.parametrize("engine", standalone_smoke_engines() or (None,), ids=engine_id)
def test_standalone_smokes_c_run_on_every_engine(engine: str | None, smoke: str) -> None:
    run_standalone_smoke(engine, smoke)
