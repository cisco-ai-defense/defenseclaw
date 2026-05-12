"""Shared pytest fixtures for the dctest harness's own test suite."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from dctest import config as config_mod


@pytest.fixture(autouse=True)
def isolated_runs_root(tmp_path, monkeypatch):
    """Force every test's runs to land under a tmp directory."""
    runs_root = tmp_path / "runs"
    runs_root.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("DCTEST_RUNS_ROOT", str(runs_root))
    config_mod.reset_settings_for_tests()
    yield runs_root
    config_mod.reset_settings_for_tests()


@pytest.fixture
def scrub_provider_env(monkeypatch):
    """Pretend we have no API keys so doctor/provider checks fail cleanly."""
    for var in ["ANTHROPIC_API_KEY", "OPENAI_API_KEY", "BIFROST_API_KEY"]:
        monkeypatch.delenv(var, raising=False)
    yield


@pytest.fixture
def cwd_to(tmp_path):
    prev = Path.cwd()
    os.chdir(tmp_path)
    yield tmp_path
    os.chdir(prev)
