"""Helpers for locating packaged prompt and YAML assets."""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path


def prompt_asset_path(*parts: str) -> Path:
    """Return an absolute path to a prompt asset shipped with the package.

    Mirrors avarice's ``prompt_loader.prompt_asset_path``. Joining all parts
    under ``dctest/prompt_assets/``.
    """
    root = files("dctest").joinpath("prompt_assets")
    return Path(str(root.joinpath(*parts)))


def case_path(*parts: str) -> Path:
    """Return an absolute path to a case file shipped with the package."""
    root = files("dctest").joinpath("cases")
    return Path(str(root.joinpath(*parts)))


def matrix_path(*parts: str) -> Path:
    """Return an absolute path to a matrix dimension file."""
    root = files("dctest").joinpath("matrix")
    return Path(str(root.joinpath(*parts)))


def fixtures_path(*parts: str) -> Path:
    """Return an absolute path to a fixture asset shipped with the package."""
    root = files("dctest").joinpath("fixtures")
    return Path(str(root.joinpath(*parts)))


def load_preamble() -> str:
    """Return the agent preamble used in every staged prompt."""
    return prompt_asset_path("prompts", "preamble.agent.md").read_text(encoding="utf-8")


def load_stage_prompt(stage: str) -> str:
    """Return the body of a per-stage prompt."""
    return prompt_asset_path("prompts", "stages", f"{stage}.md").read_text(encoding="utf-8")
