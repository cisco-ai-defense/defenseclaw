# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""rel-1-0-10 GAP-1669: config set routing.enabled said "Restart the gateway to
apply routing.enabled" although the gateway reads it on a reload with a
classifier that runs inside it. RESTART_KEYS stays the conservative list (it
cannot see the running classifier); the message looks at config.yaml."""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner
from defenseclaw import config_writer
from defenseclaw.commands import cmd_config
from defenseclaw.config_writer import Change


@pytest.fixture(autouse=True)
def _offline(monkeypatch):
    from defenseclaw.logger import Logger

    monkeypatch.setattr(Logger, "from_config", classmethod(lambda cls, cfg: cls.no_runtime()))
    monkeypatch.delenv("DEFENSECLAW_DEPLOYMENT_MODE", raising=False)


def _write(tmp_path, classifier):
    path = tmp_path / "config.yaml"
    routing = (
        "routing:\n  enabled: false\n"
        + (f"  classifier: {classifier}\n" if classifier else "")
        + "  models:\n    - name: fast\n      provider: ollama\n      model: qwen2.5:0.5b\n"
        + "      base_url: http://127.0.0.1:11434\n"
    )
    path.write_text(f"config_version: 9\ndata_dir: {tmp_path}\n{routing}observability: {{}}\n")
    return str(path)


@pytest.mark.parametrize(
    ("classifier", "hot"),
    [("rules", True), ("systemone", True), ("vllm_sr", False), (None, False)],
)
def test_the_reload_note_follows_the_classifier(tmp_path, classifier, hot):
    path = _write(tmp_path, classifier)
    result = config_writer.apply([Change("routing.enabled", True)], "cli:test", "t", path=path)
    assert result.restart_required == ["routing.enabled"]  # the writer list stays conservative
    got = cmd_config._routing_enabled_applies_on_reload(result.restart_required, result.changed, path)
    assert got == (classifier if hot else "")


def test_changing_the_classifier_in_the_same_write_stays_a_restart(tmp_path):
    path = _write(tmp_path, "vllm_sr")
    result = config_writer.apply(
        [Change("routing.enabled", True), Change("routing.classifier", "rules")], "cli:test", "t", path=path
    )
    assert cmd_config._routing_enabled_applies_on_reload(result.restart_required, result.changed, path) == ""


def test_an_unreadable_config_keeps_the_restart_message(tmp_path):
    assert cmd_config._routing_enabled_applies_on_reload(["routing.enabled"], ["routing.enabled"], str(tmp_path / "x")) == ""


@pytest.mark.parametrize(("classifier", "hot"), [("rules", True), ("vllm_sr", False)])
def test_config_set_prints_the_right_message(tmp_path, monkeypatch, classifier, hot):
    path = _write(tmp_path, classifier)
    monkeypatch.setenv("DEFENSECLAW_CONFIG", path)
    monkeypatch.setattr(cmd_config.config_module, "config_path", lambda: Path(path))
    real = config_writer.apply
    monkeypatch.setattr(config_writer, "apply", lambda *a, **k: real(*a, **{**k, "path": path}))
    from defenseclaw.context import AppContext

    result = CliRunner().invoke(cmd_config.config_cmd, ["set", "routing.enabled", "true"], obj=AppContext())
    out = result.output
    assert result.exception is None or isinstance(result.exception, SystemExit), repr(result.exception)
    if hot:
        assert "routing.enabled applies on reload" in out and f"with the {classifier} classifier" in out, out
        assert "Restart the gateway" not in out, out
    else:
        assert "Restart the gateway to apply routing.enabled" in out, out
