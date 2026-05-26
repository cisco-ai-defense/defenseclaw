# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Launcher first-run parity tests for the Textual backend."""

from __future__ import annotations

import subprocess
from typing import Any

from defenseclaw.tui import run_textual_tui


def test_textual_launcher_activates_first_run_when_config_load_fails(monkeypatch) -> None:
    launched: dict[str, Any] = {}

    class FakeApp:
        def __init__(self, **kwargs: Any) -> None:
            launched.update(kwargs)

        def run(self) -> None:
            launched["ran"] = True

    def fail_load() -> object:
        raise FileNotFoundError("missing config")

    monkeypatch.setattr("defenseclaw.config.load", fail_load)
    monkeypatch.setattr("defenseclaw.tui.app.DefenseClawTUI", FakeApp)

    run_textual_tui()

    assert launched["config"] is None
    assert launched["first_run"] is True
    assert launched["ran"] is True


def test_textual_launcher_skips_first_run_when_config_loads(monkeypatch) -> None:
    launched: dict[str, Any] = {}
    cfg = object()

    class FakeApp:
        def __init__(self, **kwargs: Any) -> None:
            launched.update(kwargs)

        def run(self) -> None:
            launched["ran"] = True

    monkeypatch.setattr("defenseclaw.config.load", lambda: cfg)
    monkeypatch.setattr("defenseclaw.tui.app.DefenseClawTUI", FakeApp)

    run_textual_tui()

    assert launched["config"] is cfg
    assert launched["first_run"] is False
    assert launched["ran"] is True


def test_textual_launcher_hands_missing_config_to_init_when_tty(monkeypatch) -> None:
    launched: dict[str, Any] = {}
    calls = {"load": 0, "init": 0}
    cfg = object()

    class FakeApp:
        def __init__(self, **kwargs: Any) -> None:
            launched.update(kwargs)

        def run(self) -> None:
            launched["ran"] = True

    def load_config() -> object:
        calls["load"] += 1
        if calls["load"] == 1:
            raise FileNotFoundError("missing config")
        return cfg

    def run_init(argv: tuple[str, ...], *, check: bool) -> subprocess.CompletedProcess:
        assert argv == ("defenseclaw", "init")
        assert check is False
        calls["init"] += 1
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr("defenseclaw.config.load", load_config)
    monkeypatch.setattr("defenseclaw.config.config_path", lambda: "/tmp/config.yaml")
    monkeypatch.setattr("defenseclaw.tui.app.DefenseClawTUI", FakeApp)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _prompt: "")
    monkeypatch.setattr("subprocess.run", run_init)

    run_textual_tui()

    assert calls == {"load": 2, "init": 1}
    assert launched["config"] is cfg
    assert launched["first_run"] is False
    assert launched["ran"] is True


def test_textual_launcher_decline_opens_without_embedded_first_run(monkeypatch) -> None:
    launched: dict[str, Any] = {}

    class FakeApp:
        def __init__(self, **kwargs: Any) -> None:
            launched.update(kwargs)

        def run(self) -> None:
            launched["ran"] = True

    monkeypatch.setattr("defenseclaw.config.load", lambda: (_ for _ in ()).throw(FileNotFoundError("missing")))
    monkeypatch.setattr("defenseclaw.config.config_path", lambda: "/tmp/config.yaml")
    monkeypatch.setattr("defenseclaw.tui.app.DefenseClawTUI", FakeApp)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _prompt: "n")

    run_textual_tui()

    assert launched["config"] is None
    assert launched["first_run"] is False
    assert launched["ran"] is True
