# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from types import SimpleNamespace

from click.testing import CliRunner
from defenseclaw.codeguard_skill import (
    codeguard_status,
    ensure_codeguard_skill,
    install_codeguard_asset,
)
from defenseclaw.commands.cmd_codeguard import codeguard
from defenseclaw.context import AppContext


def _cfg(active: str, root):
    return SimpleNamespace(
        active_connector=lambda: active,
        claw=SimpleNamespace(
            home_dir=str(root / ".openclaw"),
            config_file=str(root / ".openclaw" / "openclaw.json"),
        ),
    )


def test_codeguard_skill_install_is_idempotent(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    cfg = _cfg("cursor", tmp_path)

    status = codeguard_status(cfg, connector="cursor", target="skill")
    assert status.status == "missing"

    first = install_codeguard_asset(cfg, connector="cursor", target="skill")
    assert first.startswith("installed to ")

    second = install_codeguard_asset(cfg, connector="cursor", target="skill")
    assert second.startswith("already installed at ")


def test_codeguard_rule_install_conflict_requires_replace(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cfg = _cfg("cursor", tmp_path)
    rule = tmp_path / ".cursor" / "rules" / "codeguard.mdc"
    rule.parent.mkdir(parents=True)
    rule.write_text("user-owned rule\n", encoding="utf-8")

    status = install_codeguard_asset(cfg, connector="cursor", target="rule")
    assert status.startswith("conflict at ")

    replaced = install_codeguard_asset(cfg, connector="cursor", target="rule", replace=True)
    assert replaced.startswith("installed to ")
    assert "defenseclaw:codeguard" in rule.read_text(encoding="utf-8")


def test_codeguard_cli_conflict_exits_nonzero(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cfg = _cfg("cursor", tmp_path)
    rule = tmp_path / ".cursor" / "rules" / "codeguard.mdc"
    rule.parent.mkdir(parents=True)
    rule.write_text("user-owned rule\n", encoding="utf-8")
    app = AppContext()
    app.cfg = cfg

    result = CliRunner().invoke(
        codeguard,
        ["install", "--connector", "cursor", "--target", "rule"],
        obj=app,
    )

    assert result.exit_code != 0
    assert "conflict at " in result.output
    assert "use --replace" in result.output


def test_ensure_codeguard_skill_is_noop(tmp_path):
    ensure_codeguard_skill(str(tmp_path / ".openclaw"), str(tmp_path / ".openclaw" / "openclaw.json"))
    assert not (tmp_path / ".openclaw" / "skills" / "codeguard").exists()
