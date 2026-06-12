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


def _cfg(active: str, root, *, data_dir: str | None = None):
    return SimpleNamespace(
        active_connector=lambda: active,
        data_dir=data_dir or str(root / ".defenseclaw"),
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


# ---------------------------------------------------------------------------
# C-1: --replace must archive prior content under the data_dir backup root
# instead of silently rm-rf'ing it. Operator-authored skills/rules can take
# significant effort to write; an irreversible delete is unsafe behavior for
# a security tool.
# ---------------------------------------------------------------------------

def test_codeguard_rule_replace_archives_prior_content(tmp_path, monkeypatch):
    """``--replace`` must back up the previous file under data_dir/connector_backups."""
    import os
    from pathlib import Path

    monkeypatch.chdir(tmp_path)
    cfg = _cfg("cursor", tmp_path)
    rule = tmp_path / ".cursor" / "rules" / "codeguard.mdc"
    rule.parent.mkdir(parents=True)
    rule.write_text("HAND-WRITTEN OPERATOR RULE — DO NOT LOSE", encoding="utf-8")

    msg = install_codeguard_asset(
        cfg, connector="cursor", target="rule", replace=True
    )
    assert "previous content archived to " in msg, msg
    archive_root = Path(cfg.data_dir) / "connector_backups" / "codeguard"
    assert archive_root.is_dir(), f"archive root missing: {archive_root}"
    archived = list(archive_root.rglob("codeguard.mdc"))
    assert archived, f"no archived rule under {archive_root}"
    assert "HAND-WRITTEN OPERATOR RULE" in archived[0].read_text(encoding="utf-8")
    # Per-connector dir must not be world-readable — it leaks operator
    # state and the archived payload may carry intent the operator
    # considered private.
    mode = os.stat(archive_root.parent).st_mode & 0o777
    assert mode & 0o077 == 0, f"archive root group/world-readable: {oct(mode)}"


def test_codeguard_skill_replace_archives_prior_content(tmp_path, monkeypatch):
    """Skill-target ``--replace`` must archive the entire prior directory."""
    from pathlib import Path

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    cfg = _cfg("cursor", tmp_path)

    # First install creates the skill dir under the default user-global
    # cursor skill path; mutate it to look like a user-customized
    # payload that --replace must preserve.
    install_codeguard_asset(cfg, connector="cursor", target="skill")
    skill_root = tmp_path / "home" / ".cursor" / "skills" / "codeguard"
    assert skill_root.is_dir(), f"skill root missing: {skill_root}"
    user_artifact = skill_root / "USER_PATCH.md"
    user_artifact.write_text("operator customization", encoding="utf-8")

    msg = install_codeguard_asset(
        cfg, connector="cursor", target="skill", replace=True
    )
    assert "previous content archived to " in msg, msg
    archive_root = Path(cfg.data_dir) / "connector_backups" / "codeguard"
    archived = list(archive_root.rglob("USER_PATCH.md"))
    assert archived, "user artifact not archived under codeguard backup root"
    assert archived[0].read_text(encoding="utf-8") == "operator customization"


# ---------------------------------------------------------------------------
# Uniform-UX: `codeguard status` is a per-connector *read* command, so it must
# fan out over every active connector by default — the same loop rendering one
# line per connector whether one or N are active — matching skill/plugin/mcp
# list. `--connector X` narrows to a single validated peer.
# ---------------------------------------------------------------------------

def _multi_cfg(active: list[str], root):
    return SimpleNamespace(
        active_connector=lambda: sorted(active)[0],
        active_connectors=lambda: list(active),
        data_dir=str(root / ".defenseclaw"),
        claw=SimpleNamespace(
            home_dir=str(root / ".openclaw"),
            config_file=str(root / ".openclaw" / "openclaw.json"),
        ),
    )


def test_codeguard_status_lists_all_active_connectors(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    app = AppContext()
    app.cfg = _multi_cfg(["claudecode", "codex"], tmp_path)

    result = CliRunner().invoke(codeguard, ["status"], obj=app)

    assert result.exit_code == 0, result.output
    assert "[claudecode]" in result.output
    assert "[codex]" in result.output
    # One line per active connector — no single-vs-multi branching.
    status_lines = [ln for ln in result.output.splitlines() if ln.startswith("CodeGuard ")]
    assert len(status_lines) == 2, result.output


def test_codeguard_status_connector_flag_narrows_to_one(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    app = AppContext()
    app.cfg = _multi_cfg(["claudecode", "codex"], tmp_path)

    result = CliRunner().invoke(codeguard, ["status", "--connector", "codex"], obj=app)

    assert result.exit_code == 0, result.output
    assert "[codex]" in result.output
    assert "[claudecode]" not in result.output


def test_codeguard_status_single_connector_unchanged(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    app = AppContext()
    app.cfg = _multi_cfg(["cursor"], tmp_path)

    result = CliRunner().invoke(codeguard, ["status"], obj=app)

    assert result.exit_code == 0, result.output
    status_lines = [ln for ln in result.output.splitlines() if ln.startswith("CodeGuard ")]
    assert len(status_lines) == 1, result.output
    assert "[cursor]" in result.output


# ---------------------------------------------------------------------------
# Uniform-UX: `codeguard install` is a *mutating* command that, with no
# `--connector`, fans out over every active connector (matching `status`),
# so installing on a multi-connector box never silently lands on just the
# primary. `--connector X` scopes the install to one validated peer.
# ---------------------------------------------------------------------------

def test_codeguard_install_fans_out_to_all_active_connectors(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    app = AppContext()
    app.cfg = _multi_cfg(["claudecode", "codex"], tmp_path)

    result = CliRunner().invoke(codeguard, ["install", "--target", "skill"], obj=app)

    assert result.exit_code == 0, result.output
    # One install line per active connector — not just the primary.
    install_lines = [ln for ln in result.output.splitlines() if ln.startswith("CodeGuard skill [")]
    assert len(install_lines) == 2, result.output
    assert "[claudecode]" in result.output
    assert "[codex]" in result.output


def test_codeguard_install_connector_flag_narrows_to_one(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    app = AppContext()
    app.cfg = _multi_cfg(["claudecode", "codex"], tmp_path)

    result = CliRunner().invoke(
        codeguard, ["install", "--connector", "codex", "--target", "skill"], obj=app
    )

    assert result.exit_code == 0, result.output
    install_lines = [ln for ln in result.output.splitlines() if ln.startswith("CodeGuard skill [")]
    assert len(install_lines) == 1, result.output
    assert "[codex]" in result.output
    assert "[claudecode]" not in result.output


def test_codeguard_install_explicit_surface_only_connector(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    app = AppContext()
    app.cfg = _multi_cfg(["claudecode", "codex"], tmp_path)

    result = CliRunner().invoke(
        codeguard, ["install", "--connector", "scout", "--target", "skill"], obj=app
    )

    assert result.exit_code == 0, result.output
    assert "CodeGuard skill [scout]: installed to " in result.output
    assert (tmp_path / "home" / ".copilot" / "skills" / "codeguard").is_dir()
    assert "[claudecode]" not in result.output
    assert "[codex]" not in result.output


def test_codeguard_install_unsupported_connector_is_skip_not_failure(tmp_path, monkeypatch):
    # A connector with no skill install target (antigravity) must be reported
    # as "unsupported" but NOT fail the command when the other connectors
    # install successfully. antigravity sorts first in active_connectors().
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    app = AppContext()
    app.cfg = _multi_cfg(["antigravity", "claudecode", "codex"], tmp_path)

    result = CliRunner().invoke(codeguard, ["install", "--target", "skill"], obj=app)

    assert result.exit_code == 0, result.output
    assert "[antigravity]" in result.output
    assert "unsupported" in result.output
    # the supported connectors still get a line and the command succeeds
    assert "[claudecode]" in result.output
    assert "[codex]" in result.output
    assert "install failed" not in result.output
