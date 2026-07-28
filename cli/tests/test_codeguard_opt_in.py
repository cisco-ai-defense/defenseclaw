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

import os
import runpy
import shlex
import stat
from pathlib import Path
from types import SimpleNamespace
from unittest import skipUnless

from click.testing import CliRunner
from defenseclaw import commands as command_helpers
from defenseclaw import gateway
from defenseclaw.codeguard_skill import (
    codeguard_status,
    ensure_codeguard_skill,
    install_codeguard_asset,
)
from defenseclaw.commands.cmd_codeguard import codeguard
from defenseclaw.context import AppContext

from tests.permissions import assert_owner_only_directory


def _cfg(active: str, root, *, data_dir: str | None = None):
    return SimpleNamespace(
        active_connector=lambda: active,
        data_dir=data_dir or str(root / ".defenseclaw"),
        claw=SimpleNamespace(
            home_dir=str(root / ".openclaw"),
            config_file=str(root / ".openclaw" / "openclaw.json"),
        ),
    )


def _make_runnable(path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"gateway test fixture\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def _expected_scan_hint(executable) -> str:
    argv = (os.path.abspath(str(executable)), "scan", "code", "<path to scan>")
    if os.name == "nt":
        quoted = ("'" + arg.replace("'", "''") + "'" for arg in argv)
        command = "& " + " ".join(quoted)
        return f"Scan code now (PowerShell):  {command}"
    return f"Scan code now:  {shlex.join(argv)}"


def _capture_hints(monkeypatch) -> list[str]:
    captured: list[str] = []
    monkeypatch.setattr(command_helpers, "hint", lambda *lines: captured.extend(lines))
    return captured


def _load_bundled_codeguard_module(monkeypatch):
    monkeypatch.delenv("DEFENSECLAW_SIDECAR_URL", raising=False)
    repository_root = Path(__file__).resolve().parents[2]
    return runpy.run_path(str(repository_root / "skills" / "codeguard" / "main.py"))


def test_bundled_codeguard_validates_fixed_sidecar_endpoint(monkeypatch):
    module = _load_bundled_codeguard_module(monkeypatch)
    validate = module["_validated_scan_url"]
    loopback = "http://" + ".".join(("127", "0", "0", "1")) + ":18790"

    assert module["SIDECAR_URL"] == loopback
    assert validate(loopback) == loopback + "/api/v1/scan/code"
    assert (
        validate("https://sidecar.example.test:8443/")
        == "https://sidecar.example.test:8443/api/v1/scan/code"
    )


def test_bundled_codeguard_rejects_ambiguous_sidecar_origins(monkeypatch):
    module = _load_bundled_codeguard_module(monkeypatch)
    validate = module["_validated_scan_url"]

    for value in (
        "",
        " sidecar.example.test",
        "ftp://sidecar.example.test",
        "http://user:password@sidecar.example.test",
        "http://sidecar.example.test/prefix",
        "http://sidecar.example.test/?query=value",
        "http://sidecar.example.test/#fragment",
        "http://sidecar%2eexample.test",
        "http://sidecar.example.test\\redirect",
        "http://sidecar.example.test\n",
        "http://sidecar.example.test:0",
    ):
        assert validate(value) is None, value


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
    assert_owner_only_directory(archive_root.parent)


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


def test_codeguard_install_hint_uses_standard_absolute_gateway(tmp_path, monkeypatch):
    gateway_name = "defenseclaw-gateway.exe" if os.name == "nt" else gateway.GATEWAY_BIN_NAME
    trusted_dir = tmp_path / "Source Profile With Spaces" / ".local" / "bin"
    trusted_gateway = trusted_dir / gateway_name
    _make_runnable(trusted_gateway)

    hostile_dir = tmp_path / "hostile-current-directory"
    hostile_gateway = hostile_dir / gateway_name
    _make_runnable(hostile_gateway)
    monkeypatch.chdir(hostile_dir)
    monkeypatch.setenv("PATH", str(hostile_dir))
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex-home"))
    monkeypatch.delenv("DEFENSECLAW_INSTALL_ROOT", raising=False)
    monkeypatch.delenv("DEFENSECLAW_GATEWAY_BIN", raising=False)
    monkeypatch.setattr(gateway, "_CANONICAL_INSTALL_DIR", str(trusted_dir))
    monkeypatch.setattr(gateway.shutil, "which", lambda _name: str(hostile_gateway))
    hints = _capture_hints(monkeypatch)

    app = AppContext()
    app.cfg = _multi_cfg(["codex"], tmp_path)
    result = CliRunner().invoke(codeguard, ["install", "--target", "skill"], obj=app)

    assert result.exit_code == 0, result.output
    assert hints == [_expected_scan_hint(trusted_gateway)]
    assert str(hostile_gateway) not in hints[0]
    assert "defenseclaw scan code" not in hints[0]


def test_codeguard_install_hint_accepts_absolute_gateway_override(tmp_path, monkeypatch):
    gateway_name = "defenseclaw-gateway.exe" if os.name == "nt" else gateway.GATEWAY_BIN_NAME
    trusted_gateway = tmp_path / "Operator's Gateway" / gateway_name
    _make_runnable(trusted_gateway)

    hostile_dir = tmp_path / "hostile-current-directory"
    hostile_gateway = hostile_dir / gateway_name
    _make_runnable(hostile_gateway)
    monkeypatch.chdir(hostile_dir)
    monkeypatch.setenv("PATH", str(hostile_dir))
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex-home"))
    monkeypatch.delenv("DEFENSECLAW_INSTALL_ROOT", raising=False)
    monkeypatch.setenv("DEFENSECLAW_GATEWAY_BIN", str(trusted_gateway))
    monkeypatch.setattr(
        gateway,
        "_CANONICAL_INSTALL_DIR",
        str(tmp_path / "missing-profile" / ".local" / "bin"),
    )
    monkeypatch.setattr(gateway.shutil, "which", lambda _name: str(hostile_gateway))
    hints = _capture_hints(monkeypatch)

    app = AppContext()
    app.cfg = _multi_cfg(["codex"], tmp_path)
    result = CliRunner().invoke(codeguard, ["install-skill"], obj=app)

    assert result.exit_code == 0, result.output
    assert hints == [_expected_scan_hint(trusted_gateway)]
    assert str(hostile_gateway) not in hints[0]
    assert "defenseclaw scan code" not in hints[0]


@skipUnless(os.name == "nt", "native Windows package contract")
def test_codeguard_install_skill_hint_uses_packaged_sibling_over_path_shadow(tmp_path, monkeypatch):
    install_root = tmp_path / "Native Package With Spaces"
    packaged_python = install_root / "runtime" / "python" / "python.exe"
    packaged_gateway = install_root / "bin" / "defenseclaw-gateway.exe"
    _make_runnable(packaged_python)
    _make_runnable(packaged_gateway)

    hostile_dir = tmp_path / "hostile-current-directory"
    hostile_gateway = hostile_dir / "defenseclaw-gateway.exe"
    _make_runnable(hostile_gateway)
    monkeypatch.chdir(hostile_dir)
    monkeypatch.setenv("PATH", str(hostile_dir))
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex-home"))
    monkeypatch.setenv("DEFENSECLAW_INSTALL_ROOT", str(install_root))
    monkeypatch.setenv("DEFENSECLAW_GATEWAY_BIN", str(hostile_gateway))
    monkeypatch.setattr(gateway.sys, "executable", str(packaged_python))
    monkeypatch.setattr(gateway.shutil, "which", lambda _name: str(hostile_gateway))
    hints = _capture_hints(monkeypatch)

    app = AppContext()
    app.cfg = _multi_cfg(["codex"], tmp_path)
    result = CliRunner().invoke(codeguard, ["install-skill"], obj=app)

    assert result.exit_code == 0, result.output
    assert hints == [_expected_scan_hint(packaged_gateway)]
    assert str(hostile_gateway) not in hints[0]
    assert "defenseclaw scan code" not in hints[0]


@skipUnless(os.name == "nt", "native Windows package contract")
def test_codeguard_hint_uses_absolute_override_when_packaged_sibling_missing(
    tmp_path, monkeypatch
):
    install_root = tmp_path / "Damaged Native Package"
    packaged_python = install_root / "runtime" / "python" / "python.exe"
    _make_runnable(packaged_python)

    override_gateway = tmp_path / "Repair Tools" / "defenseclaw-gateway.exe"
    _make_runnable(override_gateway)
    hostile_dir = tmp_path / "hostile-current-directory"
    hostile_gateway = hostile_dir / "defenseclaw-gateway.exe"
    _make_runnable(hostile_gateway)

    monkeypatch.chdir(hostile_dir)
    monkeypatch.setenv("PATH", str(hostile_dir))
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex-home"))
    monkeypatch.setenv("DEFENSECLAW_INSTALL_ROOT", str(install_root))
    monkeypatch.setenv("DEFENSECLAW_GATEWAY_BIN", str(override_gateway))
    monkeypatch.setattr(gateway.sys, "executable", str(packaged_python))
    monkeypatch.setattr(gateway.shutil, "which", lambda _name: str(hostile_gateway))
    hints = _capture_hints(monkeypatch)

    app = AppContext()
    app.cfg = _multi_cfg(["codex"], tmp_path)
    result = CliRunner().invoke(codeguard, ["install-skill"], obj=app)

    assert result.exit_code == 0, result.output
    assert hints == [_expected_scan_hint(override_gateway)]
    assert str(hostile_gateway) not in hints[0]
    assert "defenseclaw scan code" not in hints[0]


def test_codeguard_install_hint_reports_unresolved_gateway(tmp_path, monkeypatch):
    hostile_dir = tmp_path / "hostile-current-directory"
    hostile_gateway = hostile_dir / gateway.GATEWAY_BIN_NAME
    _make_runnable(hostile_gateway)
    monkeypatch.chdir(hostile_dir)
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex-home"))
    monkeypatch.delenv("DEFENSECLAW_INSTALL_ROOT", raising=False)
    monkeypatch.setattr(
        gateway,
        "_CANONICAL_INSTALL_DIR",
        str(tmp_path / "missing-profile" / ".local" / "bin"),
    )
    hints = _capture_hints(monkeypatch)

    app = AppContext()
    app.cfg = _multi_cfg(["codex"], tmp_path)
    missing_gateway = tmp_path / "missing" / gateway.GATEWAY_BIN_NAME
    monkeypatch.setenv("DEFENSECLAW_GATEWAY_BIN", str(missing_gateway))
    monkeypatch.setattr(gateway.shutil, "which", lambda _name: str(hostile_gateway))

    result = CliRunner().invoke(codeguard, ["install", "--target", "skill"], obj=app)

    assert result.exit_code == 0, result.output
    assert len(hints) == 1
    assert "Code scan unavailable" in hints[0]
    assert "DEFENSECLAW_GATEWAY_BIN" in hints[0]
    assert "scan code" not in hints[0]
    assert "defenseclaw scan code" not in hints[0]

    for unresolved in (None, gateway.GATEWAY_BIN_NAME, "~/.local/bin/defenseclaw-gateway"):
        hints.clear()
        if unresolved is None:
            monkeypatch.delenv("DEFENSECLAW_GATEWAY_BIN", raising=False)
        else:
            monkeypatch.setenv("DEFENSECLAW_GATEWAY_BIN", unresolved)
        result = CliRunner().invoke(codeguard, ["install", "--target", "skill"], obj=app)

        assert result.exit_code == 0, result.output
        assert len(hints) == 1
        assert "Code scan unavailable" in hints[0]
        assert "DEFENSECLAW_GATEWAY_BIN" in hints[0]
        assert "scan code" not in hints[0]
        assert "defenseclaw scan code" not in hints[0]


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


def test_codeguard_install_skill_alias_fans_out_to_all_active_connectors(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    app = AppContext()
    app.cfg = _multi_cfg(["claudecode", "codex"], tmp_path)

    result = CliRunner().invoke(codeguard, ["install-skill"], obj=app)

    assert result.exit_code == 0, result.output
    install_lines = [ln for ln in result.output.splitlines() if ln.startswith("CodeGuard skill [")]
    assert len(install_lines) == 2, result.output
    assert "[claudecode]" in result.output
    assert "[codex]" in result.output


def test_codeguard_install_skill_alias_connector_flag_narrows_to_one(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    app = AppContext()
    app.cfg = _multi_cfg(["claudecode", "codex"], tmp_path)

    result = CliRunner().invoke(
        codeguard, ["install-skill", "--connector", "codex"], obj=app
    )

    assert result.exit_code == 0, result.output
    install_lines = [ln for ln in result.output.splitlines() if ln.startswith("CodeGuard skill [")]
    assert len(install_lines) == 1, result.output
    assert "[codex]" in result.output
    assert "[claudecode]" not in result.output


def test_codeguard_install_antigravity_skill_fans_out_with_peers(tmp_path, monkeypatch):
    # Antigravity exposes the AgentSkills folder form, so CodeGuard skill
    # installation should include it alongside the other active connectors.
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    app = AppContext()
    app.cfg = _multi_cfg(["antigravity", "claudecode", "codex"], tmp_path)

    result = CliRunner().invoke(codeguard, ["install", "--target", "skill"], obj=app)

    assert result.exit_code == 0, result.output
    assert "[antigravity]" in result.output
    assert "unsupported" not in result.output
    # the other supported connectors still get a line and the command succeeds
    assert "[claudecode]" in result.output
    assert "[codex]" in result.output
    assert "install failed" not in result.output
