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

"""Empty image-store locks do not require OpenShell teardown at uninstall."""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from click.testing import CliRunner
from defenseclaw.commands import cmd_uninstall

pytestmark = pytest.mark.skipif(os.name == "nt", reason="per-user OpenShell uninstall runs on Linux and macOS")


@pytest.fixture()
def install(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    home = tmp_path / "home"
    data_dir = home / ".defenseclaw"
    bin_dir = home / ".local" / "bin"
    data_dir.mkdir(parents=True)
    bin_dir.mkdir(parents=True)
    config_file = data_dir / "config.yaml"
    config_file.write_text("openshell:\n  enabled: false\n", encoding="utf-8")
    calls = tmp_path / "gateway-calls"
    gateway = bin_dir / "defenseclaw-gateway"
    gateway.write_text(
        "#!/bin/sh\n"
        'printf "%s\\n" "$*" >> "$DC_TEST_GATEWAY_CALLS"\n'
        'if [ "$1" = sandbox ] && [ "$2" = list ]; then\n'
        '  if [ "${DC_TEST_LIST_OK:-}" = 1 ]; then\n'
        '    printf "%s\\n" \'{"sandboxes":[]}\'\n'
        "    exit 0\n"
        "  fi\n"
        '  printf "%s\\n" \'{"available": false, "enabled": false, "reason": "OpenShell sandboxes are off"}\'\n'
        "  printf \"%s\\n\" '✗ OpenShell sandboxes are off; run `defenseclaw sandbox setup` to turn them on' >&2\n"
        "  exit 1\n"
        "fi\n"
        'if [ "$1" = sandbox ] && [ "$2" = teardown ] && [ "$3" = --help ]; then\n'
        '  printf "%s\\n" --keep-images\n'
        "  exit 0\n"
        "fi\n"
        # The off-state dry run names what OpenShell still has (GAP-0765).
        'if [ "$1" = sandbox ] && [ "$2" = teardown ] && [ "$3" = --dry-run ]; then\n'
        '  printf "%s\\n" "Sandbox teardown" "sandboxes         ${DC_TEST_TEARDOWN_SANDBOXES:-kept}"\n'
        "  exit 0\n"
        "fi\n"
        'if [ "$1" = sandbox ] && [ "$2" = teardown ]; then exit 0; fi\n'
        "exit 0\n",
        encoding="utf-8",
    )
    gateway.chmod(0o755)
    cli = bin_dir / "defenseclaw"
    cli.write_text("launcher\n", encoding="utf-8")
    cfg = SimpleNamespace(openshell=SimpleNamespace(enabled=False, wrappers=[]))

    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    monkeypatch.delenv("XDG_STATE_HOME", raising=False)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
    monkeypatch.setenv("DC_TEST_GATEWAY_CALLS", str(calls))
    monkeypatch.delenv("DC_TEST_LIST_OK", raising=False)
    monkeypatch.delenv("DC_TEST_TEARDOWN_SANDBOXES", raising=False)
    monkeypatch.setattr(cmd_uninstall.config_module, "default_data_path", lambda: data_dir)
    monkeypatch.setattr(cmd_uninstall.config_module, "config_path_for_data_dir", lambda _=None: config_file)
    monkeypatch.setattr(cmd_uninstall.config_module, "load", lambda **_: cfg)
    monkeypatch.setattr(cmd_uninstall, "tui_lock_held", lambda _: False)
    monkeypatch.setattr(cmd_uninstall, "_hook_temp_dirs", lambda _: ())
    # Keep ancillary cleanup within this fixture; data and binary removal
    # still run through the real command path.
    for name in (
        "_stop_gateway",
        "_remove_orphan_copilot_plugin",
        "_remove_mcp_writer_backups",
        "_remove_legacy_codex_candidate",
        "_remove_empty_plugin_cache",
        "remove_own_api_port_claims",
    ):
        monkeypatch.setattr(cmd_uninstall, name, lambda *_, **__: None)
    return SimpleNamespace(
        home=home,
        data_dir=data_dir,
        bin_dir=bin_dir,
        config_file=config_file,
        calls=calls,
        gateway=gateway,
        cli=cli,
        cfg=cfg,
    )


def _calls(install: SimpleNamespace) -> list[str]:
    return install.calls.read_text(encoding="utf-8").splitlines() if install.calls.exists() else []


@pytest.mark.parametrize("layout", ["lock", "empty", "manager-and-lock", "nested-empty", "empty-config-dir"])
def test_uninstall_empty_sandbox_state_needs_no_teardown(install: SimpleNamespace, layout: str) -> None:
    sandboxes = install.data_dir / "sandboxes"
    sandboxes.mkdir()
    if layout != "empty":
        (sandboxes / "images.json.lock").touch()
    if layout == "manager-and-lock":
        (sandboxes / "manager").mkdir()
    if layout == "nested-empty":
        (sandboxes / "nested" / "empty").mkdir(parents=True)
    if layout == "empty-config-dir":
        (install.home / ".config" / "openshell").mkdir(parents=True)

    dry = CliRunner().invoke(cmd_uninstall.uninstall_cmd, ["--all", "--binaries", "--dry-run"])
    assert dry.exit_code == 0, dry.output
    assert "sandbox teardown:    no (no OpenShell sandbox state)" in dry.output
    assert _calls(install) == []

    result = CliRunner().invoke(cmd_uninstall.uninstall_cmd, ["--all", "--binaries", "--yes"])
    assert result.exit_code == 0, result.output
    assert "the sandbox list could not be read" not in result.output
    assert _calls(install) == []  # neither sandbox list nor teardown ran
    assert not install.data_dir.exists()  # includes the empty lock
    assert not install.gateway.exists()
    assert not install.cli.exists()


@pytest.mark.parametrize(
    "state",
    [
        "record",
        "images",
        "vm-disk",
        "openshell-state",
        "gateway-config",
        "empty-gateway-config",
        "xdg-gateway-config",
        "xdg-state",
        "enabled",
        "wrappers",
    ],
)
def test_real_state_still_refuses_unreadable_list_and_skip_works(
    install: SimpleNamespace, monkeypatch: pytest.MonkeyPatch, state: str
) -> None:
    sandboxes = install.data_dir / "sandboxes"
    sandboxes.mkdir()
    (sandboxes / "images.json.lock").touch()
    if state == "record":
        manager = sandboxes / "manager"
        manager.mkdir()
        (manager / "kept.json").write_text("{}", encoding="utf-8")
    elif state == "images":
        (sandboxes / "images.json").write_text('{"images":[]}', encoding="utf-8")
    elif state == "vm-disk":
        disk = install.home / ".local" / "state" / "openshell" / "vm-driver"
        disk.mkdir(parents=True)
        (disk / "disk.img").write_bytes(b"disk")
    elif state == "openshell-state":
        (install.home / ".local" / "state" / "openshell").mkdir(parents=True)
    elif state == "gateway-config":
        config_dir = install.home / ".config" / "openshell"
        config_dir.mkdir(parents=True)
        (config_dir / "gateway.toml").write_text("[openshell]\n", encoding="utf-8")
    elif state == "empty-gateway-config":
        config_dir = install.home / ".config" / "openshell"
        config_dir.mkdir(parents=True)
        (config_dir / "gateway.toml").touch()
    elif state == "xdg-gateway-config":
        config_home = install.home / "xdg-config"
        config_dir = config_home / "openshell"
        config_dir.mkdir(parents=True)
        (config_dir / "gateway.env").write_text("OPENSHELL_LOG=info\n", encoding="utf-8")
        monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))
    elif state == "xdg-state":
        state_home = install.home / "xdg-state"
        (state_home / "openshell").mkdir(parents=True)
        monkeypatch.setenv("XDG_STATE_HOME", str(state_home))
    elif state == "enabled":
        install.cfg.openshell.enabled = True
        install.config_file.write_text("openshell:\n  enabled: true\n", encoding="utf-8")
    elif state == "wrappers":
        install.cfg.openshell.wrappers = ["claude"]

    result = CliRunner().invoke(cmd_uninstall.uninstall_cmd, ["--all", "--binaries", "--yes"])
    assert result.exit_code == 1, result.output
    assert "the sandbox list could not be read (`sandbox list` failed: OpenShell sandboxes are off" in result.output
    assert "nothing was changed" in result.output
    assert install.data_dir.exists() and (sandboxes / "images.json.lock").exists()
    assert install.gateway.exists() and install.cli.exists()
    assert _calls(install) == OFF_LIST_CALLS

    skipped = CliRunner().invoke(
        cmd_uninstall.uninstall_cmd, ["--all", "--binaries", "--skip-sandbox-teardown", "--yes"]
    )
    assert skipped.exit_code == 0, skipped.output
    assert "sandbox teardown:    skipped (--skip-sandbox-teardown)" in skipped.output
    assert not install.data_dir.exists()
    assert not install.gateway.exists() and not install.cli.exists()
    assert _calls(install) == OFF_LIST_CALLS


# The list says sandboxes are off; the dry run of the off-state teardown
# names a sandbox OpenShell still has, so the answer stays unknown.
OFF_LIST_CALLS = [
    "sandbox list --output json",
    "sandbox teardown --help",
    "sandbox teardown --dry-run",
    "sandbox teardown --help",
]


@pytest.mark.parametrize("plan", ["none", "nothing"])
def test_sandboxes_off_with_no_sandbox_left_uninstalls(
    install: SimpleNamespace, monkeypatch: pytest.MonkeyPatch, plan: str
) -> None:
    """GAP-0765: after `sandbox teardown` (sandboxes off, none left) the
    documented `uninstall --all --binaries --yes` goes on: off is no
    sandbox running when the off-state teardown finds none to delete."""
    (install.home / ".local" / "state" / "openshell").mkdir(parents=True)
    if plan == "none":
        monkeypatch.setenv("DC_TEST_TEARDOWN_SANDBOXES", "none")
    else:
        # A dry run with nothing at all prints only its "nothing to tear
        # down" line.
        script = install.gateway.read_text(encoding="utf-8").replace(
            '"sandboxes         ${DC_TEST_TEARDOWN_SANDBOXES:-kept}"', '"✓ nothing to tear down"'
        )
        install.gateway.write_text(script, encoding="utf-8")
    result = CliRunner().invoke(cmd_uninstall.uninstall_cmd, ["--all", "--binaries", "--yes"])
    assert result.exit_code == 0, result.output
    assert "the sandbox list could not be read" not in result.output
    assert "sandbox teardown --yes" in _calls(install)
    assert not install.data_dir.exists()
    assert not install.gateway.exists() and not install.cli.exists()


@pytest.mark.parametrize("trace", ["gateway-config", "openshell-state", "snapshots-and-shadows", "empty-manager"])
def test_uninstall_preserves_no_teardown_without_sandbox_entries(install: SimpleNamespace, trace: str) -> None:
    if trace in ("gateway-config", "empty-manager"):
        config_dir = install.home / ".config" / "openshell"
        config_dir.mkdir(parents=True)
        (config_dir / "gateway.toml").write_text("[openshell]\n", encoding="utf-8")
    if trace == "openshell-state":
        disk = install.home / ".local" / "state" / "openshell" / "vm-driver" / "disk.img"
        disk.parent.mkdir(parents=True)
        disk.write_bytes(b"disk")
    if trace == "snapshots-and-shadows":
        snapshot = install.data_dir / "snapshots" / "kept" / "snapshot.json"
        snapshot.parent.mkdir(parents=True)
        snapshot.write_text("{}", encoding="utf-8")
        shadow = install.data_dir / "shadows" / "project.git"
        shadow.parent.mkdir()
        shadow.write_text("git", encoding="utf-8")
    if trace == "empty-manager":
        (install.data_dir / "sandboxes" / "manager").mkdir(parents=True)

    result = CliRunner().invoke(cmd_uninstall.uninstall_cmd, ["--all", "--binaries", "--yes"])
    assert result.exit_code == 0, result.output
    assert _calls(install) == []
    assert not install.data_dir.exists()
    assert not install.gateway.exists() and not install.cli.exists()


def test_stop_sandboxes_still_runs_teardown(install: SimpleNamespace) -> None:
    manager = install.data_dir / "sandboxes" / "manager"
    manager.mkdir(parents=True)
    (manager / "kept.json").write_text("{}", encoding="utf-8")
    result = CliRunner().invoke(cmd_uninstall.uninstall_cmd, ["--all", "--binaries", "--stop-sandboxes", "--yes"])
    assert result.exit_code == 0, result.output
    assert "sandbox teardown --yes" in _calls(install)
    assert not install.data_dir.exists()


def test_real_state_with_readable_empty_list_still_runs_teardown(install: SimpleNamespace, monkeypatch) -> None:
    manager = install.data_dir / "sandboxes" / "manager"
    manager.mkdir(parents=True)
    (manager / "kept.json").write_text("{}", encoding="utf-8")
    monkeypatch.setenv("DC_TEST_LIST_OK", "1")
    result = CliRunner().invoke(cmd_uninstall.uninstall_cmd, ["--all", "--binaries", "--yes"])
    assert result.exit_code == 0, result.output
    assert _calls(install) == ["sandbox list --output json", "sandbox teardown --help", "sandbox teardown --yes"]


def test_reset_ignores_only_empty_sandbox_state(install: SimpleNamespace) -> None:
    sandboxes = install.data_dir / "sandboxes"
    sandboxes.mkdir()
    (sandboxes / "images.json.lock").touch()
    result = CliRunner().invoke(cmd_uninstall.reset_cmd, ["--yes"])
    assert result.exit_code == 0, result.output
    assert "sandbox teardown:    no (no OpenShell sandbox state)" in result.output
    assert _calls(install) == []
    assert not install.data_dir.exists()
    assert install.gateway.exists() and install.cli.exists()


def test_plain_uninstall_keeps_empty_lock_with_data(install: SimpleNamespace) -> None:
    sandboxes = install.data_dir / "sandboxes"
    sandboxes.mkdir()
    lock = sandboxes / "images.json.lock"
    lock.touch()
    result = CliRunner().invoke(cmd_uninstall.uninstall_cmd, ["--yes"])
    assert result.exit_code == 0, result.output
    assert "sandbox teardown:    no (no OpenShell sandbox state)" in result.output
    assert _calls(install) == []
    assert lock.exists() and install.data_dir.exists()
    assert install.gateway.exists() and install.cli.exists()


def test_sandbox_tree_state_scan_handles_empty_files_links_and_errors(tmp_path: Path) -> None:
    root = tmp_path / "sandboxes"
    root.mkdir()
    (root / "images.json.lock").touch()
    (root / "empty.json").touch()
    (root / "manager" / "nested").mkdir(parents=True)
    assert not cmd_uninstall._sandbox_tree_has_state(str(root))
    record = root / "manager" / "nested" / "record.json"
    record.write_text("{}", encoding="utf-8")
    assert cmd_uninstall._sandbox_tree_has_state(str(root))
    record.unlink()

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "record.json").write_text("{}", encoding="utf-8")
    (root / "linked").symlink_to(outside, target_is_directory=True)
    real_scandir = os.scandir

    def scan_without_following(path):
        assert Path(path) != outside
        return real_scandir(path)

    with patch.object(cmd_uninstall.os, "scandir", side_effect=scan_without_following):
        assert cmd_uninstall._sandbox_tree_has_state(str(root))
    (root / "linked").unlink()

    with patch.object(cmd_uninstall.os, "access", return_value=False):
        assert cmd_uninstall._sandbox_tree_has_state(str(root))

    def unreadable(path):
        if Path(path) == root / "manager":
            raise PermissionError("unreadable sandbox directory")
        return real_scandir(path)

    with patch.object(cmd_uninstall.os, "scandir", side_effect=unreadable):
        assert cmd_uninstall._sandbox_tree_has_state(str(root))


def test_sandbox_state_helper_preserves_old_empty_tree_decision(
    install: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_dir = install.home / ".config" / "openshell"
    config_dir.mkdir(parents=True)
    (config_dir / "gateway.toml").write_text("[openshell]\n", encoding="utf-8")

    def present() -> bool:
        return cmd_uninstall._sandbox_state_present(install.cfg, str(install.data_dir), "linux")

    assert not present()  # No sandboxes entry: external config alone is not a trigger.

    manager = install.data_dir / "sandboxes" / "manager"
    manager.mkdir(parents=True)
    assert not present()  # The old preflight ignored one empty manager directory.
    lock = manager.parent / "images.json.lock"
    lock.touch()
    assert present()  # A marker with gateway config still requests teardown.

    lock.unlink()
    (manager / "nested").mkdir()
    assert present()  # Nested empty directories used to count as state.
    (manager / "nested").rmdir()
    monkeypatch.setenv("XDG_CONFIG_HOME", "relative-config")
    assert not present()  # Relative XDG_CONFIG_HOME is not an independent trigger.
    lock.touch()
    assert present()
