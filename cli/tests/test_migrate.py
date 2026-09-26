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

"""Tests for ``defenseclaw migrate`` and :func:`defenseclaw.migrations.migrate`."""

from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path

import pytest
from click.testing import CliRunner
from defenseclaw import migrations
from defenseclaw.commands.cmd_migrate import migrate_cmd
from defenseclaw.migrations import ConfigTooNewError, MigrationError, migrate


@pytest.fixture()
def data_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.delenv("DEFENSECLAW_CONFIG", raising=False)
    root = tmp_path / "data"
    root.mkdir()
    return root


def _write_config(data_dir: Path, body: str) -> Path:
    path = data_dir / "config.yaml"
    path.write_text(body, encoding="utf-8")
    return path


@pytest.fixture()
def recorded(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Replace the frozen 0.x chain with recording steps."""

    calls: list[str] = []

    def step(version: str):
        def run(ctx: migrations.MigrationContext) -> None:
            calls.append(version)
            if version == "0.8.5":
                # Stands in for the real v8 conversion.
                path = Path(ctx.active_config_path())
                path.write_text(re.sub(r"(?m)^config_version: \d+", "config_version: 8", path.read_text()))

        return run

    chain = [(version, f"step {version}", step(version)) for version, _desc, _fn in migrations.MIGRATIONS]
    monkeypatch.setattr(migrations, "MIGRATIONS", chain)
    monkeypatch.setattr(migrations, "_refresh_local_observability_bundle", lambda *_args: None)
    return calls


def test_fresh_install_has_nothing_to_migrate(data_dir: Path) -> None:
    result = migrate(str(data_dir))

    assert result.from_config_version is None
    assert result.applied == []
    assert not result.changed


def test_current_config_is_a_no_op(data_dir: Path, recorded: list[str]) -> None:
    _write_config(data_dir, "config_version: 8\n")

    result = migrate(str(data_dir), from_version="0.8.10")

    assert result.from_config_version == 8
    assert result.applied == []
    assert recorded == []


def test_config_from_a_newer_release_is_refused(data_dir: Path) -> None:
    config = _write_config(data_dir, "config_version: 9\n")

    with pytest.raises(ConfigTooNewError):
        migrate(str(data_dir), check=True)

    assert config.read_text(encoding="utf-8") == "config_version: 9\n"


def test_v7_import_runs_only_steps_after_the_previous_version(data_dir: Path, recorded: list[str]) -> None:
    _write_config(data_dir, "config_version: 7\n")

    result = migrate(str(data_dir), from_version="0.8.4")

    assert recorded == ["0.8.5"]
    assert result.changed
    assert result.applied == ["0.x import 0.8.5: step 0.8.5"]


def test_v6_import_from_0_7_2_runs_the_0_8_0_step_first(data_dir: Path, recorded: list[str]) -> None:
    _write_config(data_dir, "config_version: 6\n")

    migrate(str(data_dir), from_version="0.7.2")

    assert recorded == ["0.8.0", "0.8.5"]


def test_legacy_cursor_decides_which_0x_steps_remain(data_dir: Path, recorded: list[str]) -> None:
    _write_config(data_dir, "config_version: 7\n")
    (data_dir / ".migration_state.json").write_text(
        json.dumps({"schema": 1, "applied": ["0.3.0", "0.4.0", "0.5.0", "0.7.0"]}),
        encoding="utf-8",
    )

    migrate(str(data_dir))

    # 0.8.0 was never recorded (for example it failed on an earlier upgrade),
    # so it is retried even though no --from-version was given.
    assert recorded == ["0.8.0", "0.8.5"]


def test_unknown_0x_origin_is_refused_before_any_step(data_dir: Path, recorded: list[str]) -> None:
    _write_config(data_dir, "config_version: 7\n")

    with pytest.raises(MigrationError, match="--from-version"):
        migrate(str(data_dir))

    assert recorded == []


def test_check_reports_without_running(data_dir: Path, recorded: list[str]) -> None:
    _write_config(data_dir, "config_version: 7\n")

    result = migrate(str(data_dir), from_version="0.8.4", check=True)

    assert recorded == []
    assert result.applied == ["0.x import 0.8.5: step 0.8.5"]
    assert not result.changed


def test_check_converts_a_scratch_copy_with_the_staged_gateway(
    data_dir: Path, recorded: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_config(data_dir, "config_version: 7\n")
    seen: dict[str, object] = {}

    def preflight(ctx, scratch, *, gateway_binary=None):
        seen["scratch"] = scratch
        seen["gateway"] = gateway_binary

    monkeypatch.setattr(migrations, "_preflight_observability_v8", preflight)

    migrate(str(data_dir), from_version="0.8.4", check=True, gateway_binary="/staged/defenseclaw-gateway")

    assert seen["gateway"] == "/staged/defenseclaw-gateway"
    assert str(seen["scratch"]).startswith(str(data_dir))
    assert not Path(str(seen["scratch"])).exists()


def test_failing_step_names_itself(data_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write_config(data_dir, "config_version: 7\n")

    def broken(ctx: migrations.MigrationContext) -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr(migrations, "MIGRATIONS", [("0.8.5", "hard cut", broken)])

    with pytest.raises(MigrationError, match=r"0\.8\.5.*boom"):
        migrate(str(data_dir), from_version="0.8.4")


def test_config_migrations_bump_the_version_line(data_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from defenseclaw import config as config_module

    config = _write_config(data_dir, "# operator comment\nconfig_version: 8\nguardrail:\n  enabled: true\n")
    seen: list[int] = []
    monkeypatch.setattr(config_module, "CURRENT_CONFIG_VERSION", 9)
    monkeypatch.setattr(migrations, "CONFIG_MIGRATIONS", {8: lambda ctx: seen.append(8)})
    monkeypatch.setattr(migrations, "_refresh_local_observability_bundle", lambda *_args: None)

    result = migrate(str(data_dir))

    assert seen == [8]
    assert result.to_config_version == 9
    assert config.read_text(encoding="utf-8") == "# operator comment\nconfig_version: 9\nguardrail:\n  enabled: true\n"


def test_missing_config_migration_step_is_an_error(data_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from defenseclaw import config as config_module

    _write_config(data_dir, "config_version: 8\n")
    monkeypatch.setattr(config_module, "CURRENT_CONFIG_VERSION", 9)
    monkeypatch.setattr(migrations, "CONFIG_MIGRATIONS", {})

    with pytest.raises(MigrationError, match="config_version 8 to 9"):
        migrate(str(data_dir))


def test_openclaw_home_comes_from_the_config(data_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write_config(data_dir, "config_version: 7\nclaw:\n  home_dir: /srv/openclaw\n")
    homes: list[str] = []
    monkeypatch.setattr(
        migrations,
        "MIGRATIONS",
        [("0.8.5", "hard cut", lambda ctx: homes.append(ctx.openclaw_home))],
    )
    monkeypatch.setattr(migrations, "_refresh_local_observability_bundle", lambda *_args: None)

    migrate(str(data_dir), from_version="0.8.4", check=True)

    assert homes == []
    with pytest.raises(MigrationError, match="config_version 7 after migrating"):
        migrate(str(data_dir), from_version="0.8.4")
    assert homes == ["/srv/openclaw"]


def test_installed_observability_bundle_is_refreshed(data_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from defenseclaw import bundle_refresh

    _write_config(data_dir, "config_version: 8\n")
    (data_dir / "observability-stack").mkdir()
    calls: list[tuple[str, str]] = []

    class Result:
        installed = True
        restart_required = False

    def upgrade(data, backup, *, bundle_version):
        calls.append((data, bundle_version))
        return Result()

    monkeypatch.setattr(bundle_refresh, "upgrade_local_observability_stack", upgrade)

    migrate(str(data_dir))

    assert len(calls) == 1
    assert calls[0][0] == str(data_dir)


def test_bundle_refresh_failure_only_warns(data_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from defenseclaw import bundle_refresh

    _write_config(data_dir, "config_version: 8\n")
    (data_dir / "observability-stack").mkdir()

    def upgrade(*_args, **_kwargs):
        raise bundle_refresh.LocalObservabilityUpgradeError("unsafe_install_root", "preflight")

    monkeypatch.setattr(bundle_refresh, "upgrade_local_observability_stack", upgrade)

    assert migrate(str(data_dir)).applied == []


def test_cli_exit_codes(data_dir: Path, recorded: list[str]) -> None:
    runner = CliRunner()

    _write_config(data_dir, "config_version: 9\n")
    too_new = runner.invoke(migrate_cmd, ["--data-dir", str(data_dir), "--check"])
    assert too_new.exit_code == 2

    _write_config(data_dir, "config_version: 7\n")
    unknown = runner.invoke(migrate_cmd, ["--data-dir", str(data_dir)])
    assert unknown.exit_code == 1

    done = runner.invoke(migrate_cmd, ["--data-dir", str(data_dir), "--from-version", "0.8.4", "--yes", "--json"])
    assert done.exit_code == 0, done.output
    payload = json.loads(done.stdout)
    assert "0.x import 0.8.5" in done.stderr
    assert payload["from_config_version"] == 7
    assert payload["changed"] is True
    assert recorded == ["0.8.5"]


def test_a_pre_v8_config_always_gets_the_v8_conversion(data_dir: Path, recorded: list[str]) -> None:
    # A cursor that claims 0.8.5 ran, beside a v7 config, must not skip the conversion.
    _write_config(data_dir, "config_version: 7\n")
    applied = [version for version, _desc, _fn in migrations.MIGRATIONS]
    (data_dir / ".migration_state.json").write_text(json.dumps({"applied": applied}))

    migrate(str(data_dir))

    assert recorded == ["0.8.5"]


@pytest.mark.skipif(os.name != "posix", reason="POSIX modes")
def test_a_group_writable_0x_config_is_made_private_before_importing(data_dir: Path, recorded: list[str]) -> None:
    config = _write_config(data_dir, "config_version: 7\n")
    config.chmod(0o664)

    migrate(str(data_dir), from_version="0.8.4")

    assert recorded == ["0.8.5"]
    assert stat.S_IMODE(config.stat().st_mode) == 0o600


def test_check_skips_the_v8_preflight_when_earlier_0x_steps_come_first(
    data_dir: Path, recorded: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # The conversion reads the config as it is; steps before it would change it.
    _write_config(data_dir, "config_version: 6\n")
    monkeypatch.setattr(migrations, "_preflight_observability_v8", lambda *_a, **_k: pytest.fail("preflight ran"))

    result = migrate(str(data_dir), from_version="0.7.2", check=True, gateway_binary="/staged/defenseclaw-gateway")

    assert result.applied[0].startswith("0.x import 0.8.0:")


def test_only_a_0x_import_selects_the_windows_agents(data_dir: Path, recorded: list[str], monkeypatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(migrations, "_select_windows_agents", calls.append)
    _write_config(data_dir, "config_version: 7\n")

    migrate(str(data_dir), from_version="0.8.4")
    migrate(str(data_dir))

    assert calls == [str(data_dir)]


def test_windows_agent_selection_keeps_the_agents_it_found(data_dir: Path, monkeypatch, capsys) -> None:
    from types import SimpleNamespace

    from defenseclaw import agent_selection, config

    monkeypatch.setattr(
        config,
        "load",
        lambda **_kwargs: SimpleNamespace(active_connectors=lambda: ["codex", "hermes"]),
    )
    requests: list[list[str]] = []

    def record(_data_dir, connectors):
        requests.append(list(connectors))
        found = {"codex": SimpleNamespace(executable=r"C:\codex\codex.exe")}
        return found, ({} if requests[1:] else {"hermes": "not installed"})

    monkeypatch.setattr(agent_selection, "record_setup_agent_selections", record)
    monkeypatch.setattr(os, "name", "nt")

    migrations._select_windows_agents(str(data_dir))

    assert requests == [["codex", "hermes"], ["codex"]]
    out = capsys.readouterr().out
    assert r"selected C:\codex\codex.exe for the codex connector" in out
    assert "run 'defenseclaw setup hermes'" in out
