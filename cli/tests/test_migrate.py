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

import hashlib
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
def v8_target(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin the target to config_version 8 so a test sees only the 0.x chain
    and the framework (the 8 -> 9 step is test_v8_config_runs_the_go_v9_step)."""
    from defenseclaw import config as config_module

    monkeypatch.setattr(config_module, "CURRENT_CONFIG_VERSION", 8)
    monkeypatch.setattr(migrations, "CONFIG_MIGRATIONS", {})


@pytest.fixture()
def recorded(monkeypatch: pytest.MonkeyPatch, v8_target: None) -> list[str]:
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
    config = _write_config(data_dir, "config_version: 10\n")

    with pytest.raises(ConfigTooNewError):
        migrate(str(data_dir), check=True)

    assert config.read_text(encoding="utf-8") == "config_version: 10\n"


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


def test_check_refuses_a_config_the_staged_gateway_would_refuse(data_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """GAP-0158: a stale custom_packs pin ends the upgrade check, before the installer swaps anything."""
    from defenseclaw import config_inspect

    _write_config(data_dir, "config_version: 9\n")
    seen: list[str | None] = []

    def validate(operation, *, gateway_binary=None, **_kwargs):
        seen.append(gateway_binary)
        raise config_inspect.ConfigInspectError(
            "candidate",
            field_path="$.guardrail",
            reason='[config_semantic_invalid] config rule pack "p0m": digest sha256:ab does not match '
            "guardrail.custom_packs.p0m.digest; fix the reference, then retry",
        )

    monkeypatch.setattr(config_inspect, "inspect_v8_config", validate)

    migrate(str(data_dir), check=True)
    assert seen == []
    with pytest.raises(MigrationError, match=r"would refuse your configuration: guardrail: digest sha256:ab does not match guardrail\.custom_packs\.p0m\.digest"):
        migrate(str(data_dir), check=True, gateway_binary="/staged/defenseclaw-gateway")
    assert seen == ["/staged/defenseclaw-gateway"]


def test_v8_update_check_preflight_uses_migrated_document(
    data_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _write_config(data_dir, "config_version: 8\nupdate_check: false\n")
    seen = []

    def preview(path: str, _gateway: str) -> None:
        seen.append(path)

    def reject_original(*_args) -> None:
        pytest.fail("the staged validator must not inspect unmigrated v8 keys")

    monkeypatch.setattr(migrations, "_preview_config_v9", preview)
    monkeypatch.setattr(migrations, "_check_staged_gateway_accepts", reject_original)
    result = migrate(str(data_dir), check=True, gateway_binary="/staged/defenseclaw-gateway")

    assert result.applied == ["config_version 8 → 9"]
    assert seen == [str(config)]


def test_failing_step_names_itself(data_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write_config(data_dir, "config_version: 7\n")

    def broken(ctx: migrations.MigrationContext) -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr(migrations, "MIGRATIONS", [("0.8.5", "hard cut", broken)])

    with pytest.raises(MigrationError, match=r"0\.8\.5.*boom"):
        migrate(str(data_dir), from_version="0.8.4")


def test_v8_config_runs_the_go_v9_step(
    data_dir: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from defenseclaw import config_inspect

    config = _write_config(data_dir, "config_version: 8\nobservability: {}\n")
    calls: list[str] = []

    def go_migrate(*, config_path: str, **_kwargs):
        calls.append(config_path)
        Path(config_path).write_text("config_version: 9\nobservability: {}\n", encoding="utf-8")
        moved = [{"to": "update.check"}, {"to": "asset_policy.mcp.denied", "value": "bad-mcp"}]
        record = {
            "moved": moved,
            "conflicts": [],
            "detection_only_rules": ["ACME-A", "ACME-B", "CUSTOM-CMD-SUDO"],
            "expressed_rules": ["CUSTOM-CMD-RM-RF", "ACME-LIT"],
            "renamed_rules": ["CMD-RM-RF -> CUSTOM-CMD-RM-RF", "CMD-SUDO -> CUSTOM-CMD-SUDO"],
            "rule_file_merges": ["/p/acme-1.0: rules/b.yaml (category \"acme\") merged into rules/a.yaml; 2 rule(s) kept"],
        }
        (data_dir / "migration-v9.json").write_text(json.dumps(record), encoding="utf-8")
        return {"migrated": True, "record": record}

    # GAP-1340: the servers a scan refuses to start are named; the bare
    # launchers with a package and URL entries are not.
    from types import SimpleNamespace

    from defenseclaw import config as config_module
    from defenseclaw.config import MCPServerEntry

    servers = {
        "claudecode": [
            MCPServerEntry(name="u33a-mcp", command="/usr/bin/true"),
            MCPServerEntry(name="rel", command="./srv.sh"),
            MCPServerEntry(name="binsrv", command="bin/srv"),
            MCPServerEntry(name="win", command="C:\\tools\\srv.exe"),
            MCPServerEntry(name="pathnpx", command="/opt/homebrew/bin/npx", args=["-y", "pkg"]),
            MCPServerEntry(name="launcher", command="npx", args=["-y", "pkg"]),
            MCPServerEntry(name="bare-uvx", command="uvx", args=["pkg"]),
            MCPServerEntry(name="web", url="https://mcp.example.com/mcp"),
            MCPServerEntry(name="bad-mcp", command="/usr/bin/false"),
        ],
        "codex": [MCPServerEntry(name="u33a-mcp", command="/usr/bin/true")],
    }
    cfg = SimpleNamespace(
        active_connectors=lambda: ["claudecode", "codex"],
        mcp_servers=lambda connector: servers[connector],
        gateway=SimpleNamespace(watcher=SimpleNamespace(mcp=SimpleNamespace(take_action=True))),
    )
    monkeypatch.setattr(config_module, "load", lambda **_kwargs: cfg)
    monkeypatch.setattr(config_inspect, "migrate_config_v9", go_migrate)
    monkeypatch.setattr(migrations, "_refresh_local_observability_bundle", lambda *_args: None)

    result = migrate(str(data_dir), from_version="1.0.0")

    assert calls == [str(config)]
    assert result.applied == ["config_version 8 → 9"]
    assert result.to_config_version == 9
    out = capsys.readouterr().out
    # GAP-1225: the upgrade names the custom rules that stopped blocking tool calls.
    assert "3 custom rule(s) now detection-only for tool calls: ACME-A, ACME-B, CUSTOM-CMD-SUDO" in out
    # GAP-1314: an edited built-in is named by both IDs, with what it does now.
    assert "3 rule(s) of your custom pack changed by the 1.0 upgrade" in out
    assert (
        "CUSTOM-CMD-RM-RF (your edited CMD-RM-RF; CMD-RM-RF is the shipped 1.0 rule): enforced as on 0.8.x (its "
        "severity decides block or alert) when the text of a tool call holds its literal" in out
    )
    # GAP-1478: a literal rule blocks its literal anywhere in the call, as on 0.8.x.
    assert "ACME-LIT: enforced as on 0.8.x (its severity decides block or alert) when the text of a tool call" in out
    assert "CUSTOM-CMD-SUDO (your edited CMD-SUDO; CMD-SUDO is the shipped 1.0 rule): detection-only" in out
    # GAP-1339: the summary says which rule files of one category were merged.
    assert 'rule pack /p/acme-1.0: rules/b.yaml (category "acme") merged into rules/a.yaml; 2 rule(s) kept' in out
    # GAP-1227: the summary names the MCP servers the upgrade keeps blocked.
    assert "MCP servers that stay blocked (asset_policy.mcp.denied): bad-mcp" in out
    expected = [
        ("u33a-mcp", "claudecode"), ("rel", "claudecode"), ("binsrv", "claudecode"),
        ("win", "claudecode"), ("pathnpx", "claudecode"), ("u33a-mcp", "codex"),
    ]
    assert "MCP servers that can no longer be scanned (6)" in out
    named = re.findall(r"^\s*\S+ +(\S+) \((\w+)\): command ", out, re.MULTILINE)
    assert named == expected
    rows = json.loads((data_dir / "migration-v9.json").read_text(encoding="utf-8"))["unscannable_mcp"]
    assert [(row["name"], row["connector"]) for row in rows] == expected
    assert rows[0]["runtime_effect"].startswith("still runs, without a scan")
    assert rows[0]["fix"] == (
        "defenseclaw mcp set u33a-mcp --command npx --args <package> --connector claudecode (or --url <url>)"
    )
    assert rows[4]["fix"] == "defenseclaw mcp set pathnpx --command npx --args '[\"-y\", \"pkg\"]' --connector claudecode"

    from defenseclaw.commands import cmd_doctor

    result = cmd_doctor._DoctorResult()
    cmd_doctor._check_unscannable_mcp(cfg, {"unscannable_mcp": rows}, result)
    warned = [(c["label"], c["remediation"]) for c in result.checks if c["status"] == "warn"]
    assert [label for label, _ in warned] == [f"MCP server {name} ({connector})" for name, connector in expected]
    assert warned[0][1] == rows[0]["fix"]


def test_secure_client_config_stays_on_v8_without_a_migration(data_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from defenseclaw import config_inspect

    body = "config_version: 8\ndeployment_mode: managed_enterprise\nenterprise:\n  profile: secure_client\nobservability: {}\n"
    config = _write_config(data_dir, body)
    monkeypatch.setattr(
        config_inspect, "migrate_config_v9", lambda **_kwargs: pytest.fail("a Secure Client config must not run the 8 -> 9 step")
    )
    monkeypatch.setattr(migrations, "_refresh_local_observability_bundle", lambda *_args: None)

    result = migrate(str(data_dir), from_version="1.0.0")

    assert result.applied == []
    assert result.to_config_version == 8
    assert config.read_text(encoding="utf-8") == body


def test_config_migrations_bump_the_version_line(data_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from defenseclaw import config as config_module

    config = _write_config(data_dir, "# operator comment\nconfig_version: 8\nguardrail:\n  mode: observe\n")
    seen: list[int] = []
    monkeypatch.setattr(config_module, "CURRENT_CONFIG_VERSION", 9)
    monkeypatch.setattr(migrations, "CONFIG_MIGRATIONS", {8: lambda ctx: seen.append(8)})
    monkeypatch.setattr(migrations, "_refresh_local_observability_bundle", lambda *_args: None)

    result = migrate(str(data_dir))

    assert seen == [8]
    assert result.to_config_version == 9
    assert config.read_text(encoding="utf-8") == "# operator comment\nconfig_version: 9\nguardrail:\n  mode: observe\n"


def test_missing_config_migration_step_is_an_error(data_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from defenseclaw import config as config_module

    _write_config(data_dir, "config_version: 8\n")
    monkeypatch.setattr(config_module, "CURRENT_CONFIG_VERSION", 9)
    monkeypatch.setattr(migrations, "CONFIG_MIGRATIONS", {})

    with pytest.raises(MigrationError, match="config_version 8 to 9"):
        migrate(str(data_dir))


def test_openclaw_home_comes_from_the_config(data_dir: Path, monkeypatch: pytest.MonkeyPatch, v8_target: None) -> None:
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


def test_installed_observability_bundle_is_refreshed(data_dir: Path, monkeypatch: pytest.MonkeyPatch, v8_target: None) -> None:
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


def test_bundle_refresh_failure_only_warns(data_dir: Path, monkeypatch: pytest.MonkeyPatch, v8_target: None) -> None:
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

    done = runner.invoke(migrate_cmd, ["--data-dir", str(data_dir), "--from-version", "0.8.4", "--json"])
    assert done.exit_code == 0, done.output
    payload = json.loads(done.stdout)
    assert "step 0.8.5" in done.stderr
    assert payload["applied"] == ["0.x import 0.8.5: step 0.8.5"]
    assert payload["from_config_version"] == 7
    assert payload["changed"] is True
    assert recorded == ["0.8.5"]


def test_upgrade_names_hooks_that_now_fail_open(data_dir: Path, recorded: list[str]) -> None:
    # 0.8.x sealed the global fail mode into observe-mode hooks. From 1.0.3
    # an observe-mode hook follows the global closed outside Secure Client,
    # so the upgrade keeps it closed and says nothing about fail-open.
    _write_config(data_dir, "config_version: 7\nguardrail:\n  mode: observe\n  hook_fail_mode: closed\n")
    lock = {"connectors": {"claudecode": {"hook_fail_mode": "closed"}, "codex": {"hook_fail_mode": "open"}}}
    (data_dir / "hook_contract_lock.json").write_text(json.dumps(lock), encoding="utf-8")

    result = CliRunner().invoke(migrate_cmd, ["--data-dir", str(data_dir), "--from-version", "0.8.4"])

    assert result.exit_code == 0, result.output
    assert "now fail open" not in result.output
    assert "codex" not in result.output

    # GAP-0276: a reinstall of a current config migrates nothing and says nothing.
    again = CliRunner().invoke(migrate_cmd, ["--data-dir", str(data_dir)])
    assert again.exit_code == 0, again.output
    assert "Configuration is current" in again.output
    assert "fail open" not in again.output


def test_upgrade_cursor_action_does_not_report_observe_fail_open(data_dir: Path, recorded: list[str]) -> None:
    _write_config(
        data_dir,
        "config_version: 8\nguardrail:\n  mode: action\n  connector: cursor\n"
        "  hook_fail_mode: open\n  connectors:\n    cursor:\n"
        "      mode: action\n      hook_fail_mode: open\n",
    )
    lock = {"connectors": {"cursor": {"hook_fail_mode": "closed"}}}
    (data_dir / "hook_contract_lock.json").write_text(json.dumps(lock), encoding="utf-8")

    result = CliRunner().invoke(migrate_cmd, ["--data-dir", str(data_dir)])

    assert result.exit_code == 0, result.output
    assert "cursor hooks now fail open" not in result.output


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
    migrate(str(data_dir), from_version="1.0.0")

    assert calls == [str(data_dir)]


def test_every_upgrade_seals_the_windows_hook_credentials(data_dir: Path, recorded: list[str], monkeypatch) -> None:
    # GAP-2207: 1.0.2 left .hook-amp/.hook-opencode/... tokens with an
    # inherited DACL; after a 1.0.2 -> 1.0.5 upgrade setup rotate-token
    # refused them, because only a 0.x import sealed them. A check changes
    # nothing.
    calls: list[str] = []
    monkeypatch.setattr(migrations, "_seal_windows_hook_credentials", calls.append)
    _write_config(data_dir, f"config_version: {migrations._FIRST_V8_CONFIG_VERSION}\n")

    migrate(str(data_dir), from_version="1.0.2", check=True)
    assert calls == []
    migrate(str(data_dir), from_version="1.0.2")
    migrate(str(data_dir), from_version="1.0.4")
    migrate(str(data_dir))

    assert calls == [str(data_dir)] * 3


def test_a_0x_import_with_a_v8_config_selects_the_windows_agents(
    data_dir: Path, recorded: list[str], monkeypatch
) -> None:
    # GAP-1390: 0.8.10 already writes config_version 8 but never recorded the
    # Codex executable, so the 1.x gateway refused Codex after the upgrade.
    calls: list[str] = []
    monkeypatch.setattr(migrations, "_select_windows_agents", calls.append)
    _write_config(data_dir, "config_version: 8\n")

    migrate(str(data_dir), from_version="0.8.10")

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


def test_0x_windows_hook_credentials_get_a_private_dacl(tmp_path: Path, monkeypatch) -> None:
    # GAP-0364: 0.8.10 left hook credentials with an inherited DACL, which
    # setup rotate-token refused after the upgrade, naming no file. Only a
    # file nobody untrusted can read is sealed; an exposed one is left.
    import click
    from defenseclaw import file_permissions
    from defenseclaw.commands import cmd_setup

    hooks = tmp_path / "hooks"
    hooks.mkdir()
    for name in (".hook-openclaw.token", ".otlp-codex.token", ".hook-exposed.token", ".hook-ok.token", ".hookcfg.lock"):
        (hooks / name).write_text("x", encoding="utf-8")
    exposed = str(hooks / ".hook-exposed.token")

    def custody(path, *, allow_inheritable=False):
        name = os.path.basename(path)
        if name == ".hook-ok.token" or (allow_inheritable and name != ".hook-exposed.token"):
            return None
        return "ACL grants read access to untrusted SID S-1-5-32-545" if allow_inheritable else "Windows DACL is inheritable"

    sealed: list[str] = []
    monkeypatch.setattr(file_permissions, "windows_acl_custody_confidentiality_error", custody)
    monkeypatch.setattr(file_permissions, "protect_private_file", lambda path: sealed.append(os.path.basename(path)))
    monkeypatch.setattr(os, "name", "nt")

    migrations._seal_windows_hook_credentials(str(tmp_path))

    assert sealed == [".hook-openclaw.token", ".otlp-codex.token"]
    monkeypatch.setattr(cmd_setup, "windows_acl_custody_confidentiality_error", custody)
    monkeypatch.setattr(cmd_setup, "reject_reparse_path", lambda _path: None)
    with pytest.raises(click.ClickException) as refused:
        cmd_setup._rotate_token_hook_metadata(exposed)
    assert f"The connector hook credential {exposed} is not private (Windows DACL is inheritable)" in refused.value.message
    assert f'icacls "{exposed}" /inheritance:r' in refused.value.message


def test_v8_preflight_converts_without_the_retired_0_5_0_keys(data_dir: Path, monkeypatch) -> None:
    body = b"config_version: 7\nguardrail:\n  mode: observe\n  codex_enforcement_enabled: true\n  claudecode_enforcement_enabled: false\n"
    # Bytes, so Windows does not translate the newlines.
    config = data_dir / "config.yaml"
    config.write_bytes(body)
    converted: list[bytes] = []

    class StopError(Exception):
        pass

    def convert(source, *_args, **_kwargs):
        converted.append(source)
        raise StopError

    monkeypatch.setattr(migrations, "convert_v7_observability_to_v8", convert)
    ctx = migrations.MigrationContext(openclaw_home="", data_dir=str(data_dir), from_version="", to_version="1.0.0")

    with pytest.raises(StopError):
        migrations._preflight_observability_v8(ctx, str(data_dir / "scratch"))

    assert converted == [b"config_version: 7\nguardrail:\n  mode: observe\n"]
    assert config.read_bytes() == body


def test_windows_agent_selection_reports_nothing_when_the_retry_fails(data_dir: Path, monkeypatch, capsys) -> None:
    from types import SimpleNamespace

    from defenseclaw import agent_selection, config

    monkeypatch.setattr(
        config,
        "load",
        lambda **_kwargs: SimpleNamespace(active_connectors=lambda: ["codex", "hermes"]),
    )
    calls: list[list[str]] = []

    def record(_data_dir, connectors):
        calls.append(list(connectors))
        found = {"codex": SimpleNamespace(executable=r"C:\\codex\\codex.exe")}
        return found, ({"hermes": "not installed"} if len(calls) == 1 else {"codex": "changed while probing"})

    monkeypatch.setattr(agent_selection, "record_setup_agent_selections", record)
    monkeypatch.setattr(os, "name", "nt")

    migrations._select_windows_agents(str(data_dir))

    out = capsys.readouterr().out
    assert "selected" not in out
    assert "run 'defenseclaw setup codex'" in out
    assert "run 'defenseclaw setup hermes'" in out


def test_windows_agent_selection_writes_no_receipt_without_a_native_agent(data_dir: Path, monkeypatch) -> None:
    from types import SimpleNamespace

    from defenseclaw import agent_selection, config

    monkeypatch.setattr(config, "load", lambda **_kwargs: SimpleNamespace(active_connectors=lambda: ["openclaw"]))
    monkeypatch.setattr(
        agent_selection,
        "record_setup_agent_selections",
        lambda *_args: pytest.fail("nothing to select, so no receipt"),
    )
    monkeypatch.setattr(os, "name", "nt")

    migrations._select_windows_agents(str(data_dir))


def test_cli_check_lists_pending_steps_as_pending(data_dir: Path, recorded: list[str]) -> None:
    # GAP-1117: --check names each step, uses no success tick, and its JSON
    # lists them under "pending" (nothing was applied).
    config = _write_config(data_dir, "config_version: 7\n")
    runner = CliRunner()

    text = runner.invoke(migrate_cmd, ["--data-dir", str(data_dir), "--from-version", "0.8.4", "--check"])
    assert text.exit_code == 0, text.output
    assert "1 migration step(s) pending (config_version 7 -> 8)" in text.stdout
    # GAP-1500: human output shows the step in user terms, no "0.x import" id.
    assert "step 0.8.5" in text.stdout
    assert "0.x import" not in text.stdout
    assert "✓" not in text.stdout

    js = runner.invoke(migrate_cmd, ["--data-dir", str(data_dir), "--from-version", "0.8.4", "--check", "--json"])
    assert js.exit_code == 0, js.output
    payload = json.loads(js.stdout)
    assert payload["pending"] == ["0.x import 0.8.5: step 0.8.5"]
    assert payload["applied"] == []
    assert config.read_text(encoding="utf-8") == "config_version: 7\n"


def test_cli_rejects_a_from_version_that_is_not_a_release(data_dir: Path, v8_target: None) -> None:
    # GAP-1449: --from-version banana is a usage error, not "current", rc 0.
    _write_config(data_dir, "config_version: 8\n")
    result = CliRunner().invoke(migrate_cmd, ["--data-dir", str(data_dir), "--check", "--from-version", "banana"])
    assert result.exit_code == 2
    assert "not a release version" in result.output
    ok = CliRunner().invoke(migrate_cmd, ["--data-dir", str(data_dir), "--check", "--from-version", "1.0.1.dev3"])
    assert ok.exit_code == 0, ok.output


def test_cli_check_omits_unchanged_version_range(data_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        migrations,
        "migrate",
        lambda *_args, **_kwargs: migrations.MigrateResult(
            from_config_version=9,
            to_config_version=9,
            applied=["update renamed and removed connectors"],
            changed=True,
        ),
    )
    result = CliRunner().invoke(migrate_cmd, ["--data-dir", str(data_dir), "--check"])
    assert result.exit_code == 0, result.output
    assert "1 migration step(s) pending (config_version 9):" in result.output
    assert "9 -> 9" not in result.output
    assert "update renamed and removed connectors" in result.output


# GAP-0163: a legacy custom-providers.json next to a config_version 9 file.


def _legacy_overlay(data_dir: Path, payload: dict) -> Path:
    path = data_dir / "custom-providers.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


@pytest.mark.parametrize(
    ("config", "overlay", "pending"),
    [
        ("config_version: 9\n", {"providers": [{"name": "acme-gw", "domains": ["alt.acme.test"]}]}, True),
        ("config_version: 9\n", {"providers": [], "ollama_ports": [11500]}, True),
        ("config_version: 9\n", {"_derived_from": "sha256:x", "providers": [{"name": "acme-gw"}]}, False),
        ("config_version: 9\n", {"providers": [{"name": "acme-gw", "request_overrides": {"x": 1}}]}, False),
        ("config_version: 9\ndeployment_mode: managed_enterprise\n", {"providers": [{"name": "acme-gw"}]}, False),
        ("config_version: 9\n", {"providers": []}, False),
    ],
)
def test_a_v9_config_with_a_legacy_provider_overlay_has_the_fold_step_pending(
    data_dir: Path, monkeypatch: pytest.MonkeyPatch, config: str, overlay: dict, pending: bool
) -> None:
    monkeypatch.delenv("DEFENSECLAW_DEPLOYMENT_MODE", raising=False)
    monkeypatch.setattr(migrations, "_connector_roster_pending", lambda *_args: False)
    _write_config(data_dir, config)
    _legacy_overlay(data_dir, overlay)

    result = migrate(str(data_dir), check=True)

    assert (migrations._PROVIDERS_FOLD_STEP_NAME in result.applied) is pending


def test_the_fold_step_warns_and_changes_nothing_when_fields_disagree(
    data_dir: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from defenseclaw import config_inspect

    monkeypatch.delenv("DEFENSECLAW_DEPLOYMENT_MODE", raising=False)
    monkeypatch.setattr(migrations, "_connector_roster_pending", lambda *_args: False)
    monkeypatch.setattr(migrations, "_refresh_local_observability_bundle", lambda *_args: None)
    monkeypatch.setattr(migrations, "_refresh_guardrail_profiles", lambda *_args: None)
    monkeypatch.setattr(migrations, "_refresh_rego_policies", lambda *_args: None)
    config = _write_config(data_dir, "config_version: 9\n")
    overlay = _legacy_overlay(data_dir, {"providers": [{"name": "acme-gw", "base_url": "https://legacy.test"}]})
    refusal = (
        f"{overlay} was not folded into config.yaml: config.yaml and the file set different values for "
        "acme-gw (base_url: config.yaml's value is in use). Neither file was changed"
    )
    calls: list[str] = []

    def go_migrate(*, config_path: str, dry_run: bool = False, ack: bool = False, gateway_binary=None) -> dict:
        calls.append(config_path)
        return {"migrated": False, "dry_run": False, "written": [], "record": {"from_version": 9},
                "providers_fold": {"overlay": str(overlay), "refused": refusal,
                                   "conflicts": [{"provider": "acme-gw", "fields": ["base_url"],
                                                  "in_use": {"base_url": "config.yaml"}}]}}

    monkeypatch.setattr(config_inspect, "migrate_config_v9", go_migrate)

    result = migrate(str(data_dir))

    assert calls == [str(config)]
    assert result.applied == [migrations._PROVIDERS_FOLD_STEP_NAME]
    out = capsys.readouterr().out
    assert "acme-gw (base_url: config.yaml's value is in use)" in out
    assert "Neither file was changed" in out
    assert "moved provider(s)" not in out


def test_the_fold_step_reports_the_providers_config_yaml_took(
    data_dir: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from defenseclaw import config_inspect

    monkeypatch.delenv("DEFENSECLAW_DEPLOYMENT_MODE", raising=False)
    monkeypatch.setattr(migrations, "_connector_roster_pending", lambda *_args: False)
    monkeypatch.setattr(migrations, "_refresh_local_observability_bundle", lambda *_args: None)
    monkeypatch.setattr(migrations, "_refresh_guardrail_profiles", lambda *_args: None)
    monkeypatch.setattr(migrations, "_refresh_rego_policies", lambda *_args: None)
    _write_config(data_dir, "config_version: 9\n")
    overlay = _legacy_overlay(data_dir, {"providers": [{"name": "acme-gw", "domains": ["alt.acme.test"]}]})
    retired = f"{overlay}.migrated-v9"
    monkeypatch.setattr(
        config_inspect,
        "migrate_config_v9",
        lambda **_kwargs: {"migrated": False, "dry_run": False, "written": [retired], "record": {"from_version": 9},
                           "providers_fold": {"overlay": str(overlay), "folded": ["acme-gw"], "retired": retired,
                                              "headers_after_fold": [{"provider": "openai",
                                                                      "fields": ["extra_headers.X-Team"]}]}},
    )

    result = migrate(str(data_dir))

    assert result.changed
    out = capsys.readouterr().out
    assert f"moved provider(s) acme-gw from {overlay} into config.yaml llm_providers.custom" in out
    assert retired in out
    # GAP-0184: the headers sent from now on are named, never their values.
    assert "the gateway now also sends openai (extra_headers.X-Team)" in out


# GAP-0137: a downgrade set openshell.trusted_ca_bundle aside (upgrade_shim);
# this release puts it back unless config.yaml sets it again, and keeps the
# keys of a later release for that release.
def _set_aside_record(data_dir: Path, keys: dict) -> Path:
    from defenseclaw.upgrade_shim import SET_ASIDE_FILE

    path = data_dir / SET_ASIDE_FILE
    path.write_text(json.dumps({"version": 1, "for": "1.0.2", "keys": keys}), encoding="utf-8")
    return path


def test_migrate_puts_back_the_keys_a_downgrade_set_aside(data_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import yaml

    for name in ("_refresh_local_observability_bundle", "_refresh_guardrail_profiles", "_refresh_rego_policies"):
        monkeypatch.setattr(migrations, name, lambda *_args: None)
    config = _write_config(data_dir, "config_version: 9\n")
    record = _set_aside_record(data_dir, {"openshell.trusted_ca_bundle": "~/proxy-root-ca.pem"})

    migrate(str(data_dir))

    assert yaml.safe_load(config.read_text(encoding="utf-8"))["openshell"]["trusted_ca_bundle"] == "~/proxy-root-ca.pem"
    assert not record.exists()



def test_migrate_puts_back_the_1_0_6_blocks_a_downgrade_set_aside(
    data_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import yaml

    for name in ("_refresh_local_observability_bundle", "_refresh_guardrail_profiles", "_refresh_rego_policies"):
        monkeypatch.setattr(migrations, name, lambda *_args: None)
    config = _write_config(data_dir, "config_version: 9\n")
    record = _set_aside_record(
        data_dir, {"guardrail.chains": {"root_scope": True}, "connectors": {"agent_gateway": {"enabled": True}}}
    )

    migrate(str(data_dir))

    restored = yaml.safe_load(config.read_text(encoding="utf-8"))
    assert restored["guardrail"]["chains"] == {"root_scope": True}
    assert restored["connectors"] == {"agent_gateway": {"enabled": True}}
    assert not record.exists()


def test_set_aside_keys_keep_a_value_set_again_and_a_later_release_key(data_dir: Path) -> None:
    import yaml

    config = _write_config(data_dir, "config_version: 9\nopenshell:\n  trusted_ca_bundle: /etc/corp/root.pem\n")
    record = _set_aside_record(
        data_dir, {"openshell.trusted_ca_bundle": "~/proxy-root-ca.pem", "openshell.future_key": True}
    )

    migrations._restore_set_aside_keys(str(data_dir), str(config))

    assert yaml.safe_load(config.read_text(encoding="utf-8"))["openshell"] == {"trusted_ca_bundle": "/etc/corp/root.pem"}
    assert json.loads(record.read_text(encoding="utf-8"))["keys"] == {"openshell.future_key": True}


def test_set_aside_key_that_cannot_be_put_back_is_named_with_its_command(
    data_dir: Path, capsys: pytest.CaptureFixture
) -> None:
    config = _write_config(data_dir, "config_version: 9\n")
    record = _set_aside_record(data_dir, {"openshell.trusted_ca_bundle": "relative.pem"})

    migrations._restore_set_aside_keys(str(data_dir), str(config))

    assert config.read_text(encoding="utf-8") == "config_version: 9\n"
    assert record.exists()
    captured = capsys.readouterr()
    assert "defenseclaw config set openshell.trusted_ca_bundle relative.pem" in captured.out + captured.err


def _sealed_codex_lock(data_dir: Path, exe: Path, digest: str) -> None:
    lock = {
        "version": 1,
        "connectors": {
            "codex": {
                "connector": "codex",
                "agent_executable_source": "setup-selected",
                "agent_executable": str(exe),
                "agent_executable_sha256": digest,
                "raw_agent_version": "codex-cli 0.160.0",
            }
        },
    }
    (data_dir / "hook_contract_lock.json").write_text(json.dumps(lock), encoding="utf-8")


def _reselect_fixture(data_dir: Path, monkeypatch, *, mode: str = ""):
    from types import SimpleNamespace

    from defenseclaw import agent_selection, config

    exe = data_dir / "codex.exe"
    exe.write_bytes(b"codex 0.160.0")
    _sealed_codex_lock(data_dir, exe, hashlib.sha256(b"codex 0.160.0").hexdigest())
    monkeypatch.setattr(
        config,
        "load",
        lambda **_kwargs: SimpleNamespace(active_connectors=lambda: ["codex", "claudecode"], deployment_mode=mode),
    )
    monkeypatch.delenv(config.DEPLOYMENT_MODE_ENV, raising=False)

    def digest(path: str) -> str:
        # Plain open: pathlib refuses a Path once os.name says nt.
        with open(path, "rb") as handle:
            return hashlib.sha256(handle.read()).hexdigest()

    monkeypatch.setattr(agent_selection, "stable_executable_sha256", digest)
    requests: list[list[str]] = []

    def record(_data_dir, connectors):
        requests.append(list(connectors))
        return {"codex": SimpleNamespace(executable=str(exe), raw_version="codex-cli 0.165.0")}, {}

    monkeypatch.setattr(agent_selection, "record_setup_agent_selections", record)
    monkeypatch.setattr(os, "name", "nt")
    return exe, requests


def test_an_upgrade_selects_again_a_windows_agent_that_updated_itself(data_dir: Path, monkeypatch, capsys) -> None:
    # GAP-2513: Codex updated itself (npm 0.159.3 -> 0.165.0) after setup, so
    # its sealed SHA-256 no longer matched and the upgrade restored the old
    # install with the gateway stopped. The upgrade now records the selection
    # setup codex records, for the changed agent only.
    exe, requests = _reselect_fixture(data_dir, monkeypatch)
    exe.write_bytes(b"codex 0.165.0")

    migrations.reselect_updated_windows_agents(str(data_dir))

    assert requests == [["codex"]]
    out = capsys.readouterr().out
    assert "codex changed since DefenseClaw set it up" in out
    assert f"selected {exe} (codex-cli 0.165.0) for the codex connector" in out


def test_an_upgrade_keeps_the_sealed_lock_of_an_unchanged_windows_agent(data_dir: Path, monkeypatch) -> None:
    _exe, requests = _reselect_fixture(data_dir, monkeypatch)

    migrations.reselect_updated_windows_agents(str(data_dir))

    assert requests == []


def test_a_managed_upgrade_does_not_select_an_updated_windows_agent(data_dir: Path, monkeypatch) -> None:
    exe, requests = _reselect_fixture(data_dir, monkeypatch, mode="managed_enterprise")
    exe.write_bytes(b"codex 0.165.0")

    migrations.reselect_updated_windows_agents(str(data_dir))

    assert requests == []


def test_every_upgrade_checks_the_windows_agents_setup_selected(
    data_dir: Path, recorded: list[str], monkeypatch
) -> None:
    reselected: list[str] = []
    selected: list[str] = []
    monkeypatch.setattr(migrations, "reselect_updated_windows_agents", reselected.append)
    monkeypatch.setattr(migrations, "_select_windows_agents", selected.append)
    _write_config(data_dir, "config_version: 7\n")

    migrate(str(data_dir), from_version="0.8.4")
    migrate(str(data_dir), from_version="1.0.4")

    assert selected == [str(data_dir)]
    assert reselected == [str(data_dir), str(data_dir)]


def test_the_rollback_reselect_entry_prints_its_warning_on_a_cp1252_console(data_dir: Path, monkeypatch) -> None:
    # GAP-2513 review: install.ps1 -Rollback ran the reselect through
    # 'python -c', which skips the CLI's console stream setup, so its
    # warning glyph raised UnicodeEncodeError on a cp1252 stream and a
    # traceback printed in the middle of a successful rollback. The installer
    # now runs 'defenseclaw migrate --reselect-updated-agents'.
    import io
    import sys

    from defenseclaw import main as main_module
    from defenseclaw import ux

    seen: list[str] = []

    def reselect(path: str) -> None:
        seen.append(path)
        ux.warn("codex changed since DefenseClaw set it up (an agent update does this)", indent="    ")

    monkeypatch.setattr(migrations, "reselect_updated_windows_agents", reselect)
    monkeypatch.setattr(ux, "_configured_unicode_output", None)
    monkeypatch.setattr(ux, "_configured_unicode_error_output", None)
    monkeypatch.setenv("COLUMNS", "120")
    out = io.TextIOWrapper(io.BytesIO(), encoding="cp1252", errors="strict")
    err = io.TextIOWrapper(io.BytesIO(), encoding="cp1252", errors="strict")
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", err)
    monkeypatch.setattr(
        sys, "argv", ["defenseclaw", "migrate", "--reselect-updated-agents", "--data-dir", str(data_dir)]
    )

    with pytest.raises(SystemExit) as exited:
        main_module.main()

    out.flush()
    err.flush()
    printed = out.buffer.getvalue().decode("utf-8") + err.buffer.getvalue().decode("utf-8")
    assert exited.value.code in (0, None), printed
    assert seen == [str(data_dir)]
    assert "codex changed since DefenseClaw set it up" in printed
    assert "Traceback" not in printed
    assert not (data_dir / "config.yaml").exists()


def test_the_rollback_selects_updated_agents_through_the_cli_entry() -> None:
    # GAP-2513 review: not 'python -c', which has no console stream setup.
    script = (Path(__file__).resolve().parents[2] / "scripts" / "install.ps1").read_text(encoding="utf-8")
    body = script[script.index("function Select-UpdatedAgents") :]
    body = body[: body.index("\n}\n")]
    assert '@("migrate", "--reselect-updated-agents", "--data-dir", $Data)' in body
    assert '"-c"' not in body
