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

"""Cross-process TUI config refresh regressions."""

from __future__ import annotations

import asyncio
import copy
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml
from defenseclaw import config as config_module
from defenseclaw.tui import app as app_module
from defenseclaw.tui.app import DefenseClawTUI
from defenseclaw.tui.panels.overview import EnforcementCounts
from defenseclaw.tui.panels.setup import SetupWizard
from defenseclaw.tui.services import config_watch
from defenseclaw.tui.services.config_watch import (
    ConfigChangeWatcher,
    probe_config_generation,
)
from textual.containers import VerticalScroll


def _config_payload(
    data_dir: Path,
    connectors: dict[str, dict[str, object]],
    *,
    primary: str = "claudecode",
    global_mode: str = "observe",
) -> dict[str, object]:
    return {
        "data_dir": str(data_dir),
        "claw": {"mode": primary},
        "guardrail": {
            "enabled": True,
            "connector": primary,
            "mode": global_mode,
            "connectors": connectors,
        },
    }


def _atomic_write(path: Path, payload: dict[str, object]) -> None:
    replacement = path.with_name(path.name + ".next")
    replacement.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    os.replace(replacement, path)


def _configure_active_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, payload: dict[str, object]) -> Path:
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    monkeypatch.setenv("DEFENSECLAW_CONFIG", str(path))
    return path


def _detach_ui(app: DefenseClawTUI, monkeypatch: pytest.MonkeyPatch) -> None:
    """Let model-level poll tests run without mounting Textual widgets."""

    monkeypatch.setattr(app, "_set_status", lambda message: setattr(app, "status_text", message))
    monkeypatch.setattr(app, "_write_activity", lambda message: app.activity_lines.append(message))
    monkeypatch.setattr(app, "_render_chrome", lambda: None)
    monkeypatch.setattr(app, "_schedule_active_panel_refresh", lambda _reason="": 0)
    monkeypatch.setattr(app, "_schedule_signal_data_refresh", lambda: None)
    monkeypatch.setattr(app, "_schedule_roster_catalog_refresh", lambda: None)


def test_atomic_replace_emits_one_generation(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("mode: observe\n", encoding="utf-8")
    watcher = ConfigChangeWatcher(path)

    replacement = tmp_path / "replacement.yaml"
    replacement.write_text("mode: action\n", encoding="utf-8")
    os.replace(replacement, path)

    generation = watcher.poll(now=1.0)
    assert generation is not None
    watcher.accept(generation)
    assert watcher.poll(now=2.0) is None


def test_same_size_rapid_in_place_updates_use_content_fallback(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("mode: one\n", encoding="utf-8")
    # Simulate a coarse filesystem where both timestamp fields remain equal.
    # Identity and size are also unchanged, leaving only the content digest.
    monkeypatch.setattr(config_watch, "_nanoseconds", lambda *_args: 7)
    watcher = ConfigChangeWatcher(path)

    path.write_text("mode: two\n", encoding="utf-8")
    assert watcher.poll(now=1.0) is None
    path.write_text("mode: six\n", encoding="utf-8")
    assert watcher.poll(now=2.0) is None
    generation = watcher.poll(now=3.0)

    assert generation is not None
    assert generation.digest == probe_config_generation(path).digest


def test_missing_or_locked_probe_keeps_generation_unavailable(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    path = tmp_path / "config.yaml"
    assert probe_config_generation(path) is None
    path.write_text("mode: observe\n", encoding="utf-8")
    original_open = Path.open

    def locked_open(self: Path, *args: object, **kwargs: object):
        if self == path:
            raise PermissionError("simulated sharing violation")
        return original_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", locked_open)
    assert probe_config_generation(path) is None


@pytest.mark.asyncio
async def test_external_mode_change_refreshes_without_health_and_without_duplicates(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    observe = _config_payload(tmp_path, {"claudecode": {"mode": "observe"}})
    path = _configure_active_path(monkeypatch, tmp_path, observe)
    app = DefenseClawTUI(config=config_module.load(), config_path=path)
    _detach_ui(app, monkeypatch)
    assert app.overview_model.health is None
    app.setup_model.queue_restart("existing operator restart")

    render_count = 0
    refresh_reasons: list[str] = []
    load_count = 0
    real_loader = app_module._load_config_generation

    def counted_loader(*args: object):
        nonlocal load_count
        load_count += 1
        return real_loader(*args)

    def counted_render() -> None:
        nonlocal render_count
        render_count += 1

    monkeypatch.setattr(app_module, "_load_config_generation", counted_loader)
    monkeypatch.setattr(app, "_render_chrome", counted_render)
    monkeypatch.setattr(
        app,
        "_schedule_active_panel_refresh",
        lambda reason="": refresh_reasons.append(reason) or len(refresh_reasons),
    )
    monkeypatch.setattr(app, "_set_status", lambda _message: None)
    # CLI-shaped single-connector update: connector override advances while
    # the inherited global mode remains observe.
    action = _config_payload(tmp_path, {"claudecode": {"mode": "action"}})
    _atomic_write(path, action)

    await app._poll_config_once(now=1.0)  # noqa: SLF001 - deterministic timer tick.
    await app._poll_config_once(now=2.0)  # unchanged generation.

    assert app.config.guardrail.effective_mode("claudecode") == "action"
    assert app.config.guardrail.mode == "observe"
    assert app.overview_model.cfg is not None
    assert app.overview_model.cfg.guardrail_mode == "action"
    assert app.setup_model.config is app.config
    assert app.setup_model.restart_queue.pending is True
    assert app._hint_status_model().policy_posture == "policy action"  # noqa: SLF001
    assert app.overview_model.health is None
    assert app._config_reload_count == 1  # noqa: SLF001
    assert load_count == 1
    assert render_count == 0
    assert refresh_reasons == ["config-generation"]


@pytest.mark.asyncio
async def test_multi_connector_add_disable_and_independent_policy_refresh(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    initial = _config_payload(
        tmp_path,
        {
            "claudecode": {"mode": "observe", "rule_pack_dir": "/packs/base"},
            "codex": {"mode": "action", "rule_pack_dir": "/packs/strict"},
        },
    )
    path = _configure_active_path(monkeypatch, tmp_path, initial)
    app = DefenseClawTUI(config=config_module.load(), config_path=path)
    _detach_ui(app, monkeypatch)
    app.overview_model.set_enforcement_counts(EnforcementCounts(total_scans=17, active_alerts=3))

    changed = _config_payload(
        tmp_path,
        {
            "claudecode": {"mode": "action", "rule_pack_dir": "/packs/strict"},
            "codex": {"mode": "observe", "rule_pack_dir": "/packs/base", "enabled": False},
            "cursor": {"mode": "observe", "rule_pack_dir": "/packs/cursor"},
        },
    )
    changed["asset_policy"] = {
        "skill": {"registry": [{"name": "corp-skill", "reason": "registry:corp"}]},
        "mcp": {"registry": [{"name": "corp-mcp", "reason": "registry:smithery"}]},
    }
    _atomic_write(path, changed)
    await app._poll_config_once(now=1.0)  # noqa: SLF001

    cfg = app.overview_model.cfg
    assert cfg is not None
    assert dict(cfg.connector_modes) == {
        "claudecode": "action",
        "codex": "observe",
        "cursor": "observe",
    }
    assert dict(cfg.connector_packs) == {
        "claudecode": "strict",
        "codex": "base",
        "cursor": "cursor",
    }
    assert cfg.connector_is_disabled("codex") is True
    assert app.overview_model.enforcement.total_scans == 17
    assert app.overview_model.enforcement.active_alerts == 3
    assert app.skills_model.connector == "claudecode"
    assert app.mcps_model.connector == "claudecode"
    assert app.plugins_model.connector == "claudecode"
    assert app.tools_model.connector == "claudecode"
    assert app.inventory_model.connector == "claudecode"
    assert app.skills_model.registry_by_name == {"corp-skill": "corp"}
    assert app.mcps_model.registry_by_name == {"corp-mcp": "smithery"}


@pytest.mark.asyncio
async def test_selected_connector_removal_falls_back_to_all_and_valid_primary(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    initial = _config_payload(
        tmp_path,
        {
            "claudecode": {"mode": "observe"},
            "codex": {"mode": "action"},
        },
    )
    path = _configure_active_path(monkeypatch, tmp_path, initial)
    app = DefenseClawTUI(config=config_module.load(), config_path=path)
    _detach_ui(app, monkeypatch)
    app.connector_filter = "codex"

    remaining = _config_payload(tmp_path, {"claudecode": {"mode": "action"}}, global_mode="action")
    _atomic_write(path, remaining)
    await app._poll_config_once(now=1.0)  # noqa: SLF001

    assert app.connector_filter == ""
    assert app._connector_filter() == ""  # noqa: SLF001
    assert app.overview_model.active_connector_name() == "claudecode"
    for model in (
        app.skills_model,
        app.mcps_model,
        app.plugins_model,
        app.tools_model,
        app.inventory_model,
    ):
        assert model.connector == "claudecode"
        assert model.connector_filter == ""


@pytest.mark.asyncio
async def test_external_data_dir_change_rebinds_all_file_backed_models(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    first_data = tmp_path / "data-one"
    second_data = tmp_path / "data-two"
    first_data.mkdir()
    second_data.mkdir()
    initial = _config_payload(first_data, {"claudecode": {"mode": "observe"}})
    path = _configure_active_path(monkeypatch, tmp_path, initial)
    app = DefenseClawTUI(config=config_module.load(), config_path=path)
    _detach_ui(app, monkeypatch)

    changed = _config_payload(second_data, {"claudecode": {"mode": "action"}})
    _atomic_write(path, changed)
    await app._poll_config_once(now=1.0)  # noqa: SLF001

    assert app.data_dir == second_data
    assert app.overview_model.cfg is not None
    assert app.overview_model.cfg.data_dir == str(second_data)
    assert app.setup_model.config.data_dir == str(second_data)
    assert app.logs_model.data_dir == second_data
    assert app.activity_model.data_dir == second_data
    assert app.alerts_model.data_dir == second_data
    assert app.registries_model.data_dir == str(second_data)
    assert app.state_store.path == second_data / "tui-state.json"


@pytest.mark.asyncio
async def test_malformed_then_valid_atomic_replacement_applies_once(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    initial = _config_payload(tmp_path, {"claudecode": {"mode": "observe"}})
    path = _configure_active_path(monkeypatch, tmp_path, initial)
    app = DefenseClawTUI(config=config_module.load(), config_path=path)
    _detach_ui(app, monkeypatch)

    malformed = path.with_name("malformed.yaml")
    malformed.write_text("guardrail: [\n", encoding="utf-8")
    os.replace(malformed, path)
    await app._poll_config_once(now=1.0)  # noqa: SLF001

    assert app.config.guardrail.effective_mode("claudecode") == "observe"
    assert app._config_reload_count == 0  # noqa: SLF001
    assert any("last valid snapshot" in line for line in app.activity_lines)

    valid = _config_payload(tmp_path, {"claudecode": {"mode": "action"}}, global_mode="action")
    _atomic_write(path, valid)
    await app._poll_config_once(now=2.0)  # noqa: SLF001
    await app._poll_config_once(now=3.0)  # harmless on filesystems that reuse identity.

    assert app.config.guardrail.effective_mode("claudecode") == "action"
    assert app._config_reload_count == 1  # noqa: SLF001


@pytest.mark.asyncio
async def test_partial_in_place_write_is_deferred_until_valid_and_stable(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    initial = _config_payload(tmp_path, {"claudecode": {"mode": "observe"}})
    path = _configure_active_path(monkeypatch, tmp_path, initial)
    app = DefenseClawTUI(config=config_module.load(), config_path=path)
    _detach_ui(app, monkeypatch)

    path.write_text("guardrail: [\n", encoding="utf-8")
    await app._poll_config_once(now=1.0)  # first same-identity observation only.
    assert app._config_reload_count == 0  # noqa: SLF001

    valid = _config_payload(tmp_path, {"claudecode": {"mode": "action"}}, global_mode="action")
    path.write_text(yaml.safe_dump(valid, sort_keys=False), encoding="utf-8")
    await app._poll_config_once(now=2.0)  # new candidate.
    assert app._config_reload_count == 0  # noqa: SLF001
    await app._poll_config_once(now=3.0)  # stable candidate.

    assert app.config.guardrail.effective_mode("claudecode") == "action"
    assert app._config_reload_count == 1  # noqa: SLF001


@pytest.mark.asyncio
async def test_external_refresh_preserves_active_setup_form_snapshot(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    initial = _config_payload(tmp_path, {"claudecode": {"mode": "observe"}})
    path = _configure_active_path(monkeypatch, tmp_path, initial)
    app = DefenseClawTUI(config=config_module.load(), config_path=path)
    _detach_ui(app, monkeypatch)
    app.setup_model.open_wizard_form(SetupWizard.GUARDRAIL)
    editable = next(
        index
        for index, field in enumerate(app.setup_model.form_fields)
        if field.kind not in {"section", "bool"} and not field.options
    )
    field = app.setup_model.form_fields[editable]
    app.setup_model.form_fields[editable] = field.with_value(field.value + " unsaved-draft")
    form_snapshot = copy.copy(app.setup_model.form_fields)

    changed = _config_payload(tmp_path, {"claudecode": {"mode": "action"}}, global_mode="action")
    _atomic_write(path, changed)
    await app._poll_config_once(now=1.0)  # noqa: SLF001

    assert app.setup_model.form_active is True
    assert app.setup_model.form_fields == form_snapshot
    assert app.setup_model.disk_change_pending is True
    assert app.setup_model.config is app.config
    assert app.config.guardrail.effective_mode("claudecode") == "action"
    assert "Config changed on disk" in app._setup_body_text()  # noqa: SLF001


@pytest.mark.asyncio
async def test_external_mode_refresh_preserves_filter_and_overview_scroll(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    initial = _config_payload(
        tmp_path,
        {
            "claudecode": {"mode": "observe"},
            "codex": {"mode": "action"},
            "cursor": {"mode": "observe"},
            "opencode": {"mode": "action"},
        },
    )
    path = _configure_active_path(monkeypatch, tmp_path, initial)
    app = DefenseClawTUI(config=config_module.load(), config_path=path)
    monkeypatch.setattr(app, "_schedule_health_poll", lambda: None)
    monkeypatch.setattr(app, "_schedule_ai_usage_poll", lambda: None)
    monkeypatch.setattr(app, "_schedule_credentials_refresh", lambda: None)

    async with app.run_test(size=(110, 18)) as pilot:
        app._set_connector_filter("codex")  # noqa: SLF001
        scroller = app.query_one("#body-scroll", VerticalScroll)
        scroller.scroll_to(y=min(8, scroller.max_scroll_y), animate=False, immediate=True)
        await pilot.pause()
        before = scroller.scroll_y
        assert before > 0

        changed = copy.deepcopy(initial)
        changed["guardrail"]["connectors"]["codex"]["mode"] = "observe"  # type: ignore[index]
        _atomic_write(path, changed)
        await app._poll_config_once(now=1.0)  # noqa: SLF001
        await pilot.pause()

        assert app._connector_filter() == "codex"  # noqa: SLF001
        assert scroller.scroll_y == before


@pytest.mark.skipif(os.name != "nt", reason="native Windows current-source acceptance")
@pytest.mark.allow_subprocess
@pytest.mark.asyncio
async def test_native_windows_open_tui_observes_external_cli_mode_change(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Two-terminal acceptance: an open TUI observes setup CLI replacement."""

    initial = _config_payload(tmp_path, {"claudecode": {"mode": "observe"}})
    path = _configure_active_path(monkeypatch, tmp_path, initial)
    app = DefenseClawTUI(config=config_module.load(), config_path=path)
    # This acceptance targets config polling, not network/process pollers.
    monkeypatch.setattr(app, "_schedule_health_poll", lambda: None)
    monkeypatch.setattr(app, "_schedule_ai_usage_poll", lambda: None)
    monkeypatch.setattr(app, "_schedule_credentials_refresh", lambda: None)
    monkeypatch.setattr(app, "_schedule_config_poll", lambda: None)

    isolated_home = tmp_path / "user-home"
    isolated_home.mkdir()
    environment = os.environ.copy()
    environment.update(
        {
            "DEFENSECLAW_CONFIG": str(path),
            "DEFENSECLAW_HOME": str(tmp_path),
            "HOME": str(isolated_home),
            "USERPROFILE": str(isolated_home),
        }
    )
    uv = shutil.which("uv")
    assert uv is not None
    command = (
        uv,
        "run",
        "--frozen",
        "defenseclaw",
        "setup",
        "claude-code",
        "--yes",
        "--mode",
        "action",
        "--no-restart",
    )

    async with app.run_test(size=(140, 45)) as pilot:
        assert app.overview_model.cfg is not None
        assert app.overview_model.cfg.guardrail_mode == "observe"
        result = await asyncio.to_thread(
            subprocess.run,
            command,
            cwd=Path(__file__).resolve().parents[3],
            env=environment,
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )
        output = result.stdout + result.stderr
        assert result.returncode == 0, output
        assert "Config saved" in output
        assert "Claude Code action setup" in output
        persisted = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert persisted["guardrail"]["connectors"]["claudecode"]["mode"] == "action"
        for poll_number in range(1, 4):
            # Exercise the same poll operation used by the one-second TUI
            # timer with deterministic intervals. Same-identity writes may
            # need two stable observations; atomic replacements need one.
            await app._poll_config_once(now=float(poll_number))  # noqa: SLF001
            if app.overview_model.cfg and app.overview_model.cfg.guardrail_mode == "action":
                break
            await pilot.pause()

        assert app.overview_model.cfg is not None
        assert app.overview_model.cfg.guardrail_mode == "action"
        assert app.config.guardrail.effective_mode("claudecode") == "action"
        assert app.setup_model.config is app.config
        assert app._config_reload_count == 1  # noqa: SLF001
