# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""App-shell refresh and command plumbing: background polls, repository refresh, mutation reloads."""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest
from defenseclaw.models import Counts
from defenseclaw.tui.app import (
    DefenseClawTUI,
    _catalog_panel_invalidated_by_command,
    _fetch_ai_usage,
)
from defenseclaw.tui.panels.alerts import AlertEvent, AlertsPanelModel
from defenseclaw.tui.panels.audit import AuditPanelModel
from defenseclaw.tui.panels.overview import (
    EnforcementCounts,
    OverviewPanelModel,
)
from defenseclaw.tui.panels.skills import SkillRow, SkillsPanelModel
from defenseclaw.tui.panels.tools import ToolsPanelModel
from textual.css.query import NoMatches


def test_command_progress_tick_stops_at_app_lifecycle_boundary(monkeypatch) -> None:
    """A final timer callback must not render after Textual starts teardown."""

    app = DefenseClawTUI()
    app._strip_state = "running"  # noqa: SLF001
    initial_spinner_tick = app._strip_spinner_tick  # noqa: SLF001
    render_calls = 0

    def render_missing_child() -> None:
        nonlocal render_calls
        render_calls += 1
        raise NoMatches("missing command strip child")

    monkeypatch.setattr(app, "_render_command_strip", render_missing_child)

    # Detached and shutting-down apps both report ``is_running == False``.
    # The interval callback must stop before changing state or querying DOM.
    app._tick_command_strip()  # noqa: SLF001
    assert app._strip_spinner_tick == initial_spinner_tick  # noqa: SLF001
    assert render_calls == 0

    # During the mounted lifecycle the same missing-widget failure remains
    # strict, so the teardown guard cannot conceal real command-strip drift.
    app._running = True  # noqa: SLF001
    with pytest.raises(NoMatches, match="missing command strip child"):
        app._tick_command_strip()  # noqa: SLF001
    assert render_calls == 1


@pytest.mark.asyncio
async def test_successful_skill_policy_mutation_reloads_loaded_skills_panel() -> None:
    skills = SkillsPanelModel(connector="hermes")
    skills.apply_loaded(
        [
            SkillRow(
                name="clean-skill",
                status="blocked",
                actions="blocked",
                install_action="block",
            )
        ]
    )
    skills.detail_open = True
    app = DefenseClawTUI(skills_model=skills)
    app.active_panel = "skills"
    reloaded: list[str] = []

    async def fake_load_catalog(panel: str) -> None:
        reloaded.append(panel)
        skills.apply_loaded(
            [
                SkillRow(
                    name="clean-skill",
                    status="allowed",
                    actions="allowed",
                    install_action="allow",
                )
            ]
        )

    app._load_catalog_model = fake_load_catalog  # type: ignore[method-assign]

    await app._handle_successful_command("defenseclaw", ("skill", "allow", "clean-skill"))  # noqa: SLF001

    assert reloaded == ["skills"]
    assert skills.selected() is not None
    assert skills.selected().status == "allowed"
    assert skills.selected().actions == "allowed"
    assert "allowed" in app._detail_text()  # noqa: SLF001


@pytest.mark.asyncio
async def test_successful_tool_policy_mutation_refreshes_and_rerenders_loaded_tools_panel() -> None:
    class Store:
        def __init__(self) -> None:
            self.entries = [
                SimpleNamespace(
                    target_name="@codex/write_file",
                    actions=SimpleNamespace(install="block"),
                    reason="manual block",
                    updated_at=None,
                )
            ]

        def list_actions_by_type(self, target_type: str) -> list[SimpleNamespace]:
            assert target_type == "tool"
            return self.entries

    store = Store()
    tools = ToolsPanelModel(store)
    tools.show_connector_column = True
    tools.set_connector_filter("codex")
    tools.refresh()
    app = DefenseClawTUI(tools_model=tools)
    app.active_panel = "tools"
    rendered: list[bool] = []

    def fake_render_chrome() -> None:
        rendered.append(True)

    app._render_chrome = fake_render_chrome  # type: ignore[method-assign]
    store.entries = [
        SimpleNamespace(
            target_name="@codex/write_file",
            actions=SimpleNamespace(install="allow"),
            reason="manual allow",
            updated_at=None,
        )
    ]

    await app._handle_successful_command("defenseclaw", ("tool", "allow", "write_file"))  # noqa: SLF001

    assert rendered == [True]
    assert tools.selected() is not None
    assert tools.selected().connector == "codex"
    assert tools.selected().status == "allowed"
    assert tools.selected().dispatch_target == "write_file"


def test_catalog_mutation_command_classifier_ignores_read_only_commands() -> None:
    assert _catalog_panel_invalidated_by_command(("skill", "allow", "clean-skill")) == "skills"
    assert _catalog_panel_invalidated_by_command(("skill", "list", "--json")) is None
    assert _catalog_panel_invalidated_by_command(("mcp", "set", "filesystem")) == "mcps"
    assert _catalog_panel_invalidated_by_command(("plugin", "info", "x")) is None
    assert _catalog_panel_invalidated_by_command(("tool", "block", "write_file")) == "tools"


@pytest.mark.asyncio
async def test_raw_process_log_tail_is_read_off_the_textual_thread(tmp_path, monkeypatch) -> None:
    from defenseclaw.tui.panels import logs as logs_module

    (tmp_path / "gateway.log").write_text("gateway ready\n", encoding="utf-8")
    app = DefenseClawTUI(data_dir=tmp_path)
    app.active_panel = "logs"
    app.logs_model.source = "gateway"
    request = app.logs_model.pending_file_refresh("gateway")
    assert request is not None
    reader_threads: list[int] = []
    raw_reader = logs_module._tail_text_file

    def tracked_reader(path, **kwargs):
        reader_threads.append(threading.get_ident())
        return raw_reader(path, **kwargs)

    monkeypatch.setattr(logs_module, "_tail_text_file", tracked_reader)
    await app._run_log_file_refresh(request)  # noqa: SLF001

    assert reader_threads
    assert all(thread_id != threading.get_ident() for thread_id in reader_threads)
    assert app.logs_model.lines["gateway"] == ["gateway ready"]


def test_scheduled_background_polls_are_single_flight(tmp_path) -> None:
    config = SimpleNamespace(
        data_dir=str(tmp_path),
        gateway=SimpleNamespace(api_port=18970, host="127.0.0.1", token="token"),
    )
    app = DefenseClawTUI(config=config)
    scheduled: list[object] = []

    def fake_run_worker(coro: object, **_kwargs: object) -> None:
        scheduled.append(coro)

    def close_last_scheduled() -> None:
        close = getattr(scheduled.pop(), "close", None)
        if callable(close):
            close()

    app.run_worker = fake_run_worker  # type: ignore[method-assign]

    app._schedule_health_poll()  # noqa: SLF001
    app._schedule_health_poll()  # noqa: SLF001
    assert len(scheduled) == 1
    assert app._health_poll_running is True  # noqa: SLF001
    close_last_scheduled()
    app._health_poll_running = False  # noqa: SLF001

    app._schedule_ai_usage_poll()  # noqa: SLF001
    app._schedule_ai_usage_poll()  # noqa: SLF001
    assert len(scheduled) == 1
    assert app._ai_usage_poll_running is True  # noqa: SLF001
    close_last_scheduled()
    app._ai_usage_poll_running = False  # noqa: SLF001

    app._schedule_credentials_refresh()  # noqa: SLF001
    app._schedule_credentials_refresh()  # noqa: SLF001
    assert len(scheduled) == 1
    assert app._credentials_refresh_running is True  # noqa: SLF001
    close_last_scheduled()


@pytest.mark.asyncio
async def test_background_poll_wrappers_clear_single_flight_flags(tmp_path) -> None:
    config = SimpleNamespace(
        data_dir=str(tmp_path),
        gateway=SimpleNamespace(api_port=18970, host="127.0.0.1", token="token"),
    )
    app = DefenseClawTUI(config=config)
    calls: list[str] = []

    async def fake_health() -> None:
        calls.append("health")

    async def fake_ai_usage(*, force_render: bool) -> None:
        calls.append(f"ai:{force_render}")

    async def fake_credentials() -> None:
        calls.append("credentials")

    app._poll_health = fake_health  # type: ignore[method-assign]
    app._poll_ai_usage = fake_ai_usage  # type: ignore[method-assign]
    app._load_setup_credentials = fake_credentials  # type: ignore[method-assign]

    app._health_poll_running = True  # noqa: SLF001
    await app._poll_health_once()  # noqa: SLF001
    assert app._health_poll_running is False  # noqa: SLF001

    app._ai_usage_poll_running = True  # noqa: SLF001
    await app._poll_ai_usage_once(force_render=False)  # noqa: SLF001
    assert app._ai_usage_poll_running is False  # noqa: SLF001

    app._credentials_refresh_running = True  # noqa: SLF001
    await app._refresh_credentials_once()  # noqa: SLF001
    assert app._credentials_refresh_running is False  # noqa: SLF001
    assert calls == ["health", "ai:False", "credentials"]


def test_slow_refresh_scheduler_is_single_flight(tmp_path) -> None:
    app = DefenseClawTUI(config=SimpleNamespace(data_dir=str(tmp_path)))
    scheduled: list[object] = []

    def fake_run_worker(coro: object, **_kwargs: object) -> None:
        scheduled.append(coro)

    def close_last_scheduled() -> None:
        close = getattr(scheduled.pop(), "close", None)
        if callable(close):
            close()

    app.run_worker = fake_run_worker  # type: ignore[method-assign]

    app._schedule_slow_refresh()  # noqa: SLF001
    app._schedule_slow_refresh()  # noqa: SLF001

    assert len(scheduled) == 1
    assert app._slow_refresh_running is True  # noqa: SLF001
    close_last_scheduled()


@pytest.mark.asyncio
async def test_slow_refresh_uses_tools_store_refresh_without_catalog_subprocess(tmp_path) -> None:
    app = DefenseClawTUI(config=SimpleNamespace(data_dir=str(tmp_path)))
    app.tools_model.loaded = True
    refreshed: list[str] = []
    loaded: list[str] = []

    def fake_tools_refresh() -> None:
        refreshed.append("tools")

    async def fake_load_catalog(panel: str) -> None:
        loaded.append(panel)

    app.tools_model.refresh = fake_tools_refresh  # type: ignore[method-assign]
    app._load_catalog_model = fake_load_catalog  # type: ignore[method-assign]

    app._slow_refresh_running = True  # noqa: SLF001
    await app._run_slow_refresh()  # noqa: SLF001

    assert refreshed == ["tools"]
    assert loaded == []
    assert app._slow_refresh_running is False  # noqa: SLF001


@pytest.mark.asyncio
async def test_slow_tools_refresh_uses_repository_worker_when_available(tmp_path) -> None:
    app = DefenseClawTUI(config=SimpleNamespace(data_dir=str(tmp_path)))
    app.tools_model.loaded = True
    app._read_repository = object()  # type: ignore[assignment]  # noqa: SLF001
    scheduled: list[bool] = []
    app._schedule_data_refresh = (  # type: ignore[method-assign]
        lambda *, force=False: scheduled.append(force)
    )
    app.tools_model.refresh = lambda: pytest.fail("tools SQLite read ran on UI loop")  # type: ignore[method-assign]

    app._slow_refresh_running = True  # noqa: SLF001
    await app._run_slow_refresh()  # noqa: SLF001

    assert scheduled == [True]
    assert app._slow_refresh_running is False  # noqa: SLF001


@pytest.mark.asyncio
async def test_tool_mutation_refresh_uses_repository_worker(tmp_path) -> None:
    app = DefenseClawTUI(config=SimpleNamespace(data_dir=str(tmp_path)))
    app.tools_model.loaded = True
    app._read_repository = object()  # type: ignore[assignment]  # noqa: SLF001
    scheduled: list[bool] = []
    app._schedule_data_refresh = (  # type: ignore[method-assign]
        lambda *, force=False: scheduled.append(force)
    )
    app.tools_model.refresh = lambda: pytest.fail("tools SQLite read ran on UI loop")  # type: ignore[method-assign]

    await app._refresh_loaded_catalog_after_mutation("tools")  # noqa: SLF001

    assert scheduled == [True]


def test_fetch_ai_usage_uses_gateway_auth_and_accept_headers() -> None:
    seen: dict[str, str] = {}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - stdlib handler API.
            seen["path"] = self.path
            seen["authorization"] = self.headers.get("Authorization", "")
            seen["accept"] = self.headers.get("Accept", "")
            body = (
                b'{"enabled":true,"summary":{"active_signals":1,"new_signals":1},'
                b'"signals":[{"signal_id":"sig1","product":"Codex","vendor":"OpenAI","state":"new"}]}'
            )
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        config = SimpleNamespace(
            gateway=SimpleNamespace(
                api_port=server.server_port,
                host="127.0.0.1",
                resolved_token=lambda: "test-bearer-xyz",
            )
        )
        snapshot = _fetch_ai_usage(config)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)

    assert snapshot is not None
    assert snapshot.enabled is True
    assert snapshot.summary.active_signals == 1
    assert snapshot.fetched_at is not None
    assert seen == {
        "path": "/api/v1/ai-usage",
        "authorization": "Bearer test-bearer-xyz",
        "accept": "application/json",
    }


def test_mark_restart_passes_started_at_to_setup_model() -> None:
    """The health worker must pass ``started_at`` into the setup model.

    Calling ``mark_restart_started`` without arguments raised
    ``TypeError`` and crashed ``_poll_health`` on every poll once the
    gateway restarted (which is exactly what ``setup`` toggles like
    redaction trigger). Verify both the happy path forwards the
    timestamp *and* a model that doesn't accept that signature falls
    back to ``clear_restart_queue`` instead of bubbling.
    """

    class FakeSetupHappy:
        def __init__(self) -> None:
            self.received: list[str] = []

        def mark_restart_started(self, started_at: str) -> bool:
            self.received.append(started_at)
            return True

        def clear_restart_queue(self) -> None:
            self.received.append("CLEARED")

    class FakeSetupLegacy:
        def __init__(self) -> None:
            self.cleared = False

        def mark_restart_started(self) -> bool:  # pragma: no cover - intentional bad signature
            raise TypeError("legacy stub mimicking pre-Phase-2 SetupPanelModel")

        def clear_restart_queue(self) -> None:
            self.cleared = True

    happy = FakeSetupHappy()
    app = DefenseClawTUI(setup_model=happy)
    app._last_gateway_started_at = "old-timestamp"  # noqa: SLF001 - exercising poll path.
    snapshot = SimpleNamespace(started_at="new-timestamp")
    app._mark_restart_if_gateway_restarted(snapshot)  # type: ignore[arg-type]  # noqa: SLF001
    assert happy.received == ["new-timestamp"]
    assert app._last_gateway_started_at == "new-timestamp"  # noqa: SLF001

    legacy = FakeSetupLegacy()
    app2 = DefenseClawTUI(setup_model=legacy)
    app2._last_gateway_started_at = "old"  # noqa: SLF001
    app2._mark_restart_if_gateway_restarted(SimpleNamespace(started_at="newer"))  # type: ignore[arg-type]  # noqa: SLF001
    assert legacy.cleared is True
    assert app2._last_gateway_started_at == "newer"  # noqa: SLF001


def test_refresh_cached_config_closes_stale_audit_store(monkeypatch, tmp_path) -> None:
    """Reload must close the previous SQLite handles, not leak them.

    ``_refresh_cached_config`` swaps ``alerts_model.store`` and
    ``audit_model.store`` with a freshly-opened ``Store`` on every
    setup-driven reload. Replacing the attribute without calling
    ``close()`` on the prior handle leaked a file descriptor per
    reload, and a typical session triggers several (connector pick,
    registry add, redaction toggle, etc.). Verify the stale store
    gets closed and that an identical post-swap handle (operator
    just toggled a flag with no audit_db change) is left untouched.
    """

    class FakeStore:
        def __init__(self, tag: str) -> None:
            self.tag = tag
            self.closed = False

        def close(self) -> None:
            self.closed = True

    old_store = FakeStore("old")
    new_store = FakeStore("new")

    app = DefenseClawTUI(
        alerts_model=AlertsPanelModel(store=old_store),
        audit_model=AuditPanelModel(store=old_store),
    )
    # Stub the heavy fan-out so we only exercise the close-on-swap
    # branch. We don't need a real config reload — ``_audit_store``
    # is the seam that produces the replacement handle.
    monkeypatch.setattr(
        "defenseclaw.tui.app._audit_store",
        lambda _cfg: new_store,
    )
    monkeypatch.setattr(app, "_refresh_models_from_disk", lambda: None)
    monkeypatch.setattr(app, "_sync_setup_readiness", lambda: None)
    monkeypatch.setattr(app, "_propagate_connector", lambda _h: None)
    monkeypatch.setattr(app, "_write_activity", lambda *a, **kw: None)
    monkeypatch.setattr("defenseclaw.tui.app.config_module.load", lambda: app.config)

    app._refresh_cached_config()  # noqa: SLF001 - exercising reload path.

    assert old_store.closed is True, "previous audit store handle leaked"
    assert new_store.closed is False
    assert app.alerts_model.store is new_store
    assert app.audit_model.store is new_store
    assert app.tools_model.store is new_store

    # Second reload returning the SAME handle must NOT close it
    # (otherwise we'd close the live store we just installed).
    app._refresh_cached_config()  # noqa: SLF001
    assert new_store.closed is False, "live store was closed by no-op reload"


def test_refresh_cached_config_replaces_snapshot_repository(monkeypatch, tmp_path) -> None:
    old_db = tmp_path / "old.db"
    new_db = tmp_path / "new.db"
    old_db.touch()
    new_db.touch()
    old_config = SimpleNamespace(data_dir=str(tmp_path), audit_db=str(old_db))
    new_config = SimpleNamespace(data_dir=str(tmp_path), audit_db=str(new_db))

    class FakeStore:
        def close(self) -> None:
            pass

    stores = {str(old_db): FakeStore(), str(new_db): FakeStore()}

    class FakeRepository:
        def __init__(self, path: str) -> None:
            self.path = path
            self.closed = False

        def close(self) -> None:
            self.closed = True

    repositories: list[FakeRepository] = []

    def repository_factory(path: str) -> FakeRepository:
        repository = FakeRepository(path)
        repositories.append(repository)
        return repository

    monkeypatch.setattr(
        "defenseclaw.tui.app._audit_store",
        lambda cfg: stores[str(cfg.audit_db)],
    )
    monkeypatch.setattr("defenseclaw.tui.app.TUIReadRepository", repository_factory)
    app = DefenseClawTUI(config=old_config)
    app._read_snapshot = object()  # type: ignore[assignment]  # noqa: SLF001
    app._snapshot_panel_revisions = {"audit": 7}  # noqa: SLF001
    monkeypatch.setattr("defenseclaw.tui.app.config_module.load", lambda: new_config)
    monkeypatch.setattr(app, "_refresh_models_from_disk", lambda: None)
    monkeypatch.setattr(app, "_sync_setup_readiness", lambda: None)
    monkeypatch.setattr(app, "_propagate_connector", lambda _health: None)
    monkeypatch.setattr(app, "_schedule_observability_status_load", lambda: None)

    app._refresh_cached_config()  # noqa: SLF001

    assert [repository.path for repository in repositories] == [str(old_db), str(new_db)]
    assert repositories[0].closed is True
    assert repositories[1].closed is False
    assert app._read_repository is repositories[1]  # noqa: SLF001
    assert app._read_snapshot is None  # noqa: SLF001
    assert app._snapshot_panel_revisions == {}  # noqa: SLF001
    assert app.tools_model.store is stores[str(new_db)]


def test_startup_binds_alerts_model_to_audit_store(monkeypatch, tmp_path) -> None:
    """Startup alerts refresh must use the summary reader, not a second DB scan."""

    store = object()
    monkeypatch.setattr("defenseclaw.tui.app._audit_store", lambda _cfg: store)

    app = DefenseClawTUI(
        config=SimpleNamespace(audit_db=str(tmp_path / "audit.sqlite")),
        data_dir=tmp_path,
    )

    assert app.alerts_model.store is store


def test_startup_retries_configured_audit_db_that_does_not_exist_yet(monkeypatch, tmp_path) -> None:
    audit_db = tmp_path / "gateway-will-create.db"
    paths: list[str] = []

    class Repository:
        def __init__(self, path: str) -> None:
            paths.append(path)

        def close(self) -> None:
            pass

    monkeypatch.setattr("defenseclaw.tui.app.TUIReadRepository", Repository)
    app = DefenseClawTUI(config=SimpleNamespace(audit_db=str(audit_db)))

    assert paths == [str(audit_db)]
    assert app._read_repository is not None  # noqa: SLF001


def test_repository_mode_never_falls_back_to_ui_thread_sql_before_first_snapshot() -> None:
    calls: list[str] = []

    class Store:
        def count_scan_results_since(self, _since: object) -> int:
            calls.append("scan-count")
            return 0

        def connector_hook_event_stats(self) -> dict[str, object]:
            calls.append("hook-stats")
            return {}

        def list_connector_hook_event_summaries(self, _limit: int) -> list[object]:
            calls.append("hook-events")
            return []

    store = Store()
    app = DefenseClawTUI(
        alerts_model=AlertsPanelModel(store=store),
        audit_model=AuditPanelModel(store=store),
    )
    app._read_repository = object()  # type: ignore[assignment]  # noqa: SLF001
    app._read_snapshot = None  # noqa: SLF001

    app._overview_session_enforcement_counts()  # noqa: SLF001
    app._connector_hook_event_stats()  # noqa: SLF001
    app._recent_connector_hook_events()  # noqa: SLF001

    assert calls == []


def test_overview_uses_repository_session_scan_count() -> None:
    from defenseclaw.tui.services.read_repository import TUIReadSnapshot

    app = DefenseClawTUI()
    app._read_repository = object()  # type: ignore[assignment]  # noqa: SLF001
    app._read_snapshot = TUIReadSnapshot(  # noqa: SLF001
        revision=1,
        data_version=1,
        enforcement_counts=Counts(total_scans=99),
        session_scan_count=4,
        session_scan_since=datetime(2026, 7, 10, tzinfo=timezone.utc),
    )
    app.overview_model.set_enforcement_counts(EnforcementCounts(total_scans=99))

    assert app._overview_session_enforcement_counts().total_scans == 4  # noqa: SLF001


def test_refresh_alerts_mirrors_loaded_alerts_with_cheap_enforcement_counts(tmp_path) -> None:
    """Refreshing alerts should mirror loaded canonical rows and cheap counts."""

    class FakeStore:
        def get_counts(self) -> object:
            raise AssertionError("refresh should not scan counts")

        def get_enforcement_counts(self) -> Counts:
            return Counts(
                blocked_skills=7,
                allowed_skills=8,
                blocked_mcps=9,
                allowed_mcps=10,
                total_scans=11,
            )

    alerts = AlertsPanelModel(store=FakeStore())
    alerts.set_events([AlertEvent(id="a1", severity="HIGH", action="scan", target="skill://one")])
    # This unit isolates the app-level count projection. Canonical SQLite
    # ingestion is covered by test_v8_event_history.py.
    alerts.refresh = lambda: None  # type: ignore[method-assign]
    overview = OverviewPanelModel()
    overview.set_enforcement_counts(
        EnforcementCounts(
            blocked_skills=2,
            allowed_skills=3,
            blocked_mcps=4,
            allowed_mcps=5,
            total_scans=6,
            active_alerts=999,
        )
    )
    app = DefenseClawTUI(
        data_dir=tmp_path,
        alerts_model=alerts,
        overview_model=overview,
    )

    app._refresh_alerts()  # noqa: SLF001 - regression for the startup refresh path.

    assert overview.enforcement == EnforcementCounts(
        blocked_skills=7,
        allowed_skills=8,
        blocked_mcps=9,
        allowed_mcps=10,
        total_scans=11,
        active_alerts=1,
    )


def test_destructive_intent_modal_is_danger_gated() -> None:
    """N1: a destructive catalog intent builds a red-bordered consequence modal.
    "Go back" is preselected so stray Enter presses cancel; the run action is
    danger-gated (requires the explicit second confirm)."""

    from defenseclaw.tui.app import TOKENS
    from defenseclaw.tui.services.catalog_state import CatalogCommandIntent

    app = DefenseClawTUI()
    intent = CatalogCommandIntent(
        label="remove plugin foo",
        args=("plugin", "remove", "foo"),
        origin="plugins",
        risk="destructive",
    )
    model = app._destructive_intent_modal(intent)
    assert [action.action_id for action in model.actions] == ["back", "run"]
    assert model.default_action().danger is False
    assert model.action_for_hotkey("d").danger is True
    assert model.border_color == TOKENS.accent_red
    assert "plugin remove foo" in model.details[0]
