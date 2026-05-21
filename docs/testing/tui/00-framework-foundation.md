# 00 — Framework foundation (MAIN AGENT, build this first)

> **Audience:** the *parent* agent that bootstraps the test infrastructure
> before any sub-agent is dispatched. Sub-agents assume every artifact here
> already exists and works on `main`.
>
> **Do not delegate this file.** A sub-agent cannot land its plan if the
> conftest, fixtures, or snapshot directory are missing or inconsistent.

---

## 0. Pre-flight findings (current repo state, May 2026)

A `git grep` over the repo shows:

* `pytest-asyncio` is **not** in `uv.lock` or `[dependency-groups].dev` — yet
  every async TUI test in `cli/tests/tui/test_app_shell.py` is decorated
  with `@pytest.mark.asyncio`. Today those tests are silently skipped (or
  collected as plain async coroutines and never awaited) when the suite is
  run via `make cli-test`, which uses `unittest discover`, not pytest.
* `pytest-textual-snapshot` is **not** installed.
* `textual==7.5.0` *is* installed (verified in `.venv/lib/python3.12/`).
* `cli/tests/tui/test_visual_snapshot_smoke.py` references SVG goldens but
  the snapshot plugin is missing, so the file is dead weight.
* `cli/tests/tui/conftest.py` exists but only patches `policy_state` bundled
  asset paths. There is no shared `make_app`, `FakeConnector`, `FakeStore`,
  or `FakeExecutor` fixture.

This file is the fix.

---

## 1. Dependencies to add

Edit `pyproject.toml`:

```toml
[dependency-groups]
dev = [
  "pytest==9.0.3",
  "pytest-cov==7.1.0",
  "pytest-asyncio==1.3.0",         # NEW — needed for `await pilot.press(...)`
  "pytest-textual-snapshot==1.1.0", # NEW — SVG goldens
  "syrupy==4.10.0",                 # NEW — only if you want JSON/text goldens too
  "hypothesis==6.140.4",            # NEW — for L5 invariants on a couple panels
  "jsonschema>=4.23.0",
  "ruff==0.15.7",
  "opentelemetry-api>=1.28.0",
  "opentelemetry-sdk>=1.28.0",
]
```

Re-lock with `uv lock` and commit `uv.lock`.

### 1.1 pytest configuration

Append to `pyproject.toml`:

```toml
[tool.pytest.ini_options]
testpaths = ["cli/tests"]
asyncio_mode = "auto"            # NEW — every async def test_* is treated as asyncio
filterwarnings = [
  "error::DeprecationWarning:defenseclaw.*",
]
markers = [
  "tui_snapshot: marks SVG snapshot tests (slow on first run)",
  "tui_property: marks Hypothesis-driven invariant tests",
]
```

`asyncio_mode = "auto"` is what the Textual docs recommend so we don't have
to decorate every coroutine with `@pytest.mark.asyncio`. **Remove all
existing `@pytest.mark.asyncio` decorations as part of this PR** — they
become a lint smell once `asyncio_mode = "auto"` is set.

### 1.2 Makefile

Replace the `cli-test` target so the TUI async tests actually run:

```make
cli-test:
	$(VENV)/bin/python -m pytest cli/tests -q

cli-test-snap:
	$(VENV)/bin/python -m pytest cli/tests/tui -q --snapshot-update=$(UPDATE)
```

`unittest discover` is incompatible with async test functions; we have to
move to pytest. Confirm by running `make cli-test` after the swap and
making sure the count is **higher** than before, not lower (silent skips
disappear).

---

## 2. Shared `conftest.py`

`cli/tests/tui/conftest.py` already exists and patches policy paths. Extend
it (do **not** rewrite it) with the fixtures below. The file MUST stay a
single file; sub-agents must not split it.

```python
# cli/tests/tui/conftest.py  (additions)
from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from textual.pilot import Pilot

from defenseclaw.tui.app import DefenseClawTUI
from defenseclaw.tui.executor import CommandEvent


# ---- (existing _isolated_bundled_assets fixture stays exactly as-is) ----


# ----------------------------------------------------------------------------
# Filesystem isolation
# ----------------------------------------------------------------------------
@pytest.fixture
def tmp_data_dir(tmp_path: Path) -> Path:
    """Per-test ``data_dir``. Tests must NEVER touch ``~/.defenseclaw``."""
    d = tmp_path / "dataclaw"
    d.mkdir()
    return d


@pytest.fixture
def tmp_policy_dir(tmp_data_dir: Path) -> Path:
    d = tmp_data_dir / "policies"
    d.mkdir()
    return d


@pytest.fixture
def tmp_audit_db(tmp_data_dir: Path) -> Path:
    return tmp_data_dir / "audit.db"


# ----------------------------------------------------------------------------
# Lightweight config object
# ----------------------------------------------------------------------------
@pytest.fixture
def base_config(tmp_data_dir: Path, tmp_policy_dir: Path, tmp_audit_db: Path) -> SimpleNamespace:
    """Minimum-viable ``config`` object accepted by all panel models.

    Every test that needs a different connector / guardrail mode should
    use ``base_config`` as the seed and override the specific subfield via
    ``dataclasses.replace`` or a copy — never mutate this fixture in place.
    """
    return SimpleNamespace(
        data_dir=str(tmp_data_dir),
        policy_dir=str(tmp_policy_dir),
        audit_db=str(tmp_audit_db),
        environment="test",
        claw=SimpleNamespace(mode="openclaw"),
        guardrail=SimpleNamespace(
            enabled=True,
            mode="observe",
            connector="openclaw",
            scanner_mode="local",
            rule_pack_dir="",
            port=4141,
            model="gpt-5-mini",
            strategy="default",
            judge_enabled=False,
            judge_model="",
            hilt=SimpleNamespace(enabled=False, min_severity="HIGH"),
        ),
        notifications=SimpleNamespace(enabled=True),
        privacy=SimpleNamespace(redaction_disabled=False),
        registry_sources=(),
    )


# ----------------------------------------------------------------------------
# Fake connector / executor / store
# ----------------------------------------------------------------------------
class FakeExecutor:
    """In-memory stand-in for ``defenseclaw.tui.executor.CommandExecutor``.

    Records every ``run`` call as a tuple of ``(argv, env)``. Tests assert
    on ``.calls`` instead of patching subprocess. To simulate a streaming
    command, push ``CommandEvent`` instances into ``.scripted_events`` and
    call ``await flush(pilot)`` from the test.
    """
    def __init__(self) -> None:
        self.calls: list[tuple[tuple[str, ...], dict[str, str]]] = []
        self.scripted_events: list[CommandEvent] = []
        self.callback: Callable[[CommandEvent], None] | None = None
        self.exit_code: int = 0

    def run(self, argv, env=None, callback=None, **_):
        self.calls.append((tuple(argv), dict(env or {})))
        self.callback = callback
        return SimpleNamespace(cancel=lambda: None)

    async def flush(self, pilot: Pilot) -> None:
        for event in self.scripted_events:
            if self.callback is not None:
                self.callback(event)
            await pilot.pause()
        self.scripted_events.clear()


class FakeConnector:
    """Pure-data connector. Catalog panels (Skills/MCPs/Plugins/Tools) read
    from this object; tests pre-seed ``.rows`` and assert no network."""
    def __init__(self, *, skills=(), mcps=(), plugins=(), tools=()) -> None:
        self.skills = tuple(skills)
        self.mcps = tuple(mcps)
        self.plugins = tuple(plugins)
        self.tools = tuple(tools)
        self.list_calls = 0

    def list_skills(self):  self.list_calls += 1; return self.skills
    def list_mcps(self):    self.list_calls += 1; return self.mcps
    def list_plugins(self): self.list_calls += 1; return self.plugins
    def list_tools(self):   self.list_calls += 1; return self.tools


class FakeAuditStore:
    """In-memory audit store. Bypass the real SQLite path entirely."""
    def __init__(self, events=()) -> None:
        self.events = list(events)
        self.findings: list[Any] = []

    def list_events(self, **_): return list(self.events)
    def list_findings(self, **_): return list(self.findings)


@pytest.fixture
def fake_executor() -> FakeExecutor:
    return FakeExecutor()


@pytest.fixture
def fake_connector() -> FakeConnector:
    return FakeConnector()


@pytest.fixture
def fake_audit_store() -> FakeAuditStore:
    return FakeAuditStore()


# ----------------------------------------------------------------------------
# App factory
# ----------------------------------------------------------------------------
@pytest.fixture
def make_app(
    base_config: SimpleNamespace,
    tmp_data_dir: Path,
    fake_executor: FakeExecutor,
    fake_connector: FakeConnector,
    fake_audit_store: FakeAuditStore,
    monkeypatch,
):
    """Factory that returns a ready-to-pilot ``DefenseClawTUI``.

    Use as:
        async def test_x(make_app):
            app = make_app()                        # default models
            async with app.run_test(size=(120, 40)) as pilot:
                ...
        # or with overrides:
            app = make_app(policy_model=my_seeded_policy_model)
    """
    def _factory(**overrides: Any) -> DefenseClawTUI:
        # Default: redirect the executor and connector resolution so panel
        # models never reach for the real CLI.
        from defenseclaw.tui import app as tui_app

        monkeypatch.setattr(tui_app, "_active_connector", lambda *_a, **_kw: fake_connector, raising=True)
        monkeypatch.setattr(tui_app, "_audit_store",     lambda *_a, **_kw: fake_audit_store, raising=True)

        app = DefenseClawTUI(config=base_config, data_dir=str(tmp_data_dir), **overrides)
        # Pin executor BEFORE compose so first refresh uses the fake.
        app.executor = fake_executor
        return app

    return _factory


# ----------------------------------------------------------------------------
# Async helpers
# ----------------------------------------------------------------------------
@asynccontextmanager
async def piloted(app: DefenseClawTUI, size=(120, 40)) -> AsyncIterator[Pilot]:
    """``async with piloted(app) as pilot:`` instead of writing
    ``app.run_test`` boilerplate in every test."""
    async with app.run_test(size=size) as pilot:
        await pilot.pause()
        yield pilot


@pytest.fixture
def piloted_app(make_app):
    """Convenience: ``async with piloted_app() as (app, pilot):``."""
    @asynccontextmanager
    async def _inner(size=(120, 40), **overrides):
        app = make_app(**overrides)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            yield app, pilot
    return _inner
```

---

## 3. Shared `helpers/`

Create `cli/tests/tui/helpers/__init__.py` and the four modules below.
The whole point is that **every sub-agent imports the same helpers** — no
sub-agent should ever re-implement these.

### 3.1 `helpers/pilot.py`

```python
"""Tiny helpers on top of Textual's Pilot."""
from __future__ import annotations

from typing import TYPE_CHECKING, TypeVar

from textual.widget import Widget

if TYPE_CHECKING:
    from textual.app import App
    from textual.pilot import Pilot

W = TypeVar("W", bound=Widget)


async def press_keys(pilot: Pilot, *keys: str, pause: bool = True) -> None:
    """Press a sequence and await one render cycle per press.

    Textual's Pilot.press is fast but, in 7.5.0, the post-keypress render
    is sometimes scheduled on the next tick. Pausing after each press makes
    assertions deterministic across machines.
    """
    for key in keys:
        await pilot.press(key)
        if pause:
            await pilot.pause()


def widget(app: App, selector: str, kind: type[W]) -> W:
    """Type-safe ``app.query_one`` wrapper."""
    return app.query_one(selector, kind)


def screen_class(app: App) -> str:
    """Return the topmost screen's class name (for ``assert_screen_is``)."""
    return type(app.screen).__name__


def assert_screen_is(app: App, expected: type) -> None:
    actual = type(app.screen)
    assert actual is expected, f"expected screen {expected.__name__}, got {actual.__name__}"


def dump_body(app: App) -> str:
    """Snapshot the current ``app.body_text``, normalized for diffing."""
    return app.body_text.replace("\u00a0", " ").rstrip()
```

### 3.2 `helpers/fakes.py`

Re-export `FakeConnector`, `FakeExecutor`, `FakeAuditStore` from conftest so
sub-agents can import from one place:

```python
from defenseclaw.tests.tui.conftest import FakeAuditStore, FakeConnector, FakeExecutor

__all__ = ["FakeAuditStore", "FakeConnector", "FakeExecutor"]
```

> The path may differ depending on how `cli/tests` is exposed as a package
> on the test path. If `cli/tests` isn't importable, copy the fake classes
> into `helpers/fakes.py` directly.

### 3.3 `helpers/builders.py`

Tiny builders for the dataclasses tests need most often. Saves 5-10 lines
per test of `SimpleNamespace(...)` boilerplate.

```python
from defenseclaw.tui.panels.alerts import AlertEvent
from defenseclaw.tui.panels.mcps import MCPRow
from defenseclaw.tui.panels.skills import SkillRow
from defenseclaw.tui.services.policy_state import PolicyProfile, PolicyRule
from defenseclaw.tui.services.setup_state import ConfigField, ConfigSection, CredentialRow
# ... etc.

def alert(event_id="evt-1", severity="HIGH", target="agent-a", **kw) -> AlertEvent:
    return AlertEvent(event_id=event_id, severity=severity, target=target, **kw)

def skill(name="codeguard", source="bundled", **kw) -> SkillRow:
    return SkillRow(name=name, source=source, **kw)

def mcp(name="github", transport="stdio", **kw) -> MCPRow:
    return MCPRow(name=name, transport=transport, **kw)

def policy_rule(name="r1", severity="high", **kw) -> PolicyRule:
    return PolicyRule(name=name, severity=severity, **kw)

def credential(env_name="OPENAI_API_KEY", feature="LLM", requirement="required",
               set=False, **kw) -> CredentialRow:
    return CredentialRow(env_name=env_name, feature=feature, requirement=requirement,
                         set=set, **kw)
```

Add one builder per dataclass that two or more plans need.

### 3.4 `helpers/snapshots.py`

```python
"""Standard sizes; every snapshot test uses one of these."""
QA_SIZES = ((80, 24), (120, 40), (180, 50))

# Map a logical name -> size, so test parametrize ids are stable.
SIZE_NAMES = {"sm": (80, 24), "md": (120, 40), "lg": (180, 50)}
```

---

## 4. Snapshot directory

`cli/tests/tui/__snapshots__/` is created on first run by
`pytest-textual-snapshot`. Add to `.gitignore`:

```
# DO NOT ignore snapshots
!cli/tests/tui/__snapshots__/
```

…and check goldens in. Snapshots that differ between operating systems
should be marked `xfail(reason=..., strict=False)` on the offending OS; we
do not currently ship Windows TUI builds so macOS+Linux parity is the bar.

---

## 5. Cross-cutting safeguards the main agent must add

1. **No real subprocess.** Patch `defenseclaw.tui.executor.CommandExecutor`
   so any forgotten path explodes:

   ```python
   # in conftest.py
   @pytest.fixture(autouse=True)
   def _ban_real_subprocess(monkeypatch):
       def boom(*a, **kw):
           raise AssertionError("subprocess.Popen called in a TUI test "
                                "— route through FakeExecutor instead")
       monkeypatch.setattr("subprocess.Popen", boom)
   ```

2. **No real network.** Patch the AI-discovery fetch helper:

   ```python
   import defenseclaw.tui.app as tui_app
   monkeypatch.setattr(tui_app, "_fetch_ai_usage", lambda *_a, **_kw: None)
   ```

3. **No real HOME writes.** Patch `defenseclaw.paths` resolver functions to
   return the per-test `tmp_data_dir`. The existing
   `_isolated_bundled_assets` does this for policy bundles only — extend it
   to cover `data_dir`, `config_path`, and `audit_db`.

4. **Deterministic time.** Default `freezegun.freeze_time("2026-05-21 17:00:00+00:00")`
   so snapshots don't drift. Add `freezegun==1.5.5` to dev deps.

5. **Clipboard isolation.** The TUI uses `pyperclip` for `Y`/`Ctrl+S`.
   Patch:

   ```python
   import pyperclip
   monkeypatch.setattr(pyperclip, "copy", lambda value: _clipboard.append(value))
   monkeypatch.setattr(pyperclip, "paste", lambda: _clipboard[-1] if _clipboard else "")
   ```

6. **Locale.** Force `LC_ALL=C.UTF-8` in the pytest invocation; some Rich
   widgets render different bullet glyphs depending on locale.

---

## 6. Smoke test the foundation

Drop this canary into `cli/tests/tui/test_framework_canary.py`. It is the
parent-agent's go/no-go signal.

```python
"""Canary: if this passes, the foundation is healthy.

Sub-agents are unblocked the instant this test is green.
"""
from __future__ import annotations

from defenseclaw.tui.app import DefenseClawTUI


async def test_app_boots_and_renders_overview(piloted_app) -> None:
    async with piloted_app(size=(120, 40)) as (app, pilot):
        assert app.active_panel == "overview"
        assert "SERVICES" in app.body_text
        assert app.hint_text


async def test_global_command_palette_opens_and_closes(piloted_app) -> None:
    async with piloted_app(size=(120, 40)) as (app, pilot):
        await pilot.press("ctrl+k")
        await pilot.pause()
        assert type(app.screen).__name__ == "CommandPaletteScreen"
        await pilot.press("escape")
        await pilot.pause()
        assert type(app.screen).__name__ == "Screen"


def test_snapshot_overview_smoke(snap_compare):
    """Cheapest possible snapshot proof that ``pytest-textual-snapshot``
    is wired up correctly. Full per-panel snapshots live in each sub-agent's
    plan."""
    assert snap_compare(
        "cli/defenseclaw/tui/app.py:DefenseClawTUI",  # adjust to the entrypoint
        terminal_size=(120, 40),
    )
```

If the canary passes, fan out sub-agents per [`99-sub-agent-contract.md`](./99-sub-agent-contract.md).

---

## 7. Definition of done for the main agent

* [ ] `pyproject.toml` updated with new dev deps.
* [ ] `[tool.pytest.ini_options]` has `asyncio_mode = "auto"` and the markers above.
* [ ] `uv.lock` regenerated and committed.
* [ ] `Makefile` `cli-test` calls pytest (not `unittest discover`).
* [ ] `cli/tests/tui/conftest.py` extended with fixtures from §2.
* [ ] `cli/tests/tui/helpers/` directory created with the four modules in §3.
* [ ] `.gitignore` updated to keep snapshots checked in.
* [ ] Safeguards in §5 active (subprocess/network/HOME/time/clipboard).
* [ ] `cli/tests/tui/test_framework_canary.py` passing.
* [ ] All existing tests in `cli/tests/tui/` still pass — no regressions.
* [ ] All existing `@pytest.mark.asyncio` decorators removed (now auto-mode).
* [ ] Coverage baseline captured: `pytest cli/tests/tui --cov=defenseclaw.tui
      --cov-report=term-missing > docs/testing/tui/baseline-coverage.txt`. Sub-agents
      compare against this baseline.

When all boxes are ticked, mark this issue closed and fan out.
