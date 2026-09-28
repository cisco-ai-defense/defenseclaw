# Testing

## Policy

The Pilot-driven suite was deliberately cut down. Keep it that way.

- **Default: pure model and service unit tests.** No Pilot, no app. Test
  `handle_key` → action/intent, `data_table_rows`, `empty_state`, `apply_json`
  (including malformed JSON), and keymap ↔ handler parity.
- **Each new screen gets at most 2 Pilot tests** (it renders and dismisses with
  the right value, plus one real regression).
- **Each new mutating flow gets 1-2 journey tests**: the happy path to the
  captured argv (and stdin), plus one real regression.
- **All Pilot tests run at `size=(80, 24)`.**
- Put new tests in new files you own. Don't grow `test_app_shell.py`.
- The whole TUI suite runs in seconds. Keep it that way:
  `.venv/bin/python -m pytest cli/tests/tui -q -p no:cacheprovider -n 4`.

## Banned

- Asserting UI copy, except security or contract strings (masking, the "nothing
  written" refusals, JSON keys).
- Sleeps as synchronization. Use `await pilot.pause()` or wait on the model
  or worker state.
- Asserting private attributes where a model API exists.
- Real host discovery, network, gateway, real `~/.defenseclaw`, or real
  subprocesses. Fake `app.executor.run` and patch `_communicate_captured`
  loaders. The `allow_subprocess` marker in `pyproject.toml` is only for
  executor integration tests. No autouse ban enforces this today, so hold the
  line yourself.
- Golden SVGs or snapshot images.

## Smoke or journey test with the fake-data app

`cli/tests/tui` has no `__init__.py`, so pytest puts it on `sys.path` and
`from fixtures import ...` works.

```python
from defenseclaw.tui.executor import CommandEvent
from fixtures import screen_text, snapshot_app


async def test_block_skill_runs_block_command(tmp_path):
    app = snapshot_app(tmp_path)
    calls: list[dict] = []

    async def fake_run(binary, args, *, stdin_input=None, env_overrides=None):
        calls.append({"binary": binary, "args": tuple(args), "stdin": stdin_input})
        yield CommandEvent("start", " ".join((binary, *args)))
        yield CommandEvent("done", exit_code=0, duration=0.01)

    app.executor.run = fake_run
    async with app.run_test(size=(80, 24)) as pilot:
        app.action_switch_panel("skills")
        await pilot.pause()
        await pilot.press("b")          # the panel's key
        await pilot.pause()
        await pilot.press("enter")      # confirm CommandPreviewScreen
        await pilot.pause()
        await app.workers.wait_for_complete()
    assert calls and calls[0]["args"][:2] == ("skill", "block")
```

- Use `fixtures.snapshot_app(tmp_path, setup_config=default_config())` for Setup
  flows that need a real `Config`.
- Inject a panel model through the constructor kwarg (`sandbox_model=...`)
  when the fixture doesn't pre-load one.
- To assert something is visible, `screen_text(app)` returns what a person
  sees. Assert data (a row name) and not copy.
- Secret flows: assert `calls[0]["stdin"] == secret`, and that `secret` is in no
  element of `args` and not in the Activity text.
- Follow-ups: make the first fake `done` return `exit_code=1` and assert the
  follow-up never ran.

## Picker or screen harness

```python
from textual.app import App


class Harness(App[None]):
    def __init__(self, screen):
        super().__init__()
        self._screen = screen
        self.result = "unset"

    def on_mount(self) -> None:
        self.push_screen(self._screen, callback=lambda value: setattr(self, "result", value))


async def test_picker_escape_returns_none():
    app = Harness(XPickerScreen(current="default"))
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.press("escape")
        await pilot.pause()
    assert app.result is None
```

## Gates before committing

```bash
.venv/bin/python -m pytest cli/tests/tui -q -p no:cacheprovider -n 4
.venv/bin/ruff check cli/defenseclaw/ <new test files>
.venv/bin/python -m pytest cli/tests/test_<touched cli>.py -q -p no:cacheprovider
```

Run `ruff format` only on files you created or substantially edited.
