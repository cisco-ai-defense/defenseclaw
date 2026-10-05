---
name: defenseclaw-tui
description: Improve the DefenseClaw Textual TUI (cli/defenseclaw/tui) consistently. Use it for any TUI work - adding or changing panels, picker and consequence modals, Setup wizards and the config editor, the hint bar and help overlay, command-palette rows, TUI tests, and TUI UX reviews or render checks. It holds the golden rules, the file map, recipes, the 80x24 layout budget, the test budget, and scripts that render the screen headlessly, run a fake-data demo, audit CLI coverage and list a panel's touchpoints. Don't use it for live certification on the Windows/macOS/Linux test hosts (use defenseclaw-live-testing) or for EC2 dev-host operations (use defenseclaw-dev-host).
---

# DefenseClaw TUI

The TUI is a Python Textual 8 app in `cli/defenseclaw/tui/`. `app.py` holds
`DefenseClawTUI` (with `SandboxPanelMixin`), and every panel renders into one
shared surface: `#body`, `DataTable#panel-table`, `#detail-panel`, plus one
button bar per panel. Mutations never happen in the TUI. It builds CLI intents,
previews them, and runs the real `defenseclaw` CLI as a subprocess. Source and
tests are authoritative. If this skill disagrees with them, trust the code and
fix the skill.

## Golden rules

1. **Keep models pure.** Panel state and logic live in `services/<x>_state.py`
   (no I/O, no Textual). The app or a mixin does the I/O. `_body_text` runs on a
   2 s timer, so it must be cheap and must not read disk, spawn processes or
   make network calls.
2. **Mutate only through CLI intents.** Flow: `model.handle_key` → action/intent →
   `_confirm_and_run_intent` → `CommandPreviewScreen` →
   `CommandExecutor` → `_handle_successful_command` refresh. Destructive
   intents set `risk="destructive"` and go through
   `ConsequenceModalScreen(danger=True)`. A flow with its own consequence modal
   that shows the exact command runs it after that confirm; never stack a third
   prompt. The one sanctioned direct write is the
   Setup config editor (`apply_config_field` + `config.save()` after `ConfigDiffScreen`).
3. **Send secrets over stdin, never argv.** Set `intent.secret_stdin` and use
   `--value-stdin` (for example `keys set NAME --value-stdin`). Secrets never
   appear in the preview, the Activity log or argv. `click.prompt(hide_input)`
   and getpass ignore piped stdin.
4. **Run follow-ups only after success.** A follow-up intent runs after the
   previous command finishes, and only if it exited 0.
5. **Route all text entry through `FieldEditorScreen`** (`screens/field_editor.py`).
   Never type into fields through panel keys. `_panel_key` lowercases most
   capital letters. Test it the way a terminal sends it: a burst of keys and a
   paste must land whole (`references/gotchas.md`).
6. **Only model config-editor fields the Python `Config` can persist.**
   `Config.save()` silently drops unmodeled keys, so show those read-only with a hint.
7. **Advertise keys only through `HintEngine` or the per-view keymap**
   (`panels/setup_keys.py` for Setup). Every advertised key must be handled, and
   every handled key must appear in `?` help. No "Keys:" lines in the body.
8. **Fit at 80x24.** Primary content (the first row, field or wizard) stays
   above the fold, with at most 2-3 body lines above the table. Button bars hide
   what doesn't apply to the current view instead of disabling it.
9. **Rich-escape every data string** (`rich.markup.escape`), send bodies through
   `_safe_body_renderable`, write hotkey labels as `\\[k]`, and use no `@click`
   links in `#body`.
10. **Check Windows too.** The executor uses a PTY on POSIX but pipes and a Job
    Object on Windows. Stdin, cancel and terminal launches behave differently
    there, so check that path (or say you didn't).
11. **Stay within the test budget.** Default to pure model tests. Each new
    screen gets at most 2 Pilot tests, and each new mutating flow gets 1-2
    journey tests, all at 80x24. See `references/testing.md` for banned patterns.
12. **Check branch overlap before starting.** `feat/openshell-0.1` and `main`
    both move `app.py`/`panels/setup.py`. Run
    `git log --oneline main...HEAD -- cli/defenseclaw/tui | head` and fold in
    what's already there instead of re-doing it.

Copy style: use plain words and sentence case, start with a verb, avoid internal
jargon, and keep refusals to one line that says what to do next
(`references/ux-rules.md`).

## Workflow

1. **Map the change.** `touchpoints.py <panel>` shows which if-chains in
   `app.py`/`hint_bar.py` need the panel. `gap_audit.py --prefix <cmd>` shows
   whether a CLI command is in the palette, used by the TUI, or has `--json`.
2. **Pick a recipe** in `references/recipes.md`: panel, picker, mutating action,
   secret action, wizard/config field, or palette row.
3. **Build the model first** and write unit tests for keys → actions, rows and
   empty states.
4. **Wire it up**: the app/mixin I/O, intents, controls, hints and help.
5. **Render at 80x24 and 120x40** with `render.py`, and add `--expect` for the
   thing that must be visible.
6. **Check it interactively** in tmux with `demo.py` (fake executor), or with the
   real CLI in an isolated `mktemp` home (`references/verification.md`). Never
   use the real `~/.defenseclaw`.
7. **Run the gates**: the TUI suite, ruff, and the touched CLI tests.
8. **Commit** as `fix(tui): <plain-English behaviour>` (or `feat(tui): …`,
   `test(tui): …`). Add a short body saying why and the Co-Authored-By trailer.

## Cheat-sheet (repository root)

```bash
S=.claude/skills/defenseclaw-tui/scripts
.venv/bin/python $S/render.py --list-panels
.venv/bin/python $S/render.py --panel setup --size 80x24            # screen as text
.venv/bin/python $S/render.py --keys 0 c --expect "Config"           # exit 1 if missing
.venv/bin/python $S/render.py --keys : "text:policy list" enter      # palette + preview
.venv/bin/python $S/render.py --panel alerts --svg /tmp/alerts.svg   # SVG per size
.venv/bin/python $S/render.py --first-run
.venv/bin/python $S/demo.py --panel setup                            # interactive, fake exec
.venv/bin/python $S/gap_audit.py --missing-only                      # CLI the TUI can't reach
.venv/bin/python $S/touchpoints.py sandboxes                         # panel wiring checklist
.venv/bin/python -m pytest cli/tests/tui -q -p no:cacheprovider -n 4
.venv/bin/ruff check cli/defenseclaw/ <new test files>
tmux new-session -d -s dc-tui -x 80 -y 24 ".venv/bin/python $S/demo.py"
tmux send-keys -t dc-tui 0; tmux capture-pane -t dc-tui -p; tmux kill-session -t dc-tui
```

## References

- `references/architecture.md`: file map, render pipeline, `on_key` routing
  order, the intent pipeline, workers, state services, and theme tokens.
- `references/recipes.md`: add a panel (the Sandboxes mixin recipe), a picker, a
  mutating or destructive action, a secret action, a wizard or config field,
  or a palette row.
- `references/ux-rules.md`: 80x24 budget, hints per view, control bars, copy
  style, reserved keys, and empty states.
- `references/testing.md`: test policy and budget, smoke/journey tests with a
  fake executor, and banned patterns.
- `references/verification.md`: render.py, demo.py in tmux, isolated-home runs,
  and host passes.
- `references/gotchas.md`: verified pitfalls. Read this before touching Setup,
  secrets, policies or keys.

## Scripts

All scripts run from the repository root with `.venv/bin/python` and are hermetic
(fake-data app from `cli/tests/tui/fixtures.py`, no agent discovery, no sandbox
doctor, and a temp `DEFENSECLAW_HOME`).

- `scripts/render.py`: headless screen-text dump. Options: `--panel`, `--keys`,
  `--size` (repeatable), `--first-run`, `--setup-config default|empty`,
  `--expect TEXT`, `--svg PATH`, `--list-panels`.
- `scripts/demo.py`: runs the same app interactively. HOME, DEFENSECLAW_HOME,
  CLAUDE_CONFIG_DIR and CODEX_HOME point into a scratch dir. Confirmed commands
  only echo their argv unless you pass `--real-exec`. The scratch home is deleted
  on exit unless you pass `--keep-home`. Options: `--panel`, `--first-run`,
  `--setup-config`, `--real-exec`, `--keep-home`.
- `scripts/gap_audit.py`: Click tree against palette rows, TUI argv literals and
  `--json`. Options: `--missing-only`, `--groups`, `--prefix`.
- `scripts/touchpoints.py PANEL [--stem S]`: which per-panel if-chains mention
  the panel.
