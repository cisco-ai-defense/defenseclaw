# Verification

Look at the screen before you claim a UI change works. There are three levels,
from cheapest to most expensive.

## 1. Headless render (`scripts/render.py`)

This builds the fake-data app from `cli/tests/tui/fixtures.py`, presses keys,
and prints the screen as text at each size (default 80x24 and 120x40).

```bash
S=.claude/skills/defenseclaw-tui/scripts
.venv/bin/python $S/render.py --list-panels                     # names + keys
.venv/bin/python $S/render.py --panel setup                     # both sizes
.venv/bin/python $S/render.py --panel sandboxes --size 80x24
.venv/bin/python $S/render.py --keys 0 enter enter              # Setup wizard form
.venv/bin/python $S/render.py --keys 0 c                        # config editor
.venv/bin/python $S/render.py --keys : "text:policy list" enter # palette -> preview modal
.venv/bin/python $S/render.py --first-run
.venv/bin/python $S/render.py --setup-config empty --panel setup
.venv/bin/python $S/render.py --panel setup --size 80x24 --expect "Setup" --expect "Connector"
.venv/bin/python $S/render.py --panel alerts --svg /tmp/alerts.svg   # alerts-80x24.svg, alerts-120x40.svg
```

- Keys use Textual names (`enter`, `escape`, `tab`, `down`, `ctrl+p`).
  `text:<s>` types each character.
- `--expect TEXT` exits 1 (listing what is missing, per size) when TEXT is not
  on screen. Use it as a quick check that the primary content is above the fold.
- `--svg PATH` writes `app.export_screenshot()` so you can look at colours and
  borders (open it in a browser). It's evidence only. Never commit SVGs as tests.
- Modals are included in the dump. `--wait SECONDS` gives slow workers time to finish.

## 2. Interactive fake-data app in tmux (`scripts/demo.py`)

This is the same hermetic app, running for real. HOME, DEFENSECLAW_HOME,
CLAUDE_CONFIG_DIR and CODEX_HOME point into a fresh `mktemp` dir. Confirmed
commands only print `demo: would run: <argv>` (and `<stdin: N chars>` for
secrets) and exit 0, so follow-ups and refreshes still fire. `--real-exec`
runs the real CLI inside the scratch home.

```bash
S=.claude/skills/defenseclaw-tui/scripts
tmux new-session -d -s dc-tui-80 -x 80 -y 24 ".venv/bin/python $S/demo.py --panel setup"
sleep 3; tmux capture-pane -t dc-tui-80 -p
tmux send-keys -t dc-tui-80 Enter            # named keys: Enter Escape Tab Down Up C-p
tmux send-keys -t dc-tui-80 -l 'policy list' # -l = literal text
tmux capture-pane -t dc-tui-80 -p
tmux kill-session -t dc-tui-80               # kill only sessions you created

tmux new-session -d -s dc-tui-120 -x 120 -y 40 ".venv/bin/python $S/demo.py"
```

- Pick a unique session name. Other agents share this machine.
- Use it for focus, key routing, modals, mouse and timing (the 2 s refresh
  re-rendering over an open interaction). `render.py` can't show these.
- Log UX problems as you go (copy, fit, keys that are advertised but dead).

## 3. Real CLI in an isolated home

Use this when the change depends on real CLI behaviour (config writes, `--json`
output, stdin secrets):

```bash
SCRATCH=$(mktemp -d)
export HOME=$SCRATCH/home DEFENSECLAW_HOME=$SCRATCH/home/.defenseclaw \
       CLAUDE_CONFIG_DIR=$SCRATCH/home/.claude CODEX_HOME=$SCRATCH/home/.codex
mkdir -p "$DEFENSECLAW_HOME" "$CLAUDE_CONFIG_DIR" "$CODEX_HOME"
.venv/bin/defenseclaw init --non-interactive --yes      # only ever inside $SCRATCH
printf 'sk-test\n' | .venv/bin/defenseclaw keys set OPENAI_API_KEY --value-stdin
.venv/bin/defenseclaw policy list --json
tmux new-session -d -s dc-tui-real -x 80 -y 24 \
  "env HOME=$HOME DEFENSECLAW_HOME=$DEFENSECLAW_HOME CLAUDE_CONFIG_DIR=$CLAUDE_CONFIG_DIR CODEX_HOME=$CODEX_HOME .venv/bin/defenseclaw tui"
```

- Never touch the real `~/.defenseclaw`, real agent configs (`~/.claude`,
  `~/.codex`), or run `init`/`setup` against the real HOME.
- Don't start a gateway on a port another agent is using. Check with `lsof -i :<port>`.
- Delete only the scratch directories you created.

## Windows, macOS and Linux host passes

The executor behaves differently on Windows (pipes plus a Job Object, no PTY,
different stdin and cancel behaviour, `USERPROFILE`-based home). For anything that
touches the executor, stdin, terminal launches or paths, do a host pass through
the `defenseclaw-live-testing` skill (Windows, macOS, RHEL and Ubuntu test hosts,
Defender-safe `dcx` helpers). If you can't, say so in the report.
