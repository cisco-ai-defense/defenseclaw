# Gotchas (verified pitfalls)

Each entry covers what goes wrong and what to do instead. Several were fixed by
the TUI update that introduced this skill. The "used to" entries are there so
nobody reintroduces them.

## Keys and text entry

- **`_panel_key` lowercases most capitals.** Only `A C E G J M N R S T V X` stay
  uppercase, and everything else is folded (so `U` becomes `u`). Never route
  text entry through panel keys, because typed text loses its capitals and
  collides with shortcuts. Use `FieldEditorScreen`. For one distinct capital,
  read `event.character` (see the Sandboxes `U` undo case in
  `_handle_active_panel_key`).
- **Panel handlers run before panel shortcuts.** If your panel consumes `r`,
  `a`, `n` or `v`, that key no longer switches panel from there. That's fine
  when intended, but check the table in `ux-rules.md`.
- **`t` is pinned as a no-op** at the app level by a test. Don't bind it
  globally (panels such as AI Discovery use `t` locally).
- **`q` is local close** (drawer or overlay), never quit.
- **The Tools panel is unreachable.** `ToolsPanelModel`, `#tools-controls` and a
  hint branch exist, but `tools` is not in `PANELS`. Don't "fix" hints or tests
  for it as if users could see it, and don't assume a `T` shortcut exists.

## Config and Setup

- **`Config.save()` silently drops keys not modeled in the Python `Config`
  dataclass** (`cli/defenseclaw/config.py`). A config-editor field for an
  unmodeled key looks saved and then disappears. Model it in `Config`, or show
  it read-only with a hint.
- **`setup guardrail --non-interactive` re-enables the guardrail and re-derives
  defaults.** Don't use it to switch rule packs. Use
  `defenseclaw guardrail use-pack PACK [--connector NAME]`, which only touches
  `rule_pack_dir` or the connector override.
- **The trusted-paths editor used to scan the host on mount.** Screens and
  models must not do discovery in `on_mount`, `compose` or `_body_text`. Load
  in a worker (`asyncio.to_thread`), or take the data as a constructor argument.
- **`_body_text` re-renders every 2 s** (`set_interval(2.0, self._periodic_refresh)`).
  Any I/O there stalls the UI and hammers the disk. Anything stateful there
  (resetting a cursor, clearing a message) fires over and over.

## Secrets and commands

- **`click.prompt(hide_input=True)` and getpass ignore piped stdin** (they read
  the TTY), so feeding a secret over stdin silently hangs or prompts. The CLI
  needs `--value-stdin` (for example `keys set NAME --value-stdin`), and the TUI
  sets `intent.secret_stdin`. The executor switches to a pipe so the PTY can't
  echo the secret.
- **Follow-up intents used to race the first command.** They were queued right
  after launching it, not after it finished. Follow-ups now run only after the
  previous command finished and exited 0. Keep it that way, and test it with a
  failing first command.
- **`policy activate` didn't reload the gateway before this update.** It wrote
  the files, and the running gateway kept the old policy until restart. Now it
  POSTs `/policy/reload` (`--no-reload` to skip). If the gateway is unreachable
  it says the policy loads at start and exits 0.
- **`firewall-deny-default.yaml` is not a named policy.** It's a firewall
  template sitting in `policies/`. Use `policy_catalog.is_named_policy` /
  `list_named_policies`, never "every YAML file in the policy dir".

## Rendering

- **Rich markup in data crashes the app.** A skill name, log line or policy
  description containing `[...]` raises `MarkupError`/`MissingStyle`, sometimes
  several frames later. Escape every data string with `rich.markup.escape`,
  write key labels as `\\[k]`, and keep `_safe_body_renderable` as the last line
  of defence, not the plan.
- **No `@click` action links in `#body`.** They crash the compositor. Chips use
  the click map instead (`_handle_body_chip_click`).
- **Stale background snapshots.** Heavy panels render off-thread with a
  generation counter. If you add a new direct render path, go through
  `_render_chrome` so the generation is bumped.

## Tests and tooling

- **Pilot tests were cut aggressively.** Don't re-add broad Pilot coverage (see
  `testing.md`).
- **`render.py` and `demo.py` stub host probes** (agent discovery, sandbox
  doctor). If a new panel probes the host on mount, add a stub to
  `render._stub_host_probes`, or the renders stop being hermetic.
