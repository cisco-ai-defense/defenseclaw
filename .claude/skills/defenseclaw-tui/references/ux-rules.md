# UX rules

## 80x24 budget

The smallest supported terminal is 80 columns by 24 rows. Budget the rows:

| Region | Rows |
|---|---|
| Header, tab strip and rule | 3 |
| Body lines above the table (title, summary, filter or chip) | ≤ 3 |
| Table header plus rows | the rest |
| Button bar (only if the panel has one) | 3 (bordered) |
| Hint bar | 1-2 |
| Status line | 1 |

Rules:
- Primary content (the first table row, wizard row, form field or config
  field) must be on screen at 80x24 without scrolling. Check with
  `render.py --size 80x24 --expect "<first row text>"`.
- Aim for a body of at most 2-3 lines above the table. Move explanations into the
  detail view, the `?` sheet or the empty state.
- No "Keys:" lines in the body. Keys belong in the hint bar and the `?` sheet.
- The status line is one line of plain status, with no debug text
  (`backend=… panel=… hints=…`).
- Under 100 columns, tables go compact (`data_table_columns(compact=True)`) and
  drop what the detail view shows.
- The tab strip must fit at 120 columns with every panel (including Policies).
  Use compact labels under a width threshold and never reorder `PANELS`.
- Also check 120x40, where nothing should look stretched or duplicated.

## Hints per view

- One source of truth per view. The `HintEngine.hint_for` branch (or, for Setup,
  the per-view keymap in `panels/setup_keys.py` with views `wizards`, `goals`,
  `form`, `config`, `first-run`) feeds the hint bar, the `?` help sheet and the
  per-view button visibility.
- Every advertised key is handled in that view, and every handled key is
  advertised in `?`. A test should iterate over the keymap, not the copy.
- The hint shows the 3-5 most useful keys for the current view, with the
  verb first: `Enter open · a approve · x reject · / filter`.

## Per-view control bars

- Each panel has one `Horizontal(id="<panel>-controls")`. `_sync_<panel>_controls`
  hides buttons that don't apply to the current view or selection. Hide them
  rather than disable them, so a visible button always works.
- Button labels are sentence case and short (`New run`, `Sandboxed on/off`).
  The tooltip says what it does and ends with the key: `"Stop the sandbox (asks first) (s)"`.

## Copy style

- Plain words, sentence case, verb first: "Run setup", "Switch rule pack",
  "Unblock this destination".
- No internal jargon in user-facing text (no "intent", "wire", "v8 graph",
  "parity wave", "N1", "C1").
- Refusals are one line and say what to do: "A sandbox action is still
  running; wait for it to finish." "Pick a policy first (Enter)."
- Consequence modals say concretely what changes or is lost ("This deletes
  files from disk.") and name the command that will run.
- Empty states say what to do next: "No policies yet. Press n to create one or
  run `defenseclaw policy create`."
- Escape all data (`rich.markup.escape`) and write literal key labels as `\\[k]`.

## Reserved and taken keys

Panel handlers run before the panel shortcuts. A key your panel consumes stops
working as a shortcut while that panel is active, so only take the shortcut
letters on purpose.

| Key | Meaning | Where |
|---|---|---|
| `0`-`9` | Panel shortcuts (Setup=0, Overview=1 … Audit=9) | global, via `PANEL_SHORTCUTS` |
| `a` / `A` | Activity panel | global shortcut (case-insensitive) |
| `v` / `V` | AI Discovery panel | global shortcut |
| `n` / `N` | Runtime panel | global shortcut |
| `r` / `R` | Registries panel (many panels use `r` for refresh locally) | global shortcut |
| `P` | Policies panel | global shortcut (being added) |
| `t` | Pinned no-op at the app level (a test asserts it) | don't bind globally |
| `q` | Local close (closes the drawer or overlay; otherwise a no-op, never quits) | app binding |
| `ctrl+c` | Cancel the running command, or quit | app binding (priority) |
| `:` / `ctrl+k` | Command palette | app binding |
| `?` | Help overlay | app binding |
| `ctrl+p` | Panel jumper | app binding |
| `ctrl+\` | Theme picker | app binding |
| `Y` / `ctrl+s` | Copy / save the last command output | app binding |
| `D` | Background doctor | app binding |
| `tab` / `shift+tab` | Next / previous panel (Setup forms use them between fields) | app |
| `m` | Connector filter picker (multi-connector) | Overview, Alerts, Audit, Logs, catalogs, Inventory |
| `/` | Filter or search | most list panels |
| `Enter` / `Esc` | Open detail / close detail or cancel | everywhere |

Capital letters reach panels only if `_panel_key` keeps them
(`A C E G J M N R S T V X`). For anything else, read `event.character`
explicitly, as Sandboxes does for `U`.
