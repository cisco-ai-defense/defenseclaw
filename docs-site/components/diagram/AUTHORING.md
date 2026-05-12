# Diagram authoring guide

The docs site renders diagrams as server-side React/Tailwind/SVG via two
components: `<Flow>` (DAGs) and `<Sequence>` (swimlanes). This file is the
contract between authors and the engine. Read it before adding a new diagram.

## The one rule that matters

**Default to `direction="TB"`.**

Documentation columns are taller than wide (1168px max width on `xl:`
breakpoints; ~700px on tablets). A 7-node `direction="LR"` Flow blows past the
column on every monitor below 1920px. The same graph in `direction="TB"`
fits on a phone.

If you find yourself reaching for `direction="LR"`, ask:

- Are there ≤3 nodes per rank? (`a → b → c`, no fan-out.)
- Is the graph topologically a single line, with maybe one parallel edge?

If yes, `LR` is fine. Otherwise: `TB`.

## Sizing budget

| Width | Effect |
| --- | --- |
| ≤1168px | Renders cleanly inside the article column on every viewport down to ~360px. |
| 1168–1500px | Scales-to-fit on desktop; warning emitted by the build-time width gate. |
| >1500px | **Build fails** unless `<Flow oversize />` / `<Sequence oversize />` is set. The lightbox affordance becomes the readable path. |

The build-time gate lives at
[`scripts/check-diagram-widths.ts`](../../scripts/check-diagram-widths.ts) and
runs after `next build` via `postbuild`.

## `<Flow>` checklist

- [ ] `direction="TB"` unless your graph is genuinely linear.
- [ ] ≤4 nodes per rank.
- [ ] ≤6 nodes per path from root to leaf.
- [ ] Node label ≤2 lines, ≤22 chars per line. Long lines wrap and burn
      vertical space; long labels widen the natural diagram width.
- [ ] Reach for `compact` before `oversize` when bumping the column.
- [ ] Reach for `oversize` only after exhausting `direction="TB"` + `compact`
      + label trimming + diagram splitting.

### Knobs in order of preference

```mdx
<Flow direction="TB"> ... </Flow>                      // start here
<Flow direction="TB" compact> ... </Flow>              // tightens spacing ~15-20%
<Flow direction="TB" compact oversize> ... </Flow>     // last resort
```

`compact` shrinks dagre's `ranksep` (80→50) and `nodesep` (50→30), and drops
`NODE_MAX_W` (260→220). It buys you the column on graphs that are
structurally fine but spaced too generously. Negligible legibility cost.

`oversize` only suppresses the build-time width gate's hard-fail. The
diagram is still bigger than the column; readers see it scaled-to-fit
inline and can click the expand button for the full-size view. Use this
when the topology genuinely doesn't compress.

## `<Sequence>` checklist

- [ ] ≤5 participants. More than that, the swimlane stops being readable
      and you're better off splitting into two sequences.
- [ ] Participant labels ≤16 chars. Per-column gaps now scale only the
      columns a label spans, but a long label still widens *some* column.
      Alias long names (`Gateway` not `defenseclaw-gateway`, `Hook` not
      `beforeShellExecution`) and put the long form in the surrounding
      prose or the diagram caption.
- [ ] Message labels ≤40 chars. Chips ellipsize past 280px wide; longer
      labels just visually fail.
- [ ] Use `kind="return"` for response arrows; the engine renders them
      dashed and lower-contrast so the eye reads request/response pairs
      without re-parsing.
- [ ] Use `note` for grouping callouts ("Sinks fan-out") rather than
      forcing them through the message-label channel.

### Mobile

`<Sequence>` ships **two** renders in the same SSR HTML:

1. The desktop swimlane SVG (visible at `sm:` and above, ≥640px).
2. A vertical timeline-list (visible below 640px) — each message as a
   card with a `from → to` header and the label body.

Both ship as static HTML; CSS toggles which is visible. No JS, no
hydration cost. The timeline render uses participant *labels*, not ids,
so keep the labels self-explanatory.

`<Flow>` does **not** ship a mobile render — the topology is too free.
On phones, Flow scales down to fit and the lightbox button (always
visible at touch sizes) opens the modal for native-size pan/zoom.

## Lightbox affordance

Every Flow and Sequence is wrapped in
[`<DiagramLightbox>`](./lightbox.tsx) automatically. The expand button
is hover-revealed at desktop and always-visible on touch devices. The
modal renders the same SVG inside an `overflow: auto` surface — wide
diagrams pan horizontally, tall ones pan vertically. Esc closes;
focus restores to the trigger.

You don't need to opt in to the lightbox. It's the readable-detail path
for any diagram the column can't quite fit.

## Before/after gallery

Concrete examples from the May 2026 robustness pass.

### `index.mdx` — Architecture

**Before** — `direction="LR"`, 7 wide nodes, ~1240px:
```mdx
<Flow direction="LR">
  <Node id="agent" kind="agent">{`Agent runtime\n(Claude Code / Codex /\nOpenClaw / ...)`}</Node>
  ...
</Flow>
```

**After** — `direction="TB"` + `compact`, label trimming, fits column:
```mdx
<Flow direction="TB" compact>
  <Node id="agent" kind="agent">{`Agent runtime\nClaude · Codex ·\nOpenClaw · ...`}</Node>
  ...
</Flow>
```

Width: 1240px → ~720px. Same information, no horizontal scroll.

### `setup/skill-scanner.mdx` — Sequence

**Before** — verbose participant labels widened every column, 1441px:
```mdx
<Sequence
  participants={[
    { id: 'agent',   label: 'Agent (Claude / Cursor / ...)', kind: 'agent' },
    { id: 'watcher', label: 'DefenseClaw watcher',           kind: 'gateway' },
    ...
  ]}
>
  <Message from="policy" to="watcher" kind="return"
    label="file: none|quarantine, runtime: enable|disable, install: none|block" />
</Sequence>
```

**After** — short participant aliases + the long form in the caption.
Per-column gaps now compress because the spanning labels are shorter:
```mdx
<Sequence
  caption="...Watcher is `defenseclaw-gateway`'s install watcher; Scanner is `cisco-ai-skill-scanner`."
  participants={[
    { id: 'agent',   label: 'Agent',     kind: 'agent' },
    { id: 'watcher', label: 'Watcher',   kind: 'gateway' },
    ...
  ]}
>
  <Message from="policy" to="watcher" kind="return"
    label="file · runtime · install verdict" />
</Sequence>
```

Width: 1441px → ~1050px.

### `get-started/quickstart.mdx` — Pipeline

**Before** — 8-node `direction="LR"` pipeline, ~1960px (way past hard limit):
```mdx
<Flow direction="LR">
  <Node id="init" .../>
  ... 8 nodes ...
</Flow>
```

**After** — same 8 nodes, `direction="TB"`. Width: ~1960px → ~720px.

## When in doubt

Run `npm run build && npm run check-diagram-widths` locally. The gate
will tell you which diagram broke and what to do about it.
