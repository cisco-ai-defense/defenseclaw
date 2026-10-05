# Diagram authoring guide

The docs site renders diagrams as server-side React/Tailwind/SVG via two
components: `<Flow>` (DAGs) and `<Sequence>` (swimlanes). This file is the
contract between authors and the engine. Read it before adding a new diagram.

## The one rule that matters

**Default to `direction="TB"`.**

Documentation columns are taller than wide (840px of diagram canvas at the
required 1536px desktop viewport; ~700px on tablets). A 7-node
`direction="LR"` Flow blows past the column on common monitors. The same graph
in `direction="TB"` remains readable and pans safely on a phone.

If you find yourself reaching for `direction="LR"`, ask:

- Are there ≤3 nodes per rank? (`a → b → c`, no fan-out.)
- Is the graph topologically a single line, with maybe one parallel edge?

If yes, `LR` is fine. Otherwise: `TB`.

The renderer also recognizes a true unbranched chain. A short chain is
promoted to a horizontal operating rail when it fits the article; a longer
`TB` chain becomes a wide, numbered process rail. Authors should still choose
the direction that best communicates the topology rather than laying out the
cards by hand.

## Readability rules

These come first. A diagram that follows them reads in a few seconds;
one that does not needs the lightbox and a second look.

1. **One idea per diagram.** If the caption needs "and" twice, split it.
   Aim for 4–8 nodes; past 10, split into two diagrams (for example "how
   a request is decided" and "where the evidence goes").
2. **Ground truth is the code.** Every box, arrow, label, port, socket,
   path, account and decision branch must match the repo source. Prefer
   leaving a detail out to drawing it wrong.
3. **Plain-language labels.** Say what the thing does ("Checks the
   command against policy"), not its internal type name. Put binary,
   package and function names in the detail line or the caption.
4. **Titles are one idea, details are the rest.** The first line of a
   node is its title; every later line is a smaller, muted detail. Do not
   break one sentence across the title and a detail line
   (`On your org's or\nyour block list?` reads as two unrelated phrases).
   Write `On your block list?` as the title, or `Block list?` plus a
   detail line.
5. **Arrows are verbs.** Label an edge with what happens along it:
   `reads`, `writes as the user`, `asks`, `blocks`. Keep labels to 1–3
   words; the channel (named pipe, HTTPS) is fine on boundary crossings.
6. **Keep one direction.** Requests flow down (TB) or right (LR). Point
   replies and feedback the same way as the request when you can and use
   `variant="dashed"`; avoid arrows that run back up the whole diagram.
7. **No tags on every box.** The role glyph in front of each title
   already says what kind of thing it is. Use `tag` only when it carries
   meaning the reader needs, such as the identity a component runs as.
8. **Check it at 390px and in dark mode.** Wide Flows become a list on
   phones (see Mobile); make sure the list still reads in order.

## Visual language

- Use component roles consistently: agent runtime, connector, control plane,
  policy, evidence store, operator, decision, or system.
- Every role is a small glyph in front of the title plus a thin color rail
  on the card's left edge; color is never the only differentiator. The
  role is not printed as text unless the Flow sets `kindLabels`.
- Use single-ended arrows for direction. Reserve `bidirectional` for a real
  two-way contract, not a request followed by a response.
- Edge labels are sans text cut out of their line (the label sits on the
  fill behind it, zone or canvas). Keep them short; explain implementation
  detail in the caption or surrounding prose.
- Do not recreate editor chrome, graph paper, gradients, glows, or decorative
  topology. Diagrams are architecture evidence, not illustrations.

### Node props

```mdx
<Node id="gw" kind="gateway">{`Gateway\nchecks every tool call`}</Node>
<Node id="svc" kind="generic" tag="runs as root">Hook guardian</Node>
```

| Prop | Use |
| --- | --- |
| `kind` | Role glyph and rail color. `gateway` nodes are always emphasized. |
| `emphasis` | Blue border and tint. Use for the one component the diagram is about. |
| `tag` | Short tag above the title, only when it carries meaning (identity, trust level, "optional"). |
| `zone` | Zone id when the node is not nested in its `<Zone>`. |

`<Flow kindLabels>` prints every node's role ("Policy", "Control plane")
as its tag. It exists for legend-style diagrams; leave it off otherwise.

## Sizing budget

| Width | Effect |
| --- | --- |
| ≤840px | Renders at 1:1 inside the article canvas at the required 1536px desktop viewport. |
| 840–1168px | Scales-to-fit on common desktop widths; warning emitted by the build-time width gate. |
| >1168px | **Build fails** unless `<Flow oversize />` / `<Sequence oversize />` is set. The lightbox affordance becomes the readable path. |

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
<Flow direction="TB"> ... </Flow>                      // dense spacing is automatic
<Flow direction="LR" compact> ... </Flow>              // opt into dense spacing for wide flows
<Flow direction="TB" compact oversize> ... </Flow>     // last resort
```

`compact` shrinks dagre's rank and node spacing and drops `NODE_MAX_W`
(288→256). It buys you the column on graphs that are
structurally fine but spaced too generously. Negligible legibility cost.

Large branched `TB` trees automatically use a denser 148–184px node range and
tighter sibling spacing. This is reserved for ten-or-more-node decision trees;
shorter diagrams keep the roomier default geometry.

`oversize` only suppresses the build-time width gate's hard-fail. The
diagram is still bigger than the column; readers see it scaled-to-fit
inline and can click the expand button for the full-size view. Use this
when the topology genuinely doesn't compress.

## Zones (trust boundaries)

`<Zone>` groups `<Flow>` nodes into privilege or trust zones for threat
models: which component runs as which identity, and which edges cross a
boundary. Use zones only when the boundary is the point of the diagram.
For plain "these belong together" grouping, rely on node kinds and prose.

```mdx
<Flow direction="TB" caption="Trust zones for a service-mode install. Every edge that crosses a zone border is an attack surface.">
  <Zone id="z4" label="Z4 · User session (user)" tone="untrusted">
    <Node id="agent" kind="agent">{`Agent runtime\nClaude Code · Codex`}</Node>
    <Node id="hook" kind="connector">Hook CLI</Node>
  </Zone>
  <Zone id="z1" label="Z1 · Privileged services (LocalSystem · root)" tone="privileged">
    <Node id="gateway" kind="gateway">defenseclaw-gateway</Node>
  </Zone>
  <Zone id="z3" label="Z3 · Admin-owned state" tone="protected" />
  <Node id="policy" zone="z3" kind="policy">Config + policy</Node>
  <Edge from="agent" to="hook" label="tool call" />
  <Edge from="hook" to="gateway" label="named pipe" />
  <Edge from="gateway" to="policy" label="reads" />
</Flow>
```

A node joins a zone by nesting inside it or through `zone="id"`; if both
are given, nesting wins. Each zone is drawn as a framed region behind
the edges and nodes, with a header tab on its top border that prints
the trust level (the tone name, in the tone color) and the label. The
header carries the meaning, so the tint is never the only signal. The
tone colors are AA as text on the canvas and on their own fill, in
light and dark mode; the borders are about 3:1.

| `tone` | Use for | Border |
| --- | --- | --- |
| `trusted` | Platform and admin tooling you rely on | solid |
| `privileged` | Services running as LocalSystem or root | solid |
| `restricted` | Reduced-privilege service identities and sandboxes | solid |
| `protected` | Admin-owned state: config, policy, audit | solid |
| `untrusted` | The user session and anything a prompt can steer | dashed |
| `external` | Third-party services and the network | dotted |

- [ ] ≤6 zones, ≤5 nodes per zone.
- [ ] `direction="TB"`. Zoned flows keep the direction you choose, so a
      zoned chain is never promoted to a horizontal rail.
- [ ] ≤3 zones side by side in a rank. Cards in neighbouring zones sit
      62px apart, against 38px for bare siblings.
- [ ] Zone labels ≤32 chars, in the form `Zn · Name (identity)`. A zone
      is at least as wide as its header tab, so a label longer than
      about 20 chars widens a one-node zone. The trust level is already
      on the tab: do not repeat it in the label (`Z4 · User session
      (untrusted)` prints "Untrusted" twice).
- [ ] Order the zones by trust, most trusted first, and declare them in
      that order. Dagre stacks zones by their edges, so point edges from
      the zone that should sit higher to the one below it; the phone list
      shows zones in declaration order. The six-zone model in
      [`scripts/test-diagram-zones.tsx`](../../scripts/test-diagram-zones.tsx)
      uses labels like these and lands at 862px: the gate warns, but it
      does not fail.
- [ ] Label every edge that crosses a boundary with its channel (named
      pipe, HTTPS, file write). Those crossings are what reviewers look for.
- [ ] Zones do not nest. A `<Zone>` inside another `<Zone>` is drawn as
      a sibling, and the build logs a warning.

The build also warns, without failing, about an empty zone (which is not
drawn), a `zone=` that names no zone, a duplicate zone id, and an unknown
tone (drawn as `external`). `npm run test:diagram-zones` checks the zone
geometry.

## `<Sequence>` checklist

- [ ] ≤5 participants. More than that, the swimlane stops being readable
      and you're better off splitting into two sequences.
- [ ] Participant labels ≤16 chars. Per-column gaps now scale only the
      columns a label spans, but a long label still widens *some* column.
      Alias long names (`Gateway` not `defenseclaw-gateway`, `Hook` not
      `beforeShellExecution`) and put the long form in the surrounding
      prose or the diagram caption.
- [ ] Message labels ≤44 chars. Chips ellipsize past 300px wide; longer
      labels just visually fail.
- [ ] Use `kind="return"` for response arrows; the engine renders them
      dashed and one step lighter so the eye reads request/response pairs
      without re-parsing. The phone timeline marks them "reply" and still
      reads `from → to`.
- [ ] Participants show the role glyph and the label only (no role tag);
      a label wraps to two lines at most, so keep it to two short words.
- [ ] Use `note` for grouping callouts ("Sinks fan-out") rather than
      forcing them through the message-label channel.

### Mobile

Below 640px a diagram either becomes a list or shrinks. Both renders
ship as static HTML and CSS toggles which is visible: no JS, no
hydration cost. The expand button (always visible on touch) still opens
the drawing at full size.

`<Sequence>` ships a vertical, numbered timeline: each message is a row
with a `from → to` header (replies marked "reply") and the label. It
uses participant *labels*, not ids, so keep the labels self-explanatory.

`<Flow>` picks with `mobile`:

| `mobile` | Below 640px |
| --- | --- |
| `auto` (default) | `stack` when the drawing is wider than 460px, else `scale`. |
| `stack` | A list grouped by zone (declaration order), nodes in reading order, each listing its outgoing arrows as `verb → target`, with the target's zone when the arrow crosses a boundary. Process rails are numbered. |
| `scale` | The drawing shrinks to the column. Fine for narrow (≤460px) drawings. |
| `scroll` | The drawing keeps up to 620px and pans sideways under a "scroll sideways" hint. Use when the shape matters more than the text. |

Because the list is built from node titles and edge labels, a Flow that
follows the readability rules reads well as a list for free.

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

### October 2026 style pass (shared engine)

- Node chrome: the 30px icon box and the tracked caps role tag on every
  card are gone; a 14px role glyph sits in front of the title and the
  rail is 3px. Cards are ~25px shorter and, in dense trees, ~40px of
  text width wider, so titles wrap less.
- Edge labels: sans 11.5px on the fill behind them (zone or canvas),
  not mono text on a white box.
- Zone headers: a 22px tab with the trust level in sentence case and
  the label at 11.5px, measured generously so labels no longer clip.
- Edges longer than 600px no longer render with a gap (the old
  draw-in animation left `stroke-dasharray: 600` on every edge).
- Sequences: no alternating lane bands or row rules, participant labels
  wrap instead of truncating, labels stay inside the drawing, and the
  phone timeline no longer flips arrows on replies.
- Phones: wide Flows get the list view described under Mobile.

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
