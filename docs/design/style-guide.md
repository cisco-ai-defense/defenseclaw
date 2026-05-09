# DefenseClaw Style Guide

This guide defines an original DefenseClaw interface style for TUI, web,
dashboard, and documentation surfaces. The aesthetic is intentionally
**terminal-derived**: DefenseClaw's daily driver is the TUI
(`internal/tui/`), and the web dashboard is its larger sibling, not a
different product. Web surfaces port the TUI's palette, casing, and density
to the browser, with an optional CRT effects layer for the operator vibe.

The reference implementation lives in [`web/`](../../web/) — palette tokens
in [`web/src/styles/tokens.css`](../../web/src/styles/tokens.css) mirror
[`internal/tui/theme.go`](../../internal/tui/theme.go) one-to-one.

It must not copy Grafana source code, dashboard JSON, CSS, icons, screenshots,
wordmarks, panel layouts, palette values, typography, or branded interaction
patterns. Treat Grafana as a category reference only, not as a design source.

## License And Brand Guardrails

Allowed:

- Use common observability-console ideas such as panels, filters, time ranges,
  annotations, tables, sparklines, threshold colors, drilldowns, and saved
  views.
- Use DefenseClaw product vocabulary: guardrail, verdict, policy, scanner,
  audit, gateway, OpenClaw, run, session, trace, block, allow, quarantine.
- Use original colors, spacing, typography, icons, copy, and layouts.
- Use Apache-2.0, MIT, or internally-owned design assets when their licenses
  are compatible with DefenseClaw.

Not allowed:

- Do not use Grafana logos, icons, screenshots, brand colors, UI kit assets,
  component code, dashboard JSON, docs copy, or CSS.
- Do not import Grafana themes or reuse exact visual constants from Grafana.
- Do not market DefenseClaw as "Grafana-like" or imply endorsement,
  compatibility, or affiliation unless that is specifically documented for the
  local observability stack.
- Do not reproduce a Grafana screen composition one-for-one. If a pattern feels
  familiar, change the information structure, labels, proportions, and styling
  until it is clearly DefenseClaw-owned.

## Product Personality

DefenseClaw is a security governance surface for agentic AI. The interface
should feel:

- Operational: built for repeated daily use, not a marketing demo.
- Terminal-derived: monospace chrome, all-caps section titles, dot
  indicators, ASCII-friendly box composition. The web surface should read as
  the TUI scaled up, not a different brand.
- Decisive: verdicts and next actions are visible without reading long prose.
- Traceable: every visible event should lead to evidence, request IDs, trace
  IDs, policy IDs, and raw records.
- Calm under pressure: critical states are unmistakable but not theatrical.
- Dense but legible: high information density, strong alignment, low ornament.

Avoid decorative illustrations, soft consumer-app styling, large empty hero
sections, gradient blobs, novelty metaphors, and oversized copy.

## Color System

The palette mirrors `internal/tui/theme.go` so the web surface and the TUI
look like the same product. Hex values are the standard ANSI 256-color
mappings of the lipgloss codes used in the Go theme. The lipgloss column is
authoritative — when adding a new web token, find the matching TUI usage
first.

| Token | Hex | Lipgloss | Use |
|-------|-----|----------|-----|
| `dc-bg` | `#0a0a0f` | — | App background |
| `dc-surface-1` | `#111118` | — | Primary panels, sidebars, status strip |
| `dc-surface-2` | `#181820` | — | Raised controls, panel headers, selected nav |
| `dc-surface-3` | `#21212c` | — | Hover, active chrome, modals |
| `dc-border` | `#444444` | 238 | Panel and table borders |
| `dc-border-strong` | `#5f5fd7` | 62 | Focused / active panels (matches `dc-primary`) |
| `dc-row-hover` | `#303030` | 236 | Row hover, status bar background |
| `dc-row-selected` | `#3a3a3a` | 237 | Selected row |
| `dc-text` | `#e0e0e0` | — | Primary text |
| `dc-text-bright` | `#ffffd7` | 230 | Active state, page titles, key values |
| `dc-text-muted` | `#8a8a8a` | 245 | Secondary text |
| `dc-text-faint` | `#626262` | 241 | Hints, timestamps, disabled labels |
| `dc-primary` | `#5f5fd7` | 62 | Title chrome, panel borders, modals, active tab |
| `dc-accent` | `#00afff` | 39 | Section headers, links, active navigation |
| `dc-hint` | `#5fd7d7` | 80 | Italic hint text (bottom strip, footers) |
| `dc-critical` | `#ff0000` | 196 | Critical severity, blocked, destructive |
| `dc-high` | `#ff8700` | 208 | High severity |
| `dc-medium` | `#ffd700` | 220 | Medium severity, warning |
| `dc-low` | `#00afff` | 39 | Low severity (shares the accent cyan) |
| `dc-info` | `#8a8a8a` | 245 | Info severity (shares muted gray) |
| `dc-clean` | `#00ff00` | 46 | Clean, allowed, healthy |
| `dc-quarantine` | `#af5fd7` | 133 | Quarantine, isolated |

Rules:

- Reserve red for blocked, critical, destructive, and failed states.
- Reserve green for clean, allowed, successful, and healthy states.
- `dc-primary` (violet) is for chrome and structure; `dc-accent` (cyan) is
  for emphasis, headings, and active selection. Don't swap them.
- Severity color and accent color overlap on cyan (low ≡ low-severity ≡
  navigation accent). That overlap is fine because severity is also tagged
  with text (`LOW`, `INFO`, etc.) — never rely on color alone.
- For charts, prefer one highlighted series and muted comparison series.

## Typography

DefenseClaw is **mono-first**. The TUI is monospace by definition, and the
web surface keeps that voice. Inter is opt-in for paragraph copy where
density demands proportional fonts (long-form documentation, marketing
panels) — never the default.

```css
--dc-font-mono:
  "JetBrains Mono", "SFMono-Regular", "SF Mono",
  ui-monospace, Menlo, Monaco, Consolas, monospace;
--dc-font-body:
  "Inter", ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
```

Type scale (px):

| Token | Size / Line | Use |
|-------|-------------|-----|
| `xl` | 20 / 28 | Page title (`// SECURITY OPERATIONS OVERVIEW`) |
| `lg` | 15 / 22 | Section title |
| `md` | 13 / 20 | Default body, table cells |
| `sm` | 12 / 18 | Status strip, metadata |
| `xs` | 11 / 16 | Labels, timestamps, hints |

Rules:

- **Mono is default** for chrome, tables, forms, status, IDs, paths,
  commands, and policy IDs. Inter is opt-in via `.dc-prose` for long-form
  body copy only.
- **All-caps is canonical** for: section headers, panel titles, nav items,
  button labels, severity labels, and short status tokens. Pair with
  `letter-spacing: 0.10–0.18em`.
- **Sentence case** is reserved for body text inside panels and tables —
  metric notes, descriptions, error messages, prose.
- Page titles read like terminal banners: `// <ALL CAPS TITLE>` is allowed
  and on-brand.
- Keep table rows compact: 32–40px row height, 6–10px horizontal padding.

## Iconography

DefenseClaw prefers Unicode glyphs over icon fonts. The TUI uses
`●` / `○` for run/off state, `╭─╮│╰─╯` for panel borders, `→` `←` for
navigation hints — these all render identically in a browser without any
asset pipeline, sprite sheet, or icon library dependency.

| Concept | Glyph | Notes |
|---------|-------|-------|
| Running / active | `●` in `--dc-clean` | Saturated green dot |
| Degraded / starting | `●` in `--dc-medium` | Amber dot |
| Error / stopped | `●` in `--dc-critical` | Red dot |
| Off / disabled | `○` in `--dc-text-faint` | Outline-only dot |
| Severity | text label | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO` |
| Outcome | text verb | `blocked` / `allowed` / `quarantined` / `alerted` / `observed` |
| Section delimiter | `//` prefix | `// SECURITY OPERATIONS OVERVIEW` |
| Panel border | `╭─╮│╰─╯` (TUI) or 1px `--dc-border` (web) | |
| Drilldown / nav | `→` / `←` / `↳` | |
| Modified pip | `●` in `--dc-medium` + "modified" label | Editor states |

If a stroke-icon set is needed for a specific surface (chart legend,
toolbar overflow), Lucide is acceptable — but glyphs are the default. Do
not use Grafana icons or screenshots as references for final artwork.

## Component Style

### App Shell

- Dark full-screen shell.
- Left navigation for web or wide desktop surfaces.
- Top status strip for gateway, guardrail mode, sink health, and time range.
- Bottom hint/status strip for TUI and keyboard-heavy screens.
- Content area uses aligned panels, tables, and workbenches.

### Panels

Panels are functional containers, not decorative cards.

- Radius: `6px`.
- Border: `1px solid dc-border`.
- Header height: 40px web, one line TUI.
- Padding: 12px web, 1-2 terminal cells TUI.
- Header content: title, short status, local controls.
- Body content: metric, chart, table, event list, or detail.

Panel states:

- Normal: `dc-surface-1` with `dc-border`.
- Hover/focus: border `dc-border-strong`.
- Selected: subtle `dc-accent-deep` inset or left rule.
- Critical: red left rule plus severity label. Do not flood-fill the panel.

### Tables

Tables are primary work surfaces.

- Sticky header on web.
- Row height 32-40px depending on density.
- Left-align text, right-align numeric values, monospace technical IDs.
- Use truncation with copy actions for long IDs.
- Keep the first column stable across filtered views.
- Include empty, loading, stale, and error states in the table body.

### Badges And Chips

Badges encode status. Chips encode filters.

- Badges: fixed vocabulary, not interactive unless clearly button-styled.
- Chips: interactive filters with selected, removable, and disabled states.
- Severity badges must include the text value: `CRITICAL`, `HIGH`, `MEDIUM`,
  `LOW`, `INFO`.
- Policy outcome badges should use verbs: `blocked`, `allowed`, `alerted`,
  `quarantined`, `observed`.

### Forms

Forms should be quiet and explicit:

- Label above field for web.
- Label/value rows for TUI.
- Inline validation next to the field.
- Dangerous actions require a confirmation surface that names the target and
  consequence.
- Use progressive disclosure for advanced settings, but keep current effective
  values visible.

### Command Palette

DefenseClaw already uses `:` and `Ctrl+K` in the TUI. Keep that model:

- Search commands by noun and verb.
- Show command source when useful: `defenseclaw skill scan`.
- Show destructive commands with severity styling.
- Stream output into Activity rather than hiding it behind a modal.

## CRT Effects Layer

DefenseClaw web ships an optional CRT skin that adds three subtle effects
on top of the base palette. It is **enabled by default** in the dev build
and can be turned off without affecting layout or readability:

```html
<html data-effects="crt">   <!-- on -->
<html data-effects="">       <!-- off -->
```

Layers (all in
[`web/src/styles/effects-crt.css`](../../web/src/styles/effects-crt.css)):

1. **Scanlines** — `repeating-linear-gradient` of cyan stripes at ~1.8%
   alpha, 1px-on / 3px-off, `mix-blend-mode: screen`. Disabled when
   `prefers-reduced-motion: reduce`.
2. **Vignette** — radial darkening of the corners, ~22% black at the edge,
   transparent at the center.
3. **Accent glow** — `text-shadow: 0 0 6px` on `.dc-section` only (~45%
   alpha cyan). Reserved for accent text; never applied to body copy.

Hard rules:

- Effects must be opt-out: a deployment may set `data-effects=""` and the
  product must remain fully usable. Never depend on a glow to convey
  meaning.
- Severity / state colors carry meaning from the base palette, not from
  the glow. The glow is decorative.
- Do not stack additional effects (chromatic aberration, screen flicker,
  film grain). The current three are the canon.
- The CRT layer is web-only. The TUI does not need it; terminals already
  provide the aesthetic.

## Data Visualization

Charts exist to accelerate triage, not to decorate the page.

Use:

- Stat panels for current risk, SLO compliance, block rate, queue pressure.
- Time series for rates, latency, errors, and sink throughput.
- Stacked bars for severity distribution.
- Tables for audit evidence, verdicts, alerts, and investigations.
- Trace timelines for request/session detail.

Avoid:

- 3D charts.
- Multi-color palettes without semantic meaning.
- Tiny charts without axis context.
- Pie charts for more than three categories.
- Chart-only evidence with no path to raw rows.

Every chart should answer:

- What changed?
- Is it bad?
- Where do I drill down?
- What exact time range and filters produced this view?

## Copy And Naming

Use short, direct labels:

- `Block`, not `Deny access request`.
- `Quarantine`, not `Move component to isolation state` in button text.
- `Guardrail mode`, not `LLM safety configuration operating mode`.
- `Sink health`, not `Observability delivery backend status`.

Prefer operator verbs (rendered all-caps in chrome — `BLOCK`, `SCAN`,
`RESTORE` — and sentence-case in body copy):

- Scan
- Block
- Allow
- Quarantine
- Restore
- Inspect
- Test
- Export
- Retry

For errors:

- Say what failed.
- Say the target.
- Say the next useful action.
- Include the command or trace ID when available.

## Accessibility

- Maintain at least 4.5:1 contrast for normal text.
- Support keyboard-first navigation.
- Preserve focus rings; use `dc-accent-strong`.
- Pair icons with accessible labels.
- Do not encode severity by color alone.
- Keep terminal renderers usable in limited-color environments.
- Respect reduced motion. Use motion only for loading, streaming, or state
  transitions that carry meaning.

## Implementation Checklist

Before shipping a new DefenseClaw UI surface:

- It uses DefenseClaw tokens from `web/src/styles/tokens.css`, not copied
  third-party theme constants.
- Mono is the default font; Inter is opt-in via `.dc-prose`.
- Section/panel/nav/button labels are all-caps mono with letter-spacing.
- Severity is paired with text, not encoded in color alone.
- It avoids Grafana assets, code, dashboard JSON, screenshots, and exact
  visual styling.
- It shows state, scope, time range, and freshness.
- It exposes request IDs, trace IDs, policy IDs, or raw records where
  relevant.
- It has loading, empty, stale, error, and permission-denied states.
- It works with keyboard-only operation.
- It keeps destructive actions explicit and reversible where possible.
- It has at least one drilldown path from summary to evidence.
- It remains fully usable with `data-effects=""` (CRT layer disabled).
