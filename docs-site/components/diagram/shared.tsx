import * as React from 'react';

// Shared types, layout heuristics, and SVG <defs> for the docs-site
// diagram primitives. <Flow> and <Sequence> import from this module so
// every diagram in the site speaks the same visual vocabulary: same
// arrowhead, same panel fill, same emphasis gradient, same kind-keyed
// accent. That consistency is the whole point of replacing mermaid —
// every "Audit DB" looks like every other "Audit DB", every
// "defenseclaw-gateway" pops the same way.

export type DiagramKind =
  | 'agent'
  | 'connector'
  | 'gateway'
  | 'policy'
  | 'datastore'
  | 'operator'
  | 'decision'
  | 'generic';

export type EdgeVariant = 'solid' | 'dashed' | 'bidirectional';

export type MessageKind = 'sync' | 'return' | 'async';

export interface KindStyle {
  // Color of the 4px accent stripe on the left edge (or top, for diamonds)
  // of each non-emphasized node. Empty string means no stripe.
  accent: string;
  // Whether the node renders as a pill (full-radius rounded rectangle).
  pill?: boolean;
  // Whether the node renders as a diamond instead of a rectangle.
  diamond?: boolean;
  // Whether the node draws a doubled bottom edge — a subtle data-store
  // glyph that lets readers spot SQLite/JSONL/Prometheus at a glance.
  datastoreFooter?: boolean;
}

export const KIND_TO_STYLE: Record<DiagramKind, KindStyle> = {
  agent:     { accent: 'var(--brand-cisco)' },
  connector: { accent: 'var(--color-fd-muted-foreground)' },
  gateway:   { accent: 'var(--brand-cisco-strong)' },
  policy:    { accent: 'var(--brand-warn)' },
  datastore: { accent: 'var(--color-fd-muted-foreground)', datastoreFooter: true },
  operator:  { accent: 'var(--brand-cisco)', pill: true },
  decision:  { accent: 'var(--brand-warn)', diamond: true },
  generic:   { accent: '' },
};

// Estimation constants, calibrated to the docs-site system-ui stack
// at 14px medium. We can't measure text on the server, so every
// dimension below is conservative: text never gets clipped, but
// diagrams stay tight enough not to feel airy.
export const CHAR_WIDTH = 7;
export const LINE_HEIGHT = 20;
export const NODE_PAD_X = 20;
export const NODE_PAD_Y = 14;
export const NODE_MIN_W = 120;
export const NODE_MAX_W = 260;
// Compact mode trims the upper bound only — narrow nodes still fit.
// Combined with the tighter dagre nodesep/ranksep in <Flow>, this
// shaves ~15-20% off the natural width with negligible legibility
// cost.
export const NODE_MAX_W_COMPACT = 220;
export const NODE_MIN_H = 56;
export const STRIPE_WIDTH = 4;

// Article column targets used by the build-time width gate
// (scripts/check-diagram-widths.ts) and the runtime fit modes. Kept
// here so the engine, the gate, and the authoring guide all read
// from the same number.
export const ARTICLE_WIDTH_TARGET = 1168;
// Above this, the build-time gate fails the build unless the diagram
// opts in via `oversize` — at that point the on-page render is too
// small to read and the lightbox affordance is the readable path.
export const ARTICLE_WIDTH_HARD_LIMIT = 1500;

// Walks any React.ReactNode and produces the flat list of visual
// "lines" — split by `\n` in strings and by `<br/>` elements. Used
// both to estimate label dimensions and to render the line-by-line
// HTML inside the foreignObject.
export function flattenToLines(node: React.ReactNode): string[] {
  const lines: string[] = [''];
  const walk = (n: React.ReactNode): void => {
    if (n == null || typeof n === 'boolean') return;
    if (typeof n === 'string' || typeof n === 'number') {
      const text = String(n);
      const parts = text.split('\n');
      for (let i = 0; i < parts.length; i++) {
        if (i > 0) lines.push('');
        lines[lines.length - 1] += parts[i];
      }
      return;
    }
    if (Array.isArray(n)) {
      n.forEach(walk);
      return;
    }
    if (React.isValidElement(n)) {
      const type = n.type as unknown;
      if (type === 'br' || (typeof type === 'string' && type.toLowerCase() === 'br')) {
        lines.push('');
        return;
      }
      const props = n.props as { children?: React.ReactNode } | null;
      if (props && props.children !== undefined) walk(props.children);
    }
  };
  walk(node);
  // Trim per-line whitespace but keep blank lines that sit between content.
  const trimmed = lines.map(l => l.trim());
  // Drop leading/trailing empties so a single blank line doesn't inflate the box.
  while (trimmed.length > 1 && trimmed[0] === '') trimmed.shift();
  while (trimmed.length > 1 && trimmed[trimmed.length - 1] === '') trimmed.pop();
  return trimmed.length === 0 ? [''] : trimmed;
}

// Estimate width/height for a label. The diagram engine consumes this
// to lay out nodes; the actual render uses foreignObject + flexbox so
// CSS handles the final wrapping inside the box we reserved here.
export function measureLabel(
  lines: string[],
  opts: { kind: DiagramKind; compact?: boolean } = { kind: 'generic' },
): { width: number; height: number; lines: string[] } {
  const widthsPx = lines.map(l => Math.max(1, l.length) * CHAR_WIDTH);
  const naturalWidth = Math.max(...widthsPx) + NODE_PAD_X * 2;
  const upperBound = opts.compact ? NODE_MAX_W_COMPACT : NODE_MAX_W;
  let width = Math.min(Math.max(NODE_MIN_W, naturalWidth), upperBound);
  const innerWidth = width - NODE_PAD_X * 2;
  const wrappedLineCount = lines.reduce((sum, l) => {
    const w = Math.max(1, l.length) * CHAR_WIDTH;
    return sum + Math.max(1, Math.ceil(w / innerWidth));
  }, 0);
  let height = Math.max(NODE_MIN_H, wrappedLineCount * LINE_HEIGHT + NODE_PAD_Y * 2);

  // Diamonds need extra bounding-box room: the inscribed rectangle
  // available for the label is roughly (w/sqrt(2), h/sqrt(2)), so we
  // grow the box ~1.45x to keep the label inside without collisions.
  const style = KIND_TO_STYLE[opts.kind];
  if (style.diamond) {
    width = Math.ceil(width * 1.45);
    height = Math.ceil(height * 1.45);
  }
  if (style.pill) {
    // Pills look right when they're a bit wider than tall; nudge width
    // up so the rounded ends don't clip into the label.
    width = Math.max(width, height * 2.2);
  }
  return { width, height, lines };
}

// Ship a single <defs> block per diagram. Marker IDs are namespaced by
// a per-instance prefix so two diagrams on the same page don't fight
// over arrow-head colors.
export function DiagramDefs({ id }: { id: string }) {
  return (
    <defs>
      {/* Cisco-blue gradient, used for emphasis node strokes and the
          primary edge color. Stops are expressed via CSS variables so
          the gradient retunes itself when the operator flips light/dark. */}
      <linearGradient id={`${id}-emphasis`} x1="0" y1="0" x2="1" y2="1">
        <stop offset="0%" style={{ stopColor: 'var(--brand-cisco)' }} />
        <stop offset="100%" style={{ stopColor: 'var(--brand-cisco-strong)' }} />
      </linearGradient>

      {/* Soft drop-shadow filter — kept narrow and low-opacity so it
          reads as panel depth rather than a graphic-design flourish. */}
      <filter id={`${id}-shadow`} x="-10%" y="-10%" width="120%" height="120%">
        <feDropShadow
          dx="0"
          dy="2"
          stdDeviation="3"
          floodOpacity="0.08"
        />
      </filter>

      {/* Standard arrowhead — neutral border color, used for plain edges. */}
      <marker
        id={`${id}-arrow`}
        viewBox="0 0 10 10"
        refX="9"
        refY="5"
        markerWidth="7"
        markerHeight="7"
        orient="auto-start-reverse"
      >
        <path d="M 0 0 L 10 5 L 0 10 z" style={{ fill: 'var(--color-fd-border)' }} />
      </marker>

      {/* Cisco-blue arrowhead, used on emphasized edges. */}
      <marker
        id={`${id}-arrow-emphasis`}
        viewBox="0 0 10 10"
        refX="9"
        refY="5"
        markerWidth="7"
        markerHeight="7"
        orient="auto-start-reverse"
      >
        <path d="M 0 0 L 10 5 L 0 10 z" style={{ fill: 'var(--brand-cisco)' }} />
      </marker>
    </defs>
  );
}

// Tiny smooth-path helper. Dagre returns a list of points along the
// edge; we connect them with quadratic Béziers through midpoints so
// the curve reads as one continuous line instead of a polyline of
// chevrons.
export function smoothPath(points: { x: number; y: number }[]): string {
  if (points.length === 0) return '';
  if (points.length === 1) return `M ${points[0].x} ${points[0].y}`;
  if (points.length === 2) {
    return `M ${points[0].x} ${points[0].y} L ${points[1].x} ${points[1].y}`;
  }
  let d = `M ${points[0].x} ${points[0].y}`;
  for (let i = 1; i < points.length - 1; i++) {
    const xc = (points[i].x + points[i + 1].x) / 2;
    const yc = (points[i].y + points[i + 1].y) / 2;
    d += ` Q ${points[i].x} ${points[i].y} ${xc} ${yc}`;
  }
  const last = points[points.length - 1];
  d += ` L ${last.x} ${last.y}`;
  return d;
}

// A short, deterministic-ish id we use to namespace SVG marker/filter
// ids per diagram instance. Crypto.randomUUID isn't available during
// SSG without polyfills, and we don't need uniqueness across requests
// — only within the rendered HTML chunk.
let counter = 0;
export function nextDiagramId(prefix: string): string {
  counter = (counter + 1) % 1_000_000;
  return `${prefix}-${counter.toString(36)}`;
}

// Common shape: text node label rendered inside a foreignObject. We
// use an HTML div so CSS handles word-wrapping, ellipsis (none for
// now), and font fallback. The div fills the bounding box and
// flex-centers the lines.
export function NodeLabel({
  width,
  height,
  lines,
  emphasis,
}: {
  width: number;
  height: number;
  lines: string[];
  emphasis?: boolean;
}) {
  return (
    <foreignObject x={0} y={0} width={width} height={height}>
      <ForeignDiv
        style={{
          width: '100%',
          height: '100%',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          padding: `${NODE_PAD_Y}px ${NODE_PAD_X}px`,
          boxSizing: 'border-box',
          textAlign: 'center',
          fontFamily: 'var(--font-sans), system-ui, sans-serif',
          fontSize: emphasis ? '14.5px' : '13.5px',
          lineHeight: '1.35',
          fontWeight: emphasis ? 600 : 500,
          color: 'var(--color-fd-foreground)',
          letterSpacing: '-0.005em',
        }}
      >
        {lines.map((line, i) => (
          <span key={i} style={{ display: 'block', whiteSpace: 'normal' }}>
            {line || '\u00A0'}
          </span>
        ))}
      </ForeignDiv>
    </foreignObject>
  );
}

// Wrapper for the HTML <div> that lives inside a foreignObject. We
// emit `xmlns="http://www.w3.org/1999/xhtml"` so the SVG remains valid
// in any context where it might be served as a standalone asset (OG
// images, llms-full.txt re-renders), but TypeScript's HTMLDivElement
// type doesn't carry the xmlns attribute. The cast contains the
// untyped attribute so callers can stay strongly typed.
const ForeignDiv = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement>
>(function ForeignDiv(props, ref) {
  const extraProps = { xmlns: 'http://www.w3.org/1999/xhtml' } as Record<
    string,
    string
  >;
  return <div ref={ref} {...extraProps} {...props} />;
});

export { ForeignDiv };
