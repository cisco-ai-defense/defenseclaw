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
  // Color of the compact classification rule at the top of each node.
  // Empty string means the node uses the neutral diagram rule.
  accent: string;
  label: string;
}

export const KIND_TO_STYLE: Record<DiagramKind, KindStyle> = {
  agent:     { accent: 'var(--diagram-role-runtime)', label: 'Agent runtime' },
  connector: { accent: 'var(--diagram-role-connector)', label: 'Connector' },
  gateway:   { accent: 'var(--diagram-role-control)', label: 'Control plane' },
  policy:    { accent: 'var(--diagram-role-policy)', label: 'Policy' },
  datastore: { accent: 'var(--diagram-role-evidence)', label: 'Evidence store' },
  operator:  { accent: 'var(--diagram-role-operator)', label: 'Operator' },
  decision:  { accent: 'var(--diagram-role-policy)', label: 'Decision' },
  generic:   { accent: 'var(--diagram-role-system)', label: 'System' },
};

// Estimation constants, calibrated to the docs-site system-ui stack
// at 14px medium. We can't measure text on the server, so every
// dimension below is conservative: text never gets clipped, but
// diagrams stay tight enough not to feel airy.
export const CHAR_WIDTH = 7.2;
export const LINE_HEIGHT = 17;
export const NODE_PAD_X = 16;
export const NODE_PAD_Y = 12;
export const NODE_ICON_SPACE = 44;
export const NODE_MIN_W = 184;
export const NODE_MAX_W = 304;
// Compact mode trims the upper bound only — narrow nodes still fit.
// Combined with the tighter dagre nodesep/ranksep in <Flow>, this
// shaves ~15-20% off the natural width with negligible legibility
// cost.
export const NODE_MAX_W_COMPACT = 264;
export const NODE_MIN_W_DENSE = 148;
export const NODE_MAX_W_DENSE = 172;
export const NODE_MIN_H = 78;
export const STRIPE_WIDTH = 4;

// Article column targets used by the build-time width gate
// (scripts/check-diagram-widths.ts) and the runtime fit modes. Kept
// here so the engine, the gate, and the authoring guide all read
// from the same number.
// 840px is the actual diagram canvas width inside the docs article at the
// required 1536px desktop QA viewport (after side navigation, TOC, and canvas
// padding). Staying under it keeps labels at 1:1 rather than merely fitting
// the wider 1920px authoring layout.
export const ARTICLE_WIDTH_TARGET = 840;
// Above this, the build-time gate fails the build unless the diagram
// opts in via `oversize` — at that point the on-page render is too
// small to read and the lightbox affordance is the readable path.
export const ARTICLE_WIDTH_HARD_LIMIT = 1168;

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
  opts: { kind?: DiagramKind; compact?: boolean; dense?: boolean } = {},
): { width: number; height: number; lines: string[] } {
  const widthsPx = lines.map(l => Math.max(1, l.length) * CHAR_WIDTH);
  const naturalWidth = Math.max(...widthsPx) + NODE_PAD_X * 2 + NODE_ICON_SPACE;
  const lowerBound = opts.dense ? NODE_MIN_W_DENSE : NODE_MIN_W;
  const upperBound = opts.dense
    ? NODE_MAX_W_DENSE
    : opts.compact
      ? NODE_MAX_W_COMPACT
      : NODE_MAX_W;
  let width = Math.min(Math.max(lowerBound, naturalWidth), upperBound);
  const innerWidth = width - NODE_PAD_X * 2 - NODE_ICON_SPACE;
  const wrappedLineCount = lines.reduce((sum, l) => {
    const w = Math.max(1, l.length) * CHAR_WIDTH;
    return sum + Math.max(1, Math.ceil(w / innerWidth));
  }, 0);
  // Reserve a classification line, a primary title line, and any detail
  // lines. The icon occupies horizontal space only, so it does not make
  // short cards unnecessarily tall.
  let height = Math.max(
    NODE_MIN_H,
    wrappedLineCount * LINE_HEIGHT + NODE_PAD_Y * 2 + 18,
  );

  return { width, height, lines };
}

// Ship a single <defs> block per diagram. Marker IDs are namespaced by
// a per-instance prefix so two diagrams on the same page don't fight
// over arrow-head colors.
export function DiagramDefs({ id }: { id: string }) {
  return (
    <defs>
      {/* Kept as a namespaced paint server for backwards-compatible
          callers, but intentionally flat: the enterprise diagram system
          uses crisp rules rather than decorative gradients. */}
      <linearGradient id={`${id}-emphasis`} x1="0" y1="0" x2="1" y2="1">
        <stop offset="0%" style={{ stopColor: 'var(--diagram-accent-blue)' }} />
        <stop offset="100%" style={{ stopColor: 'var(--diagram-accent-blue)' }} />
      </linearGradient>

      {/* No visual shadow; retaining the filter id avoids brittle SVG
          references in older prerendered content during local HMR. */}
      <filter id={`${id}-shadow`} x="-10%" y="-10%" width="120%" height="120%">
        <feDropShadow dx="0" dy="0" stdDeviation="0" floodOpacity="0" />
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
        <path d="M 1 1 L 9 5 L 1 9 z" style={{ fill: 'var(--diagram-edge)' }} />
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
        <path d="M 1 1 L 9 5 L 1 9 z" style={{ fill: 'var(--diagram-accent-blue)' }} />
      </marker>
    </defs>
  );
}

// Enterprise architecture diagrams use orthogonal routing. Dagre gives us
// collision-aware intermediate points; preserve that route, convert diagonal
// segments into compact doglegs, then round only the corners. The result keeps
// the rigor of right-angle routes without the brittle circuit-board look of
// sharp elbows.
export function smoothPath(points: { x: number; y: number }[]): string {
  if (points.length === 0) return '';
  if (points.length === 1) return `M ${points[0].x} ${points[0].y}`;

  const orthogonal: { x: number; y: number }[] = [points[0]];
  for (let index = 1; index < points.length; index++) {
    const previous = points[index - 1];
    const current = points[index];
    const dx = current.x - previous.x;
    const dy = current.y - previous.y;

    if (Math.abs(dx) >= 0.5 && Math.abs(dy) >= 0.5 && Math.abs(dx) >= Math.abs(dy)) {
      const midX = (previous.x + current.x) / 2;
      orthogonal.push({ x: midX, y: previous.y }, { x: midX, y: current.y });
    } else if (Math.abs(dx) >= 0.5 && Math.abs(dy) >= 0.5) {
      const midY = (previous.y + current.y) / 2;
      orthogonal.push({ x: previous.x, y: midY }, { x: current.x, y: midY });
    }
    orthogonal.push(current);
  }

  const deduped = orthogonal.filter((point, index) => {
    if (index === 0) return true;
    const previous = orthogonal[index - 1];
    return Math.abs(point.x - previous.x) >= 0.5 || Math.abs(point.y - previous.y) >= 0.5;
  });
  if (deduped.length < 2) return `M ${deduped[0].x} ${deduped[0].y}`;

  const commands = [`M ${deduped[0].x} ${deduped[0].y}`];
  for (let index = 1; index < deduped.length - 1; index++) {
    const previous = deduped[index - 1];
    const corner = deduped[index];
    const next = deduped[index + 1];
    const incoming = Math.hypot(corner.x - previous.x, corner.y - previous.y);
    const outgoing = Math.hypot(next.x - corner.x, next.y - corner.y);
    const radius = Math.min(6, incoming / 2, outgoing / 2);
    const entry = {
      x: corner.x + ((previous.x - corner.x) / incoming) * radius,
      y: corner.y + ((previous.y - corner.y) / incoming) * radius,
    };
    const exit = {
      x: corner.x + ((next.x - corner.x) / outgoing) * radius,
      y: corner.y + ((next.y - corner.y) / outgoing) * radius,
    };
    commands.push(`L ${entry.x} ${entry.y}`, `Q ${corner.x} ${corner.y} ${exit.x} ${exit.y}`);
  }
  const last = deduped[deduped.length - 1];
  commands.push(`L ${last.x} ${last.y}`);
  return commands.join(' ');
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
  kind,
  emphasis,
}: {
  width: number;
  height: number;
  lines: string[];
  kind: DiagramKind;
  emphasis?: boolean;
}) {
  const kindStyle = KIND_TO_STYLE[kind];
  const [title = '', ...detailLines] = lines;
  return (
    <foreignObject x={0} y={0} width={width} height={height}>
      <ForeignDiv
        style={{
          width: '100%',
          height: '100%',
          display: 'flex',
          flexDirection: 'row',
          alignItems: 'center',
          justifyContent: 'center',
          gap: '12px',
          padding: `${NODE_PAD_Y}px ${NODE_PAD_X}px`,
          boxSizing: 'border-box',
          textAlign: 'left',
          fontFamily: 'var(--font-sans), system-ui, sans-serif',
          color: 'var(--diagram-text)',
        }}
      >
        <span
          style={{
            display: 'inline-flex',
            flex: '0 0 auto',
            alignItems: 'center',
            justifyContent: 'center',
            width: '30px',
            height: '30px',
            border: `1px solid color-mix(in oklab, ${kindStyle.accent} 28%, var(--diagram-border))`,
            borderRadius: '5px',
            background: `color-mix(in oklab, ${kindStyle.accent} 8%, var(--diagram-node-bg))`,
            color: kindStyle.accent,
          }}
          aria-hidden
        >
          <DiagramKindIcon kind={kind} />
        </span>
        <span
          style={{
            display: 'flex',
            minWidth: 0,
            flex: '1 1 auto',
            flexDirection: 'column',
            alignItems: 'stretch',
          }}
        >
          <span
            style={{
              color: kindStyle.accent,
              fontFamily: 'var(--font-mono), ui-monospace, monospace',
              fontSize: '9px',
              fontWeight: 750,
              letterSpacing: '0.09em',
              lineHeight: 1.2,
              textTransform: 'uppercase',
            }}
          >
            {kindStyle.label}
          </span>
          <span
            style={{
              marginTop: '4px',
              fontSize: emphasis ? '14.5px' : '14px',
              fontWeight: emphasis ? 680 : 620,
              letterSpacing: '-0.012em',
              lineHeight: 1.25,
              overflowWrap: 'anywhere',
            }}
          >
            {title || '\u00A0'}
          </span>
          {detailLines.length > 0 && (
            <span
              style={{
                display: 'block',
                marginTop: '3px',
                color: 'var(--diagram-muted)',
                fontSize: '11.5px',
                fontWeight: 480,
                lineHeight: 1.35,
              }}
            >
              {detailLines.map((line, index) => (
                <span key={index} style={{ display: 'block', overflowWrap: 'anywhere' }}>
                  {line || '\u00A0'}
                </span>
              ))}
            </span>
          )}
        </span>
      </ForeignDiv>
    </foreignObject>
  );
}

export function DiagramKindIcon({ kind }: { kind: DiagramKind }) {
  const shared = {
    width: 16,
    height: 16,
    viewBox: '0 0 24 24',
    fill: 'none',
    stroke: 'currentColor',
    strokeWidth: 1.8,
    strokeLinecap: 'round' as const,
    strokeLinejoin: 'round' as const,
  };

  if (kind === 'agent') {
    return <svg {...shared}><rect x="3" y="4" width="18" height="16" rx="2" /><path d="m7 9 2.5 2.5L7 14M12 15h5" /></svg>;
  }
  if (kind === 'connector') {
    return <svg {...shared}><path d="M8 12h8M7 7l-4 5 4 5M17 7l4 5-4 5" /></svg>;
  }
  if (kind === 'gateway') {
    return <svg {...shared}><path d="M12 3 4.5 6v5.5c0 4.4 3 7.7 7.5 9.5 4.5-1.8 7.5-5.1 7.5-9.5V6L12 3Z" /><path d="m9 12 2 2 4-4" /></svg>;
  }
  if (kind === 'policy') {
    return <svg {...shared}><path d="M7 3h7l4 4v14H7z" /><path d="M14 3v5h5M10 13h5M10 17h4" /></svg>;
  }
  if (kind === 'datastore') {
    return <svg {...shared}><ellipse cx="12" cy="5.5" rx="7.5" ry="3" /><path d="M4.5 5.5v6c0 1.7 3.4 3 7.5 3s7.5-1.3 7.5-3v-6M4.5 11.5v6c0 1.7 3.4 3 7.5 3s7.5-1.3 7.5-3v-6" /></svg>;
  }
  if (kind === 'operator') {
    return <svg {...shared}><circle cx="12" cy="8" r="3.5" /><path d="M5 21c.7-4 3-6 7-6s6.3 2 7 6" /></svg>;
  }
  if (kind === 'decision') {
    return <svg {...shared}><path d="M12 3v5M12 16v5M5 12H3M21 12h-2" /><path d="m12 8 4 4-4 4-4-4 4-4Z" /></svg>;
  }
  return <svg {...shared}><rect x="4" y="4" width="16" height="16" rx="2" /><path d="M8 9h8M8 13h8M8 17h5" /></svg>;
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
