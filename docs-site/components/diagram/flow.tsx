import * as React from 'react';
import dagre from '@dagrejs/dagre';
import type { GraphLabel, NodeLabel as DagreNodeLabel, EdgeLabel } from '@dagrejs/dagre';
import {
  type DiagramKind,
  type EdgeVariant,
  KIND_TO_STYLE,
  STRIPE_WIDTH,
  DiagramDefs,
  NodeLabel,
  ForeignDiv,
  flattenToLines,
  measureLabel,
  smoothPath,
  nextDiagramId,
} from './shared';
import { DiagramLightbox } from './lightbox';

// Marker symbols. <Node> and <Edge> are pure data carriers — they
// return null but are tagged via a non-enumerable property so <Flow>
// can identify them inside React.Children without relying on
// component-name strings (which break under prod minification).
const NODE_MARKER = Symbol.for('defenseclaw.diagram.Node');
const EDGE_MARKER = Symbol.for('defenseclaw.diagram.Edge');

export interface NodeProps {
  id: string;
  kind?: DiagramKind;
  emphasis?: boolean;
  children?: React.ReactNode;
}

export interface EdgeProps {
  from: string;
  to: string;
  label?: string;
  variant?: EdgeVariant;
  emphasis?: boolean;
}

// eslint-disable-next-line @typescript-eslint/no-unused-vars
export function Node(_props: NodeProps): React.ReactElement | null {
  return null;
}
(Node as unknown as { __diagramKind: symbol }).__diagramKind = NODE_MARKER;

// eslint-disable-next-line @typescript-eslint/no-unused-vars
export function Edge(_props: EdgeProps): React.ReactElement | null {
  return null;
}
(Edge as unknown as { __diagramKind: symbol }).__diagramKind = EDGE_MARKER;

interface ResolvedNode {
  id: string;
  kind: DiagramKind;
  emphasis: boolean;
  lines: string[];
  width: number;
  height: number;
  // Set by dagre after layout — center coordinates of the node.
  x: number;
  y: number;
}

interface ResolvedEdge {
  from: string;
  to: string;
  label?: string;
  variant: EdgeVariant;
  emphasis: boolean;
  points: { x: number; y: number }[];
}

// Three rendering strategies for the underlying SVG:
//
//  - 'native': SVG sized at natural pixels via `width`/`height`
//    attributes; the parent figure scrolls horizontally on narrow
//    viewports. Useful when the author needs guaranteed crisp text
//    and is happy to scroll.
//  - 'scale': SVG keeps its `viewBox` but renders with
//    `width: 100%; height: auto; max-width: ${natural}px`. Scales
//    down uniformly when the container is narrower than the
//    natural width; never upscales beyond natural.
//  - 'auto' (default): same as 'scale' for the inline render. The
//    lightbox affordance gives readers a 1:1 native view via the
//    expand button when the inline scale gets too small.
export type DiagramFit = 'native' | 'scale' | 'auto';

interface FlowProps {
  direction?: 'LR' | 'TB';
  caption?: string;
  // Controls how the SVG sizes inside the figure container. Default
  // 'auto' is the right choice for almost every page in the docs;
  // reach for 'native' only when readability of every label at full
  // pixel size matters more than fitting the column.
  fit?: DiagramFit;
  // Tighten dagre spacing (`ranksep` 80→50, `nodesep` 50→30) and
  // shrink the per-node max-width upper bound. Cuts ~15-20% off the
  // natural width on most graphs with negligible legibility cost.
  compact?: boolean;
  // Marks this diagram as one we know is wider than the article
  // column and we accept the trade-off (the lightbox affordance is
  // the readable path). Without this, the build-time width gate
  // (scripts/check-diagram-widths.ts) fails the build at
  // ARTICLE_WIDTH_HARD_LIMIT.
  oversize?: boolean;
  children?: React.ReactNode;
}

// Read all <Node>/<Edge> children, ignore stray whitespace/p-tags
// from the MDX renderer, and bucket them by marker.
function partitionChildren(children: React.ReactNode): {
  nodes: NodeProps[];
  edges: EdgeProps[];
} {
  const nodes: NodeProps[] = [];
  const edges: EdgeProps[] = [];
  React.Children.forEach(children, (child) => {
    if (!React.isValidElement(child)) return;
    const marker = (child.type as unknown as { __diagramKind?: symbol }).__diagramKind;
    if (marker === NODE_MARKER) {
      nodes.push(child.props as NodeProps);
    } else if (marker === EDGE_MARKER) {
      edges.push(child.props as EdgeProps);
    }
    // Anything else (whitespace, accidental <p>) is silently dropped —
    // authors get a clean error from the missing-id check below if a
    // typo turns into a no-op.
  });
  return { nodes, edges };
}

export function Flow({
  direction = 'LR',
  caption,
  fit = 'auto',
  compact = false,
  oversize = false,
  children,
}: FlowProps) {
  const { nodes: nodeProps, edges: edgeProps } = partitionChildren(children);

  if (nodeProps.length === 0) {
    return (
      <FlowContainer caption={caption}>
        <p style={{ color: 'var(--color-fd-muted-foreground)', fontSize: 14 }}>
          (Empty Flow — add at least one Node.)
        </p>
      </FlowContainer>
    );
  }

  // Resolve node labels and dimensions. We do this once before the
  // dagre layout so the engine has correct widths to work with.
  // Gateway nodes are always emphasized — every diagram in the docs
  // points at `defenseclaw-gateway` as the system-under-design.
  const resolved: ResolvedNode[] = nodeProps.map((p) => {
    const kind: DiagramKind = p.kind ?? 'generic';
    const emphasis = Boolean(p.emphasis) || kind === 'gateway';
    const lines = flattenToLines(p.children);
    const measured = measureLabel(lines, { kind, compact });
    return {
      id: p.id,
      kind,
      emphasis,
      lines: measured.lines,
      width: measured.width,
      height: measured.height,
      x: 0,
      y: 0,
    };
  });

  const idToNode = new Map(resolved.map((n) => [n.id, n]));

  // Build the dagre graph. Spacing is tuned a touch wider than the
  // dagre defaults so labels don't crowd their neighbors at docs
  // widths. `compact` halves the breathing room — useful when the
  // graph is structurally fine but bumping up against the column.
  const g = new dagre.graphlib.Graph<GraphLabel, DagreNodeLabel, EdgeLabel>();
  g.setGraph({
    rankdir: direction,
    nodesep: compact ? 30 : 50,
    ranksep: compact ? 50 : 80,
    marginx: 16,
    marginy: 16,
  });
  g.setDefaultEdgeLabel(() => ({}));

  for (const n of resolved) {
    g.setNode(n.id, { width: n.width, height: n.height });
  }
  for (const e of edgeProps) {
    if (!idToNode.has(e.from) || !idToNode.has(e.to)) {
      // Skip edges with broken refs. We don't want to crash the page;
      // an authoring typo should produce a visible-but-recoverable
      // diagram.
      continue;
    }
    g.setEdge(e.from, e.to, {
      // Edge labels need a hint to dagre about their footprint so the
      // layout makes room for them.
      labelpos: 'c',
      width: e.label ? Math.min(180, e.label.length * 6 + 16) : 0,
      height: e.label ? 22 : 0,
    });
  }

  dagre.layout(g);

  for (const n of resolved) {
    const laid = g.node(n.id);
    if (laid) {
      n.x = laid.x ?? 0;
      n.y = laid.y ?? 0;
    }
  }

  const resolvedEdges: ResolvedEdge[] = edgeProps
    .filter((e) => idToNode.has(e.from) && idToNode.has(e.to))
    .map((e) => {
      const dEdge = g.edge(e.from, e.to) as EdgeLabel | undefined;
      const points = (dEdge?.points ?? []) as { x: number; y: number }[];
      return {
        from: e.from,
        to: e.to,
        label: e.label,
        variant: e.variant ?? 'solid',
        emphasis: Boolean(e.emphasis),
        points,
      };
    });

  const graphLabel = g.graph();
  const width = Math.ceil(graphLabel.width ?? 0) + 16;
  const height = Math.ceil(graphLabel.height ?? 0) + 16;

  const id = nextDiagramId('fd-flow');
  const ariaLabel = caption ?? 'Flow diagram';

  // Fit mode controls how the SVG sizes within its container.
  // `native` keeps natural pixels (parent figure scrolls); `scale`
  // and `auto` use the viewBox with a max-width cap so the SVG
  // shrinks to fit narrow viewports without ever upscaling past its
  // natural size.
  const sizeStyle: React.CSSProperties =
    fit === 'native'
      ? {
          display: 'block',
          margin: '0 auto',
          maxWidth: 'none',
          width,
          height,
        }
      : {
          display: 'block',
          margin: '0 auto',
          width: '100%',
          height: 'auto',
          maxWidth: width,
        };

  const svgAttrs =
    fit === 'native'
      ? { width, height }
      : ({} as { width?: number; height?: number });

  const svg = (
    <svg
      viewBox={`0 0 ${width} ${height}`}
      {...svgAttrs}
      style={sizeStyle}
      role="img"
      aria-label={ariaLabel}
      preserveAspectRatio="xMidYMid meet"
    >
      <DiagramDefs id={id} />

      {/* Edges first so they sit underneath the node panels. */}
      {resolvedEdges.map((edge, i) => (
        <FlowEdge key={`e-${i}`} edge={edge} markerId={id} />
      ))}

      {resolved.map((node) => (
        <FlowNode key={node.id} node={node} filterId={id} gradientId={id} />
      ))}
    </svg>
  );

  return (
    <DiagramLightbox
      caption={caption}
      naturalWidth={width}
      naturalHeight={height}
      ariaLabel={ariaLabel}
      oversize={oversize}
    >
      {svg}
    </DiagramLightbox>
  );
}

function FlowContainer({
  caption,
  children,
}: {
  caption?: string;
  children: React.ReactNode;
}) {
  return (
    <figure className="my-6 not-prose">
      <div className="overflow-x-auto rounded-xl border border-fd-border bg-fd-card/60 p-5">
        {children}
      </div>
      {caption && (
        <figcaption className="mt-2 text-center text-sm text-fd-muted-foreground">
          {caption}
        </figcaption>
      )}
    </figure>
  );
}

function FlowNode({
  node,
  filterId,
  gradientId,
}: {
  node: ResolvedNode;
  filterId: string;
  gradientId: string;
}) {
  const style = KIND_TO_STYLE[node.kind];
  const x = node.x - node.width / 2;
  const y = node.y - node.height / 2;
  const rx = style.pill ? node.height / 2 : 12;
  const strokeColor = node.emphasis
    ? `url(#${gradientId}-emphasis)`
    : 'var(--color-fd-border)';
  const strokeWidth = node.emphasis ? 1.75 : 1;

  if (style.diamond) {
    // Diamond shape: vertices at top/right/bottom/left of the bounding box.
    const w = node.width;
    const h = node.height;
    const points = [
      `${node.x},${y}`,
      `${node.x + w / 2},${node.y}`,
      `${node.x},${y + h}`,
      `${node.x - w / 2},${node.y}`,
    ].join(' ');
    return (
      <g>
        <polygon
          points={points}
          style={{
            fill: 'var(--color-fd-card)',
            stroke: style.accent || strokeColor,
            strokeWidth: 1.25,
          }}
          filter={`url(#${filterId}-shadow)`}
        />
        {/* Slight inner highlight stripe along the top-left to suggest
            the warm decision flag. Pure aesthetic. */}
        <line
          x1={node.x - node.width / 2 + 8}
          y1={node.y - 1}
          x2={node.x}
          y2={y + 8}
          style={{ stroke: style.accent, strokeWidth: 2, strokeLinecap: 'round', opacity: 0.7 }}
        />
        <g transform={`translate(${x}, ${y})`}>
          <NodeLabel
            width={node.width}
            height={node.height}
            lines={node.lines}
            emphasis={node.emphasis}
          />
        </g>
      </g>
    );
  }

  return (
    <g>
      <rect
        x={x}
        y={y}
        width={node.width}
        height={node.height}
        rx={rx}
        ry={rx}
        style={{
          fill: 'var(--color-fd-card)',
          stroke: strokeColor,
          strokeWidth,
        }}
        filter={`url(#${filterId}-shadow)`}
      />

      {/* Kind accent stripe — left edge, rounded so it tucks behind the
          rectangle's corner radius. Skipped when the kind has no accent
          (generic) or when the node is emphasized (the gradient border
          carries the visual weight instead). */}
      {style.accent && !node.emphasis && (
        <rect
          x={x}
          y={y}
          width={STRIPE_WIDTH}
          height={node.height}
          rx={STRIPE_WIDTH / 2}
          ry={STRIPE_WIDTH / 2}
          style={{ fill: style.accent }}
          clipPath={`inset(0 0 0 0 round ${rx}px)`}
        />
      )}

      {/* Datastore footer — a thin line near the bottom that reads as
          a stacked DB. Kept subtle so it doesn't become a visual
          obstacle when many datastore nodes are in one diagram. */}
      {style.datastoreFooter && (
        <line
          x1={x + 12}
          y1={y + node.height - 8}
          x2={x + node.width - 12}
          y2={y + node.height - 8}
          style={{
            stroke: 'var(--color-fd-muted-foreground)',
            strokeWidth: 1,
            strokeDasharray: '2 3',
            opacity: 0.5,
          }}
        />
      )}

      <g transform={`translate(${x}, ${y})`}>
        <NodeLabel
          width={node.width}
          height={node.height}
          lines={node.lines}
          emphasis={node.emphasis}
        />
      </g>
    </g>
  );
}

function FlowEdge({ edge, markerId }: { edge: ResolvedEdge; markerId: string }) {
  if (edge.points.length < 2) return null;
  const isEmphasis = edge.emphasis;
  const stroke = isEmphasis ? 'var(--brand-cisco)' : 'var(--color-fd-border)';
  const strokeWidth = isEmphasis ? 1.5 : 1.25;
  const dasharray = edge.variant === 'dashed' ? '6 4' : undefined;
  const arrow = isEmphasis ? `${markerId}-arrow-emphasis` : `${markerId}-arrow`;

  const d = smoothPath(edge.points);

  // For bidirectional edges, mark both ends with arrowheads. SVG
  // `marker-start` works in conjunction with `marker-end`.
  const markerStart =
    edge.variant === 'bidirectional' ? `url(#${arrow})` : undefined;
  const markerEnd = `url(#${arrow})`;

  // Place the edge label at the midpoint. Dagre also computes an
  // (x, y) for edge labels but only when we set width/height on the
  // edge — which we did — so prefer that for accuracy.
  const mid = midpoint(edge.points);

  return (
    <g>
      <path
        d={d}
        style={{
          fill: 'none',
          stroke,
          strokeWidth,
          strokeLinecap: 'round',
          strokeLinejoin: 'round',
          strokeDasharray: dasharray,
        }}
        markerStart={markerStart}
        markerEnd={markerEnd}
      />
      {edge.label && (
        <EdgeLabelChip x={mid.x} y={mid.y} label={edge.label} />
      )}
    </g>
  );
}

function EdgeLabelChip({ x, y, label }: { x: number; y: number; label: string }) {
  // Estimate chip width from char count. The chip uses an HTML
  // foreignObject so we get full font fallback and crisp anti-aliased
  // text instead of SVG <text> spacing quirks.
  const chipW = Math.min(220, Math.max(40, label.length * 6.6 + 18));
  const chipH = 22;
  return (
    <foreignObject
      x={x - chipW / 2}
      y={y - chipH / 2}
      width={chipW}
      height={chipH}
    >
      <ForeignDiv
        style={{
          width: '100%',
          height: '100%',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          padding: '0 8px',
          boxSizing: 'border-box',
          fontFamily: 'var(--font-sans), system-ui, sans-serif',
          fontSize: '11.5px',
          fontWeight: 500,
          color: 'var(--color-fd-muted-foreground)',
          background: 'var(--color-fd-card)',
          border: '1px solid var(--color-fd-border)',
          borderRadius: '999px',
          whiteSpace: 'nowrap',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
          letterSpacing: '-0.005em',
        }}
      >
        {label}
      </ForeignDiv>
    </foreignObject>
  );
}

// Geometric midpoint along a polyline of points. We walk the segments
// and find the one that contains the half-length mark, then
// interpolate. Beats picking the literal middle index, which biases
// toward edges with non-uniform segment lengths.
function midpoint(points: { x: number; y: number }[]): { x: number; y: number } {
  if (points.length === 1) return points[0];
  let total = 0;
  const lens: number[] = [];
  for (let i = 1; i < points.length; i++) {
    const dx = points[i].x - points[i - 1].x;
    const dy = points[i].y - points[i - 1].y;
    const l = Math.hypot(dx, dy);
    lens.push(l);
    total += l;
  }
  const target = total / 2;
  let walked = 0;
  for (let i = 0; i < lens.length; i++) {
    if (walked + lens[i] >= target) {
      const remain = target - walked;
      const t = lens[i] === 0 ? 0 : remain / lens[i];
      const a = points[i];
      const b = points[i + 1];
      return { x: a.x + (b.x - a.x) * t, y: a.y + (b.y - a.y) * t };
    }
    walked += lens[i];
  }
  return points[Math.floor(points.length / 2)];
}
