import * as React from 'react';
import dagre from '@dagrejs/dagre';
import type { GraphLabel, NodeLabel as DagreNodeLabel, EdgeLabel } from '@dagrejs/dagre';
import {
  type DiagramKind,
  type EdgeVariant,
  ARTICLE_WIDTH_TARGET,
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
  labelPoint?: { x: number; y: number };
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
  compact,
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

  // A short, unbranched process is more legible as a horizontal operating
  // rail than as a narrow vertical ladder. Preserve explicit topology, but
  // promote a TB chain when its measured width still fits the article.
  const isLinear = isLinearChain(nodeProps, edgeProps);
  const compactCandidateWidth = nodeProps.reduce((sum, node) => {
    const kind = node.kind ?? 'generic';
    const measured = measureLabel(flattenToLines(node.children), {
      kind,
      compact: true,
    });
    return sum + measured.width;
  }, 0) + Math.max(0, nodeProps.length - 1) * 54 + 56;
  const autoLinearHorizontal =
    direction === 'TB' &&
    isLinear &&
    nodeProps.length <= 5 &&
    compactCandidateWidth <= ARTICLE_WIDTH_TARGET;
  const layoutDirection: 'LR' | 'TB' = autoLinearHorizontal ? 'LR' : direction;
  const compactMode = compact ?? (layoutDirection === 'TB' || autoLinearHorizontal);
  const processRail = direction === 'TB' && isLinear && !autoLinearHorizontal;
  const denseMode = layoutDirection === 'TB' && !processRail && nodeProps.length >= 10;

  // Resolve node labels and dimensions. We do this once before the
  // dagre layout so the engine has correct widths to work with.
  // Gateway nodes are always emphasized — every diagram in the docs
  // points at `defenseclaw-gateway` as the system-under-design.
  const resolved: ResolvedNode[] = nodeProps.map((p) => {
    const kind: DiagramKind = p.kind ?? 'generic';
    const emphasis = Boolean(p.emphasis) || kind === 'gateway';
    const lines = flattenToLines(p.children);
    const measured = measureLabel(lines, {
      kind,
      compact: compactMode,
      dense: denseMode,
    });
    return {
      id: p.id,
      kind,
      emphasis,
      lines: measured.lines,
      // A vertical process should read like an intentional operating
      // procedure, not a skinny stack of unrelated cards. Give each step a
      // consistent rail width while leaving branched architecture diagrams
      // topology-sized.
      width: processRail ? Math.max(420, measured.width) : measured.width,
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
    rankdir: layoutDirection,
    nodesep: denseMode ? 10 : compactMode ? 38 : 56,
    ranksep: denseMode ? 50 : compactMode ? 54 : 78,
    edgesep: denseMode ? 12 : 24,
    marginx: denseMode ? 16 : compactMode ? 26 : 28,
    marginy: denseMode ? 16 : 28,
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
        labelPoint:
          typeof dEdge?.x === 'number' && typeof dEdge?.y === 'number'
            ? { x: dEdge.x, y: dEdge.y }
            : undefined,
      };
    });

  const graphLabel = g.graph();
  const width = Math.ceil(graphLabel.width ?? 0) + 16;
  const height = Math.ceil(graphLabel.height ?? 0) + 16;

  // Rank each node along the layout's primary axis so the entrance
  // animation lights up nodes in reading order (LR → left-to-right
  // columns, TB → top-to-bottom rows). Edges inherit their source
  // node's rank + a half-step so each edge starts as soon as its
  // source has landed.
  const rankAxis = (n: ResolvedNode) => (layoutDirection === 'LR' ? n.x : n.y);
  const nodesByRank = [...resolved].sort((a, b) => rankAxis(a) - rankAxis(b));
  const rankById = new Map<string, number>();
  nodesByRank.forEach((n, i) => rankById.set(n.id, i));

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
          // On phones, wide flows retain enough width for labels to stay
          // legible and pan inside the diagram frame. Narrow vertical flows
          // keep their natural width and are not artificially enlarged.
          ['--diagram-mobile-width' as string]: `${Math.min(width, 620)}px`,
        };

  const svgAttrs =
    fit === 'native'
      ? { width, height }
      : ({} as { width?: number; height?: number });

  const svg = (
    <svg
      className="fd-flow-svg"
      data-layout={layoutDirection.toLowerCase()}
      data-process-rail={processRail ? 'true' : undefined}
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
        <FlowEdge
          key={`e-${i}`}
          edge={edge}
          markerId={id}
          fromRank={rankById.get(edge.from) ?? 0}
        />
      ))}

      {resolved.map((node) => (
        <FlowNode
          key={node.id}
          node={node}
          rank={rankById.get(node.id) ?? 0}
          processStep={processRail ? (rankById.get(node.id) ?? 0) + 1 : undefined}
        />
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

function isLinearChain(nodes: NodeProps[], edges: EdgeProps[]): boolean {
  if (nodes.length < 2 || edges.length !== nodes.length - 1) return false;
  const ids = new Set(nodes.map((node) => node.id));
  const incoming = new Map(nodes.map((node) => [node.id, 0]));
  const outgoing = new Map(nodes.map((node) => [node.id, 0]));
  for (const edge of edges) {
    if (!ids.has(edge.from) || !ids.has(edge.to)) return false;
    incoming.set(edge.to, (incoming.get(edge.to) ?? 0) + 1);
    outgoing.set(edge.from, (outgoing.get(edge.from) ?? 0) + 1);
  }
  let starts = 0;
  let ends = 0;
  for (const id of ids) {
    const inCount = incoming.get(id) ?? 0;
    const outCount = outgoing.get(id) ?? 0;
    if (inCount === 0 && outCount === 1) starts += 1;
    else if (inCount === 1 && outCount === 0) ends += 1;
    else if (inCount !== 1 || outCount !== 1) return false;
  }
  return starts === 1 && ends === 1;
}

function FlowContainer({
  caption,
  children,
}: {
  caption?: string;
  children: React.ReactNode;
}) {
  return (
    <figure className="diagram-figure my-8 not-prose">
      <div className="diagram-canvas overflow-x-auto">
        {children}
      </div>
      {caption && (
        <figcaption className="diagram-caption">
          {caption}
        </figcaption>
      )}
    </figure>
  );
}

function FlowNode({
  node,
  rank,
  processStep,
}: {
  node: ResolvedNode;
  // Layout-axis rank (left-to-right or top-to-bottom column index).
  // Used to stagger the entrance animation in reading order; the
  // class is gated on the parent figure's `data-animate="entered"`,
  // so the SSR render paints the final state until JS hydrates.
  rank: number;
  processStep?: number;
}) {
  const style = KIND_TO_STYLE[node.kind];
  const x = node.x - node.width / 2;
  const y = node.y - node.height / 2;
  const strokeColor = node.emphasis
    ? 'var(--diagram-accent-blue)'
    : 'var(--diagram-node-border)';
  const strokeWidth = node.emphasis ? 1.6 : 1;
  const nodeAnimDelay = `${rank * 60}ms`;

  return (
    <g className="fd-flow-node" style={{ animationDelay: nodeAnimDelay }}>
      <rect
        x={x}
        y={y}
        width={node.width}
        height={node.height}
        rx={6}
        ry={6}
        style={{
          fill: node.emphasis
            ? 'var(--diagram-node-emphasis-bg)'
            : 'var(--diagram-node-bg)',
          stroke: strokeColor,
          strokeWidth,
        }}
      />

      {/* Role rail pairs a stable icon and text label with color. This keeps
          the diagram accessible without turning every component into a
          different pictogram shape. */}
      {style.accent && (
        <rect
          x={x}
          y={y}
          width={STRIPE_WIDTH}
          height={node.height}
          rx={3}
          ry={3}
          style={{ fill: node.emphasis ? 'var(--diagram-accent-blue)' : style.accent }}
        />
      )}

      <g transform={`translate(${x}, ${y})`}>
        <NodeLabel
          width={node.width}
          height={node.height}
          lines={node.lines}
          kind={node.kind}
          emphasis={node.emphasis}
        />
      </g>

      {processStep !== undefined && (
        <text
          x={x + node.width - 14}
          y={y + 19}
          textAnchor="end"
          aria-hidden="true"
          style={{
            fill: 'var(--diagram-row-number)',
            fontFamily: 'var(--font-mono), ui-monospace, monospace',
            fontSize: 9,
            fontWeight: 720,
            letterSpacing: '0.08em',
          }}
        >
          {String(processStep).padStart(2, '0')}
        </text>
      )}
    </g>
  );
}

function FlowEdge({
  edge,
  markerId,
  fromRank,
}: {
  edge: ResolvedEdge;
  markerId: string;
  // Source-node rank. The edge animation starts a half-step after the
  // source node's entrance lands so the line "draws out" of an
  // already-visible node.
  fromRank: number;
}) {
  if (edge.points.length < 2) return null;
  const isEmphasis = edge.emphasis;
  const stroke = isEmphasis ? 'var(--diagram-accent-blue)' : 'var(--diagram-edge)';
  const strokeWidth = isEmphasis ? 1.75 : 1.25;
  const dasharray = edge.variant === 'dashed' ? '6 5' : undefined;
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
  const firstPoint = edge.points[0];
  const lastPoint = edge.points[edge.points.length - 1];
  const mid = edge.labelPoint ?? {
    x: (firstPoint.x + lastPoint.x) / 2,
    y: (firstPoint.y + lastPoint.y) / 2,
  };

  // Edge starts as soon as the source node has settled (rank * 60ms +
  // half a step). The label fades in 240ms after the line begins so
  // it never lands before the path it sits on is visible.
  const edgeDelayMs = (fromRank + 0.5) * 60;
  const edgeAnimDelay = `${edgeDelayMs}ms`;
  const labelAnimDelay = `${edgeDelayMs + 240}ms`;

  return (
    <g>
      <path
        className="fd-flow-edge"
        d={d}
        style={{
          fill: 'none',
          stroke,
          strokeWidth,
          strokeLinecap: 'round',
          strokeLinejoin: 'round',
          strokeDasharray: dasharray,
          animationDelay: edgeAnimDelay,
        }}
        markerStart={markerStart}
        markerEnd={markerEnd}
      />
      {edge.label && (
        <EdgeLabelChip
          x={mid.x}
          y={mid.y}
          label={edge.label}
          animationDelay={labelAnimDelay}
        />
      )}
    </g>
  );
}

function EdgeLabelChip({
  x,
  y,
  label,
  animationDelay,
}: {
  x: number;
  y: number;
  label: string;
  animationDelay?: string;
}) {
  // Estimate chip width from char count. The chip uses an HTML
  // foreignObject so we get full font fallback and crisp anti-aliased
  // text instead of SVG <text> spacing quirks.
  const chipW = Math.min(220, Math.max(40, label.length * 6.4 + 14));
  const chipH = 20;
  return (
    <foreignObject
      className="fd-flow-edge-label"
      x={x - chipW / 2}
      y={y - chipH / 2}
      width={chipW}
      height={chipH}
      style={animationDelay ? { animationDelay } : undefined}
    >
      <ForeignDiv
        style={{
          width: '100%',
          height: '100%',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          padding: '0 6px',
          boxSizing: 'border-box',
          fontFamily: 'var(--font-mono), ui-monospace, monospace',
          fontSize: '10px',
          fontWeight: 650,
          color: 'var(--diagram-edge-label)',
          background: 'var(--diagram-canvas)',
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
