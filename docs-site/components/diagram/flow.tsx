import * as React from 'react';
import dagre from '@dagrejs/dagre';
import type { Graph, GraphLabel, NodeLabel as DagreNodeLabel, EdgeLabel } from '@dagrejs/dagre';
import {
  type DiagramKind,
  type EdgeVariant,
  type ZoneTone,
  ARTICLE_WIDTH_TARGET,
  KIND_TO_STYLE,
  STRIPE_WIDTH,
  ZONE_TONE_STYLE,
  DiagramDefs,
  NodeLabel,
  ForeignDiv,
  flattenToLines,
  measureLabel,
  orthogonalRoute,
  smoothPath,
  nextDiagramId,
} from './shared';
import { DiagramLightbox } from './lightbox';

// Marker symbols. <Node>, <Edge> and <Zone> are pure data carriers —
// they return null but are tagged via a non-enumerable property so
// <Flow> can identify them inside React.Children without relying on
// component-name strings (which break under prod minification).
const NODE_MARKER = Symbol.for('defenseclaw.diagram.Node');
const EDGE_MARKER = Symbol.for('defenseclaw.diagram.Edge');
const ZONE_MARKER = Symbol.for('defenseclaw.diagram.Zone');
const EDGE_LABEL_MIN_WIDTH = 40;
const EDGE_LABEL_MAX_WIDTH = 220;
const EDGE_LABEL_CHAR_WIDTH = 6.4;
const EDGE_LABEL_PADDING = 14;

function measureEdgeLabel(label?: string): number {
  if (!label) return 0;
  return Math.min(
    EDGE_LABEL_MAX_WIDTH,
    Math.max(EDGE_LABEL_MIN_WIDTH, label.length * EDGE_LABEL_CHAR_WIDTH + EDGE_LABEL_PADDING),
  );
}

// Zone geometry. Each zone is a dagre compound cluster, which reserves
// a region only its members (and their edges) may occupy: ranksep/2
// beyond the members along the rank axis, (nodesep + edgesep)/2 across
// it. The frame is drawn from the member slots plus the padding below,
// which always fits inside that region. The frame is not drawn on the
// cluster bounds themselves: those sit exactly on the border ranks
// where edges dogleg (a frame there would run along edge segments),
// they stretch around edge dummies, and dagre takes them from the last
// rank's border nodes only.
const ZONE_PAD_SIDE = 16;
// Half the badge (it straddles the top border) plus clearance above
// the first member.
const ZONE_PAD_TOP = 24;
const ZONE_PAD_BOTTOM = 16;
// Compact TB spacing for zoned flows. Every zone spends its padding on
// both sides, so siblings sit closer (nodesep 38 -> 30, edgesep
// 24 -> 16) to keep a three-zone rank near the article column; that
// still reserves (30 + 16) / 2 = 23px beside members, 7px beyond the
// frame. ranksep grows (54 -> 64) so ranksep/2 clears ZONE_PAD_TOP by
// 8px and an edge dogleg on a cluster's border rank never lands on
// the frame line. LR keeps its spacing, which already clears the pads.
const ZONE_TB_NODESEP = 30;
const ZONE_TB_EDGESEP = 16;
const ZONE_TB_RANKSEP = 64;
const ZONE_RADIUS = 8;
const ZONE_BADGE_HEIGHT = 18;
const ZONE_BADGE_INSET = 12;
const ZONE_BADGE_PAD_X = 7;
const ZONE_BADGE_GAP = 6;
// 8.5px mono caps with 0.08em tracking, and 10.5px semibold sans.
// Deliberately generous, like the node estimates: a badge that is a
// little long is fine, a clipped zone name is not.
const ZONE_TONE_CHAR_WIDTH = 6;
const ZONE_LABEL_CHAR_WIDTH = 5.6;
// Layouts per Flow, at most: the first, plus re-layouts after widening
// member slots for badges. One re-layout is normally enough.
const ZONE_LAYOUT_PASSES = 3;

function measureZoneBadge(label: string, tone: ZoneTone): number {
  return Math.ceil(
    ZONE_BADGE_PAD_X * 2 +
      ZONE_TONE_STYLE[tone].label.length * ZONE_TONE_CHAR_WIDTH +
      ZONE_BADGE_GAP +
      label.length * ZONE_LABEL_CHAR_WIDTH,
  );
}

export interface NodeProps {
  id: string;
  kind?: DiagramKind;
  emphasis?: boolean;
  // Id of the <Zone> this node sits in. Only needed when the node is
  // not nested inside its <Zone>; nesting wins if both are given.
  zone?: string;
  children?: React.ReactNode;
}

export interface EdgeProps {
  from: string;
  to: string;
  label?: string;
  variant?: EdgeVariant;
  emphasis?: boolean;
}

export interface ZoneProps {
  id: string;
  // Printed on the zone badge, e.g. "Z1 · Privileged services".
  label: string;
  // Printed on the badge next to the label and drives the tint.
  tone: ZoneTone;
  // <Node> (and optionally <Edge>) children. A zone may instead be
  // declared empty and populated with <Node zone="id">.
  children?: React.ReactNode;
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

// eslint-disable-next-line @typescript-eslint/no-unused-vars
export function Zone(_props: ZoneProps): React.ReactElement | null {
  return null;
}
(Zone as unknown as { __diagramKind: symbol }).__diagramKind = ZONE_MARKER;

type ZoneSpec = Omit<ZoneProps, 'children'>;

interface ResolvedZone {
  id: string;
  label: string;
  tone: ZoneTone;
  members: string[];
  badgeWidth: number;
}

interface Rect {
  x: number;
  y: number;
  width: number;
  height: number;
}

interface PlacedZone extends ResolvedZone, Rect {
  // Left edge of the badge; it straddles the zone's top border.
  badgeX: number;
}

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
  // Tighten dagre spacing (`ranksep` 78→54, `nodesep` 56→38) and
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

// Read all <Node>/<Edge>/<Zone> children, ignore stray whitespace/p-tags
// from the MDX renderer, and bucket them by marker. Nodes nested in a
// <Zone> are tagged with that zone's id.
function partitionChildren(children: React.ReactNode): {
  nodes: NodeProps[];
  edges: EdgeProps[];
  zones: ZoneSpec[];
} {
  const nodes: NodeProps[] = [];
  const edges: EdgeProps[] = [];
  const zones: ZoneSpec[] = [];
  const walk = (list: React.ReactNode, zoneId?: string) => {
    React.Children.forEach(list, (child) => {
      if (!React.isValidElement(child)) return;
      const marker = (child.type as unknown as { __diagramKind?: symbol }).__diagramKind;
      if (marker === NODE_MARKER) {
        const props = child.props as NodeProps;
        if (zoneId === undefined) {
          nodes.push(props);
          return;
        }
        if (props.zone !== undefined && props.zone !== zoneId) {
          console.warn(
            `[diagram] <Node id="${props.id}" zone="${props.zone}"> is nested in <Zone id="${zoneId}">; using "${zoneId}".`,
          );
        }
        nodes.push({ ...props, zone: zoneId });
      } else if (marker === EDGE_MARKER) {
        edges.push(child.props as EdgeProps);
      } else if (marker === ZONE_MARKER) {
        const { children: zoneChildren, ...spec } = child.props as ZoneProps;
        if (zoneId !== undefined) {
          // Zones do not nest; the inner one is drawn as a sibling.
          console.warn(
            `[diagram] <Zone id="${spec.id}"> is nested in <Zone id="${zoneId}">; zones do not nest, drawing it as a sibling.`,
          );
        }
        zones.push(spec);
        walk(zoneChildren, spec.id);
      }
      // Anything else (whitespace, accidental <p>) is silently dropped —
      // authors get a clean error from the missing-id check below if a
      // typo turns into a no-op.
    });
  };
  walk(children);
  return { nodes, edges, zones };
}

// Match nodes to zones, drop zones nobody sits in (dagre would lay an
// empty cluster out as a stray point), and flag authoring mistakes
// without failing the page.
function resolveZones(specs: ZoneSpec[], nodes: NodeProps[]): ResolvedZone[] {
  const byId = new Map<string, ResolvedZone>();
  for (const spec of specs) {
    if (byId.has(spec.id)) {
      console.warn(`[diagram] duplicate <Zone id="${spec.id}">; keeping the first.`);
      continue;
    }
    let tone = spec.tone;
    if (!Object.hasOwn(ZONE_TONE_STYLE, tone)) {
      // Assume the least trust rather than guess a friendlier tone.
      console.warn(`[diagram] <Zone id="${spec.id}"> has unknown tone "${String(tone)}"; using "external".`);
      tone = 'external';
    }
    const label = spec.label ?? spec.id;
    byId.set(spec.id, {
      id: spec.id,
      label,
      tone,
      members: [],
      badgeWidth: measureZoneBadge(label, tone),
    });
  }
  for (const node of nodes) {
    if (node.zone === undefined) continue;
    const zone = byId.get(node.zone);
    if (!zone) {
      console.warn(`[diagram] <Node id="${node.id}"> references unknown zone "${node.zone}".`);
      continue;
    }
    if (!zone.members.includes(node.id)) zone.members.push(node.id);
  }
  const zones: ResolvedZone[] = [];
  for (const zone of byId.values()) {
    if (zone.members.length === 0) {
      console.warn(`[diagram] <Zone id="${zone.id}"> has no nodes; skipping it.`);
      continue;
    }
    zones.push(zone);
  }
  return zones;
}

// Dagre node id for a zone's cluster. The NUL prefix keeps it from
// colliding with any author-chosen node id.
function zoneClusterId(id: string): string {
  return `\u0000zone:${id}`;
}

export function Flow({
  direction = 'LR',
  caption,
  fit = 'auto',
  compact,
  oversize = false,
  children,
}: FlowProps) {
  const { nodes: nodeProps, edges: edgeProps, zones: zoneSpecs } = partitionChildren(children);
  const zones = resolveZones(zoneSpecs, nodeProps);
  // Every zone-specific branch below keys off this, so a Flow without
  // (populated) zones takes exactly the pre-zone code path.
  const hasZones = zones.length > 0;

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
  const compactNodeWidth = nodeProps.reduce((sum, node) => {
    const kind = node.kind ?? 'generic';
    const measured = measureLabel(flattenToLines(node.children), {
      kind,
      compact: true,
    });
    return sum + measured.width;
  }, 0);
  const compactTransitionWidth = edgeProps.reduce((sum, edge) => {
    const labelWidth = measureEdgeLabel(edge.label);
    return sum + Math.max(54, labelWidth);
  }, 0);
  const compactCandidateWidth = compactNodeWidth + compactTransitionWidth + 56;
  // Zoned flows keep the author's direction and topology-sized cards:
  // the zone frames are the organizing structure, so the chain
  // promotions and the dense geometry (whose 11px side gap cannot fit
  // a zone border) do not apply.
  const autoLinearHorizontal =
    !hasZones &&
    direction === 'TB' &&
    compact !== false &&
    isLinear &&
    nodeProps.length <= 5 &&
    compactCandidateWidth <= ARTICLE_WIDTH_TARGET;
  const layoutDirection: 'LR' | 'TB' = autoLinearHorizontal ? 'LR' : direction;
  const compactMode = compact ?? (layoutDirection === 'TB' || autoLinearHorizontal);
  const processRail = !hasZones && direction === 'TB' && isLinear && !autoLinearHorizontal;
  const denseMode =
    !hasZones && layoutDirection === 'TB' && !processRail && nodeProps.length >= 10;

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

  const zonedTB = hasZones && layoutDirection === 'TB';
  const marginX = denseMode ? 16 : compactMode ? 26 : 28;
  const marginY = denseMode ? 16 : 28;

  // Build the dagre graph. Spacing is tuned a touch wider than the
  // dagre defaults so labels don't crowd their neighbors at docs
  // widths. `compact` halves the breathing room — useful when the
  // graph is structurally fine but bumping up against the column.
  //
  // Zones become dagre compound clusters. `extraWidth` widens a
  // node's layout slot (not its card) so a zone can fit its badge.
  const runLayout = (extraWidth?: Map<string, number>) => {
    const g = hasZones
      ? new dagre.graphlib.Graph<GraphLabel, DagreNodeLabel, EdgeLabel>({ compound: true })
      : new dagre.graphlib.Graph<GraphLabel, DagreNodeLabel, EdgeLabel>();
    g.setGraph({
      rankdir: layoutDirection,
      nodesep: denseMode ? 10 : compactMode ? (zonedTB ? ZONE_TB_NODESEP : 38) : 56,
      ranksep: denseMode ? 50 : compactMode ? (zonedTB ? ZONE_TB_RANKSEP : 54) : 78,
      edgesep: denseMode ? 12 : zonedTB ? ZONE_TB_EDGESEP : 24,
      marginx: marginX,
      marginy: marginY,
    });
    g.setDefaultEdgeLabel(() => ({}));

    for (const n of resolved) {
      g.setNode(n.id, { width: n.width + (extraWidth?.get(n.id) ?? 0), height: n.height });
    }
    for (const zone of zones) {
      g.setNode(zoneClusterId(zone.id), { width: 0, height: 0 });
      for (const member of zone.members) g.setParent(member, zoneClusterId(zone.id));
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
        width: measureEdgeLabel(e.label),
        height: e.label ? 22 : 0,
      });
    }

    dagre.layout(g);
    return g;
  };

  let g = runLayout();

  // A zone must be wide enough for its badge. When one is not, widen
  // its widest member's slot until that slot alone spans the badge,
  // which guarantees the fit on the next layout however dagre places
  // the other members. The card keeps its measured size, centered in
  // the wider slot. Re-check every zone after each layout: moving one
  // zone can narrow another whose width came from offset members.
  const extraWidth = new Map<string, number>();
  if (hasZones) {
    for (let pass = 1; pass < ZONE_LAYOUT_PASSES; pass++) {
      let grew = false;
      for (const zone of zones) {
        const needed = zone.badgeWidth + ZONE_BADGE_INSET * 2;
        if (zoneBounds(g, zone, idToNode, extraWidth).width >= needed) continue;
        const widest = zone.members.reduce((best, memberId) =>
          (idToNode.get(memberId)?.width ?? 0) > (idToNode.get(best)?.width ?? 0) ? memberId : best,
        );
        const extra = Math.ceil(needed - ZONE_PAD_SIDE * 2 - (idToNode.get(widest)?.width ?? 0));
        if (extra > (extraWidth.get(widest) ?? 0)) {
          extraWidth.set(widest, extra);
          grew = true;
        }
      }
      if (!grew) break;
      g = runLayout(extraWidth);
    }
  }

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
  let contentWidth = graphLabel.width ?? 0;
  let contentHeight = graphLabel.height ?? 0;

  let placedZones: PlacedZone[] = [];
  if (hasZones) {
    // Dagre routed edges to the widened slot; pull the ends of those
    // edges back onto the visible card.
    if (extraWidth.size > 0) {
      for (const edge of resolvedEdges) {
        const pts = edge.points;
        if (pts.length < 2 || edge.from === edge.to) continue;
        const source = idToNode.get(edge.from);
        const target = idToNode.get(edge.to);
        const next = [...pts];
        if (source && extraWidth.has(source.id)) next[0] = intersectRect(source, pts[1]);
        if (target && extraWidth.has(target.id)) {
          next[next.length - 1] = intersectRect(target, pts[pts.length - 2]);
        }
        edge.points = next;
      }
    }

    placedZones = placeZoneBadges(
      zones.map((zone) => ({ ...zone, ...zoneBounds(g, zone, idToNode, extraWidth) })),
      resolvedEdges,
    );
    // Frames sit inside their clusters, which dagre already counted in
    // the graph size; take the max anyway so the width gate and the
    // lightbox can never see a frame poke out of the viewBox.
    contentWidth = Math.max(contentWidth, ...placedZones.map((z) => z.x + z.width + marginX));
    contentHeight = Math.max(contentHeight, ...placedZones.map((z) => z.y + z.height + marginY));
  }

  const width = Math.ceil(contentWidth) + 16;
  const height = Math.ceil(contentHeight) + 16;

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

      {/* Zone frames sit underneath everything else. */}
      {placedZones.length > 0 && (
        <g className="fd-flow-zones">
          {placedZones.map((zone) => (
            <FlowZone key={zone.id} zone={zone} />
          ))}
        </g>
      )}

      {/* Edges first so they sit underneath the node panels. */}
      {resolvedEdges.map((edge, i) => (
        <FlowEdge
          key={`e-${i}`}
          edge={edge}
          markerId={id}
          fromRank={rankById.get(edge.from) ?? 0}
        />
      ))}

      {/* Zone badges go over the edges, like edge label chips, so an
          edge entering a zone never strikes through its name. Padding
          keeps them clear of every node. */}
      {placedZones.length > 0 && (
        <g className="fd-flow-zone-badges">
          {placedZones.map((zone) => (
            <FlowZoneBadge key={zone.id} zone={zone} />
          ))}
        </g>
      )}

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

// Zone frame: the member layout slots (a card plus any badge-driven
// widening) padded by ZONE_PAD_*. See the note on ZONE_PAD_SIDE for
// why this, and not dagre's cluster bounds, is what gets drawn.
function zoneBounds(
  g: Graph<GraphLabel, DagreNodeLabel, EdgeLabel>,
  zone: ResolvedZone,
  idToNode: Map<string, ResolvedNode>,
  extraWidth: Map<string, number>,
): Rect {
  let left = Infinity;
  let top = Infinity;
  let right = -Infinity;
  let bottom = -Infinity;
  for (const memberId of zone.members) {
    const laid = g.node(memberId);
    const card = idToNode.get(memberId);
    if (!laid || !card) continue;
    const x = laid.x ?? 0;
    const y = laid.y ?? 0;
    const halfW = (card.width + (extraWidth.get(memberId) ?? 0)) / 2;
    left = Math.min(left, x - halfW - ZONE_PAD_SIDE);
    right = Math.max(right, x + halfW + ZONE_PAD_SIDE);
    top = Math.min(top, y - card.height / 2 - ZONE_PAD_TOP);
    bottom = Math.max(bottom, y + card.height / 2 + ZONE_PAD_BOTTOM);
  }
  return { x: left, y: top, width: right - left, height: bottom - top };
}

// Where a line from the card's center toward `point` leaves the card.
// Mirrors dagre's own endpoint rule.
function intersectRect(
  node: ResolvedNode,
  point: { x: number; y: number },
): { x: number; y: number } {
  const dx = point.x - node.x;
  const dy = point.y - node.y;
  if (dx === 0 && dy === 0) return { x: node.x, y: node.y };
  let halfW = node.width / 2;
  let halfH = node.height / 2;
  if (Math.abs(dy) * halfW > Math.abs(dx) * halfH) {
    if (dy < 0) halfH = -halfH;
    return { x: node.x + (halfH * dx) / dy, y: node.y + halfH };
  }
  if (dx < 0) halfW = -halfW;
  return { x: node.x + halfW, y: node.y + (halfW * dy) / dx };
}

// Pick where each badge sits along its zone's top border: left-aligned
// unless another spot crosses fewer edges or edge label chips. Edges
// still pass under a badge when every spot is crossed; the badge is
// opaque, so the name stays legible either way.
function placeZoneBadges(
  zones: (ResolvedZone & Rect)[],
  edges: ResolvedEdge[],
): PlacedZone[] {
  const chips: Rect[] = edges
    .filter((edge) => edge.label && edge.labelPoint)
    .map((edge) => {
      const w = measureEdgeLabel(edge.label);
      return { x: edge.labelPoint!.x - w / 2, y: edge.labelPoint!.y - 10, width: w, height: 20 };
    });
  const routes = edges
    .filter((edge) => edge.points.length >= 2)
    .map((edge) => orthogonalRoute(edge.points));
  const overlaps = (a: Rect, b: Rect) =>
    a.x < b.x + b.width && b.x < a.x + a.width && a.y < b.y + b.height && b.y < a.y + a.height;

  return zones.map((zone) => {
    const badgeW = Math.min(zone.badgeWidth, zone.width - ZONE_BADGE_INSET * 2);
    const minX = zone.x + ZONE_BADGE_INSET;
    const maxX = zone.x + zone.width - ZONE_BADGE_INSET - badgeW;
    const bandTop = zone.y - ZONE_BADGE_HEIGHT / 2;
    const bandBottom = zone.y + ZONE_BADGE_HEIGHT / 2;

    // x positions where a drawn (right-angle) edge segment passes
    // through the badge band.
    const crossings: number[] = [];
    for (const route of routes) {
      for (let i = 1; i < route.length; i++) {
        const a = route[i - 1];
        const b = route[i];
        if (Math.max(a.y, b.y) < bandTop || Math.min(a.y, b.y) > bandBottom) continue;
        if (Math.abs(a.x - b.x) < 0.5) crossings.push(a.x);
        else crossings.push(a.x, b.x, (a.x + b.x) / 2);
      }
    }

    const candidates = [minX, maxX];
    for (const cx of crossings) candidates.push(cx + 8, cx - 8 - badgeW);
    let bestX = minX;
    let bestScore = Infinity;
    for (const raw of candidates) {
      const x = Math.min(maxX, Math.max(minX, raw));
      const band = { x, y: bandTop, width: badgeW, height: ZONE_BADGE_HEIGHT };
      const crossed = crossings.filter((cx) => cx > x - 2 && cx < x + badgeW + 2).length;
      const chipHits = chips.filter((chip) => overlaps(chip, band)).length;
      // A covered edge label is worse than an edge passing underneath.
      const score = chipHits * 100 + crossed;
      if (score < bestScore || (score === bestScore && x < bestX)) {
        bestScore = score;
        bestX = x;
      }
    }
    return { ...zone, badgeWidth: badgeW, badgeX: bestX };
  });
}

function isLinearChain(nodes: NodeProps[], edges: EdgeProps[]): boolean {
  if (nodes.length < 2 || edges.length !== nodes.length - 1) return false;
  const ids = new Set(nodes.map((node) => node.id));
  if (ids.size !== nodes.length) return false;
  const incoming = new Map(nodes.map((node) => [node.id, 0]));
  const outgoing = new Map(nodes.map((node) => [node.id, 0]));
  const nextById = new Map<string, string>();
  for (const edge of edges) {
    if (!ids.has(edge.from) || !ids.has(edge.to)) return false;
    incoming.set(edge.to, (incoming.get(edge.to) ?? 0) + 1);
    outgoing.set(edge.from, (outgoing.get(edge.from) ?? 0) + 1);
    if (nextById.has(edge.from)) return false;
    nextById.set(edge.from, edge.to);
  }
  let starts = 0;
  let ends = 0;
  let startId: string | undefined;
  for (const id of ids) {
    const inCount = incoming.get(id) ?? 0;
    const outCount = outgoing.get(id) ?? 0;
    if (inCount === 0 && outCount === 1) {
      starts += 1;
      startId = id;
    }
    else if (inCount === 1 && outCount === 0) ends += 1;
    else if (inCount !== 1 || outCount !== 1) return false;
  }
  if (starts !== 1 || ends !== 1 || !startId) return false;

  const visited = new Set<string>();
  let cursor: string | undefined = startId;
  while (cursor && !visited.has(cursor)) {
    visited.add(cursor);
    cursor = nextById.get(cursor);
  }
  return cursor === undefined && visited.size === ids.size;
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

function zoneStroke(tone: ZoneTone): string {
  return `color-mix(in oklab, ${ZONE_TONE_STYLE[tone].accent} 46%, var(--diagram-border))`;
}

function FlowZone({ zone }: { zone: PlacedZone }) {
  const tone = ZONE_TONE_STYLE[zone.tone];
  return (
    <rect
      className="fd-flow-zone"
      data-zone={zone.id}
      data-zone-tone={zone.tone}
      x={zone.x}
      y={zone.y}
      width={zone.width}
      height={zone.height}
      rx={ZONE_RADIUS}
      ry={ZONE_RADIUS}
      style={{
        fill: tone.fill,
        stroke: zoneStroke(zone.tone),
        strokeWidth: 1,
        strokeDasharray: tone.dash,
      }}
    />
  );
}

// The zone's name tag, straddling its top border: tone name first (the
// same uppercase classification line nodes use), then the label.
function FlowZoneBadge({ zone }: { zone: PlacedZone }) {
  const tone = ZONE_TONE_STYLE[zone.tone];
  return (
    <foreignObject
      className="fd-flow-zone-badge"
      data-zone={zone.id}
      x={zone.badgeX}
      y={zone.y - ZONE_BADGE_HEIGHT / 2}
      width={zone.badgeWidth}
      height={ZONE_BADGE_HEIGHT}
    >
      <ForeignDiv
        style={{
          width: '100%',
          height: '100%',
          display: 'flex',
          alignItems: 'center',
          gap: `${ZONE_BADGE_GAP}px`,
          padding: `0 ${ZONE_BADGE_PAD_X - 1}px`,
          boxSizing: 'border-box',
          border: `1px solid ${zoneStroke(zone.tone)}`,
          borderRadius: '4px',
          background: 'var(--diagram-canvas)',
          whiteSpace: 'nowrap',
          overflow: 'hidden',
        }}
      >
        <span
          style={{
            flex: '0 0 auto',
            color: tone.accent,
            fontFamily: 'var(--font-mono), ui-monospace, monospace',
            fontSize: '8.5px',
            fontWeight: 750,
            letterSpacing: '0.08em',
            lineHeight: 1,
            textTransform: 'uppercase',
          }}
        >
          {tone.label}
        </span>
        <span
          style={{
            minWidth: 0,
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            color: 'var(--diagram-text)',
            fontFamily: 'var(--font-sans), system-ui, sans-serif',
            fontSize: '10.5px',
            fontWeight: 650,
            lineHeight: 1,
            letterSpacing: '-0.005em',
          }}
        >
          {zone.label}
        </span>
      </ForeignDiv>
    </foreignObject>
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
  const chipW = measureEdgeLabel(label);
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
